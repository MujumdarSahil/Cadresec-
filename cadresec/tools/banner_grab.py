import socket
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.evidence import Evidence
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService, Endpoint, ConnectionInfo, OCSFNetworkActivity


class BannerGrabInput(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    port: int = Field(..., description="TCP port to grab banner from")
    timeout_seconds: int = Field(default=5, description="Timeout in seconds")


class BannerGrabOutput(BaseModel):
    target: str = Field(..., description="Scan target IP/hostname")
    port: int = Field(..., description="Port scanned")
    success: bool = Field(..., description="True if connection succeeded and banner/response retrieved")
    banner: str = Field(default="", description="Raw banner string retrieved")
    service_guess: str = Field(default="unknown", description="Heuristic guess of the service type")
    evidence: List[Evidence] = Field(default_factory=list, description="Extracted Evidence objects")
    actual_scanned_address: str = Field(default="", description="The raw IP address/hostname requested")


class BannerGrabToolSpec(ToolSpec):
    name: str = "banner_grab"
    description: str = "Connects to a TCP port, grabs the service banner, and guesses the service type"
    risk_tier: RiskTier = RiskTier.ACTIVE_SAFE
    input_schema: type[BaseModel] = BannerGrabInput
    output_schema: type[BaseModel] = BannerGrabOutput
    sandbox_requirements: Dict[str, Any] = {}
    source: str = "builtin"

    def _execute(self, session, input_data: BannerGrabInput, use_sandbox: bool = True) -> BannerGrabOutput:
        target = input_data.target.strip()
        port = input_data.port
        timeout = input_data.timeout_seconds
        banner = ""
        success = False
        service_guess = "unknown"
        evidence_list = []

        # 1. Log NetworkActivity (4001) connection attempt
        activity = OCSFNetworkActivity(
            src_endpoint=Endpoint(ip="127.0.0.1"),
            dst_endpoint=Endpoint(ip=target, port=port),
            connection_info=ConnectionInfo(
                protocol_name="TCP",
                state="open"
            ),
            session_id=session.session_id
        )
        session.ocsf.write_event(session.session_id, 4001, activity)

        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                # Some servers send a banner immediately upon connection (e.g. SSH, FTP, SMTP)
                sock.settimeout(2.0)
                try:
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode("utf-8", errors="ignore").strip()
                        success = True
                except socket.timeout:
                    # Server didn't talk first, send a generic probe
                    pass

                if not banner:
                    # If it's a common web port, send an HTTP request probe
                    if port in (80, 443, 8080, 8443):
                        probe = f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n"
                    else:
                        probe = "\r\n"
                    
                    try:
                        sock.sendall(probe.encode("utf-8"))
                        data = sock.recv(1024)
                        if data:
                            banner = data.decode("utf-8", errors="ignore").strip()
                            success = True
                    except Exception:
                        pass

        except Exception:
            # Connection refused, timeout, host unreachable, etc.
            pass

        if success and banner:
            # 2. Service heuristic guessing
            banner_lower = banner.lower()
            if banner.startswith("SSH-"):
                service_guess = "ssh"
            elif banner.startswith("220") and ("ftp" in banner_lower or "vsftpd" in banner_lower):
                service_guess = "ftp"
            elif banner.startswith("220") and ("smtp" in banner_lower or "postfix" in banner_lower or "mail" in banner_lower):
                service_guess = "smtp"
            elif "http/" in banner_lower or "html" in banner_lower:
                service_guess = "http"
            elif "mysql" in banner_lower or "mariadb" in banner_lower:
                service_guess = "mysql"
            elif "redis" in banner_lower or "-err" in banner_lower or "pong" in banner_lower:
                service_guess = "redis"

            # 3. Populate Evidence list
            # General banner evidence
            evidence_list.append(Evidence(
                category="banner",
                value=banner,
                confidence=1.0,
                source="Banner Grab",
                originating_tool=self.name
            ))
            # Service guess evidence
            evidence_list.append(Evidence(
                category="server",
                value=service_guess,
                confidence=0.8,
                source="Banner Guess",
                originating_tool=self.name
            ))

            # 4. Log Discovery event (5010) with service description
            discovery = OCSFDiscovery(
                device=DiscoveryDevice(
                    ip=target,
                    hostname=target,
                    description=f"TCP port {port} banner grabbed. Guessed service: {service_guess}.",
                    services=[
                        DiscoveredService(
                            port=port,
                            protocol="TCP",
                            service=service_guess,
                            state="open"
                        )
                    ]
                ),
                session_id=session.session_id
            )
            session.ocsf.write_event(session.session_id, 5010, discovery)

        return BannerGrabOutput(
            target=target,
            port=port,
            success=success,
            banner=banner,
            service_guess=service_guess,
            evidence=evidence_list,
            actual_scanned_address=target
        )
