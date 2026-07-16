import socket
import subprocess
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.evidence import Evidence
from cadresec.core.exceptions import SandboxUnavailableError
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService, Endpoint, ConnectionInfo, OCSFNetworkActivity


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


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
    sandbox_requirements: Dict[str, Any] = {
        "image": "python:3.11-alpine@sha256:8068890a42d68ece5b62455ef327253249b5f094dcdee57f492635a40217f6a3"
    }
    source: str = "builtin"

    def _execute(self, session, input_data: BannerGrabInput, use_sandbox: bool = True) -> BannerGrabOutput:
        if not use_sandbox:
            raise SandboxUnavailableError("Unsandboxed execution is disabled for banner_grab.")

        original_target = input_data.target.strip()
        scan_target = original_target
        is_local = original_target.lower() in ("127.0.0.1", "localhost")
        port = input_data.port
        timeout = input_data.timeout_seconds
        banner = ""
        success = False
        service_guess = "unknown"
        evidence_list = []

        # 1. Log NetworkActivity (4001) connection attempt using resolved host IP
        activity = OCSFNetworkActivity(
            src_endpoint=Endpoint(ip=get_local_ip()),
            dst_endpoint=Endpoint(ip=original_target, port=port),
            connection_info=ConnectionInfo(
                protocol_name="TCP",
                state="open"
            ),
            session_id=session.session_id
        )
        session.ocsf.write_event(session.session_id, 4001, activity)

        cmd = ["docker", "run", "--rm"]
        if is_local:
            cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
            scan_target = "host.docker.internal"

        script = (
            "import os\n"
            "import socket\n"
            "import json\n"
            "target = os.environ.get('TARGET')\n"
            "port = int(os.environ.get('PORT'))\n"
            "timeout = int(os.environ.get('TIMEOUT', '5'))\n"
            "banner = ''\n"
            "success = False\n"
            "try:\n"
            "    with socket.create_connection((target, port), timeout=timeout) as sock:\n"
            "        sock.settimeout(2.0)\n"
            "        try:\n"
            "            data = sock.recv(1024)\n"
            "            if data:\n"
            "                banner = data.decode('utf-8', errors='ignore').strip()\n"
            "                success = True\n"
            "        except socket.timeout:\n"
            "            pass\n"
            "        if not banner:\n"
            "            probe = 'GET / HTTP/1.0\\r\\nHost: {}\\r\\n\\r\\n'.format(target) if port in (80, 443, 8080, 8443) else '\\r\\n'\n"
            "            try:\n"
            "                sock.sendall(probe.encode('utf-8'))\n"
            "                data = sock.recv(1024)\n"
            "                if data:\n"
            "                    banner = data.decode('utf-8', errors='ignore').strip()\n"
            "                    success = True\n"
            "            except Exception:\n"
            "                pass\n"
            "except Exception:\n"
            "    pass\n"
            "print(json.dumps({'success': success, 'banner': banner}))\n"
        )

        cmd.extend([
            "-e", f"TARGET={scan_target}",
            "-e", f"PORT={port}",
            "-e", f"TIMEOUT={timeout}",
            "python:3.11-alpine@sha256:8068890a42d68ece5b62455ef327253249b5f094dcdee57f492635a40217f6a3",
            "python", "-c", script
        ])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            res = json.loads(proc.stdout.strip())
            success = res.get("success", False)
            banner = res.get("banner", "")
        except Exception:
            success = False
            banner = ""

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
            evidence_list.append(Evidence(
                category="banner",
                value=banner,
                confidence=1.0,
                source="Banner Grab",
                originating_tool=self.name
            ))
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
                    ip=original_target,
                    hostname=original_target,
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
            target=original_target,
            port=port,
            success=success,
            banner=banner,
            service_guess=service_guess,
            evidence=evidence_list,
            actual_scanned_address=scan_target
        )
