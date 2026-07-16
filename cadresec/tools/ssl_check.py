import socket
import subprocess
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.exceptions import SandboxUnavailableError
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService
from cadresec.core.evidence import Evidence


class SSLInput(BaseModel):
    target: str = Field(..., description="Target hostname to check SSL cert expiry (e.g. google.com)")
    port: int = Field(default=443, description="SSL port number")


class SSLOutput(BaseModel):
    target: str = Field(..., description="Target hostname")
    success: bool = Field(..., description="True if certificate retrieved successfully")
    expiry_date: str = Field(default="", description="Expiration timestamp of the certificate")
    days_remaining: int = Field(default=-1, description="Days left until expiration")
    actual_scanned_address: str = Field(default="", description="The raw IP address/hostname requested")
    evidence: List[Evidence] = Field(default_factory=list, description="Extracted Evidence objects")


class SSLToolSpec(ToolSpec):
    name: str = "ssl_expiry"
    description: str = "Retrieves public SSL certificates and verifies expiry dates"
    risk_tier: RiskTier = RiskTier.ACTIVE_SAFE
    input_schema: type[BaseModel] = SSLInput
    output_schema: type[BaseModel] = SSLOutput
    sandbox_requirements: Dict[str, Any] = {
        "image": "python:3.11-alpine@sha256:8068890a42d68ece5b62455ef327253249b5f094dcdee57f492635a40217f6a3"
    }
    source: str = "builtin"

    def _execute(self, session, input_data: SSLInput, use_sandbox: bool = True) -> SSLOutput:
        if not use_sandbox:
            raise SandboxUnavailableError("Unsandboxed execution is disabled for ssl_expiry.")

        hostname = input_data.target.strip()
        port = input_data.port
        is_local = hostname.lower() in ("127.0.0.1", "localhost")
        scan_target = hostname
        success = False
        expiry_date = ""
        days_left = -1

        cmd = ["docker", "run", "--rm"]
        if is_local:
            cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
            scan_target = "host.docker.internal"

        script = (
            "import os\n"
            "import socket\n"
            "import ssl\n"
            "import json\n"
            "from datetime import datetime, timezone\n"
            "target = os.environ.get('TARGET')\n"
            "port = int(os.environ.get('PORT'))\n"
            "server_hostname = os.environ.get('SERVER_HOSTNAME')\n"
            "success = False\n"
            "expiry_date = ''\n"
            "days_remaining = -1\n"
            "try:\n"
            "    context = ssl.create_default_context()\n"
            "    with socket.create_connection((target, port), timeout=5) as sock:\n"
            "        with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:\n"
            "            cert = ssock.getpeercert()\n"
            "    expiry_str = cert.get('notAfter', '')\n"
            "    expiry_dt = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)\n"
            "    now = datetime.now(timezone.utc)\n"
            "    days_remaining = (expiry_dt - now).days\n"
            "    expiry_date = expiry_dt.isoformat()\n"
            "    success = True\n"
            "except Exception:\n"
            "    pass\n"
            "print(json.dumps({'success': success, 'expiry_date': expiry_date, 'days_remaining': days_remaining}))\n"
        )

        cmd.extend([
            "-e", f"TARGET={scan_target}",
            "-e", f"PORT={port}",
            "-e", f"SERVER_HOSTNAME={hostname}",
            "python:3.11-alpine@sha256:8068890a42d68ece5b62455ef327253249b5f094dcdee57f492635a40217f6a3",
            "python", "-c", script
        ])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            res = json.loads(proc.stdout.strip())
            success = res.get("success", False)
            expiry_date = res.get("expiry_date", "")
            days_left = res.get("days_remaining", -1)
        except Exception:
            success = False
            expiry_date = ""
            days_left = -1

        if success and days_left >= 0:
            # Map findings to OCSF Discovery Class 5010
            discovery = OCSFDiscovery(
                device=DiscoveryDevice(
                    ip=hostname,
                    hostname=hostname,
                    description=f"SSL certificate verified. Days remaining: {days_left}",
                    services=[
                        DiscoveredService(
                            port=port,
                            protocol="TCP",
                            service="https",
                            state="open"
                        )
                    ]
                ),
                session_id=session.session_id
            )
            session.ocsf.write_event(session.session_id, 5010, discovery)
            
            evidence_list = [
                Evidence(
                    category="tls_expiry",
                    value=str(days_left),
                    confidence=1.0,
                    source="SSL Certificate",
                    originating_tool=self.name
                )
            ]
        else:
            evidence_list = []

        return SSLOutput(
            target=hostname,
            success=success,
            expiry_date=expiry_date,
            days_remaining=days_left,
            actual_scanned_address=scan_target,
            evidence=evidence_list
        )
