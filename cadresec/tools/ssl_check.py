import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService


class SSLInput(BaseModel):
    target: str = Field(..., description="Target hostname to check SSL cert expiry (e.g. google.com)")
    port: int = Field(default=443, description="SSL port number")


class SSLOutput(BaseModel):
    target: str = Field(..., description="Target hostname")
    success: bool = Field(..., description="True if certificate retrieved successfully")
    expiry_date: str = Field(default="", description="Expiration timestamp of the certificate")
    days_remaining: int = Field(default=-1, description="Days left until expiration")
    actual_scanned_address: str = Field(default="", description="The raw IP address/hostname requested")


class SSLToolSpec(ToolSpec):
    name: str = "ssl_expiry"
    description: str = "Retrieves public SSL certificates and verifies expiry dates"
    risk_tier: RiskTier = RiskTier.ACTIVE_SAFE
    input_schema: type[BaseModel] = SSLInput
    output_schema: type[BaseModel] = SSLOutput
    sandbox_requirements: Dict[str, Any] = {}  # Active tool, but executes via native python socket context (no host binary wrapper)
    source: str = "builtin"

    def _execute(self, session, input_data: SSLInput, use_sandbox: bool = True) -> SSLOutput:
        hostname = input_data.target.strip()
        port = input_data.port
        
        try:
            context = ssl.create_default_context()
            # Enforce short timeout
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            expiry_str = cert.get("notAfter", "")
            # Example format: "Jan 15 12:00:00 2027 GMT"
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            # Make timezone aware (GMT/UTC)
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            days_left = (expiry_dt - now).days
            
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
            
            return SSLOutput(
                target=hostname,
                success=True,
                expiry_date=expiry_dt.isoformat(),
                days_remaining=days_left,
                actual_scanned_address=hostname
            )
        except Exception as e:
            # We don't raise, we return success=False so downstream agents handle it cleanly
            return SSLOutput(
                target=hostname,
                success=False,
                expiry_date="",
                days_remaining=-1,
                actual_scanned_address=hostname
            )
