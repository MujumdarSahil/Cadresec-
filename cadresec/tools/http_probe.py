import sys
import json
import subprocess
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService, Endpoint, ConnectionInfo, OCSFNetworkActivity


class HTTPProbeInput(BaseModel):
    target: str = Field(..., description="Target hostname or IP address to query")
    port: int = Field(default=80, description="HTTP port number (e.g. 80, 443)")
    path: str = Field(default="/", description="URL path to request (e.g. /index.html)")
    method: str = Field(default="GET", description="HTTP request method: GET or HEAD")
    timeout_seconds: int = Field(default=10, description="Max execution timeout in seconds")

    @field_validator("method")
    @classmethod
    def validate_method(cls, v):
        if v.upper() not in ("GET", "HEAD"):
            raise ValueError("Only GET and HEAD methods are supported in this version.")
        return v.upper()


class HTTPProbeOutput(BaseModel):
    target: str = Field(..., description="Scan target IP/hostname")
    success: bool = Field(..., description="True if command completed successfully")
    http_code: int = Field(default=0, description="HTTP response status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Parsed HTTP response headers")
    body_length: int = Field(default=0, description="HTTP response body length in bytes")
    actual_scanned_address: str = Field(default="", description="The raw IP address/hostname requested by the container process")


class HTTPProbeToolSpec(ToolSpec):
    name: str = "http_probe"
    description: str = "Sandboxed HTTP/HTTPS request utility mapping to OCSF Discovery"
    risk_tier: RiskTier = RiskTier.ACTIVE_SAFE
    input_schema: type[BaseModel] = HTTPProbeInput
    output_schema: type[BaseModel] = HTTPProbeOutput
    sandbox_requirements: Dict[str, Any] = {
        "image": "curlimages/curl@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13"
    }
    source: str = "builtin"

    def _execute(self, session, input_data: HTTPProbeInput, use_sandbox: bool = True) -> HTTPProbeOutput:
        """Executes sandboxed curl to probe the HTTP service, parses responses and logs OCSF events."""
        original_target = input_data.target.strip()
        scan_target = original_target
        is_local = original_target.lower() in ("127.0.0.1", "localhost")

        protocol = "https" if input_data.port == 443 else "http"

        if use_sandbox:
            cmd = ["docker", "run", "--rm"]
            if is_local:
                cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
                scan_target = "host.docker.internal"

            cmd.extend([
                "curlimages/curl@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13",
                "-s", "-S", "-i"
            ])
            cmd.extend(["--max-time", str(input_data.timeout_seconds)])

            if input_data.method == "HEAD":
                cmd.append("-I")
            else:
                cmd.extend(["-X", "GET"])

            # Append metadata block format
            format_str = "\n\n__CADRESEC_METADATA_START__\n" \
                         "{\"http_code\": %{http_code}, \"time_total\": %{time_total}, \"ssl_verify_result\": %{ssl_verify_result}}\n" \
                         "__CADRESEC_METADATA_END__"
            cmd.extend(["-w", format_str])

            url = f"{protocol}://{scan_target}:{input_data.port}{input_data.path}"
            cmd.append(url)
        else:
            import shutil
            host_curl = shutil.which("curl")
            if not host_curl:
                raise FileNotFoundError(
                    "Local curl executable was not found on the host system PATH. "
                    "Cannot execute unsandboxed fallback."
                )

            cmd = [host_curl, "-s", "-S", "-i"]
            cmd.extend(["--max-time", str(input_data.timeout_seconds)])

            if input_data.method == "HEAD":
                cmd.append("-I")
            else:
                cmd.extend(["-X", "GET"])

            format_str = "\n\n__CADRESEC_METADATA_START__\n" \
                         "{\"http_code\": %{http_code}, \"time_total\": %{time_total}, \"ssl_verify_result\": %{ssl_verify_result}}\n" \
                         "__CADRESEC_METADATA_END__"
            cmd.extend(["-w", format_str])

            url = f"{protocol}://{scan_target}:{input_data.port}{input_data.path}"
            cmd.append(url)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            stdout = proc.stdout
            success = True
        except subprocess.CalledProcessError as e:
            stdout = e.stdout or ""
            success = False
            if not stdout:
                return HTTPProbeOutput(
                    target=original_target,
                    success=False,
                    http_code=0,
                    headers={},
                    body_length=0,
                    actual_scanned_address=scan_target if use_sandbox else original_target
                )
        except FileNotFoundError as e:
            if use_sandbox:
                raise FileNotFoundError("Docker is not installed or not available on system PATH. Cannot execute sandboxed tools.")
            else:
                raise e

        # Parse response details
        http_code = 0
        headers: Dict[str, str] = {}
        body_length = 0

        if "__CADRESEC_METADATA_START__" in stdout:
            parts = stdout.split("__CADRESEC_METADATA_START__")
            http_response_part = parts[0]
            
            # Remove the trailing newlines we injected for the metadata block separator
            if http_response_part.endswith("\n\n"):
                http_response_part = http_response_part[:-2]
            elif http_response_part.endswith("\r\n\r\n"):
                http_response_part = http_response_part[:-4]
                
            metadata_part = parts[1].split("__CADRESEC_METADATA_END__")[0].strip()
            try:
                meta = json.loads(metadata_part)
                http_code = meta.get("http_code", 0)
            except Exception:
                pass
            
            # Extract headers and body
            normalized = http_response_part.replace("\r\n", "\n")
            if "\n\n" in normalized:
                headers_block, body_block = normalized.split("\n\n", 1)
            else:
                headers_block = normalized
                body_block = ""
                
            body_length = len(body_block.encode("utf-8"))
            
            for line in headers_block.split("\n"):
                line = line.strip()
                if not line or line.startswith("HTTP/"):
                    continue
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

        actual_addr = scan_target if use_sandbox else original_target
        
        # Write to OCSF Event Store if the request succeeded or returned an HTTP status code
        if http_code > 0:
            self._map_and_write_ocsf(session, original_target, input_data.port, http_code, headers, actual_addr)

        return HTTPProbeOutput(
            target=original_target,
            success=success and http_code > 0,
            http_code=http_code,
            headers=headers,
            body_length=body_length,
            actual_scanned_address=actual_addr
        )

    def _map_and_write_ocsf(self, session, target: str, port: int, http_code: int, headers: Dict[str, str], actual_scanned: str) -> None:
        """Maps HTTP probe results to OCSF Discovery and NetworkActivity logs."""
        protocol_name = "TCP"
        service_name = "https" if port == 443 else "http"
        server_desc = headers.get("server", "unknown server")

        # 1. Write NetworkActivity Event (4001)
        activity = OCSFNetworkActivity(
            src_endpoint=Endpoint(ip="127.0.0.1"),
            dst_endpoint=Endpoint(ip=target, port=port),
            connection_info=ConnectionInfo(
                protocol_name=protocol_name,
                state="open"
            ),
            session_id=session.session_id
        )
        session.ocsf.write_event(session.session_id, 4001, activity)

        # 2. Write Device Discovery Event (5010)
        desc = f"HTTP Service probed. Status: {http_code}. Server Header: {server_desc}."
        if target != actual_scanned:
            desc += f" Remapped localhost target to '{actual_scanned}'."

        discovery = OCSFDiscovery(
            device=DiscoveryDevice(
                ip=target,
                hostname=target,
                services=[
                    DiscoveredService(
                        port=port,
                        protocol=protocol_name,
                        service=service_name,
                        state="open"
                    )
                ],
                description=desc
            ),
            session_id=session.session_id
        )
        session.ocsf.write_event(session.session_id, 5010, discovery)
