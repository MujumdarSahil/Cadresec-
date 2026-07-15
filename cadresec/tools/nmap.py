import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService, Endpoint, ConnectionInfo, OCSFNetworkActivity
from cadresec.core.evidence import Evidence


class NmapInput(BaseModel):
    target: str = Field(..., description="Target IP or hostname to scan")
    ports: Optional[str] = Field(default=None, description="Comma-separated ports list (e.g. 80,443,8080). Optional.")


class NmapOutput(BaseModel):
    target: str = Field(..., description="Scan target IP/hostname")
    success: bool = Field(..., description="True if command completed successfully")
    raw_xml: str = Field(..., description="Raw XML output from the nmap execution")
    parsed_hosts: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted host and service discovery data")
    actual_scanned_address: str = Field(default="", description="The raw IP address/hostname requested by the container process")
    evidence: List[Evidence] = Field(default_factory=list, description="Extracted Evidence objects")


class NmapToolSpec(ToolSpec):
    name: str = "nmap"
    description: str = "Sandboxed Nmap port scanner wrapping the official docker container"
    risk_tier: RiskTier = RiskTier.ACTIVE_SAFE
    input_schema: type[BaseModel] = NmapInput
    output_schema: type[BaseModel] = NmapOutput
    sandbox_requirements: Dict[str, Any] = {"image": "instrumentisto/nmap"}
    source: str = "builtin"

    def _execute(self, session, input_data: NmapInput, use_sandbox: bool = True) -> NmapOutput:
        """Executes the containerized nmap scan, parses the XML, maps to OCSF, and returns the result."""
        original_target = input_data.target.strip()
        scan_target = original_target
        is_local = original_target.lower() in ("127.0.0.1", "localhost")
        
        if use_sandbox:
            cmd = ["docker", "run", "--rm"]
            if is_local:
                # Map host.docker.internal to host gateway IP so container can reach the host machine
                cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
                scan_target = "host.docker.internal"
                
            cmd.extend(["instrumentisto/nmap", "-oX", "-"])
            
            if input_data.ports:
                cmd.extend(["-p", input_data.ports])
            else:
                cmd.append("-F")  # Fast port scan mode
            cmd.append(scan_target)
        else:
            # Locate local host nmap binary
            import os
            import shutil
            host_nmap = None
            standard_paths = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe"
            ]
            for path in standard_paths:
                if os.path.exists(path):
                    host_nmap = path
                    break
            if not host_nmap:
                host_nmap = shutil.which("nmap")
                
            if not host_nmap:
                raise FileNotFoundError(
                    "Local nmap executable was not found on the host system PATH or standard install directories. "
                    "Cannot execute unsandboxed fallback."
                )
                
            cmd = [host_nmap, "-oX", "-"]
            if input_data.ports:
                cmd.extend(["-p", input_data.ports])
            else:
                cmd.append("-F")
            cmd.append(scan_target)

        try:
            # Run the command
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            raw_xml = proc.stdout
            success = True
        except subprocess.CalledProcessError as e:
            raw_xml = e.stdout or ""
            success = False
            # Check if there is XML output even on error exit code
            if not raw_xml:
                raise RuntimeError(f"Nmap execution failed: {e.stderr}")
        except FileNotFoundError as e:
            if use_sandbox:
                # Docker binary not installed on host
                raise FileNotFoundError("Docker is not installed or not available on system PATH. Cannot execute sandboxed tools.")
            else:
                raise e

        # Parse XML
        parsed_hosts = self._parse_nmap_xml(raw_xml)
        
        # Normalize parsed host IP back to original target if we scanned localhost
        if is_local:
            for host in parsed_hosts:
                host["ip"] = original_target
                host["hostname"] = "localhost"

        actual_addr = scan_target if use_sandbox else original_target

        # Write to OCSF Event Store
        self._map_and_write_ocsf(session, original_target, parsed_hosts, actual_addr)

        evidence_list = []
        for host in parsed_hosts:
            for p in host.get("ports", []):
                if p.get("state") == "open":
                    evidence_list.append(Evidence(
                        category="port",
                        value=f"{p.get('port')}/{p.get('protocol')}",
                        confidence=1.0,
                        source="Port Scan",
                        originating_tool=self.name
                    ))
                    if p.get("service") and p.get("service") != "unknown":
                        evidence_list.append(Evidence(
                            category="server",
                            value=p.get("service"),
                            confidence=0.8,
                            source="Service Detection",
                            originating_tool=self.name
                        ))

        return NmapOutput(
            target=original_target,
            success=success,
            raw_xml=raw_xml,
            parsed_hosts=parsed_hosts,
            actual_scanned_address=actual_addr,
            evidence=evidence_list
        )

    def _parse_nmap_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parses nmap XML stdout format into a python dict structure."""
        hosts = []
        if not xml_content.strip():
            return hosts

        try:
            root = ET.fromstring(xml_content.strip())
            for host_el in root.findall("host"):
                host_info = {
                    "ip": "",
                    "hostname": "",
                    "ports": []
                }
                
                # Retrieve IP address
                addr_el = host_el.find("address")
                if addr_el is not None:
                    host_info["ip"] = addr_el.attrib.get("addr", "")

                # Retrieve Hostname
                hostnames_el = host_el.find("hostnames")
                if hostnames_el is not None:
                    name_el = hostnames_el.find("hostname")
                    if name_el is not None:
                        host_info["hostname"] = name_el.attrib.get("name", "")

                # Retrieve open ports and services
                ports_el = host_el.find("ports")
                if ports_el is not None:
                    for port_el in ports_el.findall("port"):
                        port_id = int(port_el.attrib.get("portid", 0))
                        proto = port_el.attrib.get("protocol", "tcp")
                        
                        state_el = port_el.find("state")
                        state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"
                        
                        service_el = port_el.find("service")
                        service_name = service_el.attrib.get("name", "unknown") if service_el is not None else "unknown"

                        host_info["ports"].append({
                            "port": port_id,
                            "protocol": proto,
                            "state": state,
                            "service": service_name
                        })
                hosts.append(host_info)
        except Exception as e:
            # XML parsing error
            pass
        return hosts

    def _map_and_write_ocsf(self, session, target: str, parsed_hosts: List[Dict[str, Any]], actual_scanned: str) -> None:
        """Maps target scan details into OCSF Discovery and NetworkActivity structures and stores them."""
        for host in parsed_hosts:
            host_ip = host["ip"] or target
            host_name = host["hostname"] or None
            
            # Map discovered services to OCSF DiscoveredService list
            services = []
            for p in host["ports"]:
                srv = DiscoveredService(
                    port=p["port"],
                    protocol=p["protocol"].upper(),
                    service=p["service"],
                    state=p["state"]
                )
                services.append(srv)

                # Each open port also constitutes a NetworkActivity event
                activity = OCSFNetworkActivity(
                    src_endpoint=Endpoint(ip="127.0.0.1"),  # Source of scanner
                    dst_endpoint=Endpoint(ip=host_ip, hostname=host_name, port=p["port"]),
                    connection_info=ConnectionInfo(
                        protocol_name=p["protocol"].upper(),
                        state=p["state"]
                    ),
                    session_id=session.session_id
                )
                session.ocsf.write_event(session.session_id, 4001, activity)

            # Write Device Discovery Event
            desc = None
            if target != actual_scanned:
                desc = f"Remapped localhost scan target '{target}' to actual address '{actual_scanned}' inside container."

            discovery = OCSFDiscovery(
                device=DiscoveryDevice(
                    ip=host_ip,
                    hostname=host_name,
                    services=services,
                    description=desc
                ),
                session_id=session.session_id
            )
            session.ocsf.write_event(session.session_id, 5010, discovery)

