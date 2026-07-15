import socket
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.evidence import Evidence
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService


class DNSInput(BaseModel):
    target: str = Field(..., description="Target hostname or domain to query (e.g. google.com)")
    record_types: List[str] = Field(default_factory=lambda: ["A"], description="DNS record types to query (A, MX, NS, TXT)")


class DNSOutput(BaseModel):
    target: str = Field(..., description="Query target hostname/domain")
    success: bool = Field(..., description="True if query succeeded and returned records")
    records: Dict[str, List[str]] = Field(default_factory=dict, description="Resolved records mapped by type")
    evidence: List[Evidence] = Field(default_factory=list, description="Extracted Evidence objects")
    actual_scanned_address: str = Field(default="", description="The raw IP address/hostname requested")


class DNSLookupToolSpec(ToolSpec):
    name: str = "dns_lookup"
    description: str = "Queries DNS records (A, MX, NS, TXT) and generates structured Evidence"
    risk_tier: RiskTier = RiskTier.PASSIVE
    input_schema: type[BaseModel] = DNSInput
    output_schema: type[BaseModel] = DNSOutput
    sandbox_requirements: Dict[str, Any] = {}
    source: str = "builtin"

    def _execute(self, session, input_data: DNSInput, use_sandbox: bool = True) -> DNSOutput:
        target = input_data.target.strip()
        record_types = [r.upper() for r in input_data.record_types]
        records: Dict[str, List[str]] = {}
        evidence: List[Evidence] = []
        success = False

        # Attempt to use dnspython
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for rtype in record_types:
                try:
                    answers = resolver.resolve(target, rtype)
                    vals = []
                    for rdata in answers:
                        val = str(rdata).strip()
                        vals.append(val)
                        evidence.append(Evidence(
                            category="dns",
                            value=f"{rtype}:{val}",
                            confidence=0.99,
                            source="DNS Lookup",
                            originating_tool=self.name
                        ))
                    if vals:
                        records[rtype] = vals
                        success = True
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
                    pass
        except ImportError:
            # Fallback to standard socket library for A records only
            if "A" in record_types:
                try:
                    # socket.getaddrinfo is standard and works for DNS resolution
                    addr_info = socket.getaddrinfo(target, None, family=socket.AF_INET)
                    ips = list(set([info[4][0] for info in addr_info]))
                    if ips:
                        records["A"] = ips
                        success = True
                        for ip in ips:
                            evidence.append(Evidence(
                                category="dns",
                                value=f"A:{ip}",
                                confidence=0.95,  # Slightly lower confidence due to fallback
                                source="DNS Lookup (Socket Fallback)",
                                originating_tool=self.name
                            ))
                except socket.gaierror:
                    pass

        # Write to OCSF Event Store (Discovery Class 5010)
        resolved_ips = records.get("A", [])
        services = []
        for ip in resolved_ips:
            services.append(DiscoveredService(
                port=53,
                protocol="UDP",
                service="dns",
                state="open"
            ))

        desc = f"DNS records resolved for {target}: {records}"
        discovery = OCSFDiscovery(
            device=DiscoveryDevice(
                ip=resolved_ips[0] if resolved_ips else target,
                hostname=target,
                description=desc,
                services=services
            ),
            session_id=session.session_id
        )
        session.ocsf.write_event(session.session_id, 5010, discovery)

        return DNSOutput(
            target=target,
            success=success,
            records=records,
            evidence=evidence,
            actual_scanned_address=target
        )
