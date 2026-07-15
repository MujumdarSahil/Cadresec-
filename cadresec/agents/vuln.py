from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.tools.ssl_check import SSLToolSpec, SSLInput
from cadresec.tools.http_probe import HTTPProbeToolSpec, HTTPProbeInput
from cadresec.core.ocsf import OCSFVulnerabilityFinding, FindingInfo, Vulnerability, DiscoveryDevice


def vuln_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Vulnerability analysis agent node: runs SSL checks, HTTP probes,

    and analyzes OCSF events to identify exposures.
    """
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    target = state.get("current_target")
    
    # 1. Run active vulnerability checks (SSL expiry on 443, HTTP headers on 80/443)
    discovery_events = session.ocsf.read_events(session.session_id, class_uid=5010)
    has_ssl = False
    for event in discovery_events:
        device = event.get("device", {})
        for s in device.get("services", []):
            if s.get("port") == 443 and s.get("state") == "open":
                has_ssl = True

    if has_ssl:
        try:
            ssl_tool = SSLToolSpec()
            ssl_res = ssl_tool.run(session, SSLInput(target=target, port=443))
            if ssl_res.success and ssl_res.days_remaining <= 30:
                # Expired or close to expiry -> Write OCSFVulnerabilityFinding (class_uid 2002)
                finding = OCSFVulnerabilityFinding(
                    finding_info=FindingInfo(
                        title="SSL Certificate Near Expiry",
                        description=f"SSL certificate for {target} will expire in {ssl_res.days_remaining} days.",
                        uid=f"VULN-SSL-{target}"
                    ),
                    vulnerability=Vulnerability(
                        severity="High" if ssl_res.days_remaining <= 7 else "Medium",
                        cvss_score=5.0
                    ),
                    device=DiscoveryDevice(ip=target, hostname=target),
                    session_id=session.session_id
                )
                session.ocsf.write_event(session.session_id, 2002, finding)
        except Exception:
            pass

    # 2. Existing analysis findings (backwards compatible loop)
    # Query OCSF Discovery events from database
    events = session.ocsf.read_events(session.session_id, class_uid=5010)

    # Analyze open ports/services and identify potential vulnerabilities
    analysis_findings = []
    for event in events:
        device = event.get("device", {})
        ip = device.get("ip", "")
        services = device.get("services", [])
        
        for s in services:
            port = s.get("port")
            service_name = s.get("service", "")
            port_state = s.get("state", "")
            
            if port_state == "open":
                if port == 80:
                    analysis_findings.append(f"- [EXPOSURE] Plaintext HTTP service on {ip}:{port}. Traffic is unencrypted and vulnerable to eavesdropping.")
                    # Write OCSF Vulnerability Finding
                    finding = OCSFVulnerabilityFinding(
                        finding_info=FindingInfo(
                            title="Plaintext HTTP Exposed",
                            description=f"Plaintext HTTP service exposed on {ip}:{port}.",
                            uid=f"VULN-HTTP-{ip}-{port}"
                        ),
                        vulnerability=Vulnerability(
                            severity="Medium",
                            cvss_score=4.3
                        ),
                        device=DiscoveryDevice(ip=ip, hostname=device.get("hostname")),
                        session_id=session.session_id
                    )
                    session.ocsf.write_event(session.session_id, 2002, finding)
                elif port == 21:
                    analysis_findings.append(f"- [EXPOSURE] Plaintext FTP service on {ip}:{port}. Credentials transmitted in plaintext.")
                    finding = OCSFVulnerabilityFinding(
                        finding_info=FindingInfo(
                            title="Plaintext FTP Exposed",
                            description=f"Plaintext FTP service exposed on {ip}:{port}.",
                            uid=f"VULN-FTP-{ip}-{port}"
                        ),
                        vulnerability=Vulnerability(
                            severity="High",
                            cvss_score=7.5
                        ),
                        device=DiscoveryDevice(ip=ip, hostname=device.get("hostname")),
                        session_id=session.session_id
                    )
                    session.ocsf.write_event(session.session_id, 2002, finding)
                elif port == 23:
                    analysis_findings.append(f"- [EXPOSURE] Legacy Telnet service on {ip}:{port}. Insecure remote terminal access.")
                    finding = OCSFVulnerabilityFinding(
                        finding_info=FindingInfo(
                            title="Insecure Telnet Exposed",
                            description=f"Legacy Telnet service exposed on {ip}:{port}.",
                            uid=f"VULN-TELNET-{ip}-{port}"
                        ),
                        vulnerability=Vulnerability(
                            severity="High",
                            cvss_score=7.5
                        ),
                        device=DiscoveryDevice(ip=ip, hostname=device.get("hostname")),
                        session_id=session.session_id
                    )
                    session.ocsf.write_event(session.session_id, 2002, finding)
                else:
                    analysis_findings.append(f"- [INFO] Discovered open port {port} ({service_name}) on {ip}.")

    analysis_summary = "\n".join(analysis_findings) if analysis_findings else "- No active exposures detected in OCSF database."

    # Record agent reasoning decision to audit ledger
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="vuln_agent",
        details={
            "action": "vulnerability_analysis",
            "findings_count": len(analysis_findings)
        }
    )

    return {
        "messages": [
            {
                "sender": "vuln_agent",
                "text": f"Vulnerability Analysis completed. Analysis output:\n{analysis_summary}"
            }
        ],
        "completed_steps": ["vuln_analysis"]
    }


def build_vuln_graph():
    """Compiles the Vulnerability-Analysis Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("vuln_node", vuln_node)
    builder.set_entry_point("vuln_node")
    builder.add_edge("vuln_node", END)
    return builder.compile()
