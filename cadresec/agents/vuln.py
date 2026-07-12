from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState


def vuln_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Vulnerability analysis agent node: reasoning-only node querying OCSF event store."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

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
                elif port == 21:
                    analysis_findings.append(f"- [EXPOSURE] Plaintext FTP service on {ip}:{port}. Credentials transmitted in plaintext.")
                elif port == 23:
                    analysis_findings.append(f"- [EXPOSURE] Legacy Telnet service on {ip}:{port}. Insecure remote terminal access.")
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
