from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState


def triage_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Triage agent node: reasoning-only node that prioritizes vulnerability severity."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    # Find the analysis message from the vuln agent
    vuln_message = ""
    for msg in reversed(state.get("messages", [])):
        if msg.get("sender") == "vuln_agent":
            vuln_message = msg.get("text", "")
            break

    # Prioritize findings based on rules
    triage_results = []
    if "Telnet" in vuln_message:
        triage_results.append("- [HIGH] Legacy Telnet service exposed. Critical SSH alternative missing, credentials in plaintext.")
    if "FTP" in vuln_message:
        triage_results.append("- [HIGH] Plaintext FTP exposed. Credential harvesting vulnerability.")
    if "HTTP service" in vuln_message:
        triage_results.append("- [MEDIUM] Plaintext HTTP exposed. Lack of encryption allows network sniffing.")
    if "discovered open port" in vuln_message.lower():
        triage_results.append("- [LOW] General open port exposure without immediate exploits.")

    triage_summary = "\n".join(triage_results) if triage_results else "- [INFO] No priority vulnerabilities detected."

    # Record agent reasoning decision to audit ledger
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="triage_agent",
        details={
            "action": "triage_vulnerabilities",
            "findings_count": len(triage_results)
        }
    )

    return {
        "messages": [
            {
                "sender": "triage_agent",
                "text": f"Triage Assessment completed. Triage outputs:\n{triage_summary}"
            }
        ],
        "completed_steps": ["triage"]
    }


def build_triage_graph():
    """Compiles the Triage Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("triage_node", triage_node)
    builder.set_entry_point("triage_node")
    builder.add_edge("triage_node", END)
    return builder.compile()
