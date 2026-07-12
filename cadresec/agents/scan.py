from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.tools.nmap import NmapToolSpec, NmapInput


def scan_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Scan agent node: runs containerized port scanning using NmapToolSpec."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    # Invoke Nmap ToolSpec
    target = state.get("current_target")
    tool = NmapToolSpec()
    tool_input = NmapInput(target=target)
    
    # Tool execution handles guardrails and logging natively
    result = tool.run(session, tool_input)

    return {
        "messages": [
            {
                "sender": "scan_agent",
                "text": f"Nmap scanning completed for target {target}. Success status: {result.success}."
            }
        ],
        "completed_steps": ["scan"]
    }


def build_scan_graph():
    """Compiles the Scan Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("scan_node", scan_node)
    builder.set_entry_point("scan_node")
    builder.add_edge("scan_node", END)
    return builder.compile()
