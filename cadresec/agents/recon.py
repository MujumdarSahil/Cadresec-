from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.tools.recon_stub import ReconStubTool, ReconInput


def recon_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Recon agent node: runs simulated passive recon discovery."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    # Invoke Recon ToolSpec
    target = state.get("current_target")
    tool = ReconStubTool()
    tool_input = ReconInput(target=target)
    
    # Tool execution handles guardrails and logging natively
    result = tool.run(session, tool_input)

    return {
        "messages": [
            {
                "sender": "recon_agent",
                "text": f"Passive recon completed for target {target}. Resolved IPs: {result.detected_ips}."
            }
        ],
        "completed_steps": ["recon"]
    }


def build_recon_graph():
    """Compiles the Recon Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("recon_node", recon_node)
    builder.set_entry_point("recon_node")
    builder.add_edge("recon_node", END)
    return builder.compile()
