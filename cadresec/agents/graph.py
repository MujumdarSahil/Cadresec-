from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.agents.recon import build_recon_graph
from cadresec.agents.scan import build_scan_graph
from cadresec.agents.vuln import build_vuln_graph
from cadresec.agents.triage import build_triage_graph
from cadresec.agents.reporting import build_reporting_graph


def lead_agent_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Lead Agent Node: Initializes the engagement sequence, asserts target scope, and sets routing."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    # Pre-validation check: Lead Agent runs fast-fail scope gate
    target = state.get("current_target")
    session.guardrails.assert_in_scope(target)

    # Log routing decision
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="lead_agent",
        details={
            "action": "route_to_recon",
            "reason": "Engagement initiated. Routing to Recon Agent."
        }
    )

    return {
        "messages": [{"sender": "lead_agent", "text": "Initiating Cadresec scanning engagement pipeline."}],
        "routing_decision": "recon"
    }


def route_next_agent(state: AgentState) -> str:
    """Routes execution from Lead Agent to Recon Agent, or terminates if not set."""
    decision = state.get("routing_decision")
    if decision == "recon":
        return "recon_agent"
    return END


def build_graph(checkpointer=None):
    """Builds and compiles the parent LangGraph coordinating the five domain agents."""
    builder = StateGraph(AgentState)
    
    # 1. Register Lead Agent node
    builder.add_node("lead_agent", lead_agent_node)
    
    # 2. Register compiled subgraphs as nodes
    builder.add_node("recon_agent", build_recon_graph())
    builder.add_node("scan_agent", build_scan_graph())
    builder.add_node("vuln_agent", build_vuln_graph())
    builder.add_node("triage_agent", build_triage_graph())
    builder.add_node("reporting_agent", build_reporting_graph())
    
    # 3. Define routing edges
    builder.set_entry_point("lead_agent")
    
    builder.add_conditional_edges(
        "lead_agent",
        route_next_agent,
        {
            "recon_agent": "recon_agent",
            "end": END
        }
    )
    
    # Sequential piping between sub-agents
    builder.add_edge("recon_agent", "scan_agent")
    builder.add_edge("scan_agent", "vuln_agent")
    builder.add_edge("vuln_agent", "triage_agent")
    builder.add_edge("triage_agent", "reporting_agent")
    builder.add_edge("reporting_agent", END)
    
    # Enable checkpointing
    if checkpointer is None:
        checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)
