from typing import Dict, Any, List
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.core.evidence import Evidence


class ResearchInput(BaseModel):
    query: str = Field(..., description="The query to research (e.g. Apache 2.4.41 vulnerabilities)")
    evidence_context: List[Evidence] = Field(default_factory=list, description="List of related Evidence objects")


class ResearchOutput(BaseModel):
    query: str = Field(..., description="Original query")
    summary: str = Field(..., description="Vulnerability research synthesis summary")
    references: List[str] = Field(default_factory=list, description="References and threat intelligence resources")
    evidence_context: List[Evidence] = Field(default_factory=list, description="Related Evidence objects processed")


class ResearchAgentInterface(BaseModel):
    role: str = Field(default="research_agent", description="Domain agent role identifier")
    description: str = Field(
        default="Performs threat intelligence lookup and vulnerability research based on gathered evidence",
        description="Description of agent domain scope"
    )

    def plan_research(self, query: str, context: List[Evidence]) -> ResearchInput:
        """Helper to create a structured ResearchInput model from raw context."""
        return ResearchInput(query=query, evidence_context=context)

    def parse_research_result(self, raw_data: Dict[str, Any]) -> ResearchOutput:
        """Converts raw intelligence API/LLM responses to ResearchOutput model."""
        return ResearchOutput(
            query=raw_data.get("query", ""),
            summary=raw_data.get("summary", ""),
            references=raw_data.get("references", []),
            evidence_context=raw_data.get("evidence_context", [])
        )


def research_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Research agent node stub: returns initialized interface details (Phase 1 placeholder)."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    session.assert_not_killed()

    # Record agent interface initialization in ledger
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="research_agent",
        details={
            "action": "initialize_research_interface",
            "phase": 1,
            "status": "ready_for_phase2_reasoning"
        }
    )

    return {
        "messages": [
            {
                "sender": "research_agent",
                "text": "Research Agent interface initialized successfully. Ready for Phase 2 reasoning."
            }
        ],
        "completed_steps": ["research_interface"]
    }


def build_research_graph():
    """Compiles the Research Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("research_node", research_node)
    builder.set_entry_point("research_node")
    builder.add_edge("research_node", END)
    return builder.compile()
