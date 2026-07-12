from typing import List
from pydantic import BaseModel, Field
from langgraph.graph.state import CompiledStateGraph


class AgentSpec(BaseModel):
    role: str = Field(..., description="Unique role of the domain agent")
    allowed_tool_categories: List[str] = Field(default_factory=list, description="List of tool types this agent is permitted to call")
    system_prompt: str = Field(..., description="The agent's primary system instructions")
    source: str = Field(default="builtin", description="Source of the agent specification")

    class Config:
        arbitrary_types_allowed = True
