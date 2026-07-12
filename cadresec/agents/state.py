import operator
from typing import Annotated, Dict, List, Any, TypedDict


class AgentState(TypedDict):
    # A list of messages/logs exchanged. Uses operator.add reducer to append new items.
    messages: Annotated[List[Dict[str, Any]], operator.add]
    
    # The active target host/IP under assessment.
    current_target: str
    
    # List of steps completed during the session. Uses operator.add to append.
    completed_steps: Annotated[List[str], operator.add]
    
    # Routing flag to direct conditional graph edges.
    routing_decision: str
