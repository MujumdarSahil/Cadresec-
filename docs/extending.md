# Extending Cadresec: Developers Guide

This guide details how to implement custom tools and domain sub-agents in the Cadresec framework.

---

## 1. Custom Tools: The ToolSpec Contract

Every tool in the framework must inherit from the `ToolSpec` base class defined in [tools.py](file:///c:/Users/mujum/OneDrive/Desktop/Cadresec/cadresec/core/tools.py).

### The Guardrail Contract (CRITICAL)
Per framework principles, **all guardrails are enforced inside `ToolSpec.run()`**. This public interface validates target scope and operator approval BEFORE delegating to the custom tool's internal execution logic. Contributors must override the abstract method `_execute()`, which is only reachable after passing all guardrail gates.

### Custom Tool Example: `ssl_check.py`

Create a new file in `cadresec/tools/` (e.g. [ssl_check.py](file:///c:/Users/mujum/OneDrive/Desktop/Cadresec/cadresec/tools/ssl_check.py)):

```python
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice, DiscoveredService

class SSLInput(BaseModel):
    target: str = Field(..., description="Target hostname to check SSL cert expiry (e.g. google.com)")
    port: int = Field(default=443, description="SSL port number")

class SSLOutput(BaseModel):
    target: str = Field(..., description="Target hostname")
    success: bool = Field(..., description="True if certificate retrieved successfully")
    expiry_date: str = Field(default="", description="Expiration timestamp of the certificate")
    days_remaining: int = Field(default=-1, description="Days left until expiration")

class SSLToolSpec(ToolSpec):
    name: str = "ssl_expiry"
    description: str = "Retrieves public SSL certificates and verifies expiry dates"
    risk_tier: RiskTier = RiskTier.PASSIVE
    input_schema: type[BaseModel] = SSLInput
    output_schema: type[BaseModel] = SSLOutput
    sandbox_requirements: Dict[str, Any] = {} # Does not require Docker (Passive/Safe tool)
    source: str = "builtin"

    def _execute(self, session, input_data: SSLInput, use_sandbox: bool = True) -> SSLOutput:
        """Abstract execution logic overridden by the custom tool."""
        hostname = input_data.target.strip()
        port = input_data.port
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            expiry_str = cert.get("notAfter", "")
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.utcnow()).days
            
            # Map findings to OCSF Discovery Class 5010
            discovery = OCSFDiscovery(
                device=DiscoveryDevice(
                    ip=hostname,
                    hostname=hostname,
                    description=f"SSL certificate verified. Days remaining: {days_left}",
                    services=[
                        DiscoveredService(
                            port=port,
                            protocol="TCP",
                            service="https",
                            state="open"
                        )
                    ]
                ),
                session_id=session.session_id
            )
            session.ocsf.write_event(session.session_id, 5010, discovery)
            
            return SSLOutput(
                target=hostname,
                success=True,
                expiry_date=expiry_dt.isoformat(),
                days_remaining=days_left
            )
        except Exception as e:
            return SSLOutput(target=hostname, success=False)
```

---

## 2. Custom Domain Agents: The AgentSpec Contract

Domain sub-agents in Cadresec coordinate reasoning or execution nodes. They inherit from `AgentSpec` defined in [agents.py](file:///c:/Users/mujum/OneDrive/Desktop/Cadresec/cadresec/core/agents.py).

### Custom Agent Example: `ssl_agent.py`

Create a new file in `cadresec/agents/` (e.g. `cadresec/agents/ssl_agent.py`):

```python
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.tools.ssl_check import SSLToolSpec, SSLInput

def ssl_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Agent node that invokes the SSL Checker tool."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured.")

    session.assert_not_killed()
    target = state.get("current_target")
    
    # Instantiate and invoke tool (handles guardrail assertions internally)
    tool = SSLToolSpec()
    result = tool.run(session, SSLInput(target=target))
    
    return {
        "messages": [
            {
                "sender": "ssl_agent",
                "text": f"SSL expiry check completed for {target}. Days left: {result.days_remaining}."
            }
        ],
        "completed_steps": ["ssl_check"]
    }

def build_ssl_graph():
    """Compiles the Agent's LangGraph subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("ssl_node", ssl_node)
    builder.set_entry_point("ssl_node")
    builder.add_edge("ssl_node", END)
    return builder.compile()
```

---

## 3. Risk Tier Standard Reference

All tools must declare their risk tier inside their `ToolSpec` definition:

| Risk Tier | Code Representation | Description | Approval Flow |
| :--- | :--- | :--- | :--- |
| **Passive** | `RiskTier.PASSIVE` | Non-intrusive operations (DNS lookup, SSL checks). | Auto-approved. |
| **Active-Safe** | `RiskTier.ACTIVE_SAFE` | Interactive scans with minimal system load (Port scans). | Prompted once per session, cached. |
| **Active-Risky** | `RiskTier.ACTIVE_RISKY` | Vulnerability scanning or exploit tests. | Prompted every time before invocation. |
| **Destructive** | `RiskTier.DESTRUCTIVE` | Destructive attacks or denial of service. | Hard-rejected by framework. |
