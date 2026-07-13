from typing import Any, Dict, Type, Optional
from pydantic import BaseModel, Field
from cadresec.core.roe import RiskTier
from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError, SandboxUnavailableError


class ToolSpec(BaseModel):
    name: str = Field(..., description="Unique name of the tool")
    description: str = Field(..., description="Human-readable description of what the tool does")
    risk_tier: RiskTier = Field(..., description="Risk classification of the tool (passive, active-safe, active-risky)")
    input_schema: Type[BaseModel] = Field(..., description="Pydantic schema for tool inputs. Must include a 'target' field.")
    output_schema: Type[BaseModel] = Field(..., description="Pydantic schema for tool outputs")
    sandbox_requirements: Dict[str, Any] = Field(default_factory=dict, description="Execution sandbox specification (e.g. docker image)")
    source: str = Field(default="builtin", description="Source of the tool (builtin, user, mcp)")

    def _is_docker_available(self) -> bool:
        """Helper to determine if the local Docker daemon is running and reachable."""
        import subprocess
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
            return res.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_target(self, input_data: BaseModel) -> Optional[str]:
        """Retrieves the target address value from the input data.
        
        Subclasses (such as MCP Tool Adapters) can override this to support custom target fields.
        """
        return getattr(input_data, "target", None)

    def run(self, session, input_data: BaseModel) -> BaseModel:
        """Executes the tool wrapper, strictly gating on Rules of Engagement scope and risk-tier approvals.
        
        This method is the public entry point for all tool calls and cannot be bypassed.
        """
        # Validate that the input data matches the tool's input schema
        if not isinstance(input_data, self.input_schema):
            raise TypeError(f"Input data must be an instance of {self.input_schema.__name__}")

        target = self.get_target(input_data)
        if not target:
            raise ValueError(
                f"Tool input schema must contain a 'target' field or a custom parameter mapping "
                f"resolving to a target address. Got input: {input_data}"
            )

        # 1. ENFORCE SCOPE GUARDRAIL
        session.guardrails.assert_in_scope(target)

        # 2. ENFORCE RISK-TIER APPROVAL GUARDRAIL
        session.guardrails.assert_approved(self.name, self.risk_tier.value)

        # 3. ENFORCE SANDBOX GUARDRAIL
        use_sandbox = True
        if self.sandbox_requirements:
            docker_available = self._is_docker_available()
            if not docker_available:
                if not getattr(session.roe, "allow_unsandboxed_fallback", False):
                    session.audit.record(
                        event_type="SANDBOX_UNAVAILABLE_ABORT",
                        actor="system",
                        details={
                            "tool_name": self.name,
                            "error": f"Docker daemon is unreachable and unsandboxed fallback is disabled for tool '{self.name}'."
                        }
                    )
                    raise SandboxUnavailableError(
                        f"Sandbox environment (Docker) is unavailable for tool '{self.name}'. "
                        "Unsandboxed execution is disabled in the Rules of Engagement."
                    )
                else:
                    use_sandbox = False
                    session.audit.record(
                        event_type="SANDBOX_BYPASS_USED",
                        actor="system",
                        details={
                            "tool_name": self.name,
                            "reason": "Docker sandbox is unavailable; falling back to host execution."
                        }
                    )

        # Log tool execution start
        session.audit.record(
            event_type="TOOL_EXECUTION_START" if use_sandbox else "TOOL_UNSANDBOXED_EXECUTION_START",
            actor="system",
            details={
                "tool_name": self.name,
                "risk_tier": self.risk_tier.value,
                "input_data": input_data.model_dump(),
                "sandboxed": use_sandbox
            }
        )

        try:
            # Delegate to subclass specific execution
            result = self._execute(session, input_data, use_sandbox=use_sandbox)
            
            # Verify result matches output schema
            if not isinstance(result, self.output_schema):
                raise TypeError(f"Tool implementation returned {type(result).__name__}, expected {self.output_schema.__name__}")

            # Log tool execution success
            actual_scanned = getattr(result, "actual_scanned_address", target)
            session.audit.record(
                event_type="TOOL_EXECUTION_SUCCESS",
                actor="system",
                details={
                    "tool_name": self.name,
                    "authorized_target": target,
                    "actual_scanned_address": actual_scanned,
                    "output_summary": str(result.model_dump())[:200]
                }
            )
            return result

        except Exception as e:
            # Log tool execution failure
            session.audit.record(
                event_type="TOOL_EXECUTION_FAILURE",
                actor="system",
                details={
                    "tool_name": self.name,
                    "error": str(e)
                }
            )
            raise e

    def _execute(self, session, input_data: BaseModel, use_sandbox: bool = True) -> BaseModel:
        """Abstract execution logic. Must be overridden by subclasses."""
        raise NotImplementedError("Subclasses of ToolSpec must implement _execute()")
