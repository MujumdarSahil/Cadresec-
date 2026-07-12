from typing import Callable, Optional

from cadresec.core.exceptions import (
    ScopeViolationError,
    ApprovalViolationError,
    DestructiveToolError
)
from cadresec.core.roe import RiskTier


class Guardrails:
    def __init__(self, session, approval_callback: Optional[Callable[[str, str], bool]] = None):
        """Initializes Guardrails associated with an EngagementSession.
        
        approval_callback: optional function signature: (tool_name, risk_tier) -> bool.
        """
        self.session = session
        self.approval_callback = approval_callback

    def assert_in_scope(self, target: str) -> None:
        """Enforces that a target target is within the authorized scope of the Rules of Engagement.
        
        Raises ScopeViolationError if the target is out of scope.
        Logs all checks (success or failure) to the audit log.
        """
        self.session.assert_not_killed()
        
        in_scope = self.session.roe.is_in_scope(target)
        
        self.session.audit.record(
            event_type="GUARDRAIL_SCOPE_CHECK",
            actor="guardrails",
            details={
                "target": target,
                "allowed": in_scope
            }
        )

        if not in_scope:
            self.session.audit.record(
                event_type="SECURITY_VIOLATION",
                actor="guardrails",
                details={
                    "violation_type": "OUT_OF_SCOPE_TARGET",
                    "target": target
                }
            )
            raise ScopeViolationError(f"Target '{target}' is not within the authorized scope of the Rules of Engagement.")

    def assert_approved(self, tool_name: str, risk_tier: str) -> None:
        """Enforces the approval matrix based on the risk tier of the tool.
        
        Tiers:
        - passive: Auto-approved.
        - active-safe: Confirmed once per session.
        - active-risky: Confirmed every call.
        - destructive: Hard-rejected (unsupported).
        """
        self.session.assert_not_killed()
        
        # 1. Normalize risk tier and validate with RoE permitted tiers
        try:
            tier_enum = RiskTier(risk_tier.lower())
        except ValueError:
            raise ValueError(f"Unknown risk tier: {risk_tier}")

        # 2. Destructive tier check (permanently blocked regardless of RoE)
        if tier_enum == RiskTier.DESTRUCTIVE:
            self.session.audit.record(
                event_type="SECURITY_VIOLATION",
                actor="guardrails",
                details={
                    "violation_type": "DESTRUCTIVE_TOOL_BLOCKED",
                    "tool_name": tool_name
                }
            )
            raise DestructiveToolError(
                f"Tool '{tool_name}' has risk tier 'destructive', which is permanently blocked in this framework."
            )

        # 3. Ensure tier is permitted globally in the RoE
        if tier_enum not in self.session.roe.permitted_risk_tiers:
            self.session.audit.record(
                event_type="SECURITY_VIOLATION",
                actor="guardrails",
                details={
                    "violation_type": "UNPERMITTED_RISK_TIER",
                    "tool_name": tool_name,
                    "requested_tier": risk_tier,
                    "permitted_tiers": [t.value for t in self.session.roe.permitted_risk_tiers]
                }
            )
            raise ApprovalViolationError(
                f"Risk tier '{risk_tier}' is not permitted by the Rules of Engagement."
            )

        # 3. Passive tier (auto-approve)
        if tier_enum == RiskTier.PASSIVE:
            self.session.audit.record(
                event_type="GUARDRAIL_APPROVAL_GRANTED",
                actor="guardrails",
                details={
                    "tool_name": tool_name,
                    "risk_tier": risk_tier,
                    "mechanism": "auto-passive"
                }
            )
            return

        # 4. Active-safe tier (confirm once per session)
        if tier_enum == RiskTier.ACTIVE_SAFE:
            if tool_name in self.session.approved_active_safe_tools:
                self.session.audit.record(
                    event_type="GUARDRAIL_APPROVAL_GRANTED",
                    actor="guardrails",
                    details={
                        "tool_name": tool_name,
                        "risk_tier": risk_tier,
                        "mechanism": "cached-active-safe"
                    }
                )
                return
            
            # Request approval
            approved = self._request_human_approval(tool_name, risk_tier)
            if approved:
                self.session.approved_active_safe_tools.add(tool_name)
                self.session.audit.record(
                    event_type="GUARDRAIL_APPROVAL_GRANTED",
                    actor="guardrails",
                    details={
                        "tool_name": tool_name,
                        "risk_tier": risk_tier,
                        "mechanism": "human-interactive-first"
                    }
                )
                return
            else:
                self.session.audit.record(
                    event_type="GUARDRAIL_APPROVAL_DENIED",
                    actor="guardrails",
                    details={
                        "tool_name": tool_name,
                        "risk_tier": risk_tier
                    }
                )
                raise ApprovalViolationError(f"User denied approval for tool '{tool_name}' (tier: {risk_tier})")

        # 5. Active-risky tier (confirm every call)
        if tier_enum == RiskTier.ACTIVE_RISKY:
            approved = self._request_human_approval(tool_name, risk_tier)
            if approved:
                self.session.audit.record(
                    event_type="GUARDRAIL_APPROVAL_GRANTED",
                    actor="guardrails",
                    details={
                        "tool_name": tool_name,
                        "risk_tier": risk_tier,
                        "mechanism": "human-interactive-every"
                    }
                )
                return
            else:
                self.session.audit.record(
                    event_type="GUARDRAIL_APPROVAL_DENIED",
                    actor="guardrails",
                    details={
                        "tool_name": tool_name,
                        "risk_tier": risk_tier
                    }
                )
                raise ApprovalViolationError(f"User denied approval for tool '{tool_name}' (tier: {risk_tier})")

    def _request_human_approval(self, tool_name: str, risk_tier: str) -> bool:
        """Triggers the human approval callback. Returns True if approved, False otherwise."""
        if not self.approval_callback:
            self.session.audit.record(
                event_type="GUARDRAIL_APPROVAL_FAILED",
                actor="guardrails",
                details={
                    "tool_name": tool_name,
                    "risk_tier": risk_tier,
                    "error": "No approval callback registered"
                }
            )
            raise ApprovalViolationError(
                f"Action '{tool_name}' ({risk_tier}) requires human confirmation, but no approval callback is registered."
            )
        
        self.session.audit.record(
            event_type="GUARDRAIL_APPROVAL_REQUEST",
            actor="guardrails",
            details={
                "tool_name": tool_name,
                "risk_tier": risk_tier
            }
        )
        
        try:
            result = self.approval_callback(tool_name, risk_tier)
            self.session.audit.record(
                event_type="GUARDRAIL_APPROVAL_RESPONSE",
                actor="guardrails",
                details={
                    "tool_name": tool_name,
                    "risk_tier": risk_tier,
                    "approved": result
                }
            )
            return result
        except Exception as e:
            self.session.audit.record(
                event_type="GUARDRAIL_APPROVAL_FAILED",
                actor="guardrails",
                details={
                    "tool_name": tool_name,
                    "risk_tier": risk_tier,
                    "error": str(e)
                }
            )
            return False
