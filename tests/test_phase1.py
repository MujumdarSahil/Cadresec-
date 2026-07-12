import pytest
from datetime import datetime, timezone
from sqlalchemy import select, update

from cadresec.core.exceptions import (
    ScopeViolationError,
    ApprovalViolationError,
    DestructiveToolError,
    EngagementKilledError,
    InvalidRoEError
)
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.core.audit import AuditEvent
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from cadresec.agents.state import AgentState

def lead_agent_node(state: AgentState, config) -> dict:
    """Phase 1 local Lead Agent Node."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured.")
    session.assert_not_killed()
    target = state.get("current_target")
    session.guardrails.assert_in_scope(target)
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="lead_agent",
        details={"action": "route_to_dummy_agent"}
    )
    return {
        "messages": [{"sender": "lead_agent", "text": "Routing to dummy sub-agent."}],
        "routing_decision": "dummy"
    }

def dummy_sub_agent_node(state: AgentState, config) -> dict:
    """Phase 1 local Dummy Sub-Agent Node."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured.")
    session.assert_not_killed()
    target = state.get("current_target")
    session.guardrails.assert_in_scope(target)
    session.guardrails.assert_approved(tool_name="dummy_passive_ping", risk_tier="passive")
    session.guardrails.assert_approved(tool_name="dummy_port_scan", risk_tier="active-safe")
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="dummy_sub_agent",
        details={"action": "execute_dummy_actions"}
    )
    return {
        "messages": [{"sender": "dummy_sub_agent", "text": "Successfully executed dummy tools."}],
        "completed_steps": ["dummy_scan"],
        "routing_decision": "end"
    }


def route_next(state):
    """Router helper for the Phase 1 test graph."""
    decision = state.get("routing_decision")
    if decision == "dummy":
        return "dummy_sub_agent"
    return "end"

def build_phase1_graph():
    """Helper to reconstruct the Phase 1 graph skeleton for testing."""
    builder = StateGraph(AgentState)
    builder.add_node("lead_agent", lead_agent_node)
    builder.add_node("dummy_sub_agent", dummy_sub_agent_node)
    builder.set_entry_point("lead_agent")
    builder.add_conditional_edges(
        "lead_agent",
        route_next,
        {
            "dummy_sub_agent": "dummy_sub_agent",
            "end": END
        }
    )
    builder.add_edge("dummy_sub_agent", END)
    checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)



# --- RoE and Scope Tests ---

def test_session_requires_valid_time(expired_roe):
    """Verify that a session cannot be created with an expired or invalid RoE."""
    with pytest.raises(InvalidRoEError, match="Engagement window has expired"):
        EngagementSession(roe=expired_roe)


def test_scope_validation_cidr(valid_roe):
    """Verify CIDR and IP target scope check logic."""
    session = EngagementSession(roe=valid_roe)
    
    # In scope
    session.guardrails.assert_in_scope("127.0.0.1")
    session.guardrails.assert_in_scope("192.168.1.50")
    
    # Out of scope
    with pytest.raises(ScopeViolationError):
        session.guardrails.assert_in_scope("10.0.0.1")


def test_scope_validation_domain(valid_roe):
    """Verify exact and wildcard domain scope check logic."""
    session = EngagementSession(roe=valid_roe)
    
    # In scope (wildcard)
    session.guardrails.assert_in_scope("sub.target.local")
    session.guardrails.assert_in_scope("target.local")
    
    # In scope (exact)
    session.guardrails.assert_in_scope("exact-domain.com")
    
    # Out of scope
    with pytest.raises(ScopeViolationError):
        session.guardrails.assert_in_scope("evil.com")
    with pytest.raises(ScopeViolationError):
        session.guardrails.assert_in_scope("notsub.exact-domain.com")


# --- Tool Approval Gate Tests ---

def test_passive_tool_auto_approved(valid_roe):
    """Verify passive tier tools do not trigger callback and are auto-approved."""
    callback_called = False
    def mock_callback(tool, tier):
        nonlocal callback_called
        callback_called = True
        return True

    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    
    # Passive should not trigger callback
    session.guardrails.assert_approved("some_passive_tool", "passive")
    assert not callback_called


def test_active_safe_cached_approval(valid_roe):
    """Verify active-safe tools trigger callback once and cache the result."""
    callback_calls = 0
    def mock_callback(tool, tier):
        nonlocal callback_calls
        callback_calls += 1
        return True

    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    
    # First call: triggers callback
    session.guardrails.assert_approved("port_scan", "active-safe")
    assert callback_calls == 1
    
    # Second call: uses cache, callback calls remains 1
    session.guardrails.assert_approved("port_scan", "active-safe")
    assert callback_calls == 1


def test_active_risky_always_prompts(valid_roe):
    """Verify active-risky tools trigger callback on every single invocation."""
    callback_calls = 0
    def mock_callback(tool, tier):
        nonlocal callback_calls
        callback_calls += 1
        return True

    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    
    # First call
    session.guardrails.assert_approved("exploit_test", "active-risky")
    assert callback_calls == 1
    
    # Second call
    session.guardrails.assert_approved("exploit_test", "active-risky")
    assert callback_calls == 2


def test_approval_rejection(valid_roe):
    """Verify that rejection in callback raises an ApprovalViolationError and does not execute."""
    def mock_callback(tool, tier):
        return False  # Reject

    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    
    with pytest.raises(ApprovalViolationError, match="User denied approval"):
        session.guardrails.assert_approved("port_scan", "active-safe")


def test_destructive_tool_rejected_immediately(valid_roe):
    """Verify destructive tools are rejected instantly without running callbacks or checks."""
    callback_called = False
    def mock_callback(tool, tier):
        nonlocal callback_called
        callback_called = True
        return True

    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    
    with pytest.raises(DestructiveToolError, match="permanently blocked"):
        session.guardrails.assert_approved("nuke_target", "destructive")
        
    assert not callback_called


# --- Kill Switch Tests ---

def test_kill_switch_raises_immediately(valid_roe):
    """Verify activating the kill switch halts all execution immediately."""
    session = EngagementSession(roe=valid_roe)
    session.kill()
    
    with pytest.raises(EngagementKilledError):
        session.assert_not_killed()
        
    # Guardrail check should fail
    with pytest.raises(EngagementKilledError):
        session.guardrails.assert_in_scope("127.0.0.1")


# --- Ledger Integrity (Hash Chain) Tests ---

def test_ledger_integrity_and_tampering(valid_roe):
    """Verify audit log hash chaining works and tampering breaks validation."""
    session = EngagementSession(roe=valid_roe)
    session.audit.record("ACTION_1", "agent_1", {"msg": "started"})
    session.audit.record("ACTION_2", "agent_2", {"msg": "working"})
    
    # Initial chain must be valid
    assert session.audit.verify_chain() is True
    
    # Tamper with the details in the database directly
    db_sess = session.audit.Session()
    try:
        # Retrieve second event (sequence_number=1) and modify its details
        stmt = (
            update(AuditEvent)
            .where(AuditEvent.session_id == session.session_id)
            .where(AuditEvent.sequence_number == 1)
            .values(details='{"msg": "tampered"}')
        )
        db_sess.execute(stmt)
        db_sess.commit()
    finally:
        db_sess.close()
        
    # Verify chain should now detect tampering and fail
    assert session.audit.verify_chain() is False


# --- End-to-End Orchestrator (LangGraph) Tests ---

def test_graph_success_flow(valid_roe):
    """E2E Test: Successful routing from Lead Agent to Dummy Sub-agent with approval."""
    approval_triggered = False
    def mock_callback(tool, tier):
        nonlocal approval_triggered
        approval_triggered = True
        return True

    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    
    graph = build_phase1_graph()
    
    # Run the graph
    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    # Standard LangGraph execution using configurable session
    config = {
        "configurable": {
            "session": session,
            "thread_id": "test_thread"
        }
    }
    
    result = graph.invoke(initial_state, config)
    
    # Assert successful flow
    assert "dummy_scan" in result["completed_steps"]
    assert approval_triggered is True
    assert session.audit.verify_chain() is True
    
    # Check that events were logged correctly
    events = session.audit.get_events()
    event_types = [e["event_type"] for e in events]
    assert "SESSION_INIT" in event_types
    assert "GUARDRAIL_SCOPE_CHECK" in event_types
    assert "GUARDRAIL_APPROVAL_GRANTED" in event_types
    assert "AGENT_DECISION" in event_types


def test_graph_fails_on_out_of_scope_target(valid_roe):
    """E2E Test: Out-of-scope target fails immediately in Lead Agent node and blocks further execution."""
    session = EngagementSession(roe=valid_roe)
    graph = build_phase1_graph()
    
    initial_state = {
        "current_target": "10.0.0.1",  # out of scope
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config = {
        "configurable": {
            "session": session,
            "thread_id": "test_thread"
        }
    }
    
    # The run should abort with ScopeViolationError
    with pytest.raises(ScopeViolationError):
        graph.invoke(initial_state, config)
        
    # Verify a security violation was recorded
    events = session.audit.get_events()
    event_types = [e["event_type"] for e in events]
    assert "SECURITY_VIOLATION" in event_types
    
    # Verify sub-agent was never reached (completed_steps is empty)
    # Check pointer would show it did not proceed or finalize successfully
    assert session.audit.verify_chain() is True


def test_graph_fails_on_approval_rejection(valid_roe):
    """E2E Test: If user rejects approval for an active-safe action, graph fails and blocks."""
    def mock_callback(tool, tier):
        return False  # Reject
        
    session = EngagementSession(roe=valid_roe, approval_callback=mock_callback)
    graph = build_phase1_graph()
    
    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config = {
        "configurable": {
            "session": session,
            "thread_id": "test_thread"
        }
    }
    
    # Executing the graph should raise ApprovalViolationError when sub-agent tries to scan
    with pytest.raises(ApprovalViolationError):
        graph.invoke(initial_state, config)
        
    # Verify denial logged
    events = session.audit.get_events()
    event_types = [e["event_type"] for e in events]
    assert "GUARDRAIL_APPROVAL_DENIED" in event_types


def test_graph_halts_when_killed_mid_execution(valid_roe):
    """E2E Test: If the session is killed, graph fails to execute further nodes."""
    session = EngagementSession(roe=valid_roe)
    graph = build_phase1_graph()
    
    # Kill the session before starting
    session.kill()
    
    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config = {
        "configurable": {
            "session": session,
            "thread_id": "test_thread"
        }
    }
    
    with pytest.raises(EngagementKilledError):
        graph.invoke(initial_state, config)


# --- Adversarial Tests ---

def test_direct_node_execution_bypasses_graph_but_triggers_guardrails(valid_roe):
    """Adversarial Test: Attempting to invoke the dummy sub-agent's execution node
    directly (bypassing the Lead Agent and graph routing) with a target that is out
    of scope or missing approval callback.
    """
    # Case A: Out-of-scope target
    session_out_of_scope = EngagementSession(roe=valid_roe)
    state_out_of_scope = {
        "current_target": "10.0.0.1",  # Out of scope
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    config_out_of_scope = {
        "configurable": {
            "session": session_out_of_scope
        }
    }
    # Direct execution of dummy_sub_agent_node should fail on target scope assertion
    with pytest.raises(ScopeViolationError):
        dummy_sub_agent_node(state_out_of_scope, config_out_of_scope)
    
    # Case B: Tool approval rejection when called directly
    def mock_reject_callback(tool, tier):
        return False  # Reject everything
        
    session_reject = EngagementSession(roe=valid_roe, approval_callback=mock_reject_callback)
    
    state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config_reject = {
        "configurable": {
            "session": session_reject
        }
    }
    
    # Direct execution of dummy_sub_agent_node should fail on tool approval check
    with pytest.raises(ApprovalViolationError):
        dummy_sub_agent_node(state, config_reject)

