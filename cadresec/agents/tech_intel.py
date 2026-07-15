from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.core.evidence import Evidence
from cadresec.intelligence.fingerprint_engine import FingerprintEngine, TechnologyProfile
from cadresec.tools.http_probe import HTTPProbeToolSpec, HTTPProbeInput
from cadresec.tools.dns_lookup import DNSLookupToolSpec, DNSInput


def tech_intel_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Technology Intelligence agent node: discovers technologies, frameworks, and CMS."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    session.assert_not_killed()

    target = state.get("current_target")
    collected_evidence: List[Evidence] = []
    messages = []

    # 1. Run HTTP Probe on port 80 to collect headers, status, cookies
    try:
        probe_tool = HTTPProbeToolSpec()
        probe_res = probe_tool.run(session, HTTPProbeInput(target=target, port=80))
        if probe_res.success:
            collected_evidence.extend(probe_res.evidence)
    except Exception as e:
        messages.append({
            "sender": "tech_intel_agent",
            "text": f"HTTP Probe on port 80 skipped: {str(e)}."
        })

    # Also run on port 443 if SSL/HTTPS
    try:
        probe_tool = HTTPProbeToolSpec()
        probe_res = probe_tool.run(session, HTTPProbeInput(target=target, port=443))
        if probe_res.success:
            collected_evidence.extend(probe_res.evidence)
    except Exception:
        pass

    # 2. Run Fingerprint Engine to analyze gathered evidence
    engine = FingerprintEngine()
    profiles = engine.analyze(collected_evidence)

    # 3. Format Technology profiles for display
    profile_lines = []
    for p in profiles:
        ver_str = f" (version: {p.version})" if p.version else ""
        profile_lines.append(f"- **{p.technology}** [{p.category}] - Confidence: {p.confidence:.2f}{ver_str}")
        for ev in p.evidence[:2]:  # show up to 2 supporting evidence items
            profile_lines.append(f"  * Evidence: {ev}")

    summary = "\n".join(profile_lines) if profile_lines else "- No technology fingerprints detected."

    # Record agent decision to audit ledger
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="tech_intel_agent",
        details={
            "action": "technology_identification",
            "detected_technologies_count": len(profiles),
            "evidence_count": len(collected_evidence)
        }
    )

    messages.append({
        "sender": "tech_intel_agent",
        "text": f"Technology Intelligence completed. Profile results:\n{summary}"
    })

    return {
        "messages": messages,
        "completed_steps": ["tech_intel"]
    }


def build_tech_intel_graph():
    """Compiles the Tech Intel Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("tech_intel_node", tech_intel_node)
    builder.set_entry_point("tech_intel_node")
    builder.add_edge("tech_intel_node", END)
    return builder.compile()
