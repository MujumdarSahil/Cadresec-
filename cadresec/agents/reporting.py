import os
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState


def reporting_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Reporting agent node: read-only node compiling findings into a markdown report."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    # Query OCSF Discovery events
    events = session.ocsf.read_events(session.session_id, class_uid=5010)

    # Build report sections
    report_lines = [
        "# Cadresec Engagement Security Report",
        f"- **Engagement Session ID**: `{session.session_id}`",
        f"- **Authorized Time Window**: `{session.roe.start_time.isoformat()}` to `{session.roe.end_time.isoformat()}`",
        f"- **Authorizing Party**: {session.roe.authorizing_party}",
        "",
        "## 1. Rules of Engagement Scope",
        "The following target scopes were approved for scanning:"
    ]

    for scope in session.roe.authorized_scope:
        report_lines.append(f"- `{scope}`")

    report_lines.extend([
        "",
        "## 2. Host Discovery and Port Scanning",
        "Services identified during active scanning mapped to OCSF format:"
    ])

    if not events:
        report_lines.append("- No host or port discovery findings recorded in the OCSF event store.")
    else:
        for event in events:
            device = event.get("device", {})
            ip = device.get("ip", "")
            hostname = device.get("hostname", "unknown") or "unknown"
            services = device.get("services", [])
            
            report_lines.extend([
                f"### Target IP: {ip} (Hostname: {hostname})",
                "| Port | Protocol | Service Name | State |",
                "| :--- | :--- | :--- | :--- |"
            ])
            for srv in services:
                report_lines.append(f"| {srv.get('port')} | {srv.get('protocol')} | {srv.get('service')} | {srv.get('state')} |")
            report_lines.append("")

    # Extract triage messages from state
    triage_text = ""
    for msg in reversed(state.get("messages", [])):
        if msg.get("sender") == "triage_agent":
            triage_text = msg.get("text", "")
            break

    report_lines.extend([
        "## 3. Vulnerability Triage and Severity Matrix",
        "Prioritization of detected port exposure issues based on risk classification:"
    ])

    if triage_text:
        # Strip header
        content = triage_text.replace("Triage Assessment completed. Triage outputs:\n", "")
        report_lines.append(content)
    else:
        report_lines.append("- No priority vulnerabilities identified.")

    report_content = "\n".join(report_lines)

    # Save the report file inside the workspace directory
    report_filename = f"report_{session.session_id}.md"
    report_path = os.path.join(".", report_filename)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    # Log report creation to audit log
    session.audit.record(
        event_type="AGENT_DECISION",
        actor="reporting_agent",
        details={
            "action": "write_report_file",
            "filename": report_filename
        }
    )

    return {
        "messages": [
            {
                "sender": "reporting_agent",
                "text": f"Report generated successfully: {report_filename}."
            }
        ],
        "completed_steps": ["reporting"]
    }


def build_reporting_graph():
    """Compiles the Reporting Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("reporting_node", reporting_node)
    builder.set_entry_point("reporting_node")
    builder.add_edge("reporting_node", END)
    return builder.compile()
