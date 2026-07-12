import argparse
import sys
import os
import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

# Ensure cadresec package is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError, SandboxUnavailableError, CadresecError
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.core.audit import AuditLogger, AuditEvent
from cadresec.core.ocsf import OCSFEventStore, OcsfEventRecord
from cadresec.agents.graph import build_graph
from cadresec.tools.mcp_adapter import load_mcp_tools_from_config


def cli_console_approval(tool_name: str, risk_tier: str) -> bool:
    """Blocking console prompt for active tools validation."""
    print(f"\n[GUARDRAIL CHALLENGE] Action Required: Tool '{tool_name}' ({risk_tier}) requested execution.")
    try:
        choice = input(f"Approve execution of '{tool_name}'? (yes/no): ").strip().lower()
        return choice in ("yes", "y")
    except KeyboardInterrupt:
        print("\n[-] Human approval interrupted. Denying execution.")
        return False


def cmd_init_roe(args):
    """Generates a template Rules of Engagement JSON file."""
    now = datetime.now(timezone.utc)
    roe_dict = {
        "authorized_scope": args.scope,
        "start_time": (now - timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
        "permitted_risk_tiers": ["passive", "active-safe", "active-risky"],
        "allow_unsandboxed_fallback": False,
        "authorizing_party": args.party
    }
    
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(roe_dict, f, indent=2)
        print(f"[+] Successfully wrote template RoE to {args.output}")
    except Exception as e:
        print(f"[-] Failed to write RoE template: {e}")
        sys.exit(1)


def cmd_start_session(args):
    """Starts an engagement session, builds the graph, and triggers scanning."""
    if not os.path.exists(args.roe):
        print(f"[-] Rules of Engagement file '{args.roe}' does not exist.")
        sys.exit(1)
        
    try:
        with open(args.roe, "r", encoding="utf-8") as f:
            roe_data = json.load(f)
        roe = RulesOfEngagement.model_validate(roe_data)
    except Exception as e:
        print(f"[-] Invalid RoE configuration: {e}")
        sys.exit(1)

    print("[*] Initializing engagement session...")
    try:
        session = EngagementSession(
            roe=roe,
            db_url=args.db,
            approval_callback=cli_console_approval
        )
    except CadresecError as e:
        print(f"[-] Session initialization failed: {e}")
        sys.exit(1)

    print(f"[+] Active Session ID: {session.session_id}")

    # Register external MCP tools if config is provided
    mcp_tools = []
    if args.mcp_config:
        if not os.path.exists(args.mcp_config):
            print(f"[-] MCP config file '{args.mcp_config}' not found.")
            sys.exit(1)
        try:
            with open(args.mcp_config, "r", encoding="utf-8") as f:
                mcp_data = json.load(f)
            mcp_tools = load_mcp_tools_from_config(mcp_data)
            print(f"[+] Registered {len(mcp_tools)} external MCP tool(s) successfully.")
        except Exception as e:
            print(f"[-] Failed to load MCP tools: {e}")
            sys.exit(1)

    # Initialize graph state
    initial_state = {
        "current_target": args.target,
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }

    config = {
        "configurable": {
            "session": session,
            "thread_id": f"cli_thread_{session.session_id}"
        }
    }

    graph = build_graph()
    
    print(f"[*] Starting agent execution graph against target '{args.target}'...")
    try:
        # Check PATH for Docker binary context
        if "docker" not in os.environ.get("Path", "").lower():
            # Inject standard Docker Desktop paths on Windows if present
            docker_bin_path = r"C:\Program Files\Docker\Docker\resources\bin"
            if os.path.exists(docker_bin_path):
                os.environ["Path"] += ";" + docker_bin_path

        result = graph.invoke(initial_state, config)
        print("[+] Agent scan pipeline finished successfully.")
        report_filename = f"report_{session.session_id}.md"
        if os.path.exists(report_filename):
            print(f"[+] Audit report generated: {report_filename}")
        else:
            print("[-] Warning: Report markdown file was not generated.")
            
    except Exception as e:
        print(f"\n[-] Execution failed: {e}")
        sys.exit(1)


def cmd_status(args):
    """Prints live session information and verification logs."""
    engine = create_engine(args.db)
    Session = sessionmaker(bind=engine)
    db_session = Session()

    try:
        # Check if session exists in audit records
        stmt = select(AuditEvent).where(AuditEvent.session_id == args.session).order_by(AuditEvent.sequence_number.asc())
        events = db_session.execute(stmt).scalars().all()
        
        if not events:
            print(f"[-] Session '{args.session}' not found in database {args.db}.")
            return
            
        print("=" * 60)
        print(f"CADRESEC SESSION STATUS: {args.session}")
        print("=" * 60)
        
        # Check if killed
        is_killed = any(e.event_type == "SESSION_KILL" for e in events)
        print(f"Status: {'[KILLED / HALTED]' if is_killed else '[ACTIVE]'}")
        print(f"Total Audit Logs: {len(events)} events")
        
        # Retrieve OCSF events
        ocsf_stmt = select(OcsfEventRecord).where(OcsfEventRecord.session_id == args.session)
        ocsf_events = db_session.execute(ocsf_stmt).scalars().all()
        print(f"OCSF Logs: {len(ocsf_events)} events written")
        
        # Verify chain integrity
        # Re-initialize basic session structure to call verify_chain()
        class DummySession:
            def __init__(self, sid, db):
                self.session_id = sid
                self.audit = AuditLogger(self, db_url=db)
        
        dummy = DummySession(args.session, args.db)
        valid = dummy.audit.verify_chain()
        print(f"Ledger Integrity Verification: {'[PASS]' if valid else '[FAIL - TAMPERED]'}")
        
    finally:
        db_session.close()


def cmd_kill(args):
    """Triggers the global kill switch by writing a SESSION_KILL event to the database."""
    engine = create_engine(args.db)
    Session = sessionmaker(bind=engine)
    db_session = Session()

    try:
        # Check if session exists first
        stmt = select(AuditEvent).where(AuditEvent.session_id == args.session)
        exist = db_session.execute(stmt).first()
        if not exist:
            print(f"[-] Session '{args.session}' does not exist in database {args.db}.")
            return
            
        # Instantiate a dummy logger context to record the kill sequence safely
        class DummySession:
            def __init__(self, sid, db):
                self.session_id = sid
                self.audit = AuditLogger(self, db_url=db)
                
        dummy = DummySession(args.session, args.db)
        dummy.audit.record(
            event_type="SESSION_KILL",
            actor="system",
            details={"reason": "Kill switch triggered by administrator via CLI"}
        )
        print(f"[+] Successfully triggered global kill switch for session '{args.session}'.")
        
    finally:
        db_session.close()


def cmd_get_report(args):
    """Retrieves and prints the report contents if they are saved, or lists OCSF discovery data."""
    # Since the file may have been generated on a different machine/process,
    # we first check if the local report markdown file exists
    report_filename = f"report_{args.session}.md"
    if os.path.exists(report_filename):
        print(f"\n[+] Printing local report: {report_filename}\n")
        with open(report_filename, "r", encoding="utf-8") as f:
            print(f.read())
        return

    # Fallback: construct summary from OCSF database events
    engine = create_engine(args.db)
    Session = sessionmaker(bind=engine)
    db_session = Session()

    try:
        stmt = select(OcsfEventRecord).where(OcsfEventRecord.session_id == args.session).order_by(OcsfEventRecord.id.asc())
        records = db_session.execute(stmt).scalars().all()
        
        if not records:
            print(f"[-] No reports or OCSF events found for session '{args.session}'.")
            return
            
        print("=" * 60)
        print(f"REPORT FINDINGS FOR SESSION: {args.session}")
        print("=" * 60)
        
        for r in records:
            data = json.loads(r.data)
            if r.class_uid == 5010:
                dev = data.get("device", {})
                print(f"\nDiscovered Device: {dev.get('ip')} (Hostname: {dev.get('hostname')})")
                if dev.get("description"):
                    print(f"  Note: {dev.get('description')}")
                print("  Open Ports:")
                for srv in dev.get("services", []):
                    print(f"    - {srv.get('port')}/{srv.get('protocol')} ({srv.get('service')}) state: {srv.get('state')}")
            elif r.class_uid == 2002:
                vuln = data.get("vulnerability", {})
                info = data.get("finding_info", {})
                print(f"\nVulnerability Found: [{vuln.get('severity')}] {info.get('title')}")
                print(f"  Description: {info.get('description')}")
                if vuln.get("cve"):
                    print(f"  CVE: {vuln.get('cve')}")
    finally:
        db_session.close()


def main():
    parser = argparse.ArgumentParser(description="Cadresec Agent Engagement Console Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. init-roe
    p_init = subparsers.add_parser("init-roe", help="Generates a template Rules of Engagement JSON file")
    p_init.add_argument("--output", default="roe.json", help="Path to write the template file")
    p_init.add_argument("--scope", nargs="+", default=["127.0.0.1"], help="List of authorized CIDR target scopes")
    p_init.add_argument("--party", default="CISO Admin, SecureCorp", help="Details of the authorizing party")
    p_init.set_defaults(func=cmd_init_roe)

    # 2. start-session
    p_start = subparsers.add_parser("start-session", help="Loads RoE and starts scanning a target")
    p_start.add_argument("--roe", required=True, help="Path to the Rules of Engagement JSON configuration")
    p_start.add_argument("--target", required=True, help="Target IP or hostname to scan")
    p_start.add_argument("--db", default="sqlite:///cadresec_engagement.db", help="Connection URL for the database ledger")
    p_start.add_argument("--mcp-config", help="Optional path to allowed MCP config JSON")
    p_start.set_defaults(func=cmd_start_session)

    # 3. status
    p_status = subparsers.add_parser("status", help="Query session status and verify integrity")
    p_status.add_argument("--session", required=True, help="Session UUID to query")
    p_status.add_argument("--db", default="sqlite:///cadresec_engagement.db", help="Connection URL for the database ledger")
    p_status.set_defaults(func=cmd_status)

    # 4. kill
    p_kill = subparsers.add_parser("kill", help="Halts execution using the global session kill-switch")
    p_kill.add_argument("--session", required=True, help="Session UUID to kill")
    p_kill.add_argument("--db", default="sqlite:///cadresec_engagement.db", help="Connection URL for the database ledger")
    p_kill.set_defaults(func=cmd_kill)

    # 5. get-report
    p_report = subparsers.add_parser("get-report", help="Retrieves and prints the markdown findings report")
    p_report.add_argument("--session", required=True, help="Session UUID of the report")
    p_report.add_argument("--db", default="sqlite:///cadresec_engagement.db", help="Connection URL for the database ledger")
    p_report.set_defaults(func=cmd_get_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
