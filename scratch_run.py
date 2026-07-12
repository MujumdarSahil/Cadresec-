import os
import sys
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Ensure cadresec package is importable
sys.path.insert(0, os.path.abspath("."))

from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError, CadresecError
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.agents.graph import build_graph


MOCK_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun SYSTEM "nmap.dtd">
<nmaprun scanner="nmap" args="nmap -oX - -F 127.0.0.1" start="1700000000" version="7.92">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" method="table"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def interactive_approval(tool_name: str, risk_tier: str) -> bool:
    print(f"\n[GUARDRAIL CHALLENGE] Action Required: Tool '{tool_name}' (tier: {risk_tier}) requested execution.")
    while True:
        choice = input("Approve tool execution? (yes/no): ").strip().lower()
        if choice in ("yes", "y"):
            return True
        elif choice in ("no", "n"):
            return False
        print("Please enter 'yes' or 'no'.")


def main():
    parser = argparse.ArgumentParser(description="Cadresec E2E Pipeline Verification Runner")
    parser.add_argument(
        "--mode",
        choices=["docker", "host-nmap", "mock"],
        default="mock",
        help="Execution mode: 'docker' runs in a container, 'host-nmap' calls host nmap directly, 'mock' simulates process stdout."
    )
    args = parser.parse_args()

    # 1. Load RoE
    now = datetime.now(timezone.utc)
    roe = RulesOfEngagement(
        authorized_scope=["127.0.0.1"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE, RiskTier.ACTIVE_RISKY],
        authorizing_party="Audit Administrator - Verification Run"
    )

    db_path = "sqlite:///verification_run.db"
    # Clean up old database files
    if os.path.exists("verification_run.db"):
        os.remove("verification_run.db")

    print("=" * 60)
    print("CADRESEC E2E PIPELINE RUNNER STARTED")
    print(f"Mode: {args.mode.upper()}")
    print(f"Database Path: {db_path}")
    print("=" * 60)

    try:
        session = EngagementSession(roe=roe, db_url=db_path, approval_callback=interactive_approval)
    except CadresecError as e:
        print(f"[-] Session initialization failed: {e}")
        sys.exit(1)

    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }

    config = {
        "configurable": {
            "session": session,
            "thread_id": "verification_run_thread"
        }
    }

    # 2. Setup execution mocks if selected
    if args.mode == "mock":
        # Mock subprocess to return predefined XML
        mock_proc = MagicMock()
        mock_proc.stdout = MOCK_NMAP_XML
        mock_proc.returncode = 0
        execution_patch = patch("subprocess.run", return_value=mock_proc)
        execution_patch.start()
        print("[+] Mock runner configured (bypassing process execution).")
    elif args.mode == "host-nmap":
        # Intercept and run host nmap executable
        host_nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if not os.path.exists(host_nmap_path):
            print(f"[-] Host Nmap not found at {host_nmap_path}. Run winget install first.")
            sys.exit(1)
            
        original_run = subprocess.run
        def host_nmap_run(cmd, *args, **kwargs):
            if cmd[0] == "docker" and any("nmap" in c for c in cmd):
                try:
                    img_idx = next(i for i, c in enumerate(cmd) if "nmap" in c)
                    nmap_args = cmd[img_idx+1:]
                except StopIteration:
                    nmap_args = ["-oX", "-", "127.0.0.1"]
                # Translate host.docker.internal target back to 127.0.0.1 for host execution
                nmap_args = [c.replace("host.docker.internal", "127.0.0.1") for c in nmap_args]
                patched_cmd = [host_nmap_path] + nmap_args
                print(f"[+] Patching docker command to host executable: {' '.join(patched_cmd)}")
                return original_run(patched_cmd, *args, **kwargs)
            return original_run(cmd, *args, **kwargs)
        
        execution_patch = patch("subprocess.run", side_effect=host_nmap_run)
        execution_patch.start()
        print(f"[+] Host Nmap runner configured: using {host_nmap_path}")
    else:
        print("[+] Real container execution configured (will run 'docker run ...').")

    # 3. Execute Pipeline Graph
    graph = build_graph()
    try:
        print("\n[*] Invoking orchestrator graph...")
        result = graph.invoke(initial_state, config)
        print("[+] Graph execution finished successfully.")
    except Exception as e:
        print(f"\n[-] Graph execution failed: {e}")
        sys.exit(1)
    finally:
        if args.mode in ("mock", "host-nmap"):
            execution_patch.stop()

    # 4. Display Outputs
    print("\n" + "=" * 60)
    print("VERIFICATION DATA OUTPUT")
    print("=" * 60)

    # A. Raw Nmap XML Output (Read from events)
    discovery_events = session.ocsf.read_events(session.session_id, class_uid=5010)
    network_events = session.ocsf.read_events(session.session_id, class_uid=4001)

    print("\n[A] RAW NMAP XML OUTPUT (RECONSTRUCTED OR RETRIEVED):")
    # For mock/host, we can show XML from the stored logs if successful
    # We find nmap tool success event (index 1 of TOOL_EXECUTION_SUCCESS)
    success_events = [e for e in session.audit.get_events() if e["event_type"] == "TOOL_EXECUTION_SUCCESS"]
    nmap_success = [e for e in success_events if e["details"].get("tool_name") == "nmap"]
    if nmap_success:
        print("Success log details:")
        print(nmap_success[0]["details"])
    else:
        print("No successful nmap tool execution details found.")

    # B. OCSF Event Records from Database
    print("\n[B] OCSF EVENT STORE ROWS (JSON):")
    print(f"Found {len(discovery_events)} Discovery events (Class 5010):")
    for idx, dev in enumerate(discovery_events):
        print(f"  Event {idx+1}: {dev}")
        
    print(f"\nFound {len(network_events)} Network Activity events (Class 4001):")
    for idx, net in enumerate(network_events):
        print(f"  Event {idx+1}: {net}")

    # C. Audit Ledger & Cryptographic Chain Validation
    print("\n[C] AUDIT LEDGER EVENTS:")
    audit_events = session.audit.get_events()
    for e in audit_events:
        print(f"  Seq {e['sequence_number']} | {e['event_type']} | Actor: {e['actor']} | Hash: {e['hash'][:12]}...")

    ledger_valid = session.audit.verify_chain()
    print(f"\nCryptographic Chain Integrity Verification: {'[PASS]' if ledger_valid else '[FAIL]'}")

    # D. Generated Markdown Report
    print("\n[D] GENERATED MARKDOWN REPORT:")
    report_filename = f"report_{session.session_id}.md"
    if os.path.exists(report_filename):
        with open(report_filename, "r", encoding="utf-8") as f:
            print(f.read())
        # Clean up report file after printing
        os.remove(report_filename)
    else:
        print(f"[-] Report file {report_filename} was not generated.")


if __name__ == "__main__":
    main()
