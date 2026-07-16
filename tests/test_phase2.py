import os
import pytest
from typing import Optional
from unittest.mock import MagicMock, patch
from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError, SandboxUnavailableError
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.tools.nmap import NmapToolSpec, NmapInput
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


def test_nmap_tool_enforces_scope_internally(valid_roe):
    """Verify that NmapToolSpec.run() directly checks scope and rejects out-of-scope targets from INSIDE run() itself."""
    session = EngagementSession(roe=valid_roe)
    nmap_tool = NmapToolSpec()
    
    # Try running nmap directly with out-of-scope target
    # Guardrail inside run() must raise ScopeViolationError immediately
    with pytest.raises(ScopeViolationError, match="not within the authorized scope"):
        nmap_tool.run(session, NmapInput(target="10.0.0.1"))


def test_nmap_tool_enforces_approval_internally(valid_roe):
    """Verify that NmapToolSpec.run() directly checks risk tier approvals and rejects if callback returns False."""
    def mock_reject(tool_name, risk_tier):
        return False  # Reject approval
        
    session = EngagementSession(roe=valid_roe, approval_callback=mock_reject)
    nmap_tool = NmapToolSpec()
    
    with pytest.raises(ApprovalViolationError, match="User denied approval"):
        nmap_tool.run(session, NmapInput(target="127.0.0.1"))


def test_nmap_xml_parsing_and_ocsf_mapping(valid_roe):
    """Verify that NmapToolSpec successfully runs container execution, parses the XML, maps to OCSF, and records in database."""
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    nmap_tool = NmapToolSpec()
    
    mock_proc = MagicMock()
    mock_proc.stdout = MOCK_NMAP_XML
    mock_proc.returncode = 0
    
    with patch.object(NmapToolSpec, "_is_docker_available", return_value=True):
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            result = nmap_tool.run(session, NmapInput(target="127.0.0.1"))
        
        # Verify docker subprocess was invoked correctly
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "docker" in args
        assert "instrumentisto/nmap" in args
        assert "host.docker.internal" in args
        
        # Verify parser output
        assert result.success is True
        assert len(result.parsed_hosts) == 1
        host = result.parsed_hosts[0]
        assert host["ip"] == "127.0.0.1"
        assert host["hostname"] == "localhost"
        assert len(host["ports"]) == 2
        assert host["ports"][0]["port"] == 80
        assert host["ports"][1]["port"] == 443
        
        # Verify OCSF Event Store database contains events
        discovery_events = session.ocsf.read_events(session.session_id, class_uid=5010)
        assert len(discovery_events) == 1
        discovery = discovery_events[0]
        assert discovery["class_uid"] == 5010
        assert discovery["device"]["ip"] == "127.0.0.1"
        assert len(discovery["device"]["services"]) == 2
        
        network_events = session.ocsf.read_events(session.session_id, class_uid=4001)
        assert len(network_events) == 2
        assert network_events[0]["dst_endpoint"]["port"] == 80
        assert network_events[1]["dst_endpoint"]["port"] == 443


def test_phase2_end_to_end_run(valid_roe):
    """E2E Test: Runs Lead Agent graph -> Recon Agent -> Scan Agent (mocked) -> Vuln Agent -> Triage -> Reporting.
    Verifies that all subgraphs run in sequence, write OCSF data, and generate a markdown report.
    """
    # Active-safe scan tool is approved
    def mock_approval(tool, tier):
        return True
        
    session = EngagementSession(roe=valid_roe, approval_callback=mock_approval)
    graph = build_graph()
    
    initial_state = {
        "current_target": "127.0.0.1",
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }
    
    config = {
        "configurable": {
            "session": session,
            "thread_id": "phase2_thread"
        }
    }
    
    # Mock subprocess run inside Scan Agent subgraph nmap call
    mock_proc = MagicMock()
    mock_proc.stdout = MOCK_NMAP_XML
    mock_proc.returncode = 0
    
    # We clean any existing report for this session before running
    report_filename = f"report_{session.session_id}.md"
    if os.path.exists(report_filename):
        os.remove(report_filename)
        
    with patch.object(NmapToolSpec, "_is_docker_available", return_value=True):
        with patch("subprocess.run", return_value=mock_proc):
            result = graph.invoke(initial_state, config)
        
    # Verify graph completion
    assert "recon" in result["completed_steps"]
    assert "scan" in result["completed_steps"]
    assert "vuln_analysis" in result["completed_steps"]
    assert "triage" in result["completed_steps"]
    assert "reporting" in result["completed_steps"]
    
    # Verify markdown report file was written
    assert os.path.exists(report_filename) is True
    
    # Read report contents and verify OCSF / Triage findings are summarized
    with open(report_filename, "r", encoding="utf-8") as f:
        report_content = f.read()
        
    assert "Cadresec Engagement Security Report" in report_content
    assert "Target IP: 127.0.0.1" in report_content
    assert "| 80 | TCP | http | open |" in report_content
    assert "| 443 | TCP | https | open |" in report_content
    assert "[MEDIUM] Plaintext HTTP exposed" in report_content
    
    # Clean up report file
    if os.path.exists(report_filename):
        os.remove(report_filename)


# --- Real Local HTTP Server Port Discovery Test ---

import http.server
import threading

def start_local_server():
    server = http.server.HTTPServer(('127.0.0.1', 0), http.server.SimpleHTTPRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port

def is_docker_running() -> bool:
    import subprocess
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=3)
        return res.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def get_host_nmap_path() -> Optional[str]:
    import os
    path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    if os.path.exists(path):
        return path
    return None

def test_nmap_local_server_scan_real(valid_roe):
    """Real network scan test: Starts a local HTTP server and runs the nmap scanner.
    If Docker is available, runs in a container. If Docker is not available but
    host nmap is, it executes host nmap.
    """
    server, port = start_local_server()
    
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    nmap_tool = NmapToolSpec()
    
    docker_available = is_docker_running()
    host_nmap_path = get_host_nmap_path()
    
    if not docker_available and not host_nmap_path:
        server.shutdown()
        pytest.skip("Neither Docker nor host Nmap is available. Skipping real scan test.")
        
    if not docker_available:
        valid_roe.allow_unsandboxed_fallback = True
        
    patcher = None
    if not docker_available and host_nmap_path:
        import subprocess
        original_run = subprocess.run
        def patch_run(cmd, *args, **kwargs):
            if cmd[0] == "docker" and any("nmap" in c for c in cmd):
                # Dynamically locate the image index and extract trailing arguments
                try:
                    img_idx = next(i for i, c in enumerate(cmd) if "nmap" in c)
                    nmap_args = cmd[img_idx+1:]
                except StopIteration:
                    nmap_args = ["-oX", "-", "127.0.0.1"]
                # Translate host gateway alias back to localhost for host binary scan
                nmap_args = [c.replace("host.docker.internal", "127.0.0.1") for c in nmap_args]
                patched_cmd = [host_nmap_path] + nmap_args
                return original_run(patched_cmd, *args, **kwargs)
            return original_run(cmd, *args, **kwargs)
        patcher = patch("subprocess.run", side_effect=patch_run)
        patcher.start()
        
    try:
        # Run nmap scan targeting our local server port
        result = nmap_tool.run(session, NmapInput(target="127.0.0.1", ports=str(port)))
        
        # Verify result contains the open port
        assert result.success is True
        assert len(result.parsed_hosts) == 1
        host = result.parsed_hosts[0]
        assert host["ip"] == "127.0.0.1"
        
        # Check if the port was found open
        open_ports = [p["port"] for p in host["ports"] if p["state"] == "open"]
        assert port in open_ports
        
    finally:
        if patcher:
            patcher.stop()
        server.shutdown()
        server.server_close()


# --- Sandbox Guardrail and Fallback Tests ---

def test_nmap_sandbox_unavailable_default_failure(valid_roe):
    """Verify that if Docker is unavailable and allow_unsandboxed_fallback is False (default),
    NmapToolSpec.run() fails loudly by raising SandboxUnavailableError.
    """
    # Ensure fallback is explicitly False
    valid_roe.allow_unsandboxed_fallback = False
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    nmap_tool = NmapToolSpec()

    # Force _is_docker_available to return False
    with patch.object(NmapToolSpec, "_is_docker_available", return_value=False):
        with pytest.raises(SandboxUnavailableError, match="Sandbox environment \\(Docker\\) is unavailable"):
            nmap_tool.run(session, NmapInput(target="127.0.0.1"))

    # Assert that the SANDBOX_UNAVAILABLE_ABORT event was logged in the audit ledger
    abort_events = [e for e in session.audit.get_events() if e["event_type"] == "SANDBOX_UNAVAILABLE_ABORT"]
    assert len(abort_events) == 1
    assert abort_events[0]["details"]["tool_name"] == "nmap"


def test_nmap_sandbox_unavailable_fallback_success(valid_roe):
    """Verify that if Docker is unavailable and allow_unsandboxed_fallback is True,
    NmapToolSpec.run() falls back to host execution and logs distinct bypass audit events.
    """
    # Authorize fallback explicitly in RoE
    valid_roe.allow_unsandboxed_fallback = True
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    nmap_tool = NmapToolSpec()

    mock_proc = MagicMock()
    mock_proc.stdout = MOCK_NMAP_XML
    mock_proc.returncode = 0

    # Force _is_docker_available to return False, and mock subprocess to run host nmap
    with patch.object(NmapToolSpec, "_is_docker_available", return_value=False):
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            result = nmap_tool.run(session, NmapInput(target="127.0.0.1"))

            # Verify parser successfully parsed results
            assert result.success is True

            # Verify subprocess ran nmap executable (since use_sandbox was False)
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            # It should not call docker, it should call nmap directly
            assert "docker" not in cmd
            assert any("nmap" in c.lower() for c in cmd)

    # Verify audit events logged the bypass and unsandboxed execution
    events = session.audit.get_events()
    bypass_events = [e for e in events if e["event_type"] == "SANDBOX_BYPASS_USED"]
    start_events = [e for e in events if e["event_type"] == "TOOL_UNSANDBOXED_EXECUTION_START"]
    
    assert len(bypass_events) == 1
    assert len(start_events) == 1
    assert bypass_events[0]["details"]["tool_name"] == "nmap"
    assert start_events[0]["details"]["sandboxed"] is False

