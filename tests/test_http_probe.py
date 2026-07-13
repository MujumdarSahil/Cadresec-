import os
import sys
import time
import socket
import http.server
import threading
import pytest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

# Configure Docker environment path on Windows
if os.name == "nt":
    docker_bin = r"C:\Program Files\Docker\Docker\resources\bin"
    if os.path.exists(docker_bin) and docker_bin not in os.environ.get("Path", ""):
        os.environ["Path"] += ";" + docker_bin

from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.tools.http_probe import HTTPProbeToolSpec, HTTPProbeInput


@pytest.fixture
def valid_roe() -> RulesOfEngagement:
    """Provides a valid Rules of Engagement configuration spanning current time."""
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        authorized_scope=["127.0.0.1", "localhost"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="CISO John Doe, SecureCorp"
    )


def start_local_http_server():
    """Starts a local mock HTTP server on a random port and returns (server, port)."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]
    server_sock.close()

    class CustomHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/test-path":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Test-Response", "cadresec-ground-truth")
                self.end_headers()
                self.wfile.write(b"Hello from ground truth!")
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://10.99.99.99:8080/out-of-scope")
                self.end_headers()
            else:
                self.send_error(404)

        def do_HEAD(self):
            if self.path == "/test-path":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Test-Response", "cadresec-ground-truth-head")
                self.end_headers()
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            pass  # Suppress logging stdout noise

    httpd = http.server.HTTPServer(("127.0.0.1", port), CustomHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


_docker_running_cache = None

def is_docker_running() -> bool:
    global _docker_running_cache
    if _docker_running_cache is not None:
        return _docker_running_cache

    import subprocess
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        _docker_running_cache = (res.returncode == 0)
    except (subprocess.SubprocessError, FileNotFoundError):
        _docker_running_cache = False
    return _docker_running_cache


# --- 1. Adversarial Scope Verification ---

def test_http_probe_enforces_scope_at_boundary(valid_roe):
    """Verify that HTTPProbeToolSpec.run() checks scope at the boundary and rejects out-of-scope targets."""
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    tool = HTTPProbeToolSpec()

    # Target 10.0.0.1 is out of scope in the valid_roe
    input_data = HTTPProbeInput(target="10.0.0.1", port=80, path="/")
    
    with pytest.raises(ScopeViolationError, match="not within the authorized scope"):
        tool.run(session, input_data)


# --- 2. Risk Tier Approval Verification ---

def test_http_probe_enforces_active_safe_approval(valid_roe):
    """Verify that HTTPProbeToolSpec.run() rejects execution if the ACTIVE_SAFE approval callback returns False."""
    def deny_approval(tool_name, risk_tier):
        return False

    session = EngagementSession(roe=valid_roe, approval_callback=deny_approval)
    tool = HTTPProbeToolSpec()

    input_data = HTTPProbeInput(target="127.0.0.1", port=80, path="/")

    with pytest.raises(ApprovalViolationError, match="User denied approval"):
        tool.run(session, input_data)


# --- 3. Real E2E Container Execution Verification ---

def test_http_probe_container_execution_real(valid_roe):
    """Verify unmocked containerized HTTP probe execution against a local server with ground-truth verification."""
    docker_available = is_docker_running()
    if not docker_available:
        pytest.skip("Docker daemon not running, skipping E2E container scan.")

    # Start local mock server
    server, port = start_local_http_server()

    try:
        session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
        tool = HTTPProbeToolSpec()

        # Test GET method
        input_data_get = HTTPProbeInput(target="127.0.0.1", port=port, path="/test-path", method="GET")
        result_get = tool.run(session, input_data_get)

        assert result_get.success is True
        assert result_get.http_code == 200
        assert result_get.headers.get("x-test-response") == "cadresec-ground-truth"
        assert result_get.body_length == len("Hello from ground truth!")

        # Test HEAD method
        input_data_head = HTTPProbeInput(target="127.0.0.1", port=port, path="/test-path", method="HEAD")
        result_head = tool.run(session, input_data_head)

        assert result_head.success is True
        assert result_head.http_code == 200
        assert result_head.headers.get("x-test-response") == "cadresec-ground-truth-head"
        assert result_head.body_length == 0  # HEAD request has no body content

        # Verify OCSF Database Events were recorded
        discovery_events = session.ocsf.read_events(session.session_id, class_uid=5010)
        assert len(discovery_events) >= 2
        dev = discovery_events[0]["device"]
        assert dev["ip"] == "127.0.0.1"
        assert dev["services"][0]["port"] == port
        assert dev["services"][0]["service"] == "http"

        network_events = session.ocsf.read_events(session.session_id, class_uid=4001)
        assert len(network_events) >= 2
        assert network_events[0]["dst_endpoint"]["port"] == port

    finally:
        server.shutdown()
        server.server_close()


# --- 4. Redirect Refusal Verification ---

def test_http_probe_blocks_redirects(valid_roe):
    """Verify that HTTPProbeToolSpec does NOT follow HTTP redirects, preventing out-of-scope bypasses."""
    docker_available = is_docker_running()
    if not docker_available:
        pytest.skip("Docker daemon not running, skipping redirect test.")

    server, port = start_local_http_server()

    try:
        session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
        tool = HTTPProbeToolSpec()

        input_data = HTTPProbeInput(target="127.0.0.1", port=port, path="/redirect", method="GET")
        result = tool.run(session, input_data)

        # Confirm the tool returns a 302 response directly without following it to 10.99.99.99
        assert result.success is True
        assert result.http_code == 302
        assert result.headers.get("location") == "http://10.99.99.99:8080/out-of-scope"
    finally:
        server.shutdown()
        server.server_close()
