import os
import sys
import time
import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Ensure cadresec package is importable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))


# Set environment variable before importing API to satisfy boot security check
os.environ["CADRESEC_API_KEY"] = "test_auth_secret_key"
from cadresec.api import app, active_sessions, checkpoints_db, engagement_db


@pytest.fixture(autouse=True)
def clean_database_and_sessions():
    """Wipes session files and checkpoints between runs to keep execution isolated."""
    active_sessions.clear()
    
    from cadresec.api import request_history
    request_history.clear()
    
    # Remove SQLite checkpoints DB if present
    if os.path.exists(checkpoints_db):
        try:
            os.remove(checkpoints_db)
        except Exception:
            pass
            
    # Remove SQLite engagement DB if present
    if os.path.exists(engagement_db):
        try:
            os.remove(engagement_db)
        except Exception:
            pass
            
    yield
    
    # Cleanup after test
    active_sessions.clear()
    if os.path.exists(checkpoints_db):
        try:
            os.remove(checkpoints_db)
        except Exception:
            pass
    if os.path.exists(engagement_db):
        try:
            os.remove(engagement_db)
        except Exception:
            pass


@pytest.fixture
def api_client():
    return TestClient(app)


# --- 1. Missing Env Startup Test ---

def test_startup_fails_loud_on_missing_api_key():
    """Verify that the API server refuses to start if CADRESEC_API_KEY environment variable is unset."""
    import subprocess
    res = subprocess.run(
        [sys.executable, "-c", "import os; os.environ.pop('CADRESEC_API_KEY', None); import cadresec.api"],
        capture_output=True,
        text=True
    )
    assert res.returncode != 0
    assert "RuntimeError" in res.stderr or "RuntimeError" in res.stdout
    assert "CADRESEC_API_KEY environment variable is not configured" in res.stderr or "CADRESEC_API_KEY environment variable is not configured" in res.stdout


# --- 2. Authentication Rejection Tests ---

def test_unauthenticated_requests_are_rejected(api_client):
    """Verify that requests without X-API-Key are rejected with 401 Unauthorized."""
    endpoints = [
        ("POST", "/sessions", {"roe": {}, "target": "127.0.0.1"}),
        ("GET", "/sessions/some-id/status", None),
        ("GET", "/sessions/some-id/pending-approvals", None),
        ("POST", "/sessions/some-id/approve", {"tool_name": "nmap"}),
        ("POST", "/sessions/some-id/reject", {"tool_name": "nmap"}),
        ("POST", "/sessions/some-id/kill", None),
        ("GET", "/sessions/some-id/report", None)
    ]
    
    for method, path, json_data in endpoints:
        if method == "POST":
            res = api_client.post(path, json=json_data)
        else:
            res = api_client.get(path)
        assert res.status_code == 401, f"Path {path} did not reject unauthenticated client"


# --- 3. Rate Limiting Test ---

def test_sessions_rate_limiting(api_client):
    """Verify that exceeding session creation limits triggers 429 Too Many Requests."""
    headers = {"X-API-Key": "test_auth_secret_key"}
    fake_roe = {
        "authorized_scope": ["127.0.0.1"],
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-12-31T23:59:59Z",
        "permitted_risk_tiers": ["passive", "active-safe"],
        "allow_unsandboxed_fallback": True,
        "authorizing_party": "Test CISO"
    }
    payload = {"roe": fake_roe, "target": "127.0.0.1"}

    # Trigger multiple session requests quickly
    for i in range(5):
        res = api_client.post("/sessions", json=payload, headers=headers)
        assert res.status_code == 201

    # The 6th request should exceed the limit of 5 per minute
    res = api_client.post("/sessions", json=payload, headers=headers)
    assert res.status_code == 429
    assert "Too many requests" in res.json()["detail"]


# --- 4. E2E HTTP Approval Flow Test ---

def test_e2e_http_approval_flow(api_client):
    """Verify standard HTTP session workflow: post, pause, check approvals, approve mismatch check, approve, and retrieve report."""
    headers = {"X-API-Key": "test_auth_secret_key"}
    fake_roe = {
        "authorized_scope": ["127.0.0.1"],
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-12-31T23:59:59Z",
        "permitted_risk_tiers": ["passive", "active-safe"],
        "allow_unsandboxed_fallback": True,  # Allow fallback for local runner test
        "authorizing_party": "Test CISO"
    }
    
    payload = {
        "roe": fake_roe,
        "target": "127.0.0.1"
    }

    # 1. Create session
    res = api_client.post("/sessions", json=payload, headers=headers)
    assert res.status_code == 201
    sid = res.json()["session_id"]
    assert sid is not None

    # 2. Wait and Poll status until it reaches the 'paused' state (waiting for nmap active-safe approval)
    paused = False
    for _ in range(30):
        time.sleep(0.2)
        status_res = api_client.get(f"/sessions/{sid}/status", headers=headers)
        if status_res.json()["status"] == "paused":
            paused = True
            break
            
    assert paused is True
    assert status_res.json()["pending_approval"]["tool_name"] == "nmap"

    # 3. Test Mismatched Tool Approval Rejection
    mismatch_res = api_client.post(f"/sessions/{sid}/approve", json={"tool_name": "malicious_tool"}, headers=headers)
    assert mismatch_res.status_code == 400
    assert "Approval Rejected" in mismatch_res.json()["detail"]

    # 4. Approve the correct tool ('nmap')
    approve_res = api_client.post(f"/sessions/{sid}/approve", json={"tool_name": "nmap"}, headers=headers)
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "running"

    # 5. Wait for E2E scan and report compiling to complete
    completed = False
    for _ in range(60):
        time.sleep(0.2)
        status_res = api_client.get(f"/sessions/{sid}/status", headers=headers)
        if status_res.json()["status"] == "completed":
            completed = True
            break
            
    assert completed is True

    # 6. Fetch report findings
    report_res = api_client.get(f"/sessions/{sid}/report", headers=headers)
    assert report_res.status_code == 200
    assert "report" in report_res.json()
    assert len(report_res.json()["report"]) > 0


# --- 5. Concurrent Session Approval Test ---

def test_concurrent_sessions_resume(api_client):
    """Verify that multiple concurrent sessions run, pause, and resume correctly without DB locking or thread-safety errors."""
    headers = {"X-API-Key": "test_auth_secret_key"}
    fake_roe = {
        "authorized_scope": ["127.0.0.1"],
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-12-31T23:59:59Z",
        "permitted_risk_tiers": ["passive", "active-safe"],
        "allow_unsandboxed_fallback": True,
        "authorizing_party": "Test CISO"
    }
    
    # Spawn Session A
    payload_a = {"roe": fake_roe, "target": "127.0.0.1"}
    res_a = api_client.post("/sessions", json=payload_a, headers=headers)
    assert res_a.status_code == 201
    sid_a = res_a.json()["session_id"]

    # Spawn Session B
    payload_b = {"roe": fake_roe, "target": "127.0.0.1"}
    res_b = api_client.post("/sessions", json=payload_b, headers=headers)
    assert res_b.status_code == 201
    sid_b = res_b.json()["session_id"]

    # Wait for both to pause
    paused_a = paused_b = False
    for _ in range(40):
        time.sleep(0.2)
        if not paused_a:
            status_a = api_client.get(f"/sessions/{sid_a}/status", headers=headers).json()
            if status_a["status"] == "paused":
                paused_a = True
        if not paused_b:
            status_b = api_client.get(f"/sessions/{sid_b}/status", headers=headers).json()
            if status_b["status"] == "paused":
                paused_b = True
        if paused_a and paused_b:
            break
            
    assert paused_a is True
    assert paused_b is True

    # Approve both concurrently (or in rapid succession to verify DB connection multiplexing)
    app_res_a = api_client.post(f"/sessions/{sid_a}/approve", json={"tool_name": "nmap"}, headers=headers)
    app_res_b = api_client.post(f"/sessions/{sid_b}/approve", json={"tool_name": "nmap"}, headers=headers)
    
    assert app_res_a.status_code == 200
    assert app_res_b.status_code == 200

    # Wait for both to complete (increased timeout for concurrent scans)
    completed_a = completed_b = False
    status_a = {}
    status_b = {}
    for _ in range(120):
        time.sleep(0.2)
        if not completed_a:
            status_a = api_client.get(f"/sessions/{sid_a}/status", headers=headers).json()
            if status_a["status"] == "completed":
                completed_a = True
        if not completed_b:
            status_b = api_client.get(f"/sessions/{sid_b}/status", headers=headers).json()
            if status_b["status"] == "completed":
                completed_b = True
        if completed_a and completed_b:
            break
            
    if not (completed_a and completed_b):
        print(f"\n[DEBUG] Session A final status: {status_a}")
        print(f"\n[DEBUG] Session B final status: {status_b}")
    assert completed_a is True
    assert completed_b is True


# --- 6. Concurrent Session Metadata Database Writes Test ---

def test_concurrent_database_metadata_writes():
    """Verify that multiple concurrent threads can write and update session metadata in the SQLite DB without conflicts or data loss."""
    import threading
    from cadresec.core.roe import RulesOfEngagement
    from cadresec.core.session import EngagementSession
    from cadresec.api import save_session_to_db, SessionLocal, SessionMetadataRecord
    
    num_threads = 20
    num_updates_per_thread = 10
    threads = []
    
    # Pre-populate active_sessions with unique sessions
    for i in range(num_threads):
        sid = f"thread-session-{i}"
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        roe = RulesOfEngagement(
            authorized_scope=["127.0.0.1"],
            start_time=now - datetime.timedelta(hours=1),
            end_time=now + datetime.timedelta(hours=2),
            permitted_risk_tiers=["passive", "active-safe"],
            authorizing_party=f"CISO Admin Thread {i}"
        )
        # Create session
        sess = EngagementSession(roe, session_id=sid, db_url=f"sqlite:///{engagement_db}")
        sess.target_ip = "127.0.0.1"
        sess.status = "created"
        sess.pending_approval = None
        active_sessions[sid] = sess

    def worker_write_task(thread_index):
        sid = f"thread-session-{thread_index}"
        sess = active_sessions[sid]
        
        for u in range(num_updates_per_thread):
            # Update status dynamically to simulate active progress updates
            sess.status = f"running-step-{u}"
            if u % 2 == 0:
                sess.pending_approval = {"tool_name": f"nmap-{u}", "risk_tier": "active-safe"}
            else:
                sess.pending_approval = None
            
            # Write to database (thread-safe session setup handles this via connect_args timeout)
            save_session_to_db(sid)
            time.sleep(0.01)  # Yield/simulate small delay

    # Launch threads
    for i in range(num_threads):
        t = threading.Thread(target=worker_write_task, args=(i,))
        threads.append(t)
        t.start()

    # Join threads
    for t in threads:
        t.join()

    # Verify database contents
    db_session = SessionLocal()
    try:
        records = db_session.query(SessionMetadataRecord).filter(SessionMetadataRecord.session_id.like("thread-session-%")).all()
        assert len(records) == num_threads
        
        for record in records:
            assert record.session_id.startswith("thread-session-")
            # The status should have reached the last step (running-step-9)
            assert record.status == f"running-step-{num_updates_per_thread - 1}"
            # The last step (9) is odd, so pending_approval should be None (NULL in SQLite)
            assert record.pending_approval is None
    finally:
        db_session.close()
