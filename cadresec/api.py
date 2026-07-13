import os
import json
import time
import threading
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from cadresec.core.exceptions import CadresecError
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.agents.graph import build_graph
from cadresec.tools.mcp_adapter import load_mcp_tools_from_config
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.errors import NodeInterrupt


# --- 1. HARD SECURITY GATING: Enforce API Key on Start ---
API_KEY = os.environ.get("CADRESEC_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "CRITICAL CONFIGURATION ERROR: CADRESEC_API_KEY environment variable is not configured. "
        "Server startup aborted."
    )


app = FastAPI(title="Cadresec Security Orchestration API")


# --- 2. AUTHENTICATION & RATE LIMITS ---

async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Dependency verifying the API key header."""
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header."
        )


# In-memory IP tracking history (Single-Process Constraint)
request_history: Dict[str, List[float]] = {}

def rate_limit(endpoint_name: str, max_requests: int, window_seconds: int):
    """Factory creating a client IP rate limiting dependency."""
    def dependency(request: Request):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        key = f"{endpoint_name}:{client_ip}"
        
        history = request_history.setdefault(key, [])
        # Filter request timestamps older than window
        history[:] = [t for t in history if now - t < window_seconds]
        
        if len(history) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later."
            )
        history.append(now)
    return dependency


# --- 3. SESSION STATE ENGINE & PERSISTENCE ---

# RAM cache for active session objects
active_sessions: Dict[str, EngagementSession] = {}
checkpoints_db = "cadresec_checkpoints.db"
engagement_db = "cadresec_engagement.db"

# Database metadata engine setup
engine = create_engine(f"sqlite:///{engagement_db}", connect_args={"timeout": 30})
Base = declarative_base()

class SessionMetadataRecord(Base):
    __tablename__ = "session_metadata"
    
    session_id = Column(String, primary_key=True)
    roe = Column(Text, nullable=False)
    target = Column(String, nullable=False)
    mcp_config = Column(Text, nullable=True)
    status = Column(String, nullable=False)
    pending_approval = Column(Text, nullable=True)
    approved_active_safe_tools = Column(Text, nullable=False)
    approved_active_risky_calls = Column(Text, nullable=False)
    error = Column(Text, nullable=True)

Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)


class SessionPayload(BaseModel):
    roe: dict = Field(..., description="Rules of Engagement JSON configuration")
    target: str = Field(..., description="Target address/hostname to authorize")
    mcp_config: Optional[dict] = Field(default=None, description="Optional allowed MCP registry schema")


class ApprovalPayload(BaseModel):
    tool_name: str = Field(..., description="Name of the tool to authorize")


def save_session_to_db(session_id: str):
    """Saves/updates a single session's metadata in the SQLite DB to persist across server restarts."""
    sess = active_sessions.get(session_id)
    if not sess:
        return
    db_session = SessionLocal()
    try:
        record = SessionMetadataRecord(
            session_id=session_id,
            roe=sess.roe.model_dump_json(),
            target=getattr(sess, "target_ip", ""),
            mcp_config=json.dumps(sess.mcp_config) if getattr(sess, "mcp_config", None) else None,
            status=getattr(sess, "status", "unknown"),
            pending_approval=json.dumps(sess.pending_approval) if sess.pending_approval else None,
            approved_active_safe_tools=json.dumps(list(sess.approved_active_safe_tools)),
            approved_active_risky_calls=json.dumps(list(sess.approved_active_risky_calls)),
            error=getattr(sess, "error_msg", None)
        )
        db_session.merge(record)
        db_session.commit()
    except Exception as e:
        print(f"Error saving session metadata: {e}")
    finally:
        db_session.close()


def load_sessions_from_db():
    """Restores session instances from persistent metadata in the SQLite DB on boot."""
    db_session = SessionLocal()
    try:
        records = db_session.query(SessionMetadataRecord).all()
        for record in records:
            roe = RulesOfEngagement.model_validate_json(record.roe)
            # Reconstruct session binding
            sess = EngagementSession(roe, session_id=record.session_id, db_url=f"sqlite:///{engagement_db}")
            sess.use_interrupts = True
            sess.target_ip = record.target
            sess.mcp_config = json.loads(record.mcp_config) if record.mcp_config else None
            sess.status = record.status
            sess.pending_approval = json.loads(record.pending_approval) if record.pending_approval else None
            sess.approved_active_safe_tools = set(json.loads(record.approved_active_safe_tools))
            sess.approved_active_risky_calls = set(json.loads(record.approved_active_risky_calls))
            sess.error_msg = record.error
            
            # Register MCP tools if configured
            if sess.mcp_config:
                try:
                    sess.mcp_tools = load_mcp_tools_from_config(sess.mcp_config)
                except Exception:
                    pass

            active_sessions[record.session_id] = sess
    except Exception as e:
        print(f"Error loading sessions: {e}")
    finally:
        db_session.close()


# Restore state on app initialization
load_sessions_from_db()


# --- 4. BACKWARDS COMPATIBLE DOCKER ENVIRONMENT INJECTION ---
def configure_docker_env():
    """Appends Docker Desktop bin folder to Path on Windows if missing."""
    if os.name == "nt":
        docker_bin = r"C:\Program Files\Docker\Docker\resources\bin"
        if os.path.exists(docker_bin) and docker_bin not in os.environ.get("Path", ""):
            os.environ["Path"] += ";" + docker_bin


configure_docker_env()


# --- 5. THREAD-SAFE RESUME WORKER LOOP ---

def run_session_worker(session_id: str, target: str):
    """Background worker executing the LangGraph checkpoint within a thread-local SQLite saver."""
    sess = active_sessions.get(session_id)
    if not sess:
        return

    # Add environment Path safety to background thread execution context
    configure_docker_env()

    initial_state = {
        "current_target": target,
        "messages": [],
        "completed_steps": [],
        "routing_decision": ""
    }

    config = {
        "configurable": {
            "session": sess,
            "thread_id": f"api_thread_{session_id}"
        }
    }

    # Thread-local: Open SqliteSaver connection context inside the running thread
    with SqliteSaver.from_conn_string(checkpoints_db) as checkpointer:
        graph = build_graph(checkpointer=checkpointer)
        
        try:
            # Check if there is an active checkpoint to resume
            checkpoint_tuple = checkpointer.get_tuple(config)
            print(f"\n[WORKER] Invoking graph. session_id={session_id}, checkpoint_exists={checkpoint_tuple is not None}")
            if checkpoint_tuple is not None:
                # Resume execution from last interrupt checkpoint
                res = graph.invoke(None, config)
            else:
                # Start new run
                res = graph.invoke(initial_state, config)
            
            # Check if the execution has paused on an interrupt (standard LangGraph state return behavior)
            if isinstance(res, dict) and "__interrupt__" in res and res["__interrupt__"]:
                sess.status = "paused"
            else:
                # If graph finishes cleanly and is not paused
                sess.status = "completed"
                sess.pending_approval = None
        except NodeInterrupt as e:
            # Fallback exception handler in case NodeInterrupt bubbles up
            sess.status = "paused"
        except Exception as e:
            print(f"\n[WORKER] Caught Exception: {e} ({type(e).__name__})")
            import traceback
            traceback.print_exc()
            # Pipeline run failed
            sess.status = "failed"
            sess.error_msg = str(e)
            sess.pending_approval = None
        finally:
            save_session_to_db(session_id)


# --- 6. ENDPOINTS ROUTING ---

@app.post(
    "/sessions",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_api_key), Depends(rate_limit("create_session", 5, 60))]
)
async def create_session(payload: SessionPayload):
    """Initializes a new session from RoE schema and triggers background scan graph."""
    try:
        roe = RulesOfEngagement.model_validate(payload.roe)
        sess = EngagementSession(roe, db_url="sqlite:///cadresec_engagement.db")
    except CadresecError as e:
        raise HTTPException(status_code=400, detail=f"Invalid Rules of Engagement: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Configuration error: {str(e)}")

    sess.use_interrupts = True
    sess.target_ip = payload.target
    sess.mcp_config = payload.mcp_config
    sess.status = "running"
    sess.pending_approval = None
    sess.error_msg = None
    
    # Pre-register MCP tools if config is loaded
    if payload.mcp_config:
        try:
            sess.mcp_tools = load_mcp_tools_from_config(payload.mcp_config)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to validate MCP allowed registry: {str(e)}")

    active_sessions[sess.session_id] = sess
    save_session_to_db(sess.session_id)

    # Spawn thread-safe worker loop in background thread
    t = threading.Thread(target=run_session_worker, args=(sess.session_id, payload.target), daemon=True)
    t.start()

    return {"session_id": sess.session_id, "status": sess.status}


@app.get("/sessions/{id}/status", dependencies=[Depends(verify_api_key)])
async def get_session_status(id: str):
    """Queries current session execution state and pending approval details."""
    sess = active_sessions.get(id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
        
    return {
        "session_id": id,
        "status": sess.status,
        "pending_approval": sess.pending_approval,
        "error": sess.error_msg
    }


@app.get("/sessions/{id}/pending-approvals", dependencies=[Depends(verify_api_key)])
async def get_pending_approvals(id: str):
    """Queries pending approvals details."""
    sess = active_sessions.get(id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
    return sess.pending_approval


@app.post("/sessions/{id}/approve", dependencies=[Depends(verify_api_key)])
async def approve_tool(id: str, payload: ApprovalPayload):
    """Authorizes execution of a paused tool run and resumes pipeline thread."""
    sess = active_sessions.get(id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")

    if sess.status != "paused" or not sess.pending_approval:
        raise HTTPException(
            status_code=400,
            detail="Session is not currently paused waiting for operator approval."
        )

    # Hard Mismatch Gate: Validate client approval payload
    pending_tool = sess.pending_approval.get("tool_name")
    if payload.tool_name != pending_tool:
        raise HTTPException(
            status_code=400,
            detail=f"Approval Rejected: Request is approving tool '{payload.tool_name}', but tool '{pending_tool}' is currently pending."
        )

    tier_str = sess.pending_approval.get("risk_tier")
    
    # Cache approved decision
    if tier_str == "active-safe":
        sess.approved_active_safe_tools.add(payload.tool_name)
    elif tier_str == "active-risky":
        sess.approved_active_risky_calls.add(payload.tool_name)

    # Grant and write log response
    sess.audit.record(
        event_type="GUARDRAIL_APPROVAL_RESPONSE",
        actor="admin_api",
        details={
            "tool_name": payload.tool_name,
            "risk_tier": tier_str,
            "approved": True
        }
    )

    sess.pending_approval = None
    sess.status = "running"
    save_session_to_db(id)

    # Resume the thread-safe worker loop in background thread
    t = threading.Thread(target=run_session_worker, args=(id, sess.target_ip), daemon=True)
    t.start()

    return {"session_id": id, "status": sess.status}


@app.post("/sessions/{id}/reject", dependencies=[Depends(verify_api_key)])
async def reject_tool(id: str, payload: ApprovalPayload):
    """Denies execution of a paused tool and terminates graph run."""
    sess = active_sessions.get(id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")

    if sess.status != "paused" or not sess.pending_approval:
        raise HTTPException(
            status_code=400,
            detail="Session is not currently paused waiting for operator approval."
        )

    # Hard Mismatch Gate
    pending_tool = sess.pending_approval.get("tool_name")
    if payload.tool_name != pending_tool:
        raise HTTPException(
            status_code=400,
            detail=f"Rejection Mismatch: Request is rejecting tool '{payload.tool_name}', but tool '{pending_tool}' is currently pending."
        )

    tier_str = sess.pending_approval.get("risk_tier")

    sess.audit.record(
        event_type="GUARDRAIL_APPROVAL_RESPONSE",
        actor="admin_api",
        details={
            "tool_name": payload.tool_name,
            "risk_tier": tier_str,
            "approved": False
        }
    )

    sess.pending_approval = None
    sess.status = "rejected"
    sess.error_msg = f"Operator rejected execution of tool '{payload.tool_name}' (tier: {tier_str})"
    save_session_to_db(id)

    return {"session_id": id, "status": sess.status}


@app.post(
    "/sessions/{id}/kill",
    dependencies=[Depends(verify_api_key), Depends(rate_limit("kill_session", 10, 60))]
)
async def kill_session(id: str):
    """Appends a cryptographically chained SESSION_KILL record to halt the session's graph execution loop."""
    sess = active_sessions.get(id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
        
    sess.kill()
    sess.status = "killed"
    save_session_to_db(id)
    return {"session_id": id, "status": sess.status}


@app.get("/sessions/{id}/report", dependencies=[Depends(verify_api_key)])
async def get_session_report(id: str):
    """Fetches generated session scan findings report."""
    sess = active_sessions.get(id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")

    report_filename = f"report_{id}.md"
    if os.path.exists(report_filename):
        try:
            with open(report_filename, "r", encoding="utf-8") as f:
                return {"report": f.read()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read report: {str(e)}")
            
    # Fallback to database summary
    try:
        events = sess.audit.get_events()
        return {
            "report": f"# Session Report Summary: {id}\n\nSession finished status: {sess.status}. Total audit events logged: {len(events)}."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report not available: {str(e)}")
