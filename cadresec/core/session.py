import uuid
from typing import Callable, Optional

from cadresec.core.exceptions import EngagementKilledError, InvalidRoEError
from cadresec.core.roe import RulesOfEngagement
from cadresec.core.audit import AuditLogger
from cadresec.core.guardrails import Guardrails
from cadresec.core.ocsf import OCSFEventStore


class EngagementSession:
    def __init__(
        self,
        roe: RulesOfEngagement,
        session_id: Optional[str] = None,
        db_url: str = "sqlite:///:memory:",
        approval_callback: Optional[Callable[[str, str], bool]] = None
    ):
        """Creates a new EngagementSession.
        
        roe: The RulesOfEngagement configuration.
        session_id: A unique ID. If None, one will be generated.
        db_url: Connection string for database.
        approval_callback: A function taking (tool_name, risk_tier) and returning a bool.
        """
        self.roe = roe
        self.session_id = session_id or str(uuid.uuid4())
        
        # Verify RoE validity immediately
        self.roe.validate_current_time()
        
        # Initialize subcomponents
        self.audit = AuditLogger(self, db_url=db_url)
        self.guardrails = Guardrails(self, approval_callback=approval_callback)
        self.ocsf = OCSFEventStore(db_url=db_url)
        
        # Internal state
        self._is_killed = False
        self.approved_active_safe_tools = set()  # Cache of active-safe tools approved in this session

        # Record session initialization
        self.audit.record(
            event_type="SESSION_INIT",
            actor="system",
            details={
                "session_id": self.session_id,
                "authorizing_party": self.roe.authorizing_party,
                "scope": self.roe.authorized_scope,
                "start_time": self.roe.start_time.isoformat(),
                "end_time": self.roe.end_time.isoformat()
            }
        )

    def kill(self) -> None:
        """Triggers the global kill switch to halt all executions in this session."""
        self._is_killed = True
        self.audit.record(
            event_type="SESSION_KILL",
            actor="system",
            details={"reason": "Kill switch triggered by administrator"}
        )

    def assert_not_killed(self) -> None:
        """Asserts that the session has not been killed, raising an error if it has."""
        if self._is_killed:
            raise EngagementKilledError("This engagement session has been killed and cannot execute any commands.")
            
        # Also check the database ledger for a SESSION_KILL record (enables cross-process kills)
        try:
            events = self.audit.get_events()
            if any(e["event_type"] == "SESSION_KILL" for e in events):
                self._is_killed = True
                raise EngagementKilledError("This engagement session has been killed and cannot execute any commands.")
        except Exception:
            pass
