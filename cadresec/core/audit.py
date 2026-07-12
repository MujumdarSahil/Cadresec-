import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from sqlalchemy import create_engine, Column, Integer, String, Text, select
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sequence_number = Column(Integer, nullable=False)
    session_id = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)  # Stored as ISO 8601 string to prevent timezone/microsecond truncation discrepancies
    event_type = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    details = Column(Text, nullable=True)  # JSON-serialized payload
    previous_hash = Column(String, nullable=False)
    hash = Column(String, nullable=False)


class AuditLogger:
    def __init__(self, session_context, db_url: str = "sqlite:///:memory:"):
        """Initializes the AuditLogger.
        
        db_url can be sqlite:///:memory:, a local sqlite file, or a postgresql connection string.
        """
        self.session_context = session_context
        self.db_url = db_url
        self.engine = create_engine(self.db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def _compute_hash(self, seq: int, session_id: str, ts_str: str, event_type: str, actor: str, details_str: str, prev_hash: str) -> str:
        """Computes the cryptographic SHA-256 hash of a log entry."""
        payload = f"{seq}|{session_id}|{ts_str}|{event_type}|{actor}|{details_str}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def record(self, event_type: str, actor: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Appends a new event to the audit ledger, computing its hash relative to the previous entry."""
        session_id = self.session_context.session_id
        db_session = self.Session()
        try:
            # Retrieve the latest entry for this session to establish the hash chain
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.session_id == session_id)
                .order_by(AuditEvent.sequence_number.desc())
                .limit(1)
            )
            result = db_session.execute(stmt).scalars().first()

            if result is None:
                # Genesis block for this session
                seq = 0
                prev_hash = "0" * 64
            else:
                seq = result.sequence_number + 1
                prev_hash = result.hash

            ts_str = datetime.now(timezone.utc).isoformat()
            details_str = json.dumps(details or {}, sort_keys=True)
            current_hash = self._compute_hash(seq, session_id, ts_str, event_type, actor, details_str, prev_hash)

            event = AuditEvent(
                sequence_number=seq,
                session_id=session_id,
                timestamp=ts_str,
                event_type=event_type,
                actor=actor,
                details=details_str,
                previous_hash=prev_hash,
                hash=current_hash
            )
            db_session.add(event)
            db_session.commit()
        finally:
            db_session.close()

    def verify_chain(self) -> bool:
        """Verifies the cryptographic integrity of the entire audit chain for the current session."""
        session_id = self.session_context.session_id
        db_session = self.Session()
        try:
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.session_id == session_id)
                .order_by(AuditEvent.sequence_number.asc())
            )
            events = db_session.execute(stmt).scalars().all()

            expected_prev_hash = "0" * 64
            for i, event in enumerate(events):
                if event.sequence_number != i:
                    return False  # Sequence mismatch or missing entry

                if event.previous_hash != expected_prev_hash:
                    return False  # Hash chain link broken

                # Recompute the hash of this entry
                computed = self._compute_hash(
                    event.sequence_number,
                    event.session_id,
                    event.timestamp,
                    event.event_type,
                    event.actor,
                    event.details,
                    event.previous_hash
                )
                if event.hash != computed:
                    return False  # Content tampered with

                expected_prev_hash = event.hash

            return True
        finally:
            db_session.close()
            
    def get_events(self) -> List[Dict[str, Any]]:
        """Utility method to retrieve all log entries for debug/test validation."""
        session_id = self.session_context.session_id
        db_session = self.Session()
        try:
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.session_id == session_id)
                .order_by(AuditEvent.sequence_number.asc())
            )
            events = db_session.execute(stmt).scalars().all()
            return [
                {
                    "sequence_number": e.sequence_number,
                    "session_id": e.session_id,
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "actor": e.actor,
                    "details": json.loads(e.details),
                    "previous_hash": e.previous_hash,
                    "hash": e.hash
                }
                for e in events
            ]
        finally:
            db_session.close()
