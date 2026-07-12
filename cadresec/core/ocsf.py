import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Text, select
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class OcsfEventRecord(Base):
    __tablename__ = "ocsf_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, nullable=False)
    class_uid = Column(Integer, nullable=False)
    timestamp = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    data = Column(Text, nullable=False)  # JSON-serialized payload (JSONB in Postgres, Text in SQLite)


# --- OCSF Event Schema Schemas ---

class Endpoint(BaseModel):
    ip: str
    port: Optional[int] = None
    hostname: Optional[str] = None


class ConnectionInfo(BaseModel):
    protocol_num: Optional[int] = None
    protocol_name: str  # TCP, UDP
    state: str  # open, closed, filtered


class OCSFNetworkActivity(BaseModel):
    class_uid: int = 4001
    class_name: str = "Network Activity"
    activity_id: int = 1  # 1: Open, 2: Close, etc.
    time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    src_endpoint: Endpoint
    dst_endpoint: Endpoint
    connection_info: ConnectionInfo
    session_id: str


class DiscoveredService(BaseModel):
    port: int
    protocol: str
    service: str
    state: str


class DiscoveryDevice(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    services: List[DiscoveredService] = Field(default_factory=list)


class OCSFDiscovery(BaseModel):
    class_uid: int = 5010
    class_name: str = "Discovery"
    activity_id: int = 1  # 1: Inventory, 2: Scan
    time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    device: DiscoveryDevice
    session_id: str


# --- OCSF Event Store Backend ---

class OCSFEventStore:
    def __init__(self, db_url: str = "sqlite:///:memory:"):
        """Initializes the OCSF Event Store.
        
        db_url can be sqlite:///:memory: or a postgresql connection string.
        """
        self.db_url = db_url
        self.engine = create_engine(self.db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def write_event(self, session_id: str, class_uid: int, event: BaseModel) -> None:
        """Writes a validated OCSF event object to the database."""
        event_dict = event.model_dump()
        event_dict["session_id"] = session_id  # Ensure session binding
        
        db_session = self.Session()
        try:
            record = OcsfEventRecord(
                session_id=session_id,
                class_uid=class_uid,
                timestamp=event_dict.get("time", datetime.now(timezone.utc).isoformat()),
                event_type=event.__class__.__name__,
                data=json.dumps(event_dict, sort_keys=True)
            )
            db_session.add(record)
            db_session.commit()
        finally:
            db_session.close()

    def read_events(self, session_id: str, class_uid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Reads all events for a given session, optionally filtering by OCSF class_uid."""
        db_session = self.Session()
        try:
            stmt = select(OcsfEventRecord).where(OcsfEventRecord.session_id == session_id)
            if class_uid is not None:
                stmt = stmt.where(OcsfEventRecord.class_uid == class_uid)
            stmt = stmt.order_by(OcsfEventRecord.id.asc())
            
            records = db_session.execute(stmt).scalars().all()
            return [json.loads(r.data) for r in records]
        finally:
            db_session.close()
