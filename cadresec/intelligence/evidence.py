from datetime import datetime, timezone
from typing import Any, Union
from pydantic import BaseModel, Field, model_validator, field_serializer
from cadresec.intelligence.enums import EvidenceType


class Evidence(BaseModel):
    category: EvidenceType = Field(..., description="Category of evidence (e.g. server, cookie, port, dns, banner)")
    value: str = Field(..., description="Detected evidence value (e.g. nginx, PHPSESSID)")
    confidence: float = Field(..., description="Confidence score between 0.0 and 1.0")
    source: str = Field(..., description="Source of the evidence (e.g. HTTP Header, Cookie, HTML)")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the evidence was observed"
    )
    originating_tool: str = Field(..., description="Name of the tool that generated the evidence")

    @model_validator(mode="before")
    @classmethod
    def convert_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Parse timestamp if it is a string
            ts = data.get("timestamp")
            if isinstance(ts, str):
                try:
                    data["timestamp"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    pass
            
            # Map category from string to Enum
            cat = data.get("category")
            if isinstance(cat, str):
                try:
                    data["category"] = EvidenceType(cat.lower())
                except ValueError:
                    pass
        return data

    @field_serializer("timestamp")
    def serialize_timestamp(self, ts: datetime) -> str:
        # Serializes datetime to ISO format string for backwards compatibility
        return ts.isoformat()
