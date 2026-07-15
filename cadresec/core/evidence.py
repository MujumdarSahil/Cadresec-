from datetime import datetime, timezone
from pydantic import BaseModel, Field


class Evidence(BaseModel):
    category: str = Field(..., description="Category of evidence (e.g. server, cookie, port, dns, banner, authentication)")
    value: str = Field(..., description="Detected evidence value (e.g. nginx, PHPSESSID, NextAuth)")
    confidence: float = Field(..., description="Confidence score between 0.0 and 1.0")
    source: str = Field(..., description="Source of the evidence (e.g. HTTP Header, Cookie, HTML, Banner Grab)")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO timestamp when the evidence was observed"
    )
    originating_tool: str = Field(..., description="Name of the tool that generated the evidence")
