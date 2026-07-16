from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator


class TechnologyProfile(BaseModel):
    name: str = Field(default="", description="Name of the detected technology (e.g. Nginx)")
    technology: str = Field(default="", description="Name of the detected technology (legacy alias)")
    category: str = Field(..., description="Category of the technology (e.g. Web Server)")
    version: Optional[str] = Field(None, description="Detected version string if available")
    confidence: float = Field(..., description="Aggregated confidence score between 0.0 and 1.0")
    evidence: List[str] = Field(default_factory=list, description="Descriptions of supporting evidence")
    recommendation: Optional[str] = Field(None, description="Optional security recommendation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata dictionary")

    @model_validator(mode="before")
    @classmethod
    def sync_name_and_technology(cls, data: Any) -> Any:
        if isinstance(data, dict):
            name = data.get("name")
            tech = data.get("technology")
            if name and not tech:
                data["technology"] = name
            elif tech and not name:
                data["name"] = tech
            
            # Convert enum to string value if category is passed as an enum
            cat = data.get("category")
            if cat:
                if hasattr(cat, "value"):
                    data["category"] = cat.value
                else:
                    data["category"] = str(cat)
        return data

    def to_ocsf_service(self, port: int = 80, protocol: str = "TCP", state: str = "open") -> Any:
        """Converts this technology profile to an OCSF DiscoveredService object."""
        from cadresec.core.ocsf import DiscoveredService
        return DiscoveredService(
            port=port,
            protocol=protocol,
            service=self.name.lower(),
            state=state,
            version=self.version
        )

    def to_ocsf_discovery(self, target: str, port: int, session_id: str) -> Any:
        """Converts this technology profile and dynamic scan info to an OCSFDiscovery event."""
        from cadresec.core.ocsf import OCSFDiscovery, DiscoveryDevice
        service = self.to_ocsf_service(port=port)
        desc_parts = [f"Detected {self.name}"]
        if self.version:
            desc_parts.append(f"version {self.version}")
        desc_parts.append(f"(confidence: {self.confidence:.2f}). Evidence: {', '.join(self.evidence[:3])}")
        
        return OCSFDiscovery(
            device=DiscoveryDevice(
                ip=target,
                hostname=target,
                description=" | ".join(desc_parts),
                services=[service]
            ),
            session_id=session_id
        )
