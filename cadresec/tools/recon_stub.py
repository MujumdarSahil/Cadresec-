from typing import List
from pydantic import BaseModel, Field
from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec


class ReconInput(BaseModel):
    target: str = Field(..., description="Target domain or IP address")


class ReconOutput(BaseModel):
    target: str = Field(..., description="The query target")
    detected_ips: List[str] = Field(default_factory=list, description="IP addresses resolved")
    info: str = Field(..., description="Passive recon summary information")


class ReconStubTool(ToolSpec):
    name: str = "recon_stub"
    description: str = "Stub tool for performing passive target analysis and DNS lookup"
    risk_tier: RiskTier = RiskTier.PASSIVE
    input_schema: type[BaseModel] = ReconInput
    output_schema: type[BaseModel] = ReconOutput
    source: str = "builtin"

    def _execute(self, session, input_data: ReconInput, use_sandbox: bool = True) -> ReconOutput:
        """Simulates passive domain/IP validation without hitting the target directly."""
        target = input_data.target.strip().lower()
        
        # Hardcoded mocks for common local testing targets
        if target in ("localhost", "127.0.0.1"):
            ips = ["127.0.0.1"]
        elif "target.local" in target:
            ips = ["192.168.1.100"]
        else:
            ips = ["192.168.1.200"]
            
        return ReconOutput(
            target=input_data.target,
            detected_ips=ips,
            info=f"Recon stub successfully resolved '{target}' to {ips} using local caching simulations."
        )
