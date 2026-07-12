import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

from cadresec.core.exceptions import InvalidRoEError


class RiskTier(str, Enum):
    PASSIVE = "passive"
    ACTIVE_SAFE = "active-safe"
    ACTIVE_RISKY = "active-risky"
    DESTRUCTIVE = "destructive"


class RulesOfEngagement(BaseModel):
    authorized_scope: List[str] = Field(
        ..., 
        description="Authorized target ranges (IPs, CIDRs like 192.168.1.0/24, or domains like example.com, *.example.com)"
    )
    start_time: datetime = Field(..., description="Start of the authorized window")
    end_time: datetime = Field(..., description="End of the authorized window")
    permitted_risk_tiers: List[RiskTier] = Field(
        default=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE, RiskTier.ACTIVE_RISKY],
        description="List of risk tiers allowed for this engagement"
    )
    allow_unsandboxed_fallback: bool = Field(
        default=False,
        description="Allow tool execution on the host when container sandbox is unavailable"
    )
    authorizing_party: str = Field(..., description="Details of the authorizing organization/person")

    @field_validator("start_time", "end_time", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v):
        if isinstance(v, str):
            v = datetime.fromisoformat(v)
        if isinstance(v, datetime) and v.tzinfo is None:
            # Assume UTC if no timezone is provided
            return v.replace(tzinfo=timezone.utc)
        return v

    def validate_current_time(self) -> None:
        """Asserts that the current time is within the authorized time window."""
        now = datetime.now(timezone.utc)
        if now < self.start_time:
            raise InvalidRoEError(
                f"Engagement has not started yet. Authorization starts at {self.start_time} (current time: {now})"
            )
        if now > self.end_time:
            raise InvalidRoEError(
                f"Engagement window has expired. Authorization ended at {self.end_time} (current time: {now})"
            )

    def is_in_scope(self, target: str) -> bool:
        """Determines if a given target string is within the authorized scope.
        
        Supports:
        - Exact IP addresses
        - CIDR blocks
        - Domain names (exact match or wildcards like *.example.com)
        """
        target = target.strip().lower()
        if not target:
            return False

        # Attempt to parse target as an IP address
        target_ip = None
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            # Target is not a direct IP, treat as domain/hostname
            pass

        for scope_item in self.authorized_scope:
            scope_item = scope_item.strip().lower()
            
            # Check if scope item is a CIDR block or IP network
            try:
                scope_network = ipaddress.ip_network(scope_item, strict=False)
                if target_ip is not None:
                    if target_ip in scope_network:
                        return True
                else:
                    # If target is a hostname but scope is IP network, resolve target or skip.
                    # Since we avoid network lookups in guardrails to keep them deterministic/fast,
                    # we do not auto-resolve DNS here. Target must match scope type.
                    pass
            except ValueError:
                # Scope item is not an IP network, treat as domain match pattern
                if target_ip is not None:
                    continue  # Target is IP, scope is domain pattern
                
                # Check domain matching (wildcard vs exact)
                if scope_item.startswith("*."):
                    # e.g. *.example.com matches example.com and sub.example.com
                    base_domain = scope_item[2:]
                    if target == base_domain or target.endswith("." + base_domain):
                        return True
                else:
                    if target == scope_item:
                        return True

        return False
