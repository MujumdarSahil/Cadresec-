import pytest
from datetime import datetime, timedelta, timezone

from cadresec.core.roe import RulesOfEngagement, RiskTier


@pytest.fixture
def valid_roe() -> RulesOfEngagement:
    """Provides a valid Rules of Engagement configuration spanning current time."""
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        authorized_scope=["127.0.0.1", "192.168.1.0/24", "*.target.local", "exact-domain.com"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE, RiskTier.ACTIVE_RISKY],
        authorizing_party="CISO John Doe, SecureCorp"
    )


@pytest.fixture
def expired_roe() -> RulesOfEngagement:
    """Provides an expired Rules of Engagement configuration."""
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        authorized_scope=["127.0.0.1"],
        start_time=now - timedelta(hours=5),
        end_time=now - timedelta(hours=1),
        permitted_risk_tiers=[RiskTier.PASSIVE],
        authorizing_party="CISO John Doe, SecureCorp"
    )
