import os
import sys
import time
import json
import pytest
from datetime import datetime, timedelta, timezone

# Ensure cadresec package is importable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

# Configure Docker environment path on Windows
if os.name == "nt":
    docker_bin = r"C:\Program Files\Docker\Docker\resources\bin"
    if os.path.exists(docker_bin) and docker_bin not in os.environ.get("Path", ""):
        os.environ["Path"] += ";" + docker_bin

from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError
from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.tools.mcp_adapter import load_mcp_tools_from_config, MCPToolSpec


@pytest.fixture
def valid_roe() -> RulesOfEngagement:
    """Provides a valid Rules of Engagement configuration spanning current time."""
    now = datetime.now(timezone.utc)
    return RulesOfEngagement(
        authorized_scope=["127.0.0.1", "localhost"],
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="CISO John Doe, SecureCorp"
    )


def is_docker_running() -> bool:
    import subprocess
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        return res.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


# --- 1. Adversarial Scope Enforcement ---

def test_mcp_tools_enforce_scope(valid_roe):
    """Verify that both PASSIVE name resolution and ACTIVE_SAFE ping tools enforce scope at the boundary."""
    config = {
        "servers": {
            "external_netutils": {
                "image": "ghcr.io/patrickdappollonio/mcp-netutils@sha256:b1d7180d34f9b18b2269d8635809f850307af040b6e3e47f7e7809bebeff53c7",
                "tools": {
                    "resolve_hostname": {
                        "risk_tier": "passive",
                        "target_parameter": "hostname"
                    }
                }
            },
            "local_regression": {
                "image": "local/mcp-test-server@sha256:4d374f1d619fe093dc7e6e74873347db26f884e31cce3c2d906c23b4cc464b0a",
                "tools": {
                    "ping_check": {
                        "risk_tier": "active-safe",
                        "target_parameter": "host_ip"
                    }
                }
            }
        }
    }

    tools = load_mcp_tools_from_config(config)
    assert len(tools) == 2

    # Map tools by name
    tool_map = {t.name: t for t in tools}
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)

    # 1. Test resolve_hostname with out-of-scope target
    resolve_input = tool_map["resolve_hostname"].input_schema(hostname="10.99.99.99")
    with pytest.raises(ScopeViolationError, match="not within the authorized scope"):
        tool_map["resolve_hostname"].run(session, resolve_input)

    # 2. Test ping_check with out-of-scope target
    ping_input = tool_map["ping_check"].input_schema(host_ip="10.99.99.99")
    with pytest.raises(ScopeViolationError, match="not within the authorized scope"):
        tool_map["ping_check"].run(session, ping_input)


# --- 2. Risk Tier Approval Gating ---

def test_mcp_tools_enforce_approval_gating(valid_roe):
    """Verify that ACTIVE_SAFE blocks on approval, while PASSIVE runs auto-approved."""
    config = {
        "servers": {
            "external_netutils": {
                "image": "ghcr.io/patrickdappollonio/mcp-netutils@sha256:b1d7180d34f9b18b2269d8635809f850307af040b6e3e47f7e7809bebeff53c7",
                "tools": {
                    "resolve_hostname": {
                        "risk_tier": "passive",
                        "target_parameter": "hostname"
                    }
                }
            },
            "local_regression": {
                "image": "local/mcp-test-server@sha256:4d374f1d619fe093dc7e6e74873347db26f884e31cce3c2d906c23b4cc464b0a",
                "tools": {
                    "ping_check": {
                        "risk_tier": "active-safe",
                        "target_parameter": "host_ip"
                    }
                }
            }
        }
    }

    tools = load_mcp_tools_from_config(config)
    tool_map = {t.name: t for t in tools}

    # Callback that denies all approvals
    def deny_approval(tool_name, risk_tier):
        return False

    session = EngagementSession(roe=valid_roe, approval_callback=deny_approval)

    # ACTIVE_SAFE tool (ping_check) must raise ApprovalViolationError
    ping_input = tool_map["ping_check"].input_schema(host_ip="127.0.0.1")
    with pytest.raises(ApprovalViolationError, match="User denied approval"):
        tool_map["ping_check"].run(session, ping_input)


# --- 3. E2E Third-Party & Local Regression Container Testing ---

def test_mcp_container_execution_real(valid_roe):
    """Verify E2E execution of both the external third-party MCP tool and local regression tool in containers."""
    if not is_docker_running():
        pytest.skip("Docker daemon not running, skipping E2E container tests.")

    config = {
        "servers": {
            "external_netutils": {
                "image": "ghcr.io/patrickdappollonio/mcp-netutils@sha256:b1d7180d34f9b18b2269d8635809f850307af040b6e3e47f7e7809bebeff53c7",
                "tools": {
                    "resolve_hostname": {
                        "risk_tier": "passive",
                        "target_parameter": "hostname"
                    }
                }
            },
            "local_regression": {
                "image": "local/mcp-test-server@sha256:4d374f1d619fe093dc7e6e74873347db26f884e31cce3c2d906c23b4cc464b0a",
                "tools": {
                    "ping_check": {
                        "risk_tier": "active-safe",
                        "target_parameter": "host_ip",
                        "timeout_seconds": 5
                    }
                }
            }
        }
    }

    tools = load_mcp_tools_from_config(config)
    tool_map = {t.name: t for t in tools}
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)

    # 1. Test External resolve_hostname (PASSIVE)
    # Target 127.0.0.1 remaps to host.docker.internal inside container
    resolve_input = tool_map["resolve_hostname"].input_schema(hostname="127.0.0.1")
    resolve_result = tool_map["resolve_hostname"].run(session, resolve_input)

    assert resolve_result.success is True
    # The adapter populates result directly with the RPC result block containing 'content'
    assert "content" in resolve_result.result
    content = resolve_result.result.get("content", [])
    assert len(content) > 0
    text_content = content[0].get("text", "")
    assert "ip" in text_content.lower() or "address" in text_content.lower() or "failed" in text_content.lower()

    # 2. Test Local ping_check (ACTIVE_SAFE)
    # Target 127.0.0.1 remaps to host.docker.internal inside container
    ping_input = tool_map["ping_check"].input_schema(host_ip="127.0.0.1")
    ping_result = tool_map["ping_check"].run(session, ping_input)

    assert ping_result.success is True
    content_ping = ping_result.result.get("content", [])
    assert len(content_ping) > 0
    import json
    parsed_ping = json.loads(content_ping[0].get("text", "{}"))
    # The host machine should have some port 80 or it should just complete successfully (success is True)
    assert parsed_ping.get("host_ip") == "host.docker.internal"


# --- 4. Socket Timeout Enforcement Test ---

def test_mcp_socket_timeout_enforcement(valid_roe):
    """Verify that socket-level timeout prevents the tool from hanging against unresponsive hosts."""
    if not is_docker_running():
        pytest.skip("Docker daemon not running, skipping E2E timeout test.")

    config = {
        "servers": {
            "local_regression": {
                "image": "local/mcp-test-server@sha256:4d374f1d619fe093dc7e6e74873347db26f884e31cce3c2d906c23b4cc464b0a",
                "tools": {
                    "ping_check": {
                        "risk_tier": "active-safe",
                        "target_parameter": "host_ip",
                        "timeout_seconds": 5
                    }
                }
            }
        }
    }

    tools = load_mcp_tools_from_config(config)
    ping_tool = tools[0]
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)

    # Use a non-routable/unresponsive IP address (e.g. 192.0.2.1 - TEST-NET-1 reserved IP)
    # Wait, 192.0.2.1 is out of scope. We must use an IP that is IN SCOPE but unresponsive.
    # We can use localhost on a port we know is closed, or a non-existent port.
    # Since ping_check targets port 80, if we run it on host.docker.internal and port 80 is closed/unresponsive:
    # Actually, to make it unresponsive we can run it against an IP in authorized scope that drops connection.
    # In our local context, connecting to localhost (127.0.0.1) on port 80 will either immediately reject (refuse)
    # or succeed. To test a slow/hanging connection, we can use a target IP that does not respond (e.g. out of scope).
    # But wait, out of scope raises ScopeViolationError.
    # So we must add an authorized IP to scope that we know is unresponsive.
    # Let's create a temporary RoE with "10.255.255.1" in scope, which is in a non-routable range and will timeout.
    temp_roe = RulesOfEngagement(
        authorized_scope=["10.255.255.1"],
        start_time=datetime.now(timezone.utc) - timedelta(hours=1),
        end_time=datetime.now(timezone.utc) + timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE],
        authorizing_party="CISO John Doe, SecureCorp"
    )
    temp_session = EngagementSession(roe=temp_roe, approval_callback=lambda tool, tier: True)

    # Set socket timeout parameter in the tool call to 1 second
    ping_input = ping_tool.input_schema(host_ip="10.255.255.1", timeout_seconds=1)
    
    start_time = time.time()
    result = ping_tool.run(temp_session, ping_input)
    duration = time.time() - start_time

    assert result.success is True  # The tool ran successfully
    content = result.result.get("content", [])
    parsed = json.loads(content[0].get("text", "{}"))
    assert parsed.get("open") is False  # It failed to connect (open is False)
    assert duration < 6.0  # Allowed up to 6 seconds to account for Windows container startup latency
