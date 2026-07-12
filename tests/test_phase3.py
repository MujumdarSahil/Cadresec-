import os
import sys
import pytest
import json
from unittest.mock import MagicMock, patch, mock_open

# Ensure cadresec package is importable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from cadresec.core.roe import RulesOfEngagement, RiskTier
from cadresec.core.session import EngagementSession
from cadresec.core.exceptions import ScopeViolationError, ApprovalViolationError, SandboxUnavailableError
from cadresec.tools.mcp_adapter import load_mcp_tools_from_config, MCPToolSpec, MCPOutput
from cadresec.cli import cli_console_approval, main as cli_main


MOCK_MCP_JSON_RPC_RESPONSE = """{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {"type": "text", "text": "Discovered open port 80/tcp on host."}
    ]
  },
  "id": 1
}
"""


@pytest.fixture
def valid_roe():
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    return RulesOfEngagement(
        authorized_scope=["127.0.0.1", "google.com"],
        start_time=now - datetime.timedelta(hours=1),
        end_time=now + datetime.timedelta(hours=2),
        permitted_risk_tiers=[RiskTier.PASSIVE, RiskTier.ACTIVE_SAFE, RiskTier.ACTIVE_RISKY],
        allow_unsandboxed_fallback=False,
        authorizing_party="CISO Admin, SecureCorp"
    )


# --- 1. Image Digest Pinning Tests ---

def test_mcp_image_digest_validation():
    """Verify that MCP server registration requires images to be pinned by SHA-256 digest."""
    valid_config = {
        "servers": {
            "vuln_scanner": {
                "image": "projectdiscovery/nuclei@sha256:7f08c3a93c72d001648a31e84a22c54ee9c5123d548312e3e8f812543d3e8e1f",
                "tools": {
                    "scan_http": {
                        "risk_tier": "passive",
                        "target_parameter": "target"
                    }
                }
            }
        }
    }
    
    # Validation should succeed
    tools = load_mcp_tools_from_config(valid_config)
    assert len(tools) == 1
    assert tools[0].image.endswith("sha256:7f08c3a93c72d001648a31e84a22c54ee9c5123d548312e3e8f812543d3e8e1f")

    invalid_config = {
        "servers": {
            "vuln_scanner": {
                "image": "projectdiscovery/nuclei:latest",  # Mutable tag
                "tools": {
                    "scan_http": {
                        "risk_tier": "passive",
                        "target_parameter": "target"
                    }
                }
            }
        }
    }
    
    # Should raise ValueError due to digest pinning check
    with pytest.raises(ValueError, match="pinned by SHA-256 digest"):
        load_mcp_tools_from_config(invalid_config)


# --- 2. Target-less Passive Capping Tests ---

def test_mcp_targetless_tool_passive_capping():
    """Verify that target-less tools are strictly capped at the passive risk tier at registration."""
    invalid_config = {
        "servers": {
            "calc_server": {
                "image": "local/calculator@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
                "tools": {
                    "perform_math": {
                        "risk_tier": "active-safe",  # Active tier, but no target parameter!
                        "target_parameter": None
                    }
                }
            }
        }
    }
    
    with pytest.raises(ValueError, match="Target-less tools must be strictly capped at passive tier"):
        load_mcp_tools_from_config(invalid_config)


# --- 3. MCP Adapter Out-of-Scope Blocking ---

def test_mcp_adapter_enforces_scope(valid_roe):
    """Verify that MCPToolSpec.run() enforces target scope checks at the boundary."""
    config = {
        "servers": {
            "port_scanner": {
                "image": "local/scanner@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
                "tools": {
                    "scan_ports": {
                        "risk_tier": "passive",
                        "target_parameter": "target"
                    }
                }
            }
        }
    }
    
    tools = load_mcp_tools_from_config(config)
    mcp_tool = tools[0]
    
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    
    # Define out-of-scope input
    input_model = mcp_tool.input_schema(target="10.0.0.1")
    
    # Execution should fail immediately on scope validation without spawning any subprocess
    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(ScopeViolationError, match="not within the authorized scope"):
            mcp_tool.run(session, input_model)
            
        mock_popen.assert_not_called()


# --- 4. MCP Tool Execution Timeout ---

def test_mcp_tool_timeout_enforcement(valid_roe):
    """Verify that MCPToolSpec._execute() terminates hanging processes and logs MCP_TOOL_TIMEOUT."""
    config = {
        "servers": {
            "hanging_server": {
                "image": "local/hang@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
                "tools": {
                    "slow_query": {
                        "risk_tier": "passive",
                        "target_parameter": "target",
                        "timeout_seconds": 1  # 1 second timeout
                    }
                }
            }
        }
    }
    
    tools = load_mcp_tools_from_config(config)
    mcp_tool = tools[0]
    
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    input_model = mcp_tool.input_schema(target="127.0.0.1")
    
    # Mock subprocess.Popen to simulate a hanging readline call
    mock_proc = MagicMock()
    mock_proc.stdout.readline.side_effect = lambda: pytest.fail("Process readline blocked as expected")
    
    # We patch _is_docker_available to skip daemon validation check
    with patch.object(MCPToolSpec, "_is_docker_available", return_value=True):
        with patch("subprocess.Popen", return_value=mock_proc):
            with pytest.raises(TimeoutError, match="timed out after 1 seconds"):
                mcp_tool.run(session, input_model)
                
    # Assert that MCP_TOOL_TIMEOUT is written to database
    timeout_logs = [e for e in session.audit.get_events() if e["event_type"] == "MCP_TOOL_TIMEOUT"]
    assert len(timeout_logs) == 1
    assert timeout_logs[0]["details"]["mcp_tool_name"] == "slow_query"


# --- 5. E2E MCP Remapped Server Scan ---

def test_mcp_e2e_remapped_scan(valid_roe):
    """Verify standard stdio mapping and Docker loopback address remapping."""
    config = {
        "servers": {
            "local_scanner": {
                "image": "local/scanner@sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
                "tools": {
                    "scan_host": {
                        "risk_tier": "active-safe",
                        "target_parameter": "host_ip"
                    }
                }
            }
        }
    }
    
    tools = load_mcp_tools_from_config(config)
    mcp_tool = tools[0]
    
    session = EngagementSession(roe=valid_roe, approval_callback=lambda tool, tier: True)
    input_model = mcp_tool.input_schema(host_ip="127.0.0.1")
    
    mock_proc = MagicMock()
    # Return mock JSON-RPC response on stdout readline
    mock_proc.stdout.readline.return_value = MOCK_MCP_RPC_RESPONSE = json.dumps({
        "jsonrpc": "2.0",
        "result": {"status": "scan complete", "open_ports": [80, 443]},
        "id": 1
    }) + "\n"
    
    with patch.object(MCPToolSpec, "_is_docker_available", return_value=True):
        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            result = mcp_tool.run(session, input_model)
            
            assert result.success is True
            assert result.result["open_ports"] == [80, 443]
            
            # Assert command uses --add-host and remapped host gateway
            mock_popen.assert_called_once()
            cmd = mock_popen.call_args[0][0]
            assert "--add-host" in cmd
            assert "host.docker.internal:host-gateway" in cmd


# --- 6. CLI Stdin Rejection Blocking ---

def test_cli_approval_blocking_rejection(valid_roe):
    """Verify that when human rejects approval via console prompt, session fails and halts."""
    # Mock sys.argv to run a start-session command
    test_args = [
        "cli.py",
        "start-session",
        "--roe", "fake_roe.json",
        "--target", "127.0.0.1",
        "--db", "sqlite:///:memory:"
    ]
    
    fake_roe_json = json.dumps({
        "authorized_scope": ["127.0.0.1"],
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-12-31T23:59:59Z",
        "permitted_risk_tiers": ["passive", "active-safe"],
        "allow_unsandboxed_fallback": False,
        "authorizing_party": "Test Admin"
    })
    
    # We mock open for roe file, stdin for prompt input ('no'), and graph invocation
    with patch("sys.argv", test_args):
        with patch("builtins.open", mock_open(read_data=fake_roe_json)):
            with patch("os.path.exists", return_value=True):
                # Send 'no' to interactive approval prompt
                with patch("builtins.input", return_value="no"):
                    with pytest.raises(SystemExit) as sys_exit:
                        cli_main()
                        
                    assert sys_exit.value.code == 1
