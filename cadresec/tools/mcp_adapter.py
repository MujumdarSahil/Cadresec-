import re
import json
import os
import shutil
import subprocess
import queue
import threading
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel, Field, field_validator, create_model

from cadresec.core.roe import RiskTier
from cadresec.core.tools import ToolSpec
from cadresec.core.exceptions import SandboxUnavailableError


# Regex to enforce image reference by SHA-256 digest
DIGEST_PINNING_REGEX = r"^[a-zA-Z0-9_/.-]+@sha256:[a-fA-F0-9]{64}$"


class MCPToolConfig(BaseModel):
    risk_tier: RiskTier
    target_parameter: Optional[str] = None
    timeout_seconds: int = Field(default=30, description="Max scanning execution duration in seconds")

    @field_validator("risk_tier")
    @classmethod
    def reject_destructive(cls, v):
        if v == RiskTier.DESTRUCTIVE:
            raise ValueError("The 'destructive' risk tier is strictly rejected by the framework.")
        return v


class MCPServerConfig(BaseModel):
    image: str
    tools: Dict[str, MCPToolConfig]

    @field_validator("image")
    @classmethod
    def validate_digest_pinning(cls, v):
        if not re.match(DIGEST_PINNING_REGEX, v):
            raise ValueError(
                f"Image Reference '{v}' is invalid. For supply-chain integrity, "
                "images must be pinned by SHA-256 digest (e.g. image@sha256:digest)."
            )
        return v


class MCPServerRegistry(BaseModel):
    servers: Dict[str, MCPServerConfig]


class MCPOutput(BaseModel):
    success: bool = Field(..., description="True if the MCP tool executed successfully")
    result: Dict[str, Any] = Field(default_factory=dict, description="Raw JSON result payload returned by the tool")
    actual_scanned_address: str = Field(default="", description="The actual target address queried during execution")


class MCPToolSpec(ToolSpec):
    # Dynamic properties injected at registration
    image: str
    mcp_tool_name: str
    target_parameter: Optional[str] = None
    timeout_seconds: int = 30

    def get_target(self, input_data: BaseModel) -> Optional[str]:
        if self.target_parameter:
            return getattr(input_data, self.target_parameter, None)
        return None

    def _execute(self, session, input_data: BaseModel, use_sandbox: bool = True) -> MCPOutput:
        """Executes the sandboxed MCP container, piping JSON-RPC calls over stdin/stdout."""
        original_arguments = input_data.model_dump()
        target = original_arguments.get(self.target_parameter) if self.target_parameter else None
        
        is_local = False
        if target and isinstance(target, str) and target.strip().lower() in ("127.0.0.1", "localhost"):
            is_local = True

        # Build command array
        scan_target = target
        cmd = []
        if use_sandbox:
            cmd = ["docker", "run", "-i", "--rm"]
            if is_local:
                cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
                # Remap loopback target inside arguments for container networking compatibility
                if self.target_parameter:
                    original_arguments[self.target_parameter] = "host.docker.internal"
                    scan_target = "host.docker.internal"
            cmd.extend([self.image])
        else:
            # Unsandboxed local fallback
            host_bin = shutil.which(self.image.split("@")[0])
            if not host_bin:
                raise FileNotFoundError(
                    f"Host command binary for image alias '{self.image}' was not found. "
                    "Cannot execute unsandboxed fallback."
                )
            cmd = [host_bin]

        # Spawn stdio-piped process
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
        except FileNotFoundError:
            raise FileNotFoundError(
                "Sandbox binary (Docker) is not installed or not available on system PATH. "
                "Cannot execute containerized tool."
            )

        # JSON-RPC request format
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": self.mcp_tool_name,
                "arguments": original_arguments
            },
            "id": 1
        }

        # Write request line to container stdin
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()

        # Thread queue reader for non-blocking timeout handling
        q = queue.Queue()
        def read_stdout(stream, out_queue):
            try:
                line = stream.readline()
                out_queue.put(line)
            except Exception as e:
                out_queue.put(e)

        reader_thread = threading.Thread(target=read_stdout, args=(proc.stdout, q), daemon=True)
        reader_thread.start()

        try:
            # Block until message received or timeout occurs
            line_or_err = q.get(timeout=self.timeout_seconds)
            if isinstance(line_or_err, Exception):
                raise line_or_err
            
            # Success: Terminate the container session cleanly
            proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=2)
            
            response = json.loads(line_or_err.strip())
            
            if "error" in response:
                return MCPOutput(
                    success=False,
                    result={"error": response["error"]},
                    actual_scanned_address=scan_target or ""
                )
                
            return MCPOutput(
                success=True,
                result=response.get("result", {}),
                actual_scanned_address=scan_target or ""
            )

        except queue.Empty:
            # TIMEOUT EXPIRED: Kill the container hard and log
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                
            session.audit.record(
                event_type="MCP_TOOL_TIMEOUT",
                actor="system",
                details={
                    "tool_name": self.name,
                    "mcp_tool_name": self.mcp_tool_name,
                    "timeout_seconds": self.timeout_seconds
                }
            )
            raise TimeoutError(f"MCP tool execution timed out after {self.timeout_seconds} seconds.")
        except Exception as e:
            proc.terminate()
            raise e


def load_mcp_tools_from_config(config_data: Dict[str, Any]) -> List[MCPToolSpec]:
    """Parses allow-list config and returns validated MCPToolSpec instances."""
    registry = MCPServerRegistry.model_validate(config_data)
    tools = []
    
    for server_name, server_config in registry.servers.items():
        for tool_name, tool_config in server_config.tools.items():
            
            # Capping: Target-less tools must be passive tier
            if not tool_config.target_parameter and tool_config.risk_tier != RiskTier.PASSIVE:
                raise ValueError(
                    f"Configuration Violation: Tool '{tool_name}' on server '{server_name}' has no "
                    "target_parameter defined, but is configured as active risk tier. "
                    "Target-less tools must be strictly capped at passive tier."
                )

            # Create dynamic input schema BaseModel
            fields = {}
            if tool_config.target_parameter:
                fields[tool_config.target_parameter] = (str, Field(..., description="Target scan address"))
            
            # Generate input schema class
            input_schema_class = create_model(
                f"{tool_name}Input",
                __base__=BaseModel,
                **fields
            )

            # Instantiate dynamic tool wrapper
            tool_spec = MCPToolSpec(
                name=tool_name,
                description=f"Exposed MCP tool '{tool_name}' from server '{server_name}'",
                risk_tier=tool_config.risk_tier,
                input_schema=input_schema_class,
                output_schema=MCPOutput,
                sandbox_requirements={"image": server_config.image},
                source="mcp",
                image=server_config.image,
                mcp_tool_name=tool_name,
                target_parameter=tool_config.target_parameter,
                timeout_seconds=tool_config.timeout_seconds
            )
            tools.append(tool_spec)
            
    return tools
