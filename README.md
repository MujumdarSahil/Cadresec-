# Cadresec

Cadresec is an open-source, guardrailed multi-agent framework built for real, authorized security engagements (recon, scanning, vulnerability triage, and reporting).

Every design decision in Cadresec assumes agents act against real targets with operational and legal weight. This is not a training tool or general-purpose wrapper—it is a secure orchestration engine ensuring strict compliance with Rules of Engagement (RoE) directly in code.

---

## 🛡️ Core Security Principles

1. **One Orchestration Engine**: Built exclusively on [LangGraph](https://github.com/langchain-ai/langgraph). No competing agent loops.
2. **Unified Extensibility**: Everything in the system is either a `ToolSpec` or an `AgentSpec`. No special-case code paths.
3. **Execution Gating inside Code**: Target scope and human approvals are validated in code at the first lines of `ToolSpec.run()`. Agents are structurally unable to bypass check gates, even if misprompted.
4. **Sandboxed-per-Tool Isolation**: Tools execute inside containerized environments (Docker) with explicit CPU/Memory/Network constraints. Unsandboxed fallback must be explicitly signed off in the RoE configuration.
5. **Tamper-Evident Ledger**: Every event, decision, and discovery is recorded to an append-only ledger featuring a SHA-256 cryptographic hash chain verifying preceding blocks to prevent local tampering.
6. **Time-Aware Window Enforcement**: All operations are blocked unless the current time falls inside the timezone-aware engagement window specified in the RoE.

---

## 🗄️ OCSF Data Pipeline

Cadresec maps raw tool outputs (like Nmap XML or Nuclei JSON) directly into standardized **Open Cybersecurity Schema Framework (OCSF)** classes:

* **Class 5010: Discovery**: Represents hosts, services, and port states identified during scanning. Captures Docker gateway remappings.
* **Class 4001: Network Activity**: Represents individual active network connections mapped from open ports.
* **Class 2002: Vulnerability Finding**: Represents vulnerabilities (CVEs, severities, matching domains) parsed from scanners.

---

## ⚙️ Allowed MCP Server Configuration

Cadresec sandboxes external Model Context Protocol (MCP) servers using image-digest pinning for supply chain integrity. Define allowed servers in `mcp_servers.json`:

```json
{
  "servers": {
    "dns_server": {
      "image": "projectdiscovery/mcp-dns@sha256:7f08c3a93c72d001648a31e84a22c54ee9c5123d548312e3e8f812543d3e8e1f",
      "tools": {
        "dns_lookup": {
          "risk_tier": "passive",
          "target_parameter": "domain"
        }
      }
    }
  }
}
```

* **Image Digests**: Images must be referenced by SHA-256 digest (`image@sha256:digest`). Mutable tags are hard-rejected.
* **Capping Target-less Tools**: If `target_parameter` is not mapped, the tool is permanently capped at `RiskTier.PASSIVE` to prevent unauthorized out-of-scope active scans.

---

## 💻 CLI Usage

Cadresec provides an operator-facing console utility:

### 1. Initialize a Rules of Engagement Template
```bash
python -m cadresec.cli init-roe --output roe.json --scope 127.0.0.1 192.168.1.0/24
```

### 2. Start an Engagement Session
```bash
python -m cadresec.cli start-session --roe roe.json --target 127.0.0.1 --db sqlite:///cadresec.db
```
*If active-safe or active-risky tools are called, the CLI blocks on standard input prompting the operator for approval before execution.*

### 3. Check Session Status and Ledger Integrity
```bash
python -m cadresec.cli status --session <session-uuid> --db sqlite:///cadresec.db
```

### 4. Trigger the Global Kill Switch (Cross-Process)
```bash
python -m cadresec.cli kill --session <session-uuid> --db sqlite:///cadresec.db
```

### 5. Fetch and Render the Markdown Report
```bash
python -m cadresec.cli get-report --session <session-uuid> --db sqlite:///cadresec.db
```

---

📦 New Features (Phase 4B)
Persistent session storage – migrated to SQLite via SQLAlchemy (cadresec/api.py), consolidating session_metadata into the engagement database.
TECH_DEBT.md – added to document MCP image‑digest policy and other technical‑debt items.
http_probe tool – implemented as ACTIVE_SAFE; requires operator approval and includes redirect‑refusal and timeout controls.
ssl_expiry – re‑classified to ACTIVE_SAFE.
resolve_hostname – added as a PASSIVE MCP tool (via ghcr.io/patrickdappollonio/mcp‑netutils).
ping_check – introduced for local MCP server regression testing.
Docker info command timeout increased to 10 seconds for better reliability on Windows.
Comprehensive E2E tests added for the new tools (tests/test_http_probe.py, tests/test_mcp_ping.py).

## 🛠️ Developer Extensibility

<<<<<<< HEAD
To extend Cadresec with new tools or agents without modifying core code, refer to [docs/extending.md](docs/extending.md).

## 📦 New Features (Phase 4B)

- **Persistent session storage** migrated to SQLite via SQLAlchemy (`cadresec/api.py`), consolidating `session_metadata` into the engagement database.
- **TECH_DEBT.md** added to document MCP image‑digest policy and other technical debt.
- **http_probe** tool implemented as `ACTIVE_SAFE`; requires operator approval and includes redirect‑refusal and timeout controls.
- **ssl_expiry** reclassified to `ACTIVE_SAFE`.
- **resolve_hostname** added as a PASSIVE MCP tool (via `ghcr.io/patrickdappollonio/mcp-netutils`).
- **ping_check** introduced for local MCP server regression testing.
- Docker `info` command timeout increased to 10 seconds for reliability on Windows.
- Comprehensive E2E tests added for new tools (`tests/test_http_probe.py`, `tests/test_mcp_ping.py`).
=======
To extend Cadresec with new tools or agents without modifying core code, refer to [docs/extending.md](file:///c:/Users/mujum/OneDrive/Desktop/Cadresec/docs/extending.md).
