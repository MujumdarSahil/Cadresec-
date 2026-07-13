# Cadresec Technical Debt and Known Limitations

This document tracks deliberate design decisions, deprecation warnings, and architectural limitations in the Cadresec codebase to ensure visibility for future maintainers.

## 1. LangGraph NodeInterrupt Deprecation (Phase 4A)
* **Status:** Tracked / Deliberate Legacy Support
* **Description:** The agent pause/resume human approval gate is implemented using `langgraph.errors.NodeInterrupt` in `cadresec/core/guardrails.py`.
* **Issue:** LangGraph has deprecated `NodeInterrupt` in v1.x and scheduled its removal in v2.0 in favor of state-level/node-level interrupts via `langgraph.types.interrupt`.
* **Rationale for Leaving:** Switching to `langgraph.types.interrupt` requires a major refactoring of state variables, graph structures, and task resumption logic. Since `NodeInterrupt` is fully supported in the current v1.x version, migrating this has been postponed to a future release targeting LangGraph 2.x support.
* **Migration Action:** 
  - Update guardrails check to trigger standard state interrupts.
  - Revamp graph node entry paths to resume from state edits instead of repeating the node function invocation.

## 2. External Third-Party MCP Server Source Review Policy (Phase 4B)
* **Status:** Operational Mandate
* **Description:** Registering any external or individual-maintainer third-party MCP server requires performing a source-code review before addition to the allow-list.
* **Review: `ghcr.io/patrickdappollonio/mcp-netutils`**
  - **Source Repository:** [patrickdappollonio/mcp-netutils](https://github.com/patrickdappollonio/mcp-netutils)
  - **Internal Behavior (`resolve_hostname`):** Built in Go, utilizing the standard `net.LookupIP()` resolver. It does not open socket connections to the target hostname, operating entirely out-of-band via DNS resolvers.
  - **Assessment:** Actively maintained (active 2025/2026 releases) and featured as a verified integration in Docker's official MCP catalog. Safe and credential-free.
