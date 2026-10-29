# Agent Permission Linter report

- **Agent:** release-notes-bot
- **Generated:** 2026-01-01T00:00:00Z
- **apl version:** 0.1.0.dev0
- **Servers scanned:** 3

## Summary

| Severity | Violations | Review required |
|---|---:|---:|
| critical | 0 | 0 |
| high | 2 | 0 |
| medium | 2 | 0 |
| low | 0 | 1 |
| info | 0 | 0 |
| **total** | **4** | **1** |

Not evaluated: 6 rule check(s); see [Not evaluated](#not-evaluated).

## Findings

| ID | Severity | Status | Confidence | Tool / server | Title |
|---|---|---|---:|---|---|
| `APL-007:3bad258035a6` | high | violation | 0.90 | `github/delete_repository` | Tool capability exceeds declared purpose |
| `APL-007:809789a2e28a` | high | violation | 0.90 | `graph/runGraphQuery` | Tool capability exceeds declared purpose |
| `APL-007:c07f49f8482e` | medium | violation | 0.70 | `filesystem/move_file` | Tool capability exceeds declared purpose |
| `APL-007:ac981277f1c4` | medium | violation | 0.70 | `filesystem/write_file` | Tool capability exceeds declared purpose |
| `APL-007:6eb85aaeb952` | low | review_required | 0.00 | `graph/frobnicate` | Review required: tool capability could not be established |

## Fixes

### APL-007:3bad258035a6: github/delete_repository

Disable or remove 'delete_repository' (delete not in the declared purpose: Read PRs; create one issue with the draft.), or use a server build without it. If the agent really needs it, declare it in agent.yaml.

- Confidence 0.90: classifier: name token 'delete' -> delete; CONFLICT: readOnlyHint=true contradicts name; annotation ignored
- Granted: delete; required: read, write
- Suggested mapping: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

### APL-007:809789a2e28a: graph/runGraphQuery

Disable or remove 'runGraphQuery' (execute/network not in the declared purpose), or use a server build without it. If the agent really needs it, declare it in agent.yaml.

- Confidence 0.90: classifier: name token 'run' -> execute; name token 'query' -> read; annotation openWorldHint=true -> network
- Granted: execute, network, read; required: read
- Suggested mapping: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

### APL-007:c07f49f8482e: filesystem/move_file

Disable or remove 'move_file' (write not in the declared purpose: Read CHANGELOG template.), or use a server build without it. If the agent really needs it, declare it in agent.yaml.

- Confidence 0.70: classifier: name token 'move' -> write
- Granted: write; required: read
- Suggested mapping: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

### APL-007:ac981277f1c4: filesystem/write_file

Disable or remove 'write_file' (write not in the declared purpose: Read CHANGELOG template.), or use a server build without it. If the agent really needs it, declare it in agent.yaml.

- Confidence 0.70: classifier: name token 'write' -> write
- Granted: write; required: read
- Suggested mapping: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

### APL-007:6eb85aaeb952: graph/frobnicate

Check what 'frobnicate' does. If 'graph' does not need it, remove or disable it. If it does, add it to required_tools in agent.yaml.

- Confidence 0.00: unclassified or low-confidence tool name: no recognised verb -> unknown
- Granted: unknown; required: read
- Suggested mapping: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

## Not evaluated

| Rule | Subject | Reason |
|---|---|---|
| APL-001 | `github` | not evaluated: missing granted scopes (needs Phase 3 Entra collector) |
| APL-001 | `graph` | not evaluated: missing granted scopes (needs Phase 3 Entra collector) |
| APL-002 | `release-notes-bot` | not evaluated: missing agent.yaml invokers |
| APL-010 | `github` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `filesystem` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `graph` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |

## Assumptions and limits

**Unverified formats**

- None in this scan.

**Low-confidence classifications**

| Server | Tool | Confidence | Note |
|---|---|---:|---|
| `graph` | `frobnicate` | 0.00 | unclassified: review required |

**Parser warnings**

- github/delete_repository: possible prompt injection in tool metadata

**Always true for this version**

- Offline analysis: tool lists come from saved tools/list files; no server was contacted.
- Client config formats are client conventions, not MCP spec (A1).
- Tool descriptions are never used to classify; annotations can only add capabilities (S5, S6).
- Framework references are suggested mappings, not compliance claims.
- Granted scopes (APL-001) need the Phase 3 Entra collector; offline runs skip it.
