# Agent Permission Linter report

- **Agent:** docs-assistant
- **Generated:** 2026-01-01T00:00:00Z
- **apl version:** 0.1.0.dev0
- **Servers scanned:** 2

## Summary

| Severity | Violations | Review required |
|---|---:|---:|
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 0 |
| low | 0 | 0 |
| info | 0 | 0 |
| **total** | **0** | **0** |

Checks: 3 evaluated, 3 not evaluated; see [Not evaluated](#not-evaluated).

**No findings among the 3 checks that ran (3 not evaluated).**

## Findings

No findings among the 3 checks that ran (3 not evaluated).

## Fixes

Nothing to fix among the checks that ran.

## Not evaluated

| Rule | Subject | Reason |
|---|---|---|
| APL-001 | `tickets` | not evaluated: missing granted scopes (needs Phase 3 Entra collector) |
| APL-010 | `docs` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `tickets` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |

## Assumptions and limits

**Unverified formats**

- None in this scan.

**Low-confidence classifications**

- None in this scan.

**Always true for this version**

- Offline analysis: tool lists come from saved tools/list files; no server was contacted.
- Client config formats are client conventions, not MCP spec (A1).
- Tool descriptions are never used to classify; annotations can only add capabilities (S5, S6).
- Framework references are suggested mappings, not compliance claims.
- Granted scopes (APL-001) need the Phase 3 Entra collector; offline runs skip it.
