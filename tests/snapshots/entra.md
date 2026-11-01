# Agent Permission Linter report

- **Agent:** entra-demo
- **Generated:** 2026-01-01T00:00:00Z
- **apl version:** 0.1.0.dev0
- **Servers scanned:** 8

## Summary

| Severity | Violations | Review required |
|---|---:|---:|
| critical | 0 | 0 |
| high | 3 | 0 |
| medium | 4 | 0 |
| low | 2 | 0 |
| info | 0 | 0 |
| **total** | **9** | **0** |

Checks: 33 evaluated, 17 not evaluated; see [Not evaluated](#not-evaluated).

## Findings

| ID | Severity | Status | Confidence | Tool / server | Title |
|---|---|---|---:|---|---|
| `APL-001:cbd71fa9e09a` | high | violation | 0.90 | `mail/AZURE_CLIENT_ID` | Granted scope broader than any tool needs |
| `APL-004:c2469ff24bd9` | high | violation | 0.95 | `mailer/ownerless-mailer (a6a6...0006)` | Entra app linked to this server has no owner |
| `APL-006:3d029284dc2d` | high | violation | 0.95 | `mailer/Mail.Send` | High-risk permission granted with no justification |
| `APL-004:9be1112326cf` | medium | violation | 0.95 | `files/orphan-files (a3a3...0003)` | Entra app linked to this server has no owner |
| `APL-005:57d6ef5d6655` | medium | violation | 0.95 | `expired/expired-secret (a8a8...0008)/password-f1f1...0008` | Expired credential still present |
| `APL-005:bf124da750ac` | medium | violation | 0.80 | `longlived/long-lived-secret (a9a9...0009)/password-f1f1...0009` | Credential has no expiry |
| `APL-005:d4e28b0c93d9` | medium | violation | 0.95 | `mail/mail-triage (a1a1...0001)/password-f1f1...0001` | Expired credential still present |
| `APL-005:09f0b4a955ff` | low | violation | 0.95 | `calendar/calendar-reader (a2a2...0002)/password-f1f1...0002` | Credential lifetime over 180 days |
| `APL-005:896a0f154400` | low | violation | 0.95 | `longlived/long-lived-secret (a9a9...0009)/key-f2f2...0009` | Credential lifetime over 180 days |

## Fixes

### APL-001:cbd71fa9e09a: mail/AZURE_CLIENT_ID

Remove or narrow Mail.ReadWrite: no tool on 'mail' needs delete/write. Grant the least-privileged permission instead (suggested mapping): Mail.Read.

- Confidence 0.90: credential kind verified
- Granted: Mail.ReadWrite; required: read
- Evidence: `entra-mock` `/servicePrincipals/c1c1...0001`: Entra (mock): mail-triage; 1 application permission(s), 0 tenant-wide and 0 per-user delegated scope(s)
- Suggested mapping: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- Suggested mapping: [ASI03 Identity &amp; Privilege Abuse](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)

### APL-004:c2469ff24bd9: mailer/ownerless-mailer (a6a6...0006)

Assign an owner to 'ownerless-mailer' in Entra, or remove the app from 'mailer' if nobody is responsible for it.

- Confidence 0.95: Graph owner lists read directly; none on the application or service principal
- Granted: Mail.Send; required: at least one accountable owner
- Evidence: `entra-mock` `/applications/b6b6...0006/owners`: Graph returned no owners
- Evidence: `entra-mock` `/servicePrincipals/c6c6...0006/owners`: Graph returned no owners
- Suggested mapping: [NHI1:2025 Improper Offboarding](https://owasp.org/www-project-non-human-identities-top-10/2025/1-improper-offboarding/)

### APL-006:3d029284dc2d: mailer/Mail.Send

Remove Mail.Send from 'ownerless-mailer' if the agent does not need it, or add 'Mail.Send: &lt;reason>' under justifications in agent.yaml.

- Confidence 0.95: grant read directly from Graph; no reason in agent.yaml justifications; app has no owner (APL-004)
- Granted: Mail.Send (application); required: a justifications entry in agent.yaml
- Evidence: `entra-mock` `/servicePrincipals/c6c6...0006/appRoleAssignments`: ownerless-mailer (a6a6...0006): can send mail as any user. Reference: https://learn.microsoft.com/en-us/graph/permissions-reference#mailsend
- Suggested mapping: [NHI5:2025 Overprivileged NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/5-overprivileged-nhi/)
- Suggested mapping: [ASI03 Identity &amp; Privilege Abuse](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)

### APL-004:9be1112326cf: files/orphan-files (a3a3...0003)

Assign an owner to 'orphan-files' in Entra, or remove the app from 'files' if nobody is responsible for it.

- Confidence 0.95: Graph owner lists read directly; none on the application or service principal
- Granted: ; required: at least one accountable owner
- Evidence: `entra-mock` `/applications/b3b3...0003/owners`: Graph returned no owners
- Evidence: `entra-mock` `/servicePrincipals/c3c3...0003/owners`: Graph returned no owners
- Suggested mapping: [NHI1:2025 Improper Offboarding](https://owasp.org/www-project-non-human-identities-top-10/2025/1-improper-offboarding/)

### APL-005:57d6ef5d6655: expired/expired-secret (a8a8...0008)/password-f1f1...0008

Rotate this password credential on 'expired-secret' to one lasting at most 180 days and remove the old one, or use a managed identity.

- Confidence 0.95: dates read directly from Graph
- Granted: password credential: expired 2025-09-01; required: expiry within 180 days, rotated before it ends
- Evidence: `entra-mock` `/applications/b8b8...0008/passwordCredentials`: expired 2025-09-01
- Suggested mapping: [NHI7:2025 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/)

### APL-005:bf124da750ac: longlived/long-lived-secret (a9a9...0009)/password-f1f1...0009

Rotate this password credential on 'long-lived-secret' to one lasting at most 180 days and remove the old one, or use a managed identity.

- Confidence 0.80: Graph documents endDateTime as optional; read as no expiry
- Granted: password credential: no endDateTime; required: expiry within 180 days, rotated before it ends
- Evidence: `entra-mock` `/applications/b9b9...0009/passwordCredentials`: no endDateTime
- Suggested mapping: [NHI7:2025 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/)

### APL-005:d4e28b0c93d9: mail/mail-triage (a1a1...0001)/password-f1f1...0001

Rotate this password credential on 'mail-triage' to one lasting at most 180 days and remove the old one, or use a managed identity.

- Confidence 0.95: dates read directly from Graph
- Granted: password credential: expired 2025-01-01; required: expiry within 180 days, rotated before it ends
- Evidence: `entra-mock` `/applications/b1b1...0001/passwordCredentials`: expired 2025-01-01
- Suggested mapping: [NHI7:2025 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/)

### APL-005:09f0b4a955ff: calendar/calendar-reader (a2a2...0002)/password-f1f1...0002

Rotate this password credential on 'calendar-reader' to one lasting at most 180 days and remove the old one, or use a managed identity.

- Confidence 0.95: dates read directly from Graph
- Granted: password credential: 2557 days, 2024-01-01 to 2031-01-01; required: expiry within 180 days, rotated before it ends
- Evidence: `entra-mock` `/applications/b2b2...0002/passwordCredentials`: 2557 days, 2024-01-01 to 2031-01-01
- Suggested mapping: [NHI7:2025 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/)

### APL-005:896a0f154400: longlived/long-lived-secret (a9a9...0009)/key-f2f2...0009

Rotate this key credential on 'long-lived-secret' to one lasting at most 180 days and remove the old one, or use a managed identity.

- Confidence 0.95: dates read directly from Graph
- Granted: key credential: 730 days, 2026-01-01 to 2028-01-01; required: expiry within 180 days, rotated before it ends
- Evidence: `entra-mock` `/applications/b9b9...0009/keyCredentials`: 730 days, 2026-01-01 to 2028-01-01
- Suggested mapping: [NHI7:2025 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/)

## Not evaluated

| Rule | Subject | Reason |
|---|---|---|
| APL-001 | `custom/AZURE_CLIENT_ID/Contoso.Frobnicate` | not evaluated: missing scope mapping |
| APL-007 | `mail` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `calendar` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `files` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `custom` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `mailer` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `managed` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `expired` | not evaluated: missing declared purpose in agent.yaml |
| APL-007 | `longlived` | not evaluated: missing declared purpose in agent.yaml |
| APL-010 | `mail` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `calendar` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `files` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `custom` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `mailer` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `managed` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `expired` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
| APL-010 | `longlived` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |

## Assumptions and limits

**Unverified formats**

- None in this scan.

**Low-confidence classifications**

- None in this scan.

**Parser warnings**

- mail: in config but has no declared purpose in agent.yaml
- calendar: in config but has no declared purpose in agent.yaml
- files: in config but has no declared purpose in agent.yaml
- custom: in config but has no declared purpose in agent.yaml
- mailer: in config but has no declared purpose in agent.yaml
- managed: in config but has no declared purpose in agent.yaml
- expired: in config but has no declared purpose in agent.yaml
- longlived: in config but has no declared purpose in agent.yaml

**Always true for this version**

- Offline analysis: tool lists come from saved tools/list files; no server was contacted.
- Client config formats are client conventions, not MCP spec (A1).
- Tool descriptions are never used to classify; annotations can only add capabilities (S5, S6).
- Framework references are suggested mappings, not compliance claims.
- Granted scopes (APL-001) need Entra data (--entra or --entra-mock); otherwise skipped.
- Entra data came from saved fixtures (--entra-mock), not a real tenant.
