# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - unreleased

First release. Read-only: no `apply` command, no writes to Entra, no connection to MCP servers.

### Added

- `apl scan`: reads MCP client configs (Claude Desktop, Claude Code, VS Code, Cursor, Windsurf
  shapes; JSONC accepted), an optional `agent.yaml` with the declared purpose, and saved
  `tools/list` results, offline. Reports in Markdown, JSON (`schema_version` 1.0) and SARIF 2.1.0,
  with `--out` and `--fail-on` for CI. Exit codes: 0 ok, 1 findings at or above `--fail-on`,
  2 error.
- `apl inventory`: the parsed, redacted inventory as JSON.
- Rules:
  - APL-001 over-scoped permission (granted scope adds capabilities no tool on the server needs)
  - APL-002 maker-mode or shared credential
  - APL-004 Entra app with no owner
  - APL-005 secret hygiene on linked Entra credentials (no expiry, expired, lifetime over 180 days)
  - APL-006 high-risk permission with no justification
  - APL-007 tool capability exceeds declared purpose
  - APL-010 no human approval gate on high-impact tools
- A rule that lacks its input reports "not evaluated", and reports never claim "no findings" when
  nothing ran.
- Tool classifier from tool names, MCP annotations and `inputSchema` parameter names. Descriptions
  are never used. Unknown verbs are "unclassified: review required", not guessed.
- Entra collector: `--entra-mock DIR` over saved Graph responses, and `--entra` live, GET only,
  with an OAuth2 client-credentials token over REST. Needs `Application.Read.All` and
  `Directory.Read.All`.
- Output safety: secrets as `[REDACTED]`, salted identifier pseudonyms (`APL_ID_SALT`), URLs as
  `scheme://host/[path-redacted]`, random-looking tokens in `command` and `args` redacted, every
  output, log and crash message scrubbed.
- Debug flags `--show-ids` and `--show-urls`, which warn on stderr and mark the report itself.
- `--anonymise-names` for display, server, agent and owner names.
- Guard harness (`tools/mutation/`): 94 output guards, each broken on purpose and caught by a test.
- Release check (`tools/release_check.py`).
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `docs/THREAT_MODEL.md`,
  `docs/ASSUMPTIONS.md`.

### Known limits

- Live `--entra` mode has been tested only against Graph-shaped fixtures, not a real tenant.
- No held-out corpus in this repo still measures classifier accuracy: all have been used for
  development (ASSUMPTIONS E7).
- Tool names are server-chosen, so renaming a tool can soften a verdict. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
