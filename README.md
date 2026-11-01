# Agent Permission Linter (apl) — v0.1.0.dev0

Finds AI agents that hold more power than their declared task needs: a finding is *granted*
capability exceeding *required* capability.

**Safety:** read-only. Never connects to MCP servers (`--connect` is refused in v0.1). Entra access
is optional and GET-only, with the token held in memory. Secrets are
redacted at parse time and again on every report; only env var *names* are stored. There is no
`apply` command.

## Quickstart

```bash
pip install -e '.[dev]'
apl scan -c tests/fixtures/configs/claude_desktop.json \
  -a tests/fixtures/agents/release_notes_bot.yaml \
  -t tests/fixtures/tools/claude_desktop_tools.json \
  --format md --out report.md --fail-on high
echo $?   # 1: at least one finding at or above "high"
```

That fixture is deliberately over-powered. Excerpt of `report.md` (full report:
[tests/snapshots/dirty.md](tests/snapshots/dirty.md)):

```markdown
| Severity | Violations | Review required |
|---|---:|---:|
| critical | 0 | 0 |
| high | 2 | 0 |
| medium | 3 | 0 |
| low | 0 | 1 |
| info | 0 | 0 |
| **total** | **5** | **1** |

| ID | Severity | Status | Confidence | Tool / server | Title |
|---|---|---|---:|---|---|
| `APL-007:3bad258035a6` | high | violation | 0.90 | `github/delete_repository` | Tool capability exceeds declared purpose |
| `APL-007:809789a2e28a` | high | violation | 0.90 | `graph/runGraphQuery` | Tool capability exceeds declared purpose |
| `APL-007:c07f49f8482e` | medium | violation | 0.70 | `filesystem/move_file` | Tool capability exceeds declared purpose |
| `APL-007:ac981277f1c4` | medium | violation | 0.70 | `filesystem/write_file` | Tool capability exceeds declared purpose |
| `APL-007:13097d7d2403` | medium | violation | 0.70 | `github/push_files` | Tool capability exceeds declared purpose |
| `APL-007:6eb85aaeb952` | low | review_required | 0.00 | `graph/frobnicate` | Review required: tool capability could not be established |

| Rule | Subject | Reason |
|---|---|---|
| APL-001 | `github` | not evaluated: missing granted scopes (run with --entra or --entra-mock) |
| APL-002 | `release-notes-bot` | not evaluated: missing agent.yaml invokers |
| APL-010 | `github` | not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config) |
```

The well-scoped fixture in `tests/fixtures/clean/` produces no findings
([tests/snapshots/clean.md](tests/snapshots/clean.md)).

## `apl scan`

| Option | Meaning |
|---|---|
| `-c/--config` | MCP client config (repeatable). JSONC accepted. |
| `-a/--agent` | agent.yaml: the declared purpose (optional; some rules skip without it) |
| `-t/--tools` | saved `tools/list` result(s), offline (optional; capability rules skip without it) |
| `-f/--format` | `md` (default), `json` (`schema_version` 1.0), `sarif` (2.1.0) |
| `-o/--out` | write the report to a file instead of stdout |
| `--fail-on` | `none` (default), `low`, `medium`, `high` |
| `--entra-mock DIR` | read saved Graph responses from `DIR` (no network, no credentials) |
| `--entra` | read Entra live through Graph, GET only. Needs `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` |
| `--show-ids` | print real Entra ids, for local debugging only. Warns on stderr and marks the report. Secrets stay redacted, and finding ids do not change |
| `--anonymise-names` | replace Entra display names and server, agent and owner names with pseudonyms. In `apl inventory`, `command`, `url` and `args` become `[cmd-N]`, `[url-N]` and `[arg-N]`, so nothing derived from them prints; `[REDACTED]` args stay as they are. **Free text prints as written:** `purpose`, `justification` text and `env_keys`, so review before sharing; `apl scan` and `apl inventory` say so on stderr, and reports say so in their limits. **Also still prints:** finding titles; permission names, including custom ones that may name your organisation (`Contoso.Frobnicate`); tool names, including those that contain a server name (`payroll_search`); environment variable and header names; config file paths; capabilities, severities, rule ids and evidence dates; and, in `apl inventory`, the agent's `data_classification` and `justifications`, plus `required_tools` and `required_graph_permissions` |

Exit codes: `0` no finding at or above `--fail-on` · `1` at least one (use in CI) · `2` parse,
write or Entra error, or `--connect`.

### Identifiers and `APL_ID_SALT`

Reports never print a full tenant, client or object id. They print a pseudonym such as
`app-3f9a1c`: a keyed hash, the same on every run of one install. Secrets are different: they are
removed as `[REDACTED]` and are never hashed.

The key is a salt, which is what stops someone who has a report from checking a guessed id. It
comes from the `APL_ID_SALT` environment variable, at least 16 characters. If that is not set, `apl`
creates a random one on first use and keeps it in a file outside the repo:

| Platform | Salt file |
|---|---|
| Windows | `%APPDATA%\apl\id_salt` |
| Linux, macOS | `$XDG_CONFIG_HOME/apl/id_salt`, by default `~/.config/apl/id_salt` |

- **Never commit it.** Keep the salt out of the repo, `.env.example` and logs. `apl` scrubs it from
  its own output like a secret.
- **Set the same value on CI.** Finding ids for Entra apps depend on the salt. Laptops and CI with
  different salts report different ids for the same finding, so baselines and SARIF deduplication
  break. Store one value in your CI secret store and export it on every machine that must agree.
- **Changing or losing it changes those ids** and every pseudonym.
- No usable salt stops the scan with exit code 2: `apl` does not fall back to printing raw ids.

To make a value:

```
python -c "import secrets; print(secrets.token_hex(32))"
```

`--show-ids` prints the real ids for local debugging. It warns on stderr and the report says so
itself: a first line in md, `"contains_real_ids": true` in json, and a note in sarif. Do not share
that output. It never turns off secret redaction.

### Entra

Linking a credential to its Entra app fills in what it was really granted, so APL-001 can evaluate.
Try it with no tenant:

```bash
apl scan -c tests/fixtures/entra/mcp.json -t tests/fixtures/entra/tools.json \
  --entra-mock tests/fixtures/graph
```

`--entra` needs an app registration with the application permissions `Application.Read.All` and
`Directory.Read.All`. It has been tested only against Graph-shaped fixtures, not a real tenant.

Rules: APL-001 over-scoped permission, APL-002 maker-mode/shared credential, APL-004 Entra app with
no owner, APL-005 secret hygiene, APL-006 high-risk permission with no justification, APL-007 tool
capability exceeds declared purpose, APL-010 no human approval gate. To justify a high-risk
permission, add it to `agent.yaml`:

```yaml
justifications:
  Mail.Send: Sends the weekly digest to the team list.
```

A rule that lacks its input
says so under **Not evaluated** instead of passing silently. Framework references are labelled
"suggested mapping".

```bash
pytest && ruff check .
```

Phase status: 1 ✅ models/parsers/classifier · 2 🟡 rules APL-001/002/004/005/006/007/010 + `apl scan`
reports · 3 🟡 Entra collector (fixture-tested, not yet run on a real tenant) · 4 LLM reasoning
layer · 6 docs.

See [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md) for every format and design assumption, with its
verification status and source.
