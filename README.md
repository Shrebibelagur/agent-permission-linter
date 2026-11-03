# Agent Permission Linter (`apl`) — v0.1.0

Finds AI agents that hold more power than their declared task needs. A finding is *granted*
capability exceeding *required* capability.

`apl` reads your MCP client configs (Claude Desktop, Claude Code, VS Code, Cursor, Windsurf), an
optional `agent.yaml` that declares what the agent is for, saved `tools/list` results, and
optionally your Entra app registrations through Microsoft Graph. It reports, for example, an agent
whose purpose is "write release notes" but that can delete repositories, or an Entra app granted
`Mail.ReadWrite` behind a server whose tools only read mail.

**Read-only.** It never starts or contacts an MCP server (`--connect` is refused). Entra access is
optional and GET-only, with the token held in memory. There is no `apply` command. Secrets are
redacted at parse time and again on every output; only env var *names* are stored.

## Quickstart (5 minutes)

### 1. Install

Python 3.11 or later.

```bash
git clone <this repo> && cd agent-permission-linter
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e '.[dev]'
```

### 2. Run the offline demo

No tenant, no credentials, no network:

```bash
apl scan -c tests/fixtures/configs/claude_desktop.json \
  -a tests/fixtures/agents/release_notes_bot.yaml \
  -t tests/fixtures/tools/claude_desktop_tools.json \
  --format md --out report.md --fail-on high
echo $?   # 1: at least one finding at or above "high"
```

Then the Entra demo, over saved Graph-shaped responses:

```bash
apl scan -c tests/fixtures/entra/mcp.json -t tests/fixtures/entra/tools.json \
  --entra-mock tests/fixtures/graph
```

It reports an over-scoped `Mail.ReadWrite` grant, ownerless apps and expired or long-lived
credentials. The well-scoped fixture in `tests/fixtures/clean/` produces no findings
([tests/snapshots/clean.md](tests/snapshots/clean.md)).

### 3. Scan your own tenant (read-only)

Create a dedicated app registration for the scanner. **Live mode has been tested only against
Graph-shaped fixtures, not a real tenant**, so try it in a lab tenant first.

1. In the Microsoft Entra admin center: **App registrations** → **New registration**. Single
   tenant, no redirect URI.
2. **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**.
   Add exactly these two:

   | Permission | Type | Used for |
   |---|---|---|
   | `Application.Read.All` | Application | applications, service principals, owners, app role assignments |
   | `Directory.Read.All` | Application | `oauth2PermissionGrants` (delegated consents); least privilege for that call |

   Remove the default delegated `User.Read`; the scanner does not use it. Then **Grant admin
   consent**. Do not add any `ReadWrite` permission: `apl` never writes.
3. **Certificates & secrets** → **New client secret**, with the shortest expiry that suits you.
   Copy the value once. Do not save it in a file.
4. Set the three variables in the shell that runs `apl`. `apl` does not read `.env` files.

   PowerShell:

   ```powershell
   $env:TENANT_ID = "<directory (tenant) id>"
   $env:CLIENT_ID = "<application (client) id>"
   $env:CLIENT_SECRET = Read-Host -MaskInput "client secret"
   ```

   bash:

   ```bash
   export TENANT_ID=... CLIENT_ID=...
   read -rs CLIENT_SECRET && export CLIENT_SECRET
   ```

5. Scan:

   ```bash
   apl scan -c ~/.cursor/mcp.json -a agent.yaml -t tools.json --entra --format sarif --out apl.sarif
   ```

6. When you are done, delete the client secret, or the whole app registration.

The token is fetched with the OAuth2 client-credentials flow over REST and kept in memory. The HTTP
client refuses anything but `GET https://graph.microsoft.com/...`. Details: G1 to G12 in
[docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md).

## Declaring the purpose: `agent.yaml`

Rules compare what an agent *can* do with what it *says* it needs. Without `agent.yaml`, rules
that need a purpose report "not evaluated" instead of passing.

```yaml
name: release-notes-bot
purpose: Read merged pull requests in one repo and draft release notes as a GitHub issue.
owner: release-team@contoso.example
invokers: single            # or multiple; APL-002 skips without it
servers:
  - server: github
    required_capabilities: [read, write]
    required_tools: [create_issue]   # listed tools count as declared, even if powerful
    justification: Read PRs; create one issue with the draft.
    approval_gate: true
  - server: mail
    required_capabilities: [network]
    entra_app_id: <application (client) id>   # links the server to its Entra app
justifications:             # APL-006: why each high-risk permission is needed
  Mail.Send: Sends the weekly digest to the team list.
```

Unknown keys are rejected. Fields are defined in `AgentSpec` and `ServerPurpose` in
[src/apl/models.py](src/apl/models.py); a full example is
[tests/fixtures/agents/release_notes_bot.yaml](tests/fixtures/agents/release_notes_bot.yaml).

## Sample report

From the offline demo above. Excerpt of `report.md` (full report:
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

Each finding also gets a fix, its evidence (file and JSON pointer), a confidence with its reason,
and framework references labelled "suggested mapping". A rule that lacks its input is listed under
**Not evaluated**, never passed silently.

## Rules

| Rule | Finds | Needs |
|---|---|---|
| APL-001 | Granted scope broader than any tool on the server needs | `--entra` or `--entra-mock`, tools |
| APL-002 | Maker-mode or shared credential: one token for every invoker | `agent.yaml` `invokers` |
| APL-004 | Entra app linked to a server has no owner | Entra |
| APL-005 | Linked credential with no expiry, expired, or lifetime over 180 days | Entra |
| APL-006 | High-risk Graph permission with no justification in `agent.yaml` | Entra, `agent.yaml` |
| APL-007 | Tool capability exceeds the declared purpose | tools, `agent.yaml` |
| APL-010 | High-impact tool auto-approved with no human gate | tools, `autoApprove`/`alwaysAllow` in config |

## `apl scan` flags

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
| `--connect` | refused in v0.1 with exit code 2: `apl` never contacts an MCP server |
| `--show-ids` | print real Entra ids, for local debugging only. Warns on stderr and marks the report. Secrets stay redacted, and finding ids do not change |
| `--show-urls` | print full URLs, for local debugging only. Warns on stderr and marks the report: a first line in md, `"contains_real_urls": true` in json, and a note in sarif. By default every URL prints as `scheme://host/[path-redacted]`, as a path can hold a secret. Userinfo and query strings are always removed |
| `--anonymise-names` | replace Entra display names and server, agent and owner names with pseudonyms. In `apl inventory`, `command`, `url` and `args` become `[cmd-N]`, `[url-N]` and `[arg-N]`, so nothing derived from them prints; `[REDACTED]` args stay as they are. **Free text prints as written:** `purpose`, `justification` text and `env_keys`, so review before sharing; `apl scan` and `apl inventory` say so on stderr, and reports say so in their limits. **Also still prints:** finding titles; permission names, including custom ones that may name your organisation (`Contoso.Frobnicate`); tool names, including those that contain a server name (`payroll_search`); environment variable and header names; config file paths; capabilities, severities, rule ids and evidence dates; and, in `apl inventory`, the agent's `data_classification` and `justifications`, plus `required_tools` and `required_graph_permissions` |

Exit codes: `0` no finding at or above `--fail-on` · `1` at least one (use in CI) · `2` parse,
write or Entra error, or `--connect`.

`apl inventory -c ... [-a ...] [-t ...]` prints the parsed, redacted inventory as JSON. It takes
`--show-ids`, `--show-urls` and `--anonymise-names` too.

### Identifiers and `APL_ID_SALT`

Reports never print a full tenant, client or object id. They print a pseudonym such as
`app-3f9a1c`: a keyed hash, the same on every run of one install. Secrets are different: they are
removed as `[REDACTED]` and are never hashed.

The key is a salt, which is what stops someone who has a report from checking a guessed id. It
comes from the `APL_ID_SALT` environment variable, at least 16 characters. If that is not set, `apl`
creates a random one on first use and keeps it outside the repo: `%APPDATA%\apl\id_salt` on Windows,
`$XDG_CONFIG_HOME/apl/id_salt` (default `~/.config/apl/id_salt`) elsewhere.

- **Never commit it.** `apl` scrubs it from its own output like a secret.
- **Set the same value on CI.** Finding ids for Entra apps depend on the salt, so laptops and CI with
  different salts report different ids for the same finding, and baselines and SARIF deduplication
  break. Changing or losing it changes those ids and every pseudonym.
- No usable salt stops the scan with exit code 2: `apl` does not fall back to printing raw ids.

```
python -c "import secrets; print(secrets.token_hex(32))"
```

### Random-looking tokens

Known token shapes are always removed. On top of that, any token of 20 or more characters in a
server's `command` or `args` becomes `[REDACTED]` if it looks random (mixed case and digits, high
entropy). Only that token goes, so `C:/keys/<token>/run.exe` keeps its path. No flag brings it back.
It can miss secrets (low entropy, lower-case hex, under 20 characters) and can over-redact a
random-looking build id. See R22 in [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md).

## Limits and honesty

### The classifier

APL-001, APL-007 and APL-010 depend on a classifier that turns each tool into capabilities
(`read`, `write`, `delete`, `execute`, `network`) from its **name**, its MCP annotations and the
**names** of its `inputSchema` parameters. Descriptions are never used. A name with no recognised
verb is `unknown` with "review required", not guessed.

**No number below is an accuracy number.** Every corpus in this repo has been used to develop the
classifier, so these are regression checks. A real accuracy figure needs a new held-out set of real
tools, labelled blind and measured once. That has not been done.

Current results, classifier v2 (ASSUMPTIONS E7):

| Corpus | Tools | Exact | Missing (understated) | Missing + unclassified |
|---|---:|---:|---:|---:|
| main | 48 | 37 (77%) | 2 (4%) | 5 |
| held-out #1 | 45 | 33 (73%) | 2 (4%) | 6 |
| held-out #2 | 43 | 26 (60%) | 1 (2%) | 17 |
| held-out #3, name only | 36 | 12 (33%) | 3 (8%) | 22 |
| held-out #3, name + schema | 36 | 11 (31%) | 3 (8%) | 12 |

The closest thing to an independent measure is each held-out set's **first** run, before anything
was changed in response to it:

- **Held-out #2** (E3), names only: 21/43 exact (49%), 3 missing (7%), 18 unclassified (42%).
  About 4 in 10 tools needed human review.
- **Held-out #3** (E6), the first set with parameter names: with schema signals, 10/36 exact, 4
  missing, 13 extra, 9 unclassified. Schema signals cut "no answer" from 19 to 9 but added false
  writes: **all 6** read tools with generic parameter names (`text`, `data`, `content`) gained a
  false `write`. Those now give low reviews, not violations (E7), but the false capability remains.

"Missing" means the classifier understated a tool, the dangerous error. "Unclassified" is flagged
for review, not silent.

**Where the numbers come from:** hand-labelled corpora in `tests/fixtures/tool_corpus*.yaml`,
bucketed by [tests/corpus_report.py](tests/corpus_report.py). Reproduce them with:

```bash
pytest -s tests/test_classifier_corpus.py tests/test_classifier_holdout*.py
```

The corpora are hand-written tool names, not tools from real servers, and are small (36 to 48
tools each). History and caveats for every row: E1 to E7 in
[docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md).

### What else it cannot do

- **A server that lies consistently is not caught.** Tool names are chosen by the server. Renaming
  `run_pipeline` to `run_report` turns a high violation into a low review; a name and parameters
  that agree are trusted.
- **Live Entra mode is untested** against a real tenant.
- **Pseudonymous, not anonymous.** Permission names, tool names, env var names, file paths and free
  text still print.
- **Secrets with no known shape can print**, and a URL with no scheme is not shortened.
- **`network` is coarse:** it does not say where data goes.

The full list, with what proves each protection: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

### How the output guards are checked

Passing tests do not prove a guard works. [tools/mutation/](tools/mutation/README.md) breaks each
output guard on purpose, in a throwaway copy, and checks that a test fails. Last run: **94 guards
broken, 94 caught.** It takes 10 to 15 minutes, so it is not part of `pytest`:

```
python tools/mutation/guards.py run
```

## Development

```bash
pytest && ruff check .
python tools/release_check.py   # before a release
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
Every format and design assumption, with its verification status and source:
[docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md). Changes: [CHANGELOG.md](CHANGELOG.md).

Not yet built: rules APL-003 and APL-009, live tool listing, and an LLM reasoning layer.

## License

Apache-2.0. See [LICENSE](LICENSE).
