# Assumptions — MCP config formats and MCP spec (2026-07-28)

Status key: **[CLIENT]** = client convention, not in the MCP spec · **[SPEC]** = based on the spec,
check against the schema · **[HEURISTIC]** = our design choice · **[UNVERIFIED]** = not yet checked
against primary source. Code comments cite the IDs below as `ASSUMPTION Ax`.

Verification status (checked 2026-10-29 against official docs; source URL on each entry):
**verified** = source confirms it · **corrected** = source differs; entry and/or code updated ·
**unverified** = no primary source found yet.

## Config file formats (none of this is defined by the MCP spec)

- **A1 [CLIENT]** The MCP spec covers the wire protocol only. It does **not** define a client config
  file format, so every config shape we parse is a client convention that can change without notice.
- **A2 [CLIENT] — corrected.** All four clients use top-level `mcpServers: {name: {command, args,
  env}}`. Corrections to the original wording:
  - Claude Code: remote entries need `type` (`http`, alias `streamable-http`; `sse` deprecated; also
    `ws`). The docs say a `url` without a `type` is a configuration error, so A6's "url => HTTP"
    default does not match Claude Code. No `type` means stdio. Env syntax is `${VAR}` and
    `${VAR:-default}`; both are recognised as references (see A4).
    Source: https://code.claude.com/docs/en/mcp
  - Cursor: `.cursor/mcp.json` / `~/.cursor/mcp.json`. stdio examples set `type: "stdio"`; there is
    also `envFile`. Remote entries use `url` + `headers`. Env syntax is `${env:NAME}`.
    Source: https://cursor.com/docs/context/mcp
  - Windsurf: see A5. Headers are supported.
  - Claude Desktop: `claude_desktop_config.json` with `mcpServers` / `command` / `args` / `env` is
    verified. The page documents local (stdio) servers only; it does not show `url` or `headers`.
    Source: https://modelcontextprotocol.io/docs/develop/connect-local-servers
- **A3 [CLIENT] — corrected.** Verified: `.vscode/mcp.json` has top-level `servers` and an optional
  `inputs` array, with `type: stdio|http|sse`. stdio entries need `command` (optional `args`, `env`,
  `envFile`, `cwd`). http/sse entries need `url` (optional `headers`, `oauth`). Corrections: there is
  also an optional top-level `sandbox` object (ignored by us). VS Code now also reads a portable
  `.mcp.json` with top-level `mcpServers` (already handled). It labels `.vscode/mcp.json` and the
  user-profile `mcp.json` as deprecated but still available "for compatibility".
  Sources: https://code.visualstudio.com/docs/copilot/reference/mcp-configuration ,
  https://code.visualstudio.com/docs/copilot/chat/mcp-servers
  **Unverified:** `settings.json` → `mcp.servers` does not appear in the current official pages.
  Only third-party sources mention it. We keep parsing it, but every server from it has
  `format_status: "unverified"` and the file gets an "unverified format" warning.
- **A4 [CLIENT]** `${env:VAR}` and `${input:id}` are VS Code substitution syntax. `${VAR}` / `$VAR`
  are treated as env references for the other clients. Some clients may not expand these and may
  pass them through literally. If so, the value is a literal (non-secret) string, so treating it as
  a reference is still safe. `${VAR:-default}` and `${file:/path}` are references too, with two
  exceptions. (1) A default that looks like a known token shape is a hardcoded secret, so the
  value is not a reference. (2) In a secret slot (an env/header key with a secret-like name, or the
  value after a `--token`-style flag), any non-empty default is treated as a hardcoded fallback
  secret. It is flagged inline and redacted from args.
- **A5 [CLIENT] — verified (with a note).** The Windsurf docs URL now redirects to Devin docs.
  They say a remote server "requires a `serverUrl` or `url` field". Every example uses `serverUrl`.
  We accept both. The config path is now `~/.config/devin/mcp_config.json`
  (`%APPDATA%\devin\mcp_config.json` on Windows). Env syntax is `${env:VAR}`. There is also
  `${file:/path}`, which reads a secret from a file. It is recognised as a reference and reported
  as `env_var: "file:<path>"` (see A4).
  Source: https://docs.devin.ai/desktop/cascade/mcp (redirect from
  https://docs.windsurf.com/windsurf/cascade/mcp)
- **A6 [HEURISTIC]** If an entry has `url` but no `type`, we assume Streamable HTTP, not legacy SSE.
  If it has `command` but no `type`, we assume stdio. A `url` entry with no `type` always produces
  a warning, and the server's evidence note says the transport was assumed. Claude Code rejects
  such entries as a configuration error (see A2). `serverUrl` with no `type` (Windsurf's documented
  form) is still assumed HTTP but is not warned on.
- **A7 [CLIENT]** `disabled: true` means the client will not start the server. We keep the server
  in the inventory and mark it disabled. Its credentials still exist on disk.
- **A8 [HEURISTIC]** Credential kind comes from the env var or header *name* (e.g.
  `*_PERSONAL_ACCESS_TOKEN` is a PAT and `*CLIENT_SECRET` is a service principal). Names can mislead.
  Phase 3 (Entra) confirms the real identity where an app ID is known. Every `CredentialRef` has a
  `kind_source` field: `inferred` (guessed from a name), `unknown` (no basis), or `verified`
  (confirmed from Entra; see G10).
- **A9 [HEURISTIC]** `AZURE_CLIENT_ID` / `CLIENT_ID` values are identifiers, not secrets. We keep
  them so we can link to Entra. Tenant IDs are kept too.
- **A10 [HEURISTIC] — fixed.** Config files are parsed as JSONC (`//` and `/* */` comments, trailing
  commas). Strict JSON is tried first. Comments are blanked to spaces, so error line and column
  numbers match the original file. Parse errors report position only, never content
  (`apl/parsers/jsonc.py`). Claude Desktop, Claude Code, Cursor and Windsurf (`mcpServers` files)
  have no documented JSONC support, so we warn when a file in that format uses JSONC. The VS Code
  pages checked do not state JSONC support either (unverified); VS Code's own JSON files allow it.

## MCP protocol (spec 2026-07-28)

- **S1 [SPEC]** 2026-07-28 is the current spec version. It made the core stateless, removed the
  `initialize` handshake and `Mcp-Session-Id`, and added `server/discover`. This only matters once
  `--connect` exists (not in v0.1). The offline parser does not depend on it.
- **S2 [SPEC]** Transports are stdio and Streamable HTTP. Legacy HTTP+SSE is **Deprecated** under
  the new lifecycle policy, and we emit a warning when we see it.
- **S3 [SPEC] — corrected.** In 2026-07-28, `ListToolsResult extends PaginatedResult, CacheableResult`
  with `tools: Tool[]`. Every `Result` has a **required** `resultType` (`"complete" |
  "input_required" | string`). Servers on this version MUST send it. Clients MUST treat a missing
  `resultType` (older servers) as `"complete"`. `CacheableResult` adds required `ttlMs` and
  `cacheScope` (`public|private`). `Tool` = `name`, `title?`, `icons?`, `description?`,
  `inputSchema` (required, `type: "object"`), `outputSchema?`, `annotations?`, `_meta?`. Only
  `tools/call`, `resources/read` and `prompts/get` responses can be `input_required`.
  **Parser change:** `tools_list.py` now accepts a missing `resultType` or `"complete"`. It rejects
  any other value without echoing it, because it is untrusted server output. We still read only
  `name`, `description` and `annotations`. `ttlMs`, `cacheScope` and `nextCursor` are ignored:
  offline files are assumed to hold the full list.
  Sources: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts ,
  https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- **S4 [SPEC] — verified.** `ToolAnnotations` in 2026-07-28 has exactly `title`, `readOnlyHint`,
  `destructiveHint`, `idempotentHint` and `openWorldHint`; none were added or renamed. The spec page
  says clients "MUST consider tool annotations to be untrusted unless they come from trusted
  servers". Documented defaults: readOnly=false, destructive=true, idempotent=false,
  openWorld=true. `destructiveHint` and `idempotentHint` are "meaningful only when
  `readOnlyHint == false`". **Our handling:** defaults for missing hints are reported in
  `Tool.annotation_defaults_unapplied` but not applied, because applying destructive=true would
  mark every unannotated tool as delete. An explicit readOnly=true + destructive=true is flagged in
  `Tool.annotation_flags`.
  Sources: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts ,
  https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- **S5 [HEURISTIC]** Because annotations are untrusted, they can only **add** capabilities. They
  never remove one: `readOnlyHint=true` on `delete_*` is flagged as a conflict.
- **S6 [HEURISTIC]** Tool **descriptions** are never used for classification, because that is the
  prompt-injection surface. They are only scanned for injection markers and kept, wrapped in
  delimiters, for the Phase 4 LLM.
- **S7 [SPEC][UNVERIFIED]** MCP authorization is OAuth 2.1, with RFC 8707 resource indicators and
  RFC 9207 `iss` validation in 2026-07-28. APL-008 (missing audience binding) will rely on this.
  Static configs show only whether a header or env token exists, not the token's audience. That
  needs live or Entra data.
- **S8 [HEURISTIC]** The MCP capability set (tools, resources, prompts) is not mapped to
  read/write/delete/execute/network. Phase 1 classifies **tools only**. Resources are treated as
  read, and nothing models them yet. Deprecated Roots, Sampling and Logging are ignored.
- **S9 [SPEC]** The offline tools file accepts the JSON-RPC envelope (`{"result": {"tools": []}}`),
  a bare `{tools: []}`, or a `{server_name: ...}` map. The last one is our own format, not the
  spec's.

## Classifier evaluation

- **C1 [HEURISTIC]** A tool name with no recognised verb is not guessed. It gets
  `capabilities: {unknown}`, confidence 0, and `classification_flags: ["unclassified: review
  required"]`. Until pass 2 the default was read+write, which looked like a real classification
  and hid gaps. Annotations can still add capabilities to such a tool, but a `readOnlyHint` alone
  never classifies it (S5). `unknown` ranks above execute in `CAPABILITY_RISK`: an unreviewed
  tool cannot be shown to be less powerful. Corpus reports give it its own `unclassified` bucket,
  kept out of `missing` because it is flagged, not silent. They also print
  `missing + unclassified` as the stricter view.

- **E1 [HEURISTIC]** `tests/fixtures/tool_corpus.yaml` holds 48 tool names with hand labels (9 are
  ambiguous and labelled with the widest plausible set). Labels were not changed when the
  classifier changed. Each tool falls in one bucket: **exact**; **under** (predicted max risk below
  the labelled max risk, which is dangerous); **over** (any other mismatch).

  | 2026-10-29         | exact      | under | over |
  |--------------------|------------|-------|------|
  | before Step B      | 36/48 (75%) | 5    | 7    |
  | after Step B       | 43/48 (90%) | 0    | 5    |

  Step B added `terminate`/`kill` → delete and `sudo` → execute. Ambiguous verbs (`manage`, `sync`)
  get the widest plausible set at confidence 0.5. `query` with a database noun → execute.
  `pull/merge request(s)` are joined into a single noun, so `request` no longer reads as network.
  The `query_sql` entry could never match and was removed. Remaining over-classified names:
  `reset_password`, `archive_issue`, `take_screenshot`, `process_payment`, `DATA_EXPORT_v2`
  (unknown verbs get read+write; archive maps to delete). Floors: under ≤ 0 and exact ≥ 43.
  **Caveat:** Step B's verbs were chosen from the corpus misses, so 43/48 is a training-set number.
  It does not measure accuracy on unseen names. (The Step B table uses the old risk-based buckets.
  It is superseded by E2.)

- **E2 [HEURISTIC] Classifier pass 2 (2026-10-29).** There is now a held-out corpus,
  `tests/fixtures/tool_corpus_holdout.yaml` (45 names; 10 overlap the main corpus, so 35 are
  unseen). `download_file` was relabelled ambiguous `[network, read, write]` in both corpora
  because the two labels disagreed. New buckets (`tests/corpus_report.py`): **exact**;
  **missing** = any labelled capability not predicted (dangerous); **extra** = superset only
  (noisy); **unclassified** = `{unknown}` + review flag (C1). Floors: missing ≤ 2 (main) and
  ≤ 12 (held-out), the baselines measured before pass 2's classifier changes.

  | exact / missing / extra / unclassified | main (48) | held-out (45) | unseen (35) |
  |----------------------------------------|-----------|---------------|-------------|
  | before pass 2 (read+write default)     | 42/2/4/–  | 30/12/3/–     | 21/11/3/–   |
  | + unknown instead of read+write        | 42/2/0/4  | 30/4/0/11     | 21/3/0/11   |
  | + execute family                       | 41/2/1/4  | 32/4/0/9      | 23/3/0/9    |
  | + network family                       | 38/2/4/4  | 32/3/1/9      | 24/2/0/9    |
  | + composite family (final)             | 38/2/5/3  | 32/3/6/4      | 24/2/5/4    |

  Families: **execute** = evaluate, launch, start, stop, restart, reboot, kill (code evaluation
  and process/service lifecycle). **network** = send, email, upload, post (data crossing the
  network boundary, i.e. the exfiltration path). **composite** = migrate, cleanup/clean, reset,
  handle, install/uninstall. These get one uniform widest set (all concrete capabilities), not
  per-verb sets, so nothing is tailored to labels. Main exact fell 42→38 because write-only labels
  on send/post/upload now also get network. That is extra (noisy), not missing.
  **Caveat:** the family verb lists came from the reviewer's instructions, which were written
  after the first held-out report. The held-out set is therefore no longer fully independent
  for these verbs. Floors after pass 2: missing ≤ 2 (main) and ≤ 3 (held-out #1).

- **E3 [HEURISTIC] Held-out set #2 (2026-10-29).** `tests/fixtures/tool_corpus_holdout2.yaml`, 43
  names. Per its author, set #2 was written before seeing any classifier results. It shares no
  names with the main corpus or held-out #1 (checked by the test). It is the **first fully
  independent measure** of the classifier. Measured once, after pass 2, with no classifier or
  label changes. No floor yet.

  | held-out #2 (43) | exact       | missing   | extra    | unclassified | missing + unclassified |
  |------------------|-------------|-----------|----------|--------------|------------------------|
  | after pass 2     | 21 (49%)    | 3 (7%)    | 1 (2%)   | 18 (42%)     | 21 (49%)               |

  Missing (dangerous): `publish_event` and `push_notification` (no network; publish and push are
  only in write), and `sync_calendar` (no network). Extra: `approve_request` (bare `request` →
  network). Unclassified (18): `append_note`, `register_user`, `tag_resource`, `disable_user`,
  `discard_draft`, `compile_project`, `shutdown_server`, `ping_host`, `open_connection`,
  `forward_message`, `apply_migration`, `rebuild_index`, `call_api`, `process_order`,
  `transform_data`, `refresh_cache`, `rotate_keys`, `configure_pipeline`.
  Takeaway: on unseen names, few tools are silently understated (3/43), but verb coverage is
  thin. About 4 in 10 tools need human review.

- **E4 [HEURISTIC] Classifier v2 regression (2026-10-30).** Corpora and labels unchanged; bucket
  definitions as in E2. Measured once with the classifier frozen. Floors hold: missing ≤ 2 (main)
  and ≤ 3 (held-out #1).

  | exact / missing / extra / unclassified | main (48) | held-out #1 (45) | unseen in #1 (35) | held-out #2 (43) |
  |----------------------------------------|-----------|------------------|-------------------|------------------|
  | before v2                              | 38/2/5/3  | 32/3/6/4         | 24/2/5/4          | 21/3/1/18        |
  | after v2                               | 37/2/6/3  | 33/2/6/4         | 25/1/5/4          | 26/1/0/16        |

  Seven names moved. Main: `push_files` exact → extra: it is labelled write only, and "push" now
  also gives network, so exact dropped by one. That is noisier, not more dangerous, and the label was
  not edited. Held-out #1: `run_report` missing → exact. Held-out #2: `publish_event` and
  `push_notification` missing → exact; `ping_host` and `forward_message` unclassified → exact;
  `approve_request` extra → exact. **These numbers are not an accuracy gain:** see E5.

## Rules (Phase 2)

Shared conventions: findings have `status: violation | review_required`, a confidence with a
reason, and `suggested_mappings` that are always labelled "suggested mapping". When an input is
absent, a rule emits a visible `RuleSkip` ("not evaluated: missing X") instead of passing
silently. Tools that are unclassified or have confidence ≤ 0.5 never support a hard
`violation` (C1); they turn findings into `review_required`.

- **R1 [HEURISTIC] — mapping IDs verified.**
  `LLM06:2025 Excessive Agency` covers excessive functionality, permissions and autonomy. Its
  prevention section says "require a human to approve high-impact actions" and minimise
  extension permissions. Source: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
  `ASI03 Identity & Privilege Abuse` is from the OWASP Top 10 for Agentic Applications 2026. Only
  the title and a one-line summary were verified, not the full entry text. Source:
  https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
  Skipped as weak or unverified: ASI02 Tool Misuse for APL-007 (full text not read), and ASI09
  Human-Agent Trust Exploitation for APL-010 (it is about humans being misled into approving,
  not about missing gates).
- **R2 [HEURISTIC] — Graph naming verified.** Permissions follow
  `{resource}.{operation}.{constraint}`. `ReadWrite` grants "read, create, update, and delete".
  APL-001 maps operations to the capabilities they add over `Read`: Read/ReadBasic → read;
  ReadWrite/Manage/FullControl/AccessAsUser → write+delete; Create/Migrate → write. Any other
  operation is skipped with "missing scope mapping". Constraints (`.All`, `.OwnedBy`) are not yet
  scored. Added in Phase 3: Send → network, DeleteRestore → delete.
  Source: https://learn.microsoft.com/en-us/graph/permissions-overview

  **Delete evidence, per permission (checked 2026-10-30).** The operation-level rule above stays
  the default. Each permission in `scopemap.py` that it gave delete was checked against the
  permissions reference (https://learn.microsoft.com/en-us/graph/permissions-reference) and the
  delete API page for its resource. This corrects an earlier note here, which called
  `User.ReadWrite.All` and `Directory.ReadWrite.All` overstated without reading those pages.

  | Permission | Status | Evidence |
  |---|---|---|
  | `Mail.ReadWrite` | verified: delete | Listed. https://learn.microsoft.com/en-us/graph/api/message-delete?view=graph-rest-1.0 |
  | `Files.ReadWrite` | verified: delete | Listed. https://learn.microsoft.com/en-us/graph/api/driveitem-delete?view=graph-rest-1.0 |
  | `Files.ReadWrite.All` | verified: delete | Listed. https://learn.microsoft.com/en-us/graph/api/driveitem-delete?view=graph-rest-1.0 |
  | `Calendars.ReadWrite` | verified: delete | Listed. https://learn.microsoft.com/en-us/graph/api/event-delete?view=graph-rest-1.0 |
  | `User.ReadWrite.All` | verified: delete | Listed, as the least-privileged permission; not enough for users holding privileged admin roles. https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0 |
  | `Application.ReadWrite.All` | verified: delete | Listed for applications and service principals. https://learn.microsoft.com/en-us/graph/api/application-delete?view=graph-rest-1.0 , https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete?view=graph-rest-1.0 |
  | `Application.ReadWrite.OwnedBy` | verified: delete | Listed as least privileged, application type only. The reference limits it to apps it owns. https://learn.microsoft.com/en-us/graph/api/application-delete?view=graph-rest-1.0 |
  | `Directory.ReadWrite.All` | verified: delete, service principals only | The reference says it does not allow user or group deletion, and the user and group pages omit it, but Delete servicePrincipal lists it. Not corrected, because the docs show a delete it allows. https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete?view=graph-rest-1.0 , https://learn.microsoft.com/en-us/graph/api/group-delete?view=graph-rest-1.0 |
  | `User.ReadWrite` | corrected: no delete | Delete a user lists only `User.ReadWrite.All`, on v1.0 and beta; the reference describes reading and updating your own profile. **Judgment call:** it can delete the signed-in user's own photo, which we count as a profile update (write), not deleting an object. https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0 , https://learn.microsoft.com/en-us/graph/api/profilephoto-delete?view=graph-rest-1.0 |
  | `User.DeleteRestore.All` | unverified | The reference says it deletes and restores all users, but Delete a user does not list it on v1.0 or beta. Delete is kept, and findings cap confidence at 0.6. https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0 |

  Permissions outside `scopemap.py` (e.g. `Group.ReadWrite.All`, `Mail.ReadWrite.Shared`) were not
  checked and keep the operation-level mapping.

  **Before and after (2026-10-30).** APL-001 run for each permission on a server with read-only
  tools and a verified credential. Severity logic did not change. The other eight permissions are
  unchanged: delete+write, high, 0.90. The `mail-triage` demo finding and the report snapshots are
  also unchanged.

  | Permission | Before | After |
  |---|---|---|
  | `User.ReadWrite` | delete+write, high, 0.90 | write, medium, 0.90 |
  | `User.DeleteRestore.All` | delete, high, 0.90 | delete, high, 0.60 |
- **R3 [HEURISTIC] — GitHub scopes verified.** repo/public_repo/user/gist/write:packages → write;
  delete_repo/delete:packages → delete; admin:org/admin:repo_hook → write+delete; read:org/read:user
  → read; workflow → write+execute (workflow files run code in CI; the execute part is our
  inference). Source: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
- **R4 [HEURISTIC] APL-001.** A scope is over-scoped when none of the capabilities it adds is
  needed by any classified tool on the same server. Static configs never contain granted scopes,
  so runs without `--entra`/`--entra-mock` skip with "missing granted scopes". Confidence is 0.9 × a kind
  factor (verified 1.0, inferred 0.75, unknown 0.6). Any uncertain tool on the server makes the
  finding `review_required` with confidence ≤ 0.4. Severity is high if the excess includes
  delete or execute, otherwise medium.
- **R5 [HEURISTIC] APL-002.** Any secret in a static client config is one fixed token for every
  invoker of that agent instance. This holds whatever the kind; a `${input:...}` prompt still
  yields one token per client. Who invokes the agent comes from a new optional agent.yaml field,
  `invokers: single | multiple`. If it is absent, the rule is skipped. Severity: PAT or user
  refresh token = maker-mode (high); service principal, managed identity, API key or unknown =
  shared identity (medium). Client-ID-only refs (A9) are identifiers, not tokens, and are
  excluded. Not flagged: stdio servers with no credential, which run as the local host user. That
  is also a fixed identity, but there is no credential evidence to cite.
- **R6 [HEURISTIC] APL-007.** Declared purpose = agent.yaml `required_capabilities` plus a new
  optional `required_tools` list. Listed tools are accepted even if powerful (the owner declared
  them). With only `required_tools`, the declared set is the union of the listed tools'
  capabilities. An empty `required_capabilities` with no `required_tools` counts as "not declared"
  and is skipped. Uncertain tools (C1) get a low-severity `review_required` finding, never a
  violation. An uncertain tool whose widest set still fits the purpose gets no finding. Violation
  confidence = the tool's classifier confidence (0.7 from the name only, 0.9 with annotations).
  Severity: delete/execute high, write/network medium, read low.
- **R7 [CLIENT] auto-approve lists (APL-010).** Cline: `autoApprove` (array) on each server —
  **verified** in docs examples. The docs say "Limit `autoApprove` to safe tools"; reading it as
  "tool names run without asking" is our inference. Source:
  https://docs.cline.bot/mcp/configuring-mcp-servers
  Roo Code: `alwaysAllow` (array) — **unverified**; seen only in third-party setup guides. A
  non-list value (one source says some client uses a boolean) is ignored with a warning, not
  guessed. Key absent → `auto_approve: None` → APL-010 skipped. Claude Desktop, VS Code and
  Claude Code keep approvals elsewhere (app state or settings), so their configs always skip.
  `[]` → nothing auto-approved, so no finding. Only exact tool names match; wildcards are not
  interpreted.
- **R8 [HEURISTIC] APL-010.** High-impact = delete or execute (destructiveHint=true already maps
  to delete), or unclassified (counted as high-impact until reviewed: medium, confidence 0.5).
  Confidence otherwise = the tool's classifier confidence. Write and network tools are not
  flagged yet. A tool that is auto-approved on a server declared `approval_gate: true` in
  agent.yaml raises severity one level (medium→high, high→critical).

## Entra collector (Phase 3)

All checked 2026-10-30 against Microsoft Learn. **Nothing here has been run against a real tenant:**
tests use responses shaped from the docs' examples, so live behaviour itself is **unverified**.

- **G1 [SPEC] Token — verified.** `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`,
  form-encoded `client_id`, `client_secret`, `scope=https://graph.microsoft.com/.default`,
  `grant_type=client_credentials`. Response: `access_token`, `expires_in`, `token_type`. Errors carry
  `error` plus free-text `error_description`; we report only the HTTP status and a validated
  `error`. The token POST uses its own client, so the Graph client's guard has no exception: it
  refuses anything but `GET https://graph.microsoft.com/...`. That also stops a hostile
  `@odata.nextLink` receiving the bearer token. Commercial cloud only; national clouds are not
  supported. Source: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
- **G2 [SPEC] Permissions for the scanner — corrected.** `.env.example` listed `AuditLog.Read.All`,
  which only sign-in activity needs (G8), so it was removed. Least privilege for what we call:
  `Application.Read.All` (applications, service principals, owners, appRoleAssignments) plus
  `Directory.Read.All` (`oauth2PermissionGrants`, for which it is the least-privileged permission
  listed). Env vars are `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, replacing the `APL_`-prefixed
  names. Sources: https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0
- **G3 [SPEC] Applications and service principals — verified.** `GET /applications`,
  `GET /servicePrincipals`. `id` is the object id; `appId` is the client id, which is what configs
  hold. `passwordCredentials[]` and `keyCredentials[]` both have `keyId` and `endDateTime`.
  `secretText` is returned only by the initial `addPassword` POST; `hint` holds the secret's first
  three characters. We copy neither, nor `key`. **We send no `$select`:** the list pages say selecting
  `keyCredentials` returns `key` and carries a 150 requests/minute tenant limit. (The keyCredential
  page disagrees, saying `key` is single-object only. Not selecting avoids both.)
  `servicePrincipalType` is `Application`, `ManagedIdentity`, `Legacy`, `ServiceIdentity` or
  `SocialIdp`. Lists may also return agent identity blueprint objects, handled the same way.
  Sources: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0
- **G4 [SPEC] Delegated grants — verified.** `GET /oauth2PermissionGrants`. `clientId` and
  `resourceId` are service principal **object ids, not appIds**. `scope` is space-separated.
  `consentType` is `AllPrincipals` or `Principal` (one user). Both count as granted; they are kept
  apart so a per-user grant is not reported as tenant-wide.
  Source: https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0
- **G5 [SPEC] Application permissions — verified.** `GET /servicePrincipals/{id}/appRoleAssignments`
  lists roles granted **to** this SP (`appRoleAssignedTo` is the reverse). An assignment holds only
  a GUID `appRoleId`; the name is `value` in the `appRoles` of the SP at `resourceId`. The all-zero
  GUID means no specific role. A role id that does not resolve is kept as
  `unresolved-app-role-<id>`, so APL-001 skips it visibly. The Mail.ReadWrite application role id in
  our fixture, `e2a3a72e-5f79-4c64-b1b1-878b674786c9`, matches the permissions reference.
  Sources: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0
- **G6 [SPEC] Owners — verified.** `GET /applications/{id}/owners` and
  `GET /servicePrincipals/{id}/owners`. We take the union of both, and keep ids only: without
  user-read rights other fields come back null, and names are personal data. An app registered in
  another tenant has only a service principal here.
  Sources: https://learn.microsoft.com/en-us/graph/api/application-list-owners?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-owners?view=graph-rest-1.0
- **G7 [SPEC] Paging and throttling — verified.** Use the whole `@odata.nextLink` in a GET until it
  is absent; a page may be empty. 429 carries `Retry-After` in seconds; with no header, the docs
  recommend exponential backoff. **Our choices [HEURISTIC]:** 6 attempts; backoff 1s doubling to 60s;
  5xx treated like 429; an HTTP-date `Retry-After` is also accepted; a wait over 300s stops the scan
  rather than retrying early. Paging keeps the last good `nextLink` on retry, as the docs advise.
  Sources: https://learn.microsoft.com/en-us/graph/paging ,
  https://learn.microsoft.com/en-us/graph/throttling
- **G8 [SPEC] Sign-in activity — unverified, not collected.** Search snippets show beta
  `GET /reports/servicePrincipalSignInActivities` needing `AuditLog.Read.All`. It was optional, is
  beta only, and no rule uses it, so it is left out. The page itself was not read.
  Source: https://learn.microsoft.com/en-us/graph/api/reportroot-list-serviceprincipalsigninactivities?view=graph-rest-beta
- **G9 [HEURISTIC] Trust.** Graph responses are tenant-controlled data. Display names and scope
  values are redacted and truncated on ingest. A resource counts as Graph only by the well-known
  appId `00000003-0000-0000-c000-000000000000`, never by name; other APIs' scopes become
  `<resource>/<scope>` so `Mail.Read` on a custom API cannot pass as the Graph permission.
  Per-object calls run only for apps a scan links to, to limit throttling.
- **G10 [HEURISTIC] Linking.** A credential links on `appId`, case-insensitively, from the config's
  client id (A9) or agent.yaml `entra_app_id`. The latter always adds a separate id-only
  `CredentialRef`: APL-002 treats a ref with an app id as "not a token", so stamping it on a
  secret-bearing ref would hide that secret from APL-002. `granted_scopes` is the union of
  application permissions and all delegated grants. That is conservative: which of them a given
  token actually carries depends on its flow, which a static config does not show. An app with
  no grants gets `[]` and is evaluated; an app not found stays `None` and is skipped with a
  warning. `kind_source: verified` is set only for `servicePrincipalType` `Application` or
  `ManagedIdentity`. Sign-in scopes (`openid`, `profile`, `email`, `offline_access`) have no mapping,
  so they appear as skips. No owner, expired credentials and per-user grants are warnings, not
  findings: no rule covers them yet.
- **G11 [HEURISTIC] `scopemap.py` — permission names verified, choice of minimum is ours (suggested
  mapping).** Every name in the table was checked against the permissions reference, with
  delegated and application availability; `Files.Read` and `User.Read` have no application form, so
  those rows differ. Narrower options exist but cover only part of a resource and are not offered:
  `Mail.ReadBasic`, `Calendars.ReadBasic`, `User.ReadBasic.All`. `Mail.ReadWrite` "does not include
  permission to send mail", hence the separate `Mail.Send` row. Directory has no delete row because
  no single permission is the minimum there: `Directory.ReadWrite.All` cannot delete users or groups,
  and service principals have the narrower `Application.ReadWrite.OwnedBy` (see R2). User uses
  `User.DeleteRestore.All`, which R2 marks unverified. `Application.ReadWrite.OwnedBy` is application-only and cannot manage
  apps it does not own. Source: https://learn.microsoft.com/en-us/graph/permissions-reference
- **G12 [HEURISTIC] Secrets in this path.** Three independent layers. (1) `secretText`, `hint`, `key`
  and failure-response bodies are never copied, so they cannot reach output. (2) `redact()` also
  scrubs the exact client secret and access token, because a client secret need not match any
  pattern (the `8Q~` shape is observed, not documented). The values stay in process memory only.
  (3) Rich tracebacks are set not to print locals, and errors never chain the request. Each
  layer is tested alone. Not covered: a secret shorter than 8 characters is not scrubbed by exact
  match, and a third-party library logging at DEBUG would be outside `redact()`; httpx at this
  version logs the URL, which never holds a credential.

## Reports (`apl scan`)

- **R9 [SPEC] SARIF 2.1.0 — verified.** Output for the clean and dirty fixtures validates with 0
  errors against the official JSON schema (draft-07), checked 2026-10-29 with `jsonschema` in a
  scratch environment, not as a project dependency. Source:
  https://json.schemastore.org/sarif-2.1.0.json (spec:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html). The first validation caught
  `logicalLocations` on the result object; it belongs inside `locations[]`. Fixed. Mapping:
  critical/high → error, medium → warning, low/info → note; `review_required` → note. Skips →
  `invocations[0].toolExecutionNotifications`. Evidence is a JSON pointer, not a line, so results
  carry only `artifactLocation.uri` (relative path, or a `file://` URI when absolute) plus
  `properties.jsonPointer`. Findings without evidence fall back to their server's config entry.
  The schema is not re-validated in CI (no `jsonschema` dependency); tests check structure.
- **R10 [HEURISTIC] JSON report.** `schema_version: "1.0"`, with top-level keys pinned by a
  test. Bump the major version on removed or renamed keys or changed types; adding keys is minor.
- **R12 [HEURISTIC] "Evaluated" wording.** Each rule records a `(rule, subject)` entry in
  `RuleResult.evaluated` once it gets past its skips. A server a rule does not apply to (e.g.
  APL-001 on a server with no credential) is neither evaluated nor skipped. Reports never say
  "No findings" or "Nothing to fix" when nothing ran: they say "Nothing could be evaluated. See
  Not evaluated." (SARIF: a `warning` notification). For a partial run they say "No findings among
  the N checks that ran (M not evaluated)." (SARIF: a `note`). JSON `summary` gains
  `evaluated`, `skipped`, `outcome` and `message`. Keys were only added, so `schema_version` stays
  1.0. All three cases validate against the SARIF schema (0 errors).
- **R11 [HEURISTIC] Exit codes.** 0 = no finding at or above `--fail-on` (default `none`); 1 = at
  least one; 2 = parse error, write error or `--connect`. `review_required` findings count toward
  `--fail-on` at their own severity (APL-007 reviews are low).
