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
  any other value without echoing it, because it is untrusted server output. We read `name`,
  `description`, `annotations` and, since classifier v2, property names from `inputSchema` (C2).
  `ttlMs`, `cacheScope` and `nextCursor` are ignored:
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

- **C2 [HEURISTIC] `inputSchema` signals (`schema_signals.py`).** Vocabulary chosen from general
  knowledge of parameter naming, not from the corpora. Each parameter is judged by its head noun, so
  `command_id` is an id, and `code` needs no qualifier or a language-like one, so `zip_code` is
  ignored. `query`/`statement` are execute only with a database word in the name or parameters;
  `sql` always is. Paths are write with a write name, otherwise read.
  Walks `properties` and array `items`, bounded. **Does not follow** `$ref`, `anyOf`, `oneOf` or
  `allOf`, so parameters there are not seen.
  **Combining.** Read words (id, limit, offset, filter, read-side path, plain query) are weak: they
  support a read name and never conflict, because `update_issue(id)` is normal. Generic data words
  (text, data, content, body, payload) are weak writes: on a read-only name with no strong signal
  they add write at confidence 0.5 and flag `weak write signal: review required`; on a write name
  they agree; on an unknown name they add to `unknown`; anywhere else they add nothing. They do not
  lower confidence on a riskier name, or `delete_repository(content)` would become a review.
  Strong words all in
  the name's set raise confidence by 0.1 (cap 0.95). A strong word outside it takes the widest set,
  flags `name/schema conflict` and caps confidence at 0.6.
  **Untrusted input.** A schema is server output, so: (1) it only adds capabilities (S5);
  (2) a conflict stays above the rules' 0.5 line, because at or below it a server could add a
  `content` parameter to soften a `delete_*` violation into a review; (3) agreement cannot lift a
  tool over that line; (4) with an unknown name, strong words add to `unknown` rather than replacing
  it, at confidence 0.5, and read words add nothing; (5) only names are kept, and only vocabulary
  words reach reason strings. Schema `default` and `enum` values are never read, as they can hold
  secrets. Descriptions are scanned for injection markers, raising the existing warning, then dropped.
  **Known weaknesses.** A server can still omit or rename parameters, so a clean schema proves
  nothing. It can raise confidence by 0.1 with matching names. A weak write still gives a read
  tool a false `write`: since E7 that is a low review under APL-007, not a violation, but a real
  writer named like a reader is softened the same way. That false `write` used to suppress APL-001
  for the whole server; fixed, see E7.
- **C3 [HEURISTIC] Name vocabulary in v2.** publish, push, notify, broadcast, relay and forward are
  network and write (data leaves the system); subscribe and ping are network only. Matching is by
  token anywhere in the name, so a noun such as `get_forward_rules` also matches. "request" is
  network only straight after http, https, api, web, network, rest, graphql, ajax, url or remote; a
  bare `request` is unclassified. `run_<query|report|search>` with no database word adds read, keeps
  execute and gets confidence 0.5. Execute stays because a missed capability is the dangerous error
  and dropping it would hide the tool from APL-010. **Known evasion:** the tool name is server-chosen.
  Measured on a read-only purpose, `run_pipeline` is an APL-007 high violation and `run_report` is a
  low review at 0.5, so renaming a tool softens the verdict. The same is true of any name that
  gets confidence 0.5. "browse" alone is a read; it adds network with http, web, url, website,
  webpage or internet in the name, or a url/host parameter, which then agrees with the name.

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

- **E5 [HEURISTIC] What v2 measures, and what it does not.** E4 is a regression check only.
  - **Schema signals are unmeasured.** The corpora are names only, so `inputSchema` signals (C2)
    played no part in E4. Their only evidence is synthetic unit tests, which show the code does what
    it was written to do, not that it is right on real tools.
  - **Held-out #1 and #2 are now development sets.** Their misses were seen before v2 was written:
    E3 lists them by name, and steps 3 to 5 use the same words (publish, push, ping, forward,
    `approve_request`, `run_report`). Every name that moved on them is a known miss, so the movement
    is expected, not measured. E2's and E3's numbers stay valid for the classifier they measured.
  - The name changes were general vocabulary and were not fitted to corpus entries, but that
    does not make these sets independent again.
  - **A real number needs a new held-out set with schemas:** real tools with their `inputSchema`,
    labelled before any classifier result is seen, and measured once. The false-conflict rate on
    real read tools is the main unknown (C2).

- **E6 [HEURISTIC] Held-out set #3 (2026-10-30).** `tests/fixtures/tool_corpus_holdout3.yaml`, 36
  tools with parameter names, the first corpus to exercise schema signals. Each `inputSchema` is
  built from `params` (type object, string properties, no descriptions) and goes through the real
  parser. Measured once on classifier v2, with no classifier or label changes and no floor. It
  shares no names with the earlier corpora. Per its header, it was written after set #2's misses
  were known and before v2 results were seen.

  | held-out #3 (36) | exact    | missing  | extra    | unclassified | missing + unclassified |
  |------------------|----------|----------|----------|--------------|------------------------|
  | name only        | 11 (31%) | 4 (11%)  | 2 (6%)   | 19 (53%)     | 23 (64%)               |
  | name+schema      | 10 (28%) | 4 (11%)  | 13 (36%) | 9 (25%)      | 13 (36%)               |

  Every miss, name only. **Missing:** `browse_catalog` (read; got network), `view_page` (network),
  `get_report` and `list_items` (execute). **Extra:** `fetch_secret` (network), `handle_upload`
  (delete, execute, read). **Unclassified:** `retrieve_invoice`, `peek_queue`, `summarize_thread`,
  `open_file`, `validate_data`, `preview_content`, `stash_note`, `amend_record`, `enrol_student`,
  `annotate_file`, `expunge_record`, `clear_inbox`, `prune_branches`, `perform_task`, `orchestrate`,
  `compute`, `kick_off_build`, `probe_endpoint`, `contact_host`.

  Every miss, name+schema. **Missing:** `browse_catalog` (read; got network), `validate_data` and
  `preview_content` (read; got unknown+write), `probe_endpoint` (read; got unknown+network).
  **Extra:** `fetch_secret` (network), `handle_upload` (delete, execute, read), `search_docs`,
  `find_matches`, `count_words` and `lookup_definition` (write), and, with only `unknown` extra,
  `stash_note`, `amend_record`, `annotate_file`, `perform_task`, `orchestrate`, `compute`,
  `contact_host`. **Unclassified:** `retrieve_invoice`, `peek_queue`, `summarize_thread`, `open_file`,
  `enrol_student`, `expunge_record`, `clear_inbox`, `prune_branches`, `kick_off_build`.

  **False alarms, the 6 read tools with generic parameter names.** Counted as a capability beyond
  read, ignoring `unknown`: **0/6 name only, 6/6 (100%) name+schema.** Verdict on a read-only
  purpose: name only gives 4 no finding and 2 low reviews (`validate_data`, `preview_content`,
  both unclassified); name+schema gives **4 medium violations** (`search_docs`, `find_matches`,
  `count_words`, `lookup_definition`, each a conflict at 0.6) and the same 2 low reviews.

  Reading the table:
  - Schema signals cut tools with no answer from 19 to 9, and the stricter view from 23 to 13.
  - Missing stayed at 4 but the names differ. Schema fixed `view_page`, `get_report` and `list_items`.
    The three new misses each lack only `read` and keep `unknown`, so they stay in review and are
    not silent. They were unclassified before.
  - Exact fell by one, net: `search_docs`, `find_matches`, `count_words` and `lookup_definition` lost
    it to the false write, and `view_page`, `get_report` and `list_items` gained it. The bucket also
    understates schema help: 7 of the 13 extras hold the right capability and are extra only because
    `unknown` is kept by design (C2).
  - `text`, `data` and `content` are poor write signals: every one of the six tools tripped on them.
    The block was built to test this, so 100% is the rate on this worst case, not on read
    tools generally.

  **Limits.** This is hand-written, not real tools, and 36 tools is small. `search_docs(text)` was
  already known to false-alarm (C2) before this set was read, so that one result was no surprise.
  Any change made after seeing these misses turns this set into a development set too (E5). E7
  did that.

- **E7 [HEURISTIC] Classifier v2 follow-up (2026-10-30).** **Held-out #1, #2 and #3 are all
  development sets.** Weak writes and the `browse` fix came straight from E6's misses, so no set in
  this repo measures accuracy any more. Numbers below are regression checks. A real number needs a
  new held-out set, with schemas, labelled blind and measured once, ideally of real tools.
  Bucket split: **extra** now means a false addition; **partial** means the label is predicted
  exactly with `unknown` kept beside it. "Before" is commit 67ae845 under the same split; labels
  and rules are unchanged. Floors hold.

  | exact / missing / extra / partial / unclassified | before       | after        |
  |--------------------------------------------------|--------------|--------------|
  | main (48)                                        | 37/2/6/0/3   | 37/2/6/0/3   |
  | #1 (45)                                          | 33/2/6/0/4   | 33/2/6/0/4   |
  | #1 not in main (35)                              | 25/1/5/0/4   | 25/1/5/0/4   |
  | #2 (43)                                          | 26/1/0/0/16  | 26/1/0/0/16  |
  | #3 name only (36)                                | 11/4/2/0/19  | 12/3/2/0/19  |
  | #3 name+schema (36)                              | 10/4/6/7/9   | 11/3/6/7/9   |

  One name moved: `browse_catalog` missing → exact, on both #3 rows. The 7 partial tools are the ones
  E6 listed as extra only because `unknown` is kept. Remaining #3 name+schema extras: `fetch_secret`,
  `handle_upload` and the four `text` tools.

  **False-alarm block.** The buckets do not change: all 6 tools still gain a write capability
  (6/6). The verdict does. On a read-only purpose APL-007 went from 4 medium violations and 2 low
  reviews to **6 low reviews, 0 violations**, at confidence 0.5.

  **Defect: a false write suppressed APL-001. Fixed (2026-10-30).** APL-001 built its needs from
  every tool's capabilities and ignored confidence. A server with read-only tools and
  `Mail.ReadWrite` was a high violation; one tool with a `text` parameter made it **no finding**, and
  a server could trigger that on purpose. It was present since v2. APL-001 now separates confident
  from possible needs (R4). Measured on `Mail.ReadWrite` unless stated:

  | Server | Before | After |
  |--------|--------|-------|
  | read-only tools | violation, high, 0.9 | unchanged |
  | one tool takes `text` | **no finding** | review_required, high, 0.4 |
  | a tool is `unknown` + write | **no finding** | review_required, high, 0.4 |
  | `send_mail` present | no finding | unchanged |
  | `run_report` present | review_required, high, 0.4 | violation, high, 0.9 |
  | `delete_repo` scope, one tool takes `text` | review_required, high, 0.4 | violation, high, 0.9 |
  | `repo` scope, `delete_repository(content)` | violation, medium, 0.9 | unchanged |

  Tests in `tests/rules/test_apl001.py`: `test_read_only_tools_with_mail_readwrite_is_a_violation`,
  `test_one_text_parameter_gives_review_not_no_finding`,
  `test_partially_classified_tool_gives_review_not_no_finding`,
  `test_strong_write_signal_send_mail_is_no_finding`,
  `test_delete_repository_with_content_keeps_its_verdict`,
  `test_low_confidence_tool_cannot_soften_a_scope_it_cannot_need`,
  `test_read_leaning_run_does_not_soften_the_server`,
  `test_one_credential_can_give_a_violation_and_a_review`. The `mail-triage` demo finding and the
  report snapshots did not change.

  **Narrower form: closed (2026-10-30).** A conflict sits at confidence 0.6, which met the threshold,
  and annotations count at full confidence, so server-written signals could still justify a scope.
  Now a conflicted tool, and a capability only annotations claim, give possible needs only: they
  can soften a violation to a review but never remove a finding. Annotation-only capabilities are
  found by re-classifying without annotations, and that version must be confident too. Otherwise a
  hint launders the signal: `openWorldHint` makes `get_status(url)` agree instead of conflict, and
  `readOnlyHint=false` does the same for a weak write.

  | Server | Before | After |
  |--------|--------|-------|
  | `get_status(url)`, `Mail.Send` | **no finding** | review_required, medium, 0.4 |
  | `openWorldHint` tool, `Mail.Send` | **no finding** | review_required, medium, 0.4 |
  | `get_status(url)` + `openWorldHint`, `Mail.Send` | **no finding** | review_required, medium, 0.4 |
  | `get_x(content)` + `readOnlyHint=false`, `Mail.ReadWrite` | **no finding** | review_required, high, 0.4 |
  | `frobnicate` + `destructiveHint`, `delete_repo` | **no finding** | review_required, high, 0.4 |
  | `send_mail`, `Mail.Send` | no finding | unchanged |

  Tests in `tests/rules/test_apl001.py`: `test_get_status_url_with_mail_send_is_review_not_no_finding`,
  `test_open_world_annotation_with_mail_send_is_review_not_no_finding`,
  `test_annotation_cannot_launder_a_conflict`, `test_annotation_cannot_launder_a_weak_write`,
  `test_strong_agreeing_signals_give_no_finding`. They replace the earlier known-limit test.

  **Cost, measured.** A conflict makes every capability of the tool possible-only, including the
  name's own. A legitimate `create_issue(url)` with `repo` goes from no finding to a medium review,
  and `get_status(url)` with `Mail.Read` likewise. Any write tool taking a url can do this. An
  annotation that is true but unconfirmed by the name also becomes a review. The rate on real tools
  is unmeasured.

  **Still open.** `browse_status(url)` with `Mail.Send` is no finding. On a `browse` name a url
  parameter agrees rather than conflicts (C3), and the name is server-chosen, so it justifies network
  with no conflict flag. Agreement in general is trusted: a server can pick a name and a parameter
  that match. Name and schema together remain unverified claims; only `send_mail`-style naming
  separates them from a tool that lies consistently.

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
  Added 2026-11-01, checked against the entry pages: `NHI1:2025 Improper Offboarding`, whose text
  calls an NHI left active "without a new designated owner" orphaned and says to "ensure all NHIs
  have assigned owners". Source:
  https://owasp.org/www-project-non-human-identities-top-10/2025/1-improper-offboarding/ (served
  from owasp.github.io). Only suggested mappings: the title is about offboarding, the fit to APL-004
  is the owner text. ASI03 is not used for APL-004: an owner gap is not privilege abuse.
  `NHI7:2025 Long-Lived Secrets` covers secrets "with expiration dates that are too far in the future
  or that don't expire at all". Source:
  https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/
  `NHI5:2025 Overprivileged NHI` warns against privileges "beyond their functional requirements".
  Source: https://owasp.org/www-project-non-human-identities-top-10/2025/5-overprivileged-nhi/
  APL-006 also carries ASI03, on the same title-only basis as APL-001 and APL-002.
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
  needed by a tool on the same server. A tool with confidence ≥ 0.6, no `unknown` and no name/schema
  conflict gives a confident need, except for capabilities only annotations claim. Everything else
  is a possible need, and an `unknown` tool could need anything.
  Each scope is judged alone: a confident need means no finding; only a possible need means
  `review_required`, naming the tools, with subject `<server>/<credential>/low-confidence`; neither
  means a violation. One credential can give both. Static configs never contain granted scopes,
  so runs without `--entra`/`--entra-mock` skip with "missing granted scopes". Confidence is 0.9 × a kind
  factor (verified 1.0, inferred 0.75, unknown 0.6), capped at 0.4 for a review. Severity is high if
  the excess includes delete or execute, otherwise medium, so a review keeps that severity and counts
  toward `--fail-on` at it (R11).
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
- **R13 [HEURISTIC] APL-004.** Owners are the union of application and service principal owners
  (G6), evaluated per linked app. Zero owners is medium, high with a high-risk grant (R14).
  `owner_ids` is `None` when not collected and `[]` when Graph listed none: an owners call answering
  403 or 404 gives `None` unless the other object shows an owner, and the rule skips; other Graph
  failures still stop the scan. With no application object (another tenant, or a managed identity)
  only the service principal's owners are visible, so the finding is `review_required` at 0.6. That
  softening is our call: **unverified** whether managed identities can have owners at all. A server
  with no Entra link and no Entra-kind credential is out of scope, with no skip (R12). An owner who
  has left the company still counts as an owner; Graph's list does not show that.
- **R14 [HEURISTIC] High-risk permissions (`apl/highrisk.py`) — wording verified, choice is ours
  (suggested mapping).** Checked 2026-11-01 against
  https://learn.microsoft.com/en-us/graph/permissions-reference. Each link is that permission's
  section. Microsoft does not publish such a list.

  | Permission | Forms | Reference says |
  |---|---|---|
  | [`Application.ReadWrite.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadwriteall) | both | Allows "an application to act as other entities, and use the privileges they were granted" |
  | [`AppRoleAssignment.ReadWrite.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#approleassignmentreadwriteall) | both | Caution: can "grant additional privileges to itself, other applications, or any user" |
  | [`RoleManagement.ReadWrite.Directory`](https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreadwritedirectory) | both | The same caution; covers adding members to Microsoft Entra roles |
  | [`Directory.ReadWrite.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#directoryreadwriteall) | both | Caution: "broad access to directory (Microsoft Entra ID) resources" |
  | [`Sites.FullControl.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#sitesfullcontrolall) | both | "Have full control of all site collections" |
  | [`Mail.Send`](https://learn.microsoft.com/en-us/graph/permissions-reference#mailsend) | application | "Send mail as any user" |
  | [`Mail.ReadWrite`](https://learn.microsoft.com/en-us/graph/permissions-reference#mailreadwrite) | application | "Read and write mail in all mailboxes" |
  | [`Files.ReadWrite.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#filesreadwriteall) | application | "read, create, update and delete all files in all site collections" |

  The last three are application-only here because their delegated forms need no admin consent and
  are limited to the signed-in user. Names match case-insensitively but exactly: `<resource>/<scope>`
  from another API (G9) never matches. `User.ReadWrite.All` and `Group.ReadWrite.All` were left out
  to keep the list small, not because they are safe.
- **R15 [HEURISTIC] APL-005.** One finding per credential on a linked app, the first that applies:
  no expiry (medium, 0.8), expired (medium, 0.95), lifetime over 180 days (low, 0.95). Exactly 180
  days passes, and an expired credential is not also reported for lifetime. **Corrected:** the
  collector used to drop `startDateTime`, and turned an unparseable `endDateTime` into `None`, which
  would have read as "no expiry". It now keeps the start and records `end_unreadable`.
  Expiry is judged against `inventory.generated_at`; `run_scan(now=...)` fixes it so fixtures do not
  expire with the calendar. An empty list counts as "no credentials" only if Graph returned both
  lists on every object (`credentials_gap`). **No expiry:** `endDateTime` is documented as optional
  on passwordCredential; on keyCredential it is not marked either way. **Unverified** that Graph
  really returns null for it, as we have no tenant to check, so confidence is 0.8.
  Managed identities are skipped: Microsoft says their credentials are managed and rotated by Azure
  (seen in a search result for the page, not read in full). The 180-day limit is this project's
  policy, not a Microsoft or OWASP number.
  Sources: https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0 ,
  https://learn.microsoft.com/en-us/entra/architecture/service-accounts-managed-identities
- **R16 [HEURISTIC] APL-006.** A high-risk grant (R14) on a linked app needs an entry in a new
  optional agent.yaml mapping, `justifications: {permission: reason}`. Severity high: the brief set
  none, and the list holds only permissions the reference warns about or that reach a whole tenant.
  Confidence 0.95. The mapping is per agent, not per server, and matches names case-insensitively.
  A blank reason counts as none. A reason is not judged, so "because" passes. Without agent.yaml the
  rule is skipped, as justifications could not exist. An unresolved app role (G5) might be high-risk,
  so it is skipped by name, not passed. G10 applies: delegated grants count though a given token may
  not carry them. `required_graph_permissions` in agent.yaml is not a justification.
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
  Both also have `startDateTime`, which we keep for APL-005 (R15). `secretText` is returned only by
  the initial `addPassword` POST; `hint` holds the secret's first three characters. We copy neither,
  nor `key`. **We send no `$select`:** the list pages say selecting
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
  user-read rights other fields come back null, and names are personal data. `Application.Read.All`
  is the least-privileged permission for both (rechecked 2026-11-01). The docs do not say what 403
  or 404 means here; treating them as "not collected" is our reading (R13). An app registered in
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
  so they appear as skips. Per-user grants are warnings, not findings: no rule covers them yet. No
  owner became APL-004 (R13) and expired credentials became APL-005 (R15). `MCPServer.entra_apps` carries the linked
  apps to rules; it is excluded from any inventory dump, so owner ids stay out of output.
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
