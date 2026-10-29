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
  (reserved for Phase 3; not set anywhere yet).
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
  It does not measure accuracy on unseen names.
