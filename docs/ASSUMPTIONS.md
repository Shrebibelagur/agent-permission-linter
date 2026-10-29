# Assumptions — MCP config formats and MCP spec (2026-07-28)

Status key: **[CLIENT]** = client convention, not in the MCP spec · **[SPEC]** = based on the spec,
check against the schema · **[HEURISTIC]** = our design choice · **[UNVERIFIED]** = not yet checked
against primary source. Code comments cite the IDs below as `ASSUMPTION Ax`.

## Config file formats (none of this is defined by the MCP spec)

- **A1 [CLIENT]** The MCP spec covers the wire protocol only. It does **not** define a client config
  file format, so every config shape we parse is a client convention that can change without notice.
- **A2 [CLIENT][UNVERIFIED]** Claude Desktop, Claude Code (`.mcp.json`), Cursor and Windsurf all use
  top-level `mcpServers: {name: {command, args, env}}`. Remote entries use `url`, plus `headers`
  where the client supports them. We have not checked each client's current docs.
- **A3 [CLIENT][UNVERIFIED]** VS Code `.vscode/mcp.json` uses top-level `servers` plus an optional
  `inputs` array. Each entry has `type: stdio|http|sse`. In VS Code `settings.json` the same object
  sits under `mcp.servers`.
- **A4 [CLIENT]** `${env:VAR}` and `${input:id}` are VS Code substitution syntax. `${VAR}` / `$VAR`
  are treated as env references for the other clients. Some clients may not expand these and may
  pass them through literally. If so, the value is a literal (non-secret) string, so treating it as
  a reference is still safe.
- **A5 [CLIENT]** `windsurf` uses `serverUrl` instead of `url`. We accept both. **[UNVERIFIED]**
- **A6 [HEURISTIC]** If an entry has `url` but no `type`, we assume Streamable HTTP, not legacy SSE.
  If it has `command` but no `type`, we assume stdio.
- **A7 [CLIENT]** `disabled: true` means the client will not start the server. We keep the server
  in the inventory and mark it disabled. Its credentials still exist on disk.
- **A8 [HEURISTIC]** Credential kind comes from the env var or header *name* (e.g.
  `*_PERSONAL_ACCESS_TOKEN` is a PAT and `*CLIENT_SECRET` is a service principal). Names can mislead.
  Phase 3 (Entra) confirms the real identity where an app ID is known.
- **A9 [HEURISTIC]** `AZURE_CLIENT_ID` / `CLIENT_ID` values are identifiers, not secrets. We keep
  them so we can link to Entra. Tenant IDs are kept too.
- **A10 [HEURISTIC]** Configs are strict JSON. JSONC (comments or trailing commas, which VS Code
  allows) currently fails to parse with a clear error. **Known gap.**

## MCP protocol (spec 2026-07-28)

- **S1 [SPEC]** 2026-07-28 is the current spec version. It made the core stateless, removed the
  `initialize` handshake and `Mcp-Session-Id`, and added `server/discover`. This only matters once
  `--connect` exists (not in v0.1). The offline parser does not depend on it.
- **S2 [SPEC]** Transports are stdio and Streamable HTTP. Legacy HTTP+SSE is **Deprecated** under
  the new lifecycle policy, and we emit a warning when we see it.
- **S3 [SPEC][UNVERIFIED]** A `tools/list` result is `{tools: [{name, description?, inputSchema,
  annotations?, ...}]}`. We read only `name`, `description` and `annotations`, and ignore unknown
  fields. We have not diffed this against the 2026-07-28 `schema.ts`. Cacheable list results and
  pagination (`nextCursor`) are ignored: offline files are assumed to contain the full list.
- **S4 [SPEC][UNVERIFIED]** The tool annotations are `readOnlyHint`, `destructiveHint`,
  `idempotentHint` and `openWorldHint`. The spec says clients should treat them as untrusted hints
  from untrusted servers. We assume no annotation was added or renamed in 2026-07-28.
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
