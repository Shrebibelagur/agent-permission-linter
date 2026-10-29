"""MCP client configuration parsers.

These parse STATIC config files only. They never launch a server or open a connection.
Supported shapes (see docs/ASSUMPTIONS.md - these are client conventions, NOT MCP spec):

  * Claude Desktop / Claude Code / Cursor / Windsurf: {"mcpServers": {name: {...}}}
  * VS Code (.vscode/mcp.json):                       {"servers": {name: {...}}, "inputs": [...]}
  * VS Code settings.json:                            {"mcp": {"servers": {...}}}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from apl.models import CredentialKind, CredentialRef, Evidence, MCPServer, Transport
from apl.parsers.jsonc import JSONCError, loads_jsonc
from apl.redact import (
    SECRETY_KEY,
    env_reference_default,
    env_reference_name,
    is_clean_reference,
    is_env_reference,
    looks_like_secret,
    redact,
    redact_args,
    redact_url,
)


class ConfigParseError(ValueError):
    pass


# Env-var / header name hints -> credential kind. Heuristic; flagged as such in evidence.
_KIND_HINTS: list[tuple[str, CredentialKind]] = [
    ("PERSONAL_ACCESS_TOKEN", CredentialKind.PAT),
    ("_PAT", CredentialKind.PAT),
    ("CLIENT_SECRET", CredentialKind.SERVICE_PRINCIPAL),
    ("CLIENT_CERT", CredentialKind.SERVICE_PRINCIPAL),
    ("AZURE_CLIENT_ID", CredentialKind.SERVICE_PRINCIPAL),
    ("MANAGED_IDENTITY", CredentialKind.MANAGED_IDENTITY),
    ("OAUTH", CredentialKind.OAUTH_APP),
    ("REFRESH_TOKEN", CredentialKind.USER_DELEGATED),
    ("API_KEY", CredentialKind.API_KEY),
    ("APIKEY", CredentialKind.API_KEY),
    ("BOT_TOKEN", CredentialKind.API_KEY),
    ("TOKEN", CredentialKind.API_KEY),
    ("AUTHORIZATION", CredentialKind.API_KEY),
]


_CLIENT_ID_KEYS = {"AZURE_CLIENT_ID", "CLIENT_ID", "ENTRA_CLIENT_ID", "MS_CLIENT_ID"}


def _guess_kind(name: str) -> CredentialKind:
    up = name.upper()
    for hint, kind in _KIND_HINTS:
        if hint in up:
            return kind
    return CredentialKind.UNKNOWN


def _locate_servers(data: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    if isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"], "mcpServers", "/mcpServers"
    if isinstance(data.get("servers"), dict):
        return data["servers"], "vscode", "/servers"
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"], "vscode-settings", "/mcp/servers"
    raise ConfigParseError("no 'mcpServers', 'servers', or 'mcp.servers' object found")


def _transport(entry: dict[str, Any]) -> Transport:
    t = str(entry.get("type") or entry.get("transport") or "").lower()
    if t == "stdio":
        return Transport.STDIO
    if t in {"http", "streamable-http", "streamablehttp"}:
        return Transport.HTTP
    if t == "sse":
        return Transport.SSE
    if entry.get("command"):
        return Transport.STDIO
    if entry.get("url") or entry.get("serverUrl"):
        return Transport.HTTP  # ASSUMPTION A6: url without type => Streamable HTTP
    return Transport.UNKNOWN


def _cred_from_value(name: str, value: Any, *, header: bool, ev: Evidence) -> CredentialRef | None:
    sval = str(value) if value is not None else ""
    secret_name = bool(SECRETY_KEY.search(name)) or (header and name.lower() == "authorization")
    # In a secret slot, `${VAR:-fallback}` carries a hardcoded fallback secret.
    is_ref = is_clean_reference(sval) if secret_name else is_env_reference(sval)
    inline = bool(sval) and not is_ref and (secret_name or looks_like_secret(sval))
    if not (secret_name or inline):
        return None
    note = "kind inferred from name (heuristic)"
    if inline and env_reference_default(sval):
        note += "; literal fallback in ${VAR:-...} reference"
    env_var = None
    if is_env_reference(sval):
        env_var = env_reference_name(sval)
    elif not header:
        env_var = name
    kind = _guess_kind(name)
    return CredentialRef(
        kind=kind,
        kind_source="unknown" if kind is CredentialKind.UNKNOWN else "inferred",
        env_var=env_var,
        header=name if header else None,
        inline_secret_detected=inline,
        evidence=ev.model_copy(update={"note": note}),
    )


def _auto_approve(
    entry: dict[str, Any], where: str, ptr: str, warnings: list[str]
) -> tuple[list[str] | None, str | None]:
    """ASSUMPTION R7: Cline `autoApprove` / Roo Code `alwaysAllow` = tools run without asking."""
    for key in ("autoApprove", "alwaysAllow"):
        if key not in entry:
            continue
        value = entry[key]
        if not isinstance(value, list):
            warnings.append(f"{where}/{key}: not a list; auto-approve not evaluated")
            return None, None
        names = [redact(v)[:200] for v in value if isinstance(v, str)]
        return names, f"{ptr}/{key}"
    return None, None


def parse_config_dict(data: dict[str, Any], source: str) -> tuple[list[MCPServer], list[str]]:
    servers_obj, fmt, base_ptr = _locate_servers(data)
    servers: list[MCPServer] = []
    warnings: list[str] = []
    # ASSUMPTION A3: settings.json `mcp.servers` is not in current official VS Code docs.
    format_status = "unverified" if fmt == "vscode-settings" else "verified"
    if format_status == "unverified":
        warnings.append(
            f"{source}{base_ptr}: unverified format (VS Code settings.json 'mcp.servers' is not "
            "in current official docs); results may be incomplete"
        )
    for name, entry in servers_obj.items():
        ptr = f"{base_ptr}/{name}"
        if not isinstance(entry, dict):
            warnings.append(f"{source}{ptr}: entry is not an object; skipped")
            continue
        ev = Evidence(source=source, pointer=ptr)
        args, inline_in_args = redact_args([str(a) for a in entry.get("args") or []])
        creds: list[CredentialRef] = []
        env = entry.get("env") or {}
        for k, v in env.items():
            c = _cred_from_value(
                k, v, header=False, ev=ev.model_copy(update={"pointer": f"{ptr}/env/{k}"})
            )
            if c:
                creds.append(c)
        for k, v in (entry.get("headers") or {}).items():
            c = _cred_from_value(
                k, v, header=True, ev=ev.model_copy(update={"pointer": f"{ptr}/headers/{k}"})
            )
            if c:
                creds.append(c)
        if inline_in_args:
            creds.append(
                CredentialRef(
                    kind=CredentialKind.UNKNOWN,
                    inline_secret_detected=True,
                    evidence=ev.model_copy(
                        update={"pointer": f"{ptr}/args", "note": "secret in argv"}
                    ),
                )
            )
        # Client IDs are identifiers, not secrets: keep the value so Phase 3 can link to Entra.
        for k, v in env.items():
            if k.upper() in _CLIENT_ID_KEYS and isinstance(v, str) and not is_env_reference(v):
                creds.append(
                    CredentialRef(
                        kind=CredentialKind.SERVICE_PRINCIPAL,
                        kind_source="inferred",
                        env_var=k,
                        entra_app_id=v,
                        evidence=ev.model_copy(
                            update={
                                "pointer": f"{ptr}/env/{k}",
                                "note": "app/client id (heuristic)",
                            }
                        ),
                    )
                )
        url = entry.get("url") or entry.get("serverUrl")
        if url and "?" in str(url) and looks_like_secret(str(url)):
            creds.append(
                CredentialRef(
                    kind=CredentialKind.API_KEY,
                    kind_source="inferred",
                    inline_secret_detected=True,
                    evidence=ev.model_copy(
                        update={"pointer": f"{ptr}/url", "note": "secret in URL"}
                    ),
                )
            )
        transport = _transport(entry)
        if transport is Transport.SSE:
            warnings.append(f"{name}: legacy HTTP+SSE transport (deprecated in MCP 2026-07-28)")
        server_ev = ev
        no_type = not (entry.get("type") or entry.get("transport"))
        if entry.get("url") and not entry.get("command") and no_type:
            # ASSUMPTION A6: parsed as Streamable HTTP, but never silently. Windsurf's `serverUrl`
            # without a type is its documented form, so only `url` is warned on.
            warnings.append(
                f"{source}{ptr}: url entry has no 'type'; assumed Streamable HTTP. "
                "Claude Code treats this as a configuration error"
            )
            server_ev = ev.model_copy(update={"note": "transport assumed http: no 'type' (A6)"})
        auto_approve, aa_ptr = _auto_approve(entry, f"{source}{ptr}", ptr, warnings)
        servers.append(
            MCPServer(
                name=name,
                transport=transport,
                command=redact(str(entry["command"])) if entry.get("command") else None,
                args=args,
                url=redact_url(str(url)) if url else None,
                env_keys=sorted(env.keys()),
                credentials=creds,
                auto_approve=auto_approve,
                auto_approve_pointer=aa_ptr,
                disabled=bool(entry.get("disabled", False)),
                source_format=fmt,
                format_status=format_status,
                evidence=server_ev,
            )
        )
    return servers, warnings


def parse_config_file(path: Path) -> tuple[list[MCPServer], list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigParseError(f"cannot read {path}: {e.strerror}") from None
    try:
        # ASSUMPTION A10: accept JSONC (comments, trailing commas) as VS Code does.
        data, used_jsonc = loads_jsonc(text)
    except JSONCError as e:
        # Do not echo file content - it may contain secrets.
        raise ConfigParseError(f"{path}: {e}") from None
    if not isinstance(data, dict):
        raise ConfigParseError(f"{path}: top level must be an object")
    servers, warnings = parse_config_dict(data, str(path))
    if used_jsonc and servers and servers[0].source_format == "mcpServers":
        warnings.append(f"{path}: uses JSONC comments/trailing commas; client may need strict JSON")
    return servers, warnings
