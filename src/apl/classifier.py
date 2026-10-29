"""Capability classifier.

Deterministic. Combines (a) tool-name verb heuristics and (b) MCP annotations.
Annotations are UNTRUSTED hints (MCP spec says clients must not rely on them for security
decisions from untrusted servers), so they can only ADD capabilities, never remove them:
a tool named `delete_repo` with readOnlyHint=true stays DELETE and is flagged as conflicting.
Descriptions are NOT used for classification (prompt-injection surface).
"""

from __future__ import annotations

import re

from apl.models import Capability, Tool

_VERBS: dict[Capability, tuple[str, ...]] = {
    Capability.DELETE: (
        "delete",
        "remove",
        "destroy",
        "drop",
        "purge",
        "truncate",
        "erase",
        "revoke",
        "archive",
        "wipe",
        "rm",
        "unlink",
    ),
    Capability.EXECUTE: (
        "exec",
        "execute",
        "run",
        "shell",
        "eval",
        "spawn",
        "invoke",
        "deploy",
        "bash",
        "cmd",
        "terminal",
        "script",
        "trigger",
        "dispatch",
        "query_sql",
        "sql",
    ),
    Capability.WRITE: (
        "create",
        "update",
        "write",
        "edit",
        "set",
        "put",
        "post",
        "patch",
        "add",
        "insert",
        "upload",
        "send",
        "commit",
        "push",
        "merge",
        "move",
        "rename",
        "assign",
        "grant",
        "approve",
        "close",
        "comment",
        "reply",
        "modify",
        "save",
        "fork",
        "transfer",
        "invite",
        "publish",
    ),
    Capability.NETWORK: (
        "fetch",
        "http",
        "request",
        "browse",
        "navigate",
        "download",
        "curl",
        "webhook",
        "url",
        "scrape",
        "crawl",
        "web",
    ),
    Capability.READ: (
        "get",
        "list",
        "read",
        "search",
        "find",
        "query",
        "describe",
        "show",
        "view",
        "lookup",
        "fetch",
        "download",
        "count",
        "check",
        "inspect",
    ),
}

# Defaults from ToolAnnotations in the 2026-07-28 schema.ts (ASSUMPTION S4).
SPEC_ANNOTATION_DEFAULTS: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}
_ANN_ATTR = {
    "readOnlyHint": "read_only_hint",
    "destructiveHint": "destructive_hint",
    "idempotentHint": "idempotent_hint",
    "openWorldHint": "open_world_hint",
}

_SPLIT = re.compile(r"[_\-.\s/:]+|(?<=[a-z0-9])(?=[A-Z])")


def tokens(name: str) -> list[str]:
    return [t.lower() for t in _SPLIT.split(name) if t]


def classify_tool(tool: Tool) -> Tool:
    toks = tokens(tool.name)
    caps: set[Capability] = set()
    reasons: list[str] = []
    for cap, verbs in _VERBS.items():
        hit = [t for t in toks if t in verbs]
        if hit:
            caps.add(cap)
            reasons.append(f"name token {hit[0]!r} -> {cap.value}")

    a = tool.annotations
    defaults = {
        k: v
        for k, v in SPEC_ANNOTATION_DEFAULTS.items()
        if a is None or getattr(a, _ANN_ATTR[k]) is None
    }
    flags: list[str] = []
    if a is not None and a.read_only_hint is True and a.destructive_hint is True:
        # Spec: destructiveHint is only meaningful when readOnlyHint is false.
        flags.append("readOnlyHint=true and destructiveHint=true are contradictory")
        reasons.append("CONFLICT: readOnlyHint=true with destructiveHint=true")
    if a is not None:
        if a.destructive_hint is True:
            caps.add(Capability.DELETE)
            reasons.append("annotation destructiveHint=true -> delete")
        if a.read_only_hint is False:
            if not caps & {Capability.WRITE, Capability.DELETE, Capability.EXECUTE}:
                caps.add(Capability.WRITE)
                reasons.append("annotation readOnlyHint=false -> write")
        if a.open_world_hint is True:
            caps.add(Capability.NETWORK)
            reasons.append("annotation openWorldHint=true -> network")
        if a.read_only_hint is True and caps & {
            Capability.WRITE,
            Capability.DELETE,
            Capability.EXECUTE,
        }:
            reasons.append("CONFLICT: readOnlyHint=true contradicts name; annotation ignored")

    if not caps:
        # Unknown verb: assume worst plausible non-exec case rather than "safe".
        caps = {Capability.READ, Capability.WRITE}
        reasons.append("no recognised verb -> assume read+write (conservative)")
        confidence = 0.3
    else:
        confidence = 0.9 if a is not None else 0.7

    return tool.model_copy(
        update={
            "capabilities": caps,
            "classification_reasons": reasons,
            "classification_confidence": confidence,
            "annotation_defaults_unapplied": defaults,
            "annotation_flags": flags,
        }
    )
