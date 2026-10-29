"""Capability classifier.

Deterministic. Combines (a) tool-name verb heuristics and (b) MCP annotations.
Annotations are UNTRUSTED hints (MCP spec says clients must not rely on them for security
decisions from untrusted servers), so they can only ADD capabilities, never remove them:
a tool named `delete_repo` with readOnlyHint=true stays DELETE and is flagged as conflicting.
Descriptions are NOT used for classification (prompt-injection surface).
A name with no recognised verb is NOT guessed: it gets {UNKNOWN}, confidence 0 and a review flag.
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
        "terminate",
        "kill",
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
        "sql",
        "sudo",
        # Family: code evaluation and process/service lifecycle. These start, stop or replace
        # running code, which is execution whatever the target is.
        "evaluate",
        "launch",
        "start",
        "stop",
        "restart",
        "reboot",
        "kill",  # also delete: it ends a process
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
        "email",  # sending mail creates a message, like send/post
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
        # Family: verbs that move data across the network boundary, either outbound (send,
        # email, upload, post) or inbound. Outbound transfer is the exfiltration path, so these
        # also count as network, not just write.
        "send",
        "email",
        "upload",
        "post",
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

UNCLASSIFIED_FLAG = "unclassified: review required"

# Verbs that say "does many things": give the widest plausible set, at lower confidence.
_ALL_CONCRETE = frozenset(Capability) - {Capability.UNKNOWN}
_AMBIGUOUS_VERBS: dict[str, frozenset[Capability]] = {
    "manage": frozenset({Capability.READ, Capability.WRITE, Capability.DELETE}),
    "sync": frozenset({Capability.READ, Capability.WRITE}),
    # Family: composite verbs that name a multi-step job, not an operation. What they touch
    # depends on the implementation, so all of them get every concrete capability.
    **dict.fromkeys(
        ("migrate", "cleanup", "clean", "reset", "handle", "install", "uninstall"), _ALL_CONCRETE
    ),
}

# A query against a database usually means arbitrary SQL, not a fixed read.
_DB_NOUNS = frozenset({"database", "db", "sql", "sqlite", "postgres", "postgresql", "mysql"})

# Two-word nouns whose parts would otherwise match verbs ("request" -> network, "merge" -> write).
_COMPOUND_NOUNS: dict[tuple[str, str], str] = {
    ("pull", "request"): "pull_request",
    ("pull", "requests"): "pull_request",
    ("merge", "request"): "merge_request",
    ("merge", "requests"): "merge_request",
}

_SPLIT = re.compile(r"[_\-.\s/:]+|(?<=[a-z0-9])(?=[A-Z])")


def tokens(name: str) -> list[str]:
    return [t.lower() for t in _SPLIT.split(name) if t]


def _join_compounds(toks: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(toks):
        pair = tuple(toks[i : i + 2])
        if pair in _COMPOUND_NOUNS:
            out.append(_COMPOUND_NOUNS[pair])
            i += 2
        else:
            out.append(toks[i])
            i += 1
    return out


def classify_tool(tool: Tool) -> Tool:
    toks = _join_compounds(tokens(tool.name))
    caps: set[Capability] = set()
    reasons: list[str] = []
    for cap, verbs in _VERBS.items():
        hit = [t for t in toks if t in verbs]
        if hit:
            caps.add(cap)
            reasons.append(f"name token {hit[0]!r} -> {cap.value}")
    specific = bool(caps)
    ambiguous_hit = False
    for t in toks:
        if t in _AMBIGUOUS_VERBS:
            ambiguous_hit = True
            amb = _AMBIGUOUS_VERBS[t]
            caps |= amb
            reasons.append(
                f"ambiguous verb {t!r} -> widest plausible set "
                f"{sorted(c.value for c in amb)}"
            )
    if "query" in toks and _DB_NOUNS.intersection(toks) and Capability.EXECUTE not in caps:
        caps.add(Capability.EXECUTE)
        reasons.append("'query' on a database noun -> execute (may run arbitrary SQL)")

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

    review: list[str] = []
    if not caps:
        # No guess: a made-up default would look like a real classification. Surface it instead.
        caps = {Capability.UNKNOWN}
        reasons.append("no recognised verb -> unknown")
        review.append(UNCLASSIFIED_FLAG)
        confidence = 0.0
    elif not specific and ambiguous_hit:
        confidence = 0.5
    else:
        confidence = 0.9 if a is not None else 0.7

    return tool.model_copy(
        update={
            "capabilities": caps,
            "classification_reasons": reasons,
            "classification_confidence": confidence,
            "classification_flags": review,
            "annotation_defaults_unapplied": defaults,
            "annotation_flags": flags,
        }
    )
