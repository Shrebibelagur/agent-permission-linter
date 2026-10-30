"""Capability classifier.

Deterministic. Combines (a) tool-name verb heuristics, (b) MCP annotations and (c) inputSchema
parameter names (ASSUMPTION C2).
Annotations and schemas are UNTRUSTED (MCP spec says clients must not rely on annotations for
security decisions from untrusted servers), so they can only ADD capabilities, never remove them:
a tool named `delete_repo` with readOnlyHint=true stays DELETE and is flagged as conflicting.
Descriptions are NOT used for classification (prompt-injection surface).
A name with no recognised verb is NOT guessed: it gets {UNKNOWN}, confidence 0 and a review flag.
"""

from __future__ import annotations

from apl.models import Capability, Tool
from apl.schema_signals import DB_NOUNS, schema_signals, tokens

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
        "notify",
        "broadcast",
        "relay",
        "forward",
    ),
    Capability.NETWORK: (
        "fetch",
        "http",
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
        "publish",
        "push",
        "notify",
        "broadcast",
        "relay",
        "forward",
        "subscribe",  # inbound, so network only
        "ping",  # reachability only, so network only
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
        "browse",  # network only with web vocabulary or a url/host parameter
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

CONFLICT_FLAG = "name/schema conflict"
SCHEMA_ONLY_FLAG = "schema only: review required"
WEAK_WRITE_FLAG = "weak write signal: review required"
# Rules stop convicting at confidence <= 0.5 (rules.base.LOW_CONFIDENCE). A schema is written by
# the server, so a conflict must stay above that line: otherwise adding a `content` parameter
# would turn a `delete_repo` violation into a low-severity review. A schema also cannot lift a
# low-confidence tool over the line, or win a tool with an unknown name a hard verdict.
# A weak write sits at the line on purpose, but only on a read-only name with no strong signal:
# anywhere else lowering confidence would soften a verdict the name or a strong signal earned.
_CONFLICT_CONFIDENCE = 0.6
_SCHEMA_ONLY_CONFIDENCE = 0.5
_WEAK_WRITE_CONFIDENCE = 0.5
_UNCERTAIN_BELOW = 0.5
_AGREE_BONUS = 0.1
_MAX_CONFIDENCE = 0.95

# `run_report` usually reads, but "run" means this could still execute something. Execute stays
# (a missed capability is the dangerous error) and low confidence sends it to a human.
_READ_LEANING_RUN_NOUNS = frozenset({"query", "queries", "report", "reports", "search", "searches"})

# `browse_catalog` is a read. These words make it a web browse; http, web and url already match.
_WEB_WORDS = frozenset({"website", "webpage", "internet"})

# "request" alone is a work item as often as a network call (approve_request, change_request).
# It counts as network only straight after one of these.
_REQUEST_WORDS = frozenset({"request", "requests"})
_NETWORK_QUALIFIERS = frozenset(
    {"http", "https", "api", "web", "network", "rest", "graphql", "ajax", "url", "remote"}
)

# Two-word nouns whose parts would otherwise match verbs ("merge" -> write).
_COMPOUND_NOUNS: dict[tuple[str, str], str] = {
    ("pull", "request"): "pull_request",
    ("pull", "requests"): "pull_request",
    ("merge", "request"): "merge_request",
    ("merge", "requests"): "merge_request",
}


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


def _schema_reasons(found: dict[Capability, str]) -> list[str]:
    return [f"schema parameter {word!r} -> {cap.value}" for cap, word in found.items()]


def classify_tool(tool: Tool) -> Tool:
    toks = _join_compounds(tokens(tool.name))
    caps: set[Capability] = set()
    reasons: list[str] = []
    for cap, verbs in _VERBS.items():
        hit = [t for t in toks if t in verbs]
        if hit:
            caps.add(cap)
            reasons.append(f"name token {hit[0]!r} -> {cap.value}")
    for before, word in zip(toks, toks[1:], strict=False):
        if word in _REQUEST_WORDS and before in _NETWORK_QUALIFIERS:
            caps.add(Capability.NETWORK)
            reasons.append(f"name compound '{before} {word}' -> network")
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
    read_leaning = not DB_NOUNS.intersection(toks) and any(
        verb == "run" and noun in _READ_LEANING_RUN_NOUNS
        for verb, noun in zip(toks, toks[1:], strict=False)
    )
    if read_leaning:
        caps.add(Capability.READ)
        reasons.append("'run' on a query/report/search: read-leaning, execute kept, low confidence")
    if "query" in toks and DB_NOUNS.intersection(toks) and Capability.EXECUTE not in caps:
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

    signals = schema_signals(tool.parameters, toks, caps)
    if "browse" in toks and Capability.NETWORK not in caps:
        web_word = next(iter(_WEB_WORDS.intersection(toks)), None)
        if web_word or Capability.NETWORK in signals.strong:
            caps.add(Capability.NETWORK)
            reasons.append(f"'browse' with {web_word or 'a url/host parameter'!r} -> network")
    review: list[str] = []
    if not caps:
        # No guess: a made-up default would look like a real classification. Surface it instead.
        caps = {Capability.UNKNOWN}
        reasons.append("no recognised verb -> unknown")
        confidence = 0.0
        found = dict(signals.strong)
        if signals.weak_write:
            found.setdefault(Capability.WRITE, signals.weak_write)
        if found:
            # Only adds: UNKNOWN stays, so rules keep treating the tool as unreviewed. A read-only
            # schema adds nothing, like a readOnlyHint: it cannot make an unknown tool look safe.
            caps |= set(found)
            reasons += _schema_reasons(found)
            review.append(SCHEMA_ONLY_FLAG)
            confidence = _SCHEMA_ONLY_CONFIDENCE
        else:
            review.append(UNCLASSIFIED_FLAG)
    else:
        confidence = 0.9 if a is not None else 0.7
        if read_leaning or (not specific and ambiguous_hit):
            confidence = 0.5
        beyond_name = set(signals.strong) - caps
        if beyond_name:
            caps |= beyond_name
            reasons += _schema_reasons({c: signals.strong[c] for c in beyond_name})
            reasons.append("CONFLICT: schema shows more than the name; widest set kept")
            review.append(CONFLICT_FLAG)
            confidence = min(confidence, _CONFLICT_CONFIDENCE)
        elif signals.weak_write and caps == {Capability.READ}:
            caps.add(Capability.WRITE)
            reasons.append(f"weak schema parameter {signals.weak_write!r} -> write, low confidence")
            review.append(WEAK_WRITE_FLAG)
            confidence = min(confidence, _WEAK_WRITE_CONFIDENCE)
        elif (
            signals.strong
            or (signals.weak_read and Capability.READ in caps)
            or (signals.weak_write and Capability.WRITE in caps)
        ):
            reasons.append("schema agrees with the name")
            if confidence > _UNCERTAIN_BELOW:
                confidence = min(confidence + _AGREE_BONUS, _MAX_CONFIDENCE)

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
