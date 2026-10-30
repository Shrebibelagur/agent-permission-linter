"""Capability signals from a tool's `inputSchema` parameter names. ASSUMPTION C2.

Everything in a schema is UNTRUSTED server output: data to match against fixed vocabularies, never
instructions. Only property names are kept. Descriptions are scanned for injection markers and
dropped, and `default`/`enum` values are never read, because they can hold secrets.

A parameter is judged by its head noun, the last word of its name: `command_id` is an id and
`file_path` is a path.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from apl.models import Capability
from apl.redact import redact
from apl.untrusted import injection_suspected

C = Capability
MAX_PARAMETERS = 200
MAX_NODES = 1000
MAX_DEPTH = 6
MAX_NAME = 200

EXECUTE_PARAMS = frozenset({"command", "script", "code", "cmd", "shell"})
NETWORK_PARAMS = frozenset({"url", "uri", "endpoint", "host", "hostname", "webhook"})
PATH_PARAMS = frozenset({"path", "filepath", "file", "filename", "dir", "directory"})
DATABASE_PARAMS = frozenset({"query", "statement"})
CONTENT_PARAMS = frozenset({"content", "body", "data", "text", "payload"})
READ_PARAMS = frozenset({"id", "limit", "offset", "filter"})
DB_NOUNS = frozenset({"database", "db", "sql", "sqlite", "postgres", "postgresql", "mysql"})
# `zip_code` and `status_code` are not code. Only these qualifiers make `code` source code.
_CODE_QUALIFIERS = frozenset({"source", "python", "js", "javascript", "bash", "shell", "program"})

_SPLIT = re.compile(r"[_\-.\s/:]+|(?<=[a-z0-9])(?=[A-Z])")


def tokens(name: str) -> list[str]:
    return [t.lower() for t in _SPLIT.split(name) if t]


def extract_parameters(schema: Any) -> tuple[list[str], bool]:
    """(parameter names, injection suspected). Walks `properties` and array `items`, bounded."""
    names: dict[str, None] = {}
    suspected = False
    stack: list[tuple[Any, int]] = [(schema, 0)]
    visited = 0
    while stack and visited < MAX_NODES:
        node, depth = stack.pop()
        visited += 1
        if not isinstance(node, dict) or depth > MAX_DEPTH:
            continue
        for key in ("description", "title"):
            suspected = suspected or (
                isinstance(node.get(key), str) and injection_suspected(node[key])
            )
        props = node.get("properties")
        for name, sub in props.items() if isinstance(props, dict) else ():
            suspected = suspected or injection_suspected(name)
            if len(names) < MAX_PARAMETERS:
                names[redact(name)[:MAX_NAME]] = None
            stack.append((sub, depth + 1))
        stack.append((node.get("items"), depth + 1))
    return list(names), suspected


@dataclass(frozen=True)
class SchemaSignals:
    """`strong` maps a capability to the vocabulary word that showed it. `weak_read` is a word that
    fits a read but says nothing against a write: `update_issue(id)` is not a conflict.
    `weak_write` is a generic data word: `search_docs(text)` mostly does not write. See C2."""

    strong: dict[Capability, str] = field(default_factory=dict)
    weak_read: str | None = None
    weak_write: str | None = None

    def __bool__(self) -> bool:
        return bool(self.strong) or self.weak_read is not None or self.weak_write is not None


def _head(parameter: str) -> tuple[str, list[str]]:
    words = tokens(parameter)
    if not words:
        return "", []
    head = words[-1]
    known = EXECUTE_PARAMS | NETWORK_PARAMS | PATH_PARAMS | DATABASE_PARAMS | CONTENT_PARAMS
    known |= READ_PARAMS
    if head.endswith("s") and head not in known and head[:-1] in known:
        head = head[:-1]
    return head, words[:-1]


def _is_code(head: str, qualifiers: list[str]) -> bool:
    return head != "code" or not qualifiers or qualifiers[-1] in _CODE_QUALIFIERS


def schema_signals(
    parameters: Iterable[str], name_tokens: Iterable[str], name_caps: set[Capability]
) -> SchemaSignals:
    """Match parameter names against the vocabularies. Returned words are ours, so no untrusted
    parameter name reaches a reason string."""
    heads = [_head(p) for p in parameters]
    words = set(name_tokens) | {w for h, q in heads for w in (h, *q)}
    on_database = bool(words & DB_NOUNS)
    strong: dict[Capability, str] = {}
    weak_read: str | None = None
    weak_write: str | None = None
    for head, qualifiers in heads:
        if head in EXECUTE_PARAMS and _is_code(head, qualifiers):
            strong.setdefault(C.EXECUTE, head)
        elif head == "sql" or (head in DATABASE_PARAMS and on_database):
            strong.setdefault(C.EXECUTE, head)
        elif head in NETWORK_PARAMS:
            strong.setdefault(C.NETWORK, head)
        elif head in CONTENT_PARAMS:
            weak_write = weak_write or head
        elif head in PATH_PARAMS:
            if C.WRITE in name_caps:
                strong.setdefault(C.WRITE, head)
            else:
                weak_read = weak_read or head
        elif head in READ_PARAMS or head == "query":
            weak_read = weak_read or head
    return SchemaSignals(strong, weak_read, weak_write)
