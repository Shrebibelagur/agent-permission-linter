"""Minimal JSONC loader (ASSUMPTION A10).

VS Code config files allow `//` and `/* */` comments and trailing commas. We blank those out
(comments become spaces, newlines are kept) so line/column numbers in errors still match the
original file, then hand the result to the stdlib JSON parser.

Errors never include file content - only positions - because configs can hold secrets.
"""

from __future__ import annotations

import json
from typing import Any


class JSONCError(ValueError):
    """Parse error carrying a position only, never file content."""

    def __init__(self, msg: str, lineno: int, colno: int):
        super().__init__(f"{msg} at line {lineno} col {colno}")
        self.lineno = lineno
        self.colno = colno


def _pos(text: str, idx: int) -> tuple[int, int]:
    line = text.count("\n", 0, idx) + 1
    return line, idx - (text.rfind("\n", 0, idx) + 1) + 1


def strip_jsonc(text: str) -> tuple[str, bool]:
    """Return (strict JSON text, whether any JSONC feature was removed)."""
    out = list(text)
    n = len(text)
    i = 0
    changed = False
    last_comma: int | None = None  # index of a comma with only whitespace/comments after it
    while i < n:
        c = text[i]
        if c == '"':
            last_comma = None
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                raise JSONCError("unterminated string", *_pos(text, n))
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            changed = True
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                raise JSONCError("unterminated block comment", *_pos(text, i))
            changed = True
            for j in range(i, end + 2):
                if out[j] not in "\r\n":
                    out[j] = " "
            i = end + 2
            continue
        if c == ",":
            last_comma = i
        elif c in "}]":
            if last_comma is not None:
                out[last_comma] = " "
                changed = True
            last_comma = None
        elif not c.isspace():
            last_comma = None
        i += 1
    return "".join(out), changed


def loads_jsonc(text: str) -> tuple[Any, bool]:
    """Parse JSON or JSONC. Returns (data, used_jsonc). Raises JSONCError (position only)."""
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        pass
    stripped, changed = strip_jsonc(text)
    try:
        return json.loads(stripped), changed
    except json.JSONDecodeError as e:
        raise JSONCError("invalid JSON", e.lineno, e.colno) from None
