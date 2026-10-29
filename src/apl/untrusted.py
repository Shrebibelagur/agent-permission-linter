"""Handling of untrusted text (MCP tool names/descriptions/output).

Such text is DATA. It is never interpreted as instructions. Before any LLM sees it,
it is wrapped in randomized delimiters; delimiter look-alikes inside are neutralized.
"""

from __future__ import annotations

import re
import secrets

from apl.redact import redact

MAX_LEN = 4000

_INJECTION_HINTS = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) instructions|you are now|system prompt|"
    r"<\s*/?\s*(system|instructions?)\s*>|disregard .{0,20}instructions|do not tell the user)"
)


def injection_suspected(text: str) -> bool:
    return bool(_INJECTION_HINTS.search(text or ""))


def wrap_untrusted(text: str | None, label: str = "mcp_tool_text") -> str:
    """Wrap untrusted text for inclusion in an LLM prompt."""
    body = redact(text or "")[:MAX_LEN]
    nonce = secrets.token_hex(8)
    body = body.replace("<<<", "‹‹‹").replace(">>>", "›››")
    return f"<<<UNTRUSTED {label} id={nonce}>>>\n{body}\n<<<END UNTRUSTED id={nonce}>>>"
