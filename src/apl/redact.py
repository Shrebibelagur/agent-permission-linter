"""Secret redaction. Applied to every string that leaves a parser."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***REDACTED***"

# Known token shapes. Conservative: false positives are fine, leaks are not.
_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"),  # OpenAI / Anthropic
    re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}"),  # Slack
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),  # Google API key
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),  # JWT
    re.compile(r"[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{31,}"),  # Entra client secret
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-.=]{8,}"),
]

_GUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")

_MIN_MASKED = 12  # a shorter value would be mostly shown anyway; Graph ids are 36-char GUIDs

_known_secrets: set[str] = set()
_MIN_KNOWN_SECRET = 8  # a shorter value would scrub ordinary text; Entra secrets are 16+ chars

SECRETY_KEY = re.compile(
    r"(?i)(secret|token|password|passwd|pwd|api[_-]?key|apikey|auth|credential|private[_-]?key)"
)
_ARG_KV = re.compile(r"(?i)^(--?[\w-]*(?:token|secret|key|password|auth)[\w-]*)=(.+)$")
# ASSUMPTION A2/A4/A5: `${VAR}`, `$VAR`, `${env:VAR}`, `${input:id}`,
# `${VAR:-default}` (Claude Code), `${file:/path}` (Windsurf).
_ENV_REF = re.compile(
    r"^(?:(?i:bearer|token|basic)\s+)?"
    r"(?:\$\{file:(?P<path>[^}\s]+)\}"
    r"|\$\{(?P<kind>env:|input:)?(?P<n1>[A-Za-z0-9_.\-]+)(?::-(?P<default>[^}]*))?\}"
    r"|\$(?P<n2>[A-Za-z_][A-Za-z0-9_]*))$"
)


def mask_id(guid: str) -> str:
    """`a1a1...0001`: enough to tell ids apart in a report, not enough to look one up."""
    return f"{guid[:4]}...{guid[-4:]}" if len(guid) > _MIN_MASKED else guid


def mask_ids(text: str) -> str:
    """Mask every GUID. Report-level only: `redact()` runs on ingest, where ids are join keys."""
    return _GUID.sub(lambda m: mask_id(m.group()), text)


def looks_like_secret(value: str) -> bool:
    return any(p.search(value) for p in _PATTERNS)


def is_env_reference(value: str) -> bool:
    """`${VAR}`, `$VAR`, `${env:VAR}`, `${input:id}` (VS Code), `${VAR:-default}`, `${file:/path}`,
    optionally `Bearer `-prefixed.

    A pointer to a secret, not a secret itself. A `:-` default that looks like a token is a
    hardcoded secret, so such a value is NOT a reference.
    """
    m = _ENV_REF.match(value.strip())
    return bool(m) and not looks_like_secret(m.group("default") or "")


def env_reference_default(value: str) -> str | None:
    """The literal fallback in `${VAR:-default}`, or None. May itself be a secret: never output."""
    m = _ENV_REF.match(value.strip())
    return m.group("default") if m else None


def env_reference_name(value: str) -> str | None:
    """Return the referenced name; `input:`/`file:` refs keep their prefix (`file:<path>`)."""
    m = _ENV_REF.match(value.strip())
    if not m:
        return None
    if m.group("n2"):
        return m.group("n2")
    if m.group("path"):
        return "file:" + m.group("path")
    return ("input:" if m.group("kind") == "input:" else "") + m.group("n1")


def remember_secret(value: str) -> None:
    """Scrub this exact value everywhere from now on. For secrets we hold that may have no known
    shape (client secret, access token). Process memory only; never written anywhere."""
    if len(value) >= _MIN_KNOWN_SECRET:
        _known_secrets.add(value)


def redact(value: str) -> str:
    out = value
    for known in sorted(_known_secrets, key=len, reverse=True):
        out = out.replace(known, REDACTED)
    for p in _PATTERNS:
        out = p.sub(REDACTED, out)
    return out


def redact_obj(obj: Any) -> Any:
    """Redact every string (keys and values) in a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {redact_obj(k): redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [redact_obj(v) for v in obj]
    return obj


def redact_url(url: str) -> str:
    """Drop userinfo and query string (tokens commonly ride there)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    query = REDACTED if parts.query else ""
    return redact(urlunsplit((parts.scheme, netloc, parts.path, query, "")))


def is_clean_reference(value: str) -> bool:
    """A reference with no literal fallback. Use where the value sits in a secret slot: there a
    `${VAR:-fallback}` default is a hardcoded secret even if it does not look like a token."""
    return is_env_reference(value) and not env_reference_default(value)


def redact_args(args: list[str]) -> tuple[list[str], bool]:
    """Returns (redacted args, whether an inline secret was found)."""
    found = False
    out: list[str] = []
    prev_flag_secret = False
    for a in args:
        if prev_flag_secret and not a.startswith("-"):
            found = found or not is_clean_reference(a)
            out.append(a if is_clean_reference(a) else REDACTED)
            prev_flag_secret = False
            continue
        m = _ARG_KV.match(a)
        if m:
            if not is_clean_reference(m.group(2)):
                found = True
                out.append(f"{m.group(1)}={REDACTED}")
            else:
                out.append(a)
            continue
        prev_flag_secret = a.startswith("-") and bool(SECRETY_KEY.search(a))
        r = redact(a)
        found = found or (r != a)
        out.append(r)
    return out, found
