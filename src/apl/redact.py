"""Secret redaction. Applied to every string that leaves a parser."""

from __future__ import annotations

import logging
import math
import re
import traceback
from collections import Counter
from itertools import pairwise
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from apl.idmask import mask, mask_known

REDACTED = "[REDACTED]"  # secrets are removed outright: never hashed, never a pseudonym

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

MIN_TOKEN_CHARS = 20
MIN_TOKEN_ENTROPY = 3.8  # bits per character; 20 distinct characters reach 4.3
MIN_KIND_CHANGES = 0.3  # share of steps moving between upper, lower and digit; camelCase is lower
_TOKEN = re.compile(rf"[A-Za-z0-9_+~\-]{{{MIN_TOKEN_CHARS},}}")

PATH_REDACTED = "[path-redacted]"
# Any scheme but file: SARIF artifact uris are local paths the reader already has.
_URL = re.compile(r"(?i)\b(?!file://)([a-z][a-z0-9+.\-]*)://([^\s\"'`<>|\\)]+)")
# Exact hosts only. Our own references and $schema, and Graph, whose paths idmask has handled.
_TRUSTED_URL_HOSTS = frozenset(
    {
        "learn.microsoft.com",
        "owasp.org",
        "genai.owasp.org",
        "json.schemastore.org",
        "graph.microsoft.com",
        "login.microsoftonline.com",
    }
)
_show_urls = False

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


def _looks_random(token: str) -> bool:
    """R22. All three must hold, as each alone fires on ordinary long names."""
    if not (
        any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and any(c.isdigit() for c in token)
    ):
        return False
    size = len(token)
    entropy = -sum(n / size * math.log2(n / size) for n in Counter(token).values())
    if entropy < MIN_TOKEN_ENTROPY:
        return False
    kinds = ["u" if c.isupper() else "l" if c.islower() else "d" for c in token if c.isalnum()]
    changes = sum(a != b for a, b in pairwise(kinds))
    return changes / size >= MIN_KIND_CHANGES


def redact_random_tokens(value: str) -> str:
    """Tokens are cut at separators, so a path or version keeps everything but the random part."""
    return _TOKEN.sub(lambda m: REDACTED if _looks_random(m.group()) else m.group(), value)


def remember_secret(value: str) -> None:
    """Scrub this exact value everywhere from now on. For secrets we hold that may have no known
    shape (client secret, access token). Process memory only; never written anywhere."""
    if len(value) >= _MIN_KNOWN_SECRET:
        _known_secrets.add(value)


def remove_secrets(value: str) -> str:
    out = value
    for known in sorted(_known_secrets, key=len, reverse=True):
        out = out.replace(known, REDACTED)
    for p in _PATTERNS:
        out = p.sub(REDACTED, out)
    return out


def redact(value: str) -> str:
    """Secrets go first and always. Then the exact identifiers we hold (tenant and client id,
    and any linked object), which get a pseudonym unless --show-ids is on."""
    return mask_known(remove_secrets(value))


def showing_urls() -> bool:
    return _show_urls


def set_show_urls(on: bool) -> None:
    global _show_urls
    _show_urls = on


def _short_url(match: re.Match[str]) -> str:
    scheme, rest = match.group(1), match.group(2)
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = authority.rsplit("@", 1)[-1]
    if host.lower() in _TRUSTED_URL_HOSTS and "@" not in authority:
        return match.group()
    return f"{scheme}://{host}/{PATH_REDACTED}"


def shorten_urls(text: str) -> str:
    """`scheme://host/[path-redacted]`, wherever a URL stands. A path can be the secret, as in a
    webhook, and nothing recognises it. Hosts this tool links to itself are left alone."""
    return text if _show_urls else _URL.sub(_short_url, text)


def scrub(text: str) -> str:
    """Last step before anything leaves the process: secrets, identifiers, then URLs."""
    return shorten_urls(mask(redact(text)))


def install_log_scrub() -> None:
    """Scrub every log record as it is made, whichever logger or handler it reaches. Handler
    filters would miss a handler the host application adds; this cannot."""
    current = logging.getLogRecordFactory()
    if getattr(current, "apl_scrub", False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = current(*args, **kwargs)
        try:
            record.msg, record.args = scrub(record.getMessage()), None
            if isinstance(record.exc_info, tuple):
                record.exc_text = scrub("".join(traceback.format_exception(*record.exc_info)))
                record.exc_info = None
            if record.stack_info:
                record.stack_info = scrub(record.stack_info)
        except Exception:  # a record we cannot scrub is not emitted as it stands
            record.msg, record.args, record.exc_info, record.stack_info = (
                "(log record withheld: could not be scrubbed)",
                None,
                None,
                None,
            )
        return record

    factory.apl_scrub = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


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
