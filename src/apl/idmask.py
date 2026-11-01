"""Pseudonyms for Entra identifiers. Design and limits: docs/ASSUMPTIONS.md R19.

`pseudonym("app", value)` gives `app-3f9a1c`: HMAC-SHA256 under a per-install salt, cut to 6 hex
characters. Same install and input, same output. Identifiers are not secrets, but they say which
tenant and apps a report is about, so reports stay shareable. Secrets never come here: they are
removed outright by apl.redact, and are not hashed.

The salt is `APL_ID_SALT`, else a file in the user config dir made on first use. It is never in
the repo, and is itself scrubbed as a secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

KINDS = frozenset({"app", "tenant", "sp", "cred", "id"})  # "id": a GUID of unknown kind
SALT_ENV = "APL_ID_SALT"
MIN_SALT = 16
MIN_KNOWN_ID = 8  # a shorter value would scrub ordinary text
HEX_CHARS = 6

_GUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_DONE = r"(?!(?:app|tenant|sp|cred|id)-[0-9a-f]{6}\b)"  # already a pseudonym: leave it
_SEGMENT = rf"{_DONE}[^/\s\"'`?#|\\)]+"
_PATHS = (
    (re.compile(rf"(/applications/)({_SEGMENT})"), "app"),
    (re.compile(rf"(/servicePrincipals/)({_SEGMENT})"), "sp"),
    (re.compile(rf"(login\.microsoftonline\.com/)({_SEGMENT})"), "tenant"),
)

_salt: bytes | None = None
_known: dict[str, str] = {}  # lower-case value -> kind
_known_pattern: re.Pattern[str] | None = None
_show_ids = False


class SaltError(RuntimeError):
    """No usable salt. Fails closed: printing raw ids is not a fallback."""


def _config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming"
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "apl"


def salt_path() -> Path:
    return _config_dir() / "id_salt"


def _read_or_create(path: Path) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return path.read_text(encoding="utf-8").strip()
        value = secrets.token_hex(32)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value)
        return value
    except OSError as e:
        raise SaltError(f"cannot use the salt file: {e.strerror}; set {SALT_ENV}") from None


def _load_salt() -> bytes:
    from apl.redact import remember_secret  # apl.redact imports this module

    value = os.environ.get(SALT_ENV) or _read_or_create(salt_path())
    if len(value) < MIN_SALT:
        raise SaltError(f"salt is shorter than {MIN_SALT} characters; check {SALT_ENV} or the file")
    remember_secret(value)
    return value.encode()


def _key() -> bytes:
    global _salt
    if _salt is None:
        _salt = _load_salt()
    return _salt


def digest(value: str) -> str:
    """Full keyed digest of an identifier, for finding ids: 6 hex characters would collide."""
    return hmac.new(_key(), value.strip().lower().encode(), hashlib.sha256).hexdigest()


def pseudonym(kind: str, value: str) -> str:
    if kind not in KINDS:
        raise ValueError(f"unknown identifier kind: {kind}")
    return f"{kind}-{digest(f'{kind}:{value.strip().lower()}')[:HEX_CHARS]}"


def register(kind: str, value: str) -> None:
    """Know this exact value from now on, so it is replaced anywhere, with the right kind."""
    global _known_pattern
    if len(value) >= MIN_KNOWN_ID and _known.get(value.lower()) != kind:
        _known[value.lower()] = kind
        _known_pattern = None


def show(kind: str, value: str) -> str:
    """What to print for a known identifier in the current mode."""
    register(kind, value)
    return value if _show_ids else pseudonym(kind, value)


def _replace_known(text: str) -> str:
    global _known_pattern
    if not _known:
        return text
    if _known_pattern is None:
        names = sorted(_known, key=len, reverse=True)
        _known_pattern = re.compile("|".join(re.escape(n) for n in names), re.IGNORECASE)
    return _known_pattern.sub(lambda m: pseudonym(_known[m.group().lower()], m.group()), text)


def mask_known(text: str) -> str:
    """Exact known identifiers only, for redact(): no GUID guessing on data still being joined."""
    return text if _show_ids else _replace_known(text)


def pseudonymise(text: str) -> str:
    """Every identifier in `text`: known values, then Graph paths, then any other GUID."""
    out = _replace_known(text)
    for pattern, kind in _PATHS:
        out = pattern.sub(lambda m, k=kind: m.group(1) + pseudonym(k, m.group(2)), out)
    return _GUID.sub(lambda m: pseudonym("id", m.group()), out)


def mask(text: str) -> str:
    """`pseudonymise`, unless --show-ids is on."""
    return text if _show_ids else pseudonymise(text)


def set_show_ids(on: bool) -> None:
    global _show_ids
    _show_ids = on


def reset() -> None:
    """Forget process state. For tests."""
    global _salt, _known_pattern, _show_ids
    _salt, _known_pattern, _show_ids = None, None, False
    _known.clear()
