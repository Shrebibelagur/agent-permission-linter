"""Capability -> minimum Microsoft Graph permission, for a small set of resources.

Suggested mapping, not a guarantee: the least permission for one API call can be narrower than
this, so check the operation's own page. Source and caveats: docs/ASSUMPTIONS.md G11.
"""

from __future__ import annotations

from typing import NamedTuple

from apl.models import Capability

LABEL = "suggested mapping"
SOURCE = "https://learn.microsoft.com/en-us/graph/permissions-reference"
C = Capability


class MinPermission(NamedTuple):
    delegated: str | None
    application: str | None


def _same(name: str) -> MinPermission:
    return MinPermission(name, name)


MINIMUM_PERMISSIONS: dict[str, dict[Capability, MinPermission]] = {
    "Mail": {
        C.READ: _same("Mail.Read"),
        C.WRITE: _same("Mail.ReadWrite"),
        C.DELETE: _same("Mail.ReadWrite"),
        C.NETWORK: _same("Mail.Send"),
    },
    "Files": {
        C.READ: MinPermission("Files.Read", "Files.Read.All"),
        C.WRITE: MinPermission("Files.ReadWrite", "Files.ReadWrite.All"),
        C.DELETE: MinPermission("Files.ReadWrite", "Files.ReadWrite.All"),
    },
    "Calendars": {
        C.READ: _same("Calendars.Read"),
        C.WRITE: _same("Calendars.ReadWrite"),
        C.DELETE: _same("Calendars.ReadWrite"),
    },
    "User": {
        C.READ: MinPermission("User.Read", "User.Read.All"),
        C.WRITE: MinPermission("User.ReadWrite", "User.ReadWrite.All"),
        C.DELETE: _same("User.DeleteRestore.All"),
    },
    # No DELETE row: no one permission is the minimum (see NO_DELETE and docs/ASSUMPTIONS.md R2).
    "Directory": {
        C.READ: _same("Directory.Read.All"),
        C.WRITE: _same("Directory.ReadWrite.All"),
    },
    "Application": {
        C.READ: _same("Application.Read.All"),
        C.WRITE: MinPermission("Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"),
        C.DELETE: MinPermission("Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"),
    },
}


# Exceptions to "ReadWrite grants delete" in APL-001, from the docs. ASSUMPTIONS.md R2 has the
# source for each. Anything not listed keeps the wider mapping.
NO_DELETE = frozenset({"User.ReadWrite"})
UNVERIFIED_DELETE = frozenset({"User.DeleteRestore.All"})  # delete kept, findings less confident
UNVERIFIED_CONFIDENCE = 0.6


def minimum_permission(resource: str, capability: Capability) -> MinPermission | None:
    return MINIMUM_PERMISSIONS.get(resource, {}).get(capability)


def suggest_replacements(scope: str, needed: set[Capability]) -> list[str]:
    """Permissions that cover `needed` on `scope`'s resource, excluding `scope` itself.

    Tells delegated and application apart only where the two differ.
    """
    resource = scope.split(".", 1)[0]
    found: list[str] = []
    for capability in sorted(needed):
        row = minimum_permission(resource, capability)
        if row is None:
            continue
        if row.delegated == row.application:
            text = row.delegated
        else:
            text = " or ".join(
                f"{name} ({kind})"
                for name, kind in ((row.delegated, "delegated"), (row.application, "application"))
                if name
            )
        if text and scope not in (row.delegated, row.application) and text not in found:
            found.append(text)
    return found
