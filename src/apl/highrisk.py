"""High-risk Microsoft Graph permissions, used by APL-004 and APL-006. ASSUMPTIONS R14.

Kept small on purpose. Each entry rests on what the permissions reference says about that
permission, and `source` links its section. The choice of entries is ours (suggested mapping).
"""

from __future__ import annotations

from dataclasses import dataclass

from apl.models import EntraApp

REFERENCE = "https://learn.microsoft.com/en-us/graph/permissions-reference"


@dataclass(frozen=True)
class HighRisk:
    name: str
    why: str
    application_only: bool = False  # the delegated form needs no admin consent and is user-bound

    @property
    def source(self) -> str:
        return f"{REFERENCE}#{self.name.replace('.', '').lower()}"


_ENTRIES = (
    HighRisk(
        "Application.ReadWrite.All",
        "manages credentials, so the app can act as other entities and use their privileges",
    ),
    HighRisk(
        "AppRoleAssignment.ReadWrite.All",
        "can grant additional privileges to itself, other applications or any user",
    ),
    HighRisk(
        "RoleManagement.ReadWrite.Directory",
        "can grant additional privileges and add members to Microsoft Entra roles",
    ),
    HighRisk(
        "Directory.ReadWrite.All",
        "gives broad write access to directory resources; the reference carries a caution",
    ),
    HighRisk("Sites.FullControl.All", "has full control of all site collections"),
    HighRisk("Mail.Send", "can send mail as any user", application_only=True),
    HighRisk(
        "Mail.ReadWrite",
        "can create, read, update and delete mail in all mailboxes",
        application_only=True,
    ),
    HighRisk(
        "Files.ReadWrite.All",
        "can read, create, update and delete all files in all site collections",
        application_only=True,
    ),
)
_BY_NAME = {e.name.lower(): e for e in _ENTRIES}


def lookup(permission: str) -> HighRisk | None:
    """Exact name only. Another API's scope is `<resource>/<scope>` (G9), so it cannot match."""
    return _BY_NAME.get(permission.lower())


def high_risk_grants(app: EntraApp) -> list[HighRisk]:
    """Delegated grants count only for entries that are high-risk in both forms."""
    delegated = {*app.delegated_all_principals, *app.delegated_per_user}
    found = [e for p in app.application_permissions if (e := lookup(p))]
    found += [e for p in delegated if (e := lookup(p)) and not e.application_only]
    return sorted(set(found), key=lambda e: e.name)
