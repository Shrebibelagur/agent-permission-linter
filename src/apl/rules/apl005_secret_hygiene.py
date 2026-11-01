"""APL-005 secret hygiene: credentials on a linked Entra app that are expired or live too long.

One finding per credential, the first that applies: no expiry (medium), expired but still present
(medium), lifetime over 180 days (low). Only dates are read; secret values are never collected.
Expiry is judged against the scan time, `inventory.generated_at`. See ASSUMPTIONS R15.

What cannot be judged is a visible skip: an end date that is not a date, a start date missing when
lifetime depends on it, and credential lists Graph did not return or that live in another tenant.
Azure rotates managed identity credentials itself, so those are skipped too.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apl import idmask
from apl.models import CredentialExpiry, EntraApp, Evidence, Inventory, RuleResult, Severity
from apl.rules.base import (
    ENTRA_ORIGIN,
    NHI7,
    app_ref,
    app_subject,
    entra_targets,
    make_finding,
    skip,
)

RULE_ID = "APL-005"
MAX_LIFETIME = timedelta(days=180)


def _utc(when: datetime) -> datetime:
    return when if when.tzinfo else when.replace(tzinfo=UTC)  # Graph documents these as UTC


def _day(when: datetime) -> str:
    return when.strftime("%Y-%m-%d")


def _problem(c: CredentialExpiry, now: datetime) -> tuple[Severity, str, str] | None:
    """(severity, title, note), or None if the credential is fine."""
    if c.end_date_time is None:
        return Severity.MEDIUM, "Credential has no expiry", "no endDateTime"
    end = _utc(c.end_date_time)
    if end < now:
        return Severity.MEDIUM, "Expired credential still present", f"expired {_day(end)}"
    if c.start_date_time is None:
        return None
    start = _utc(c.start_date_time)
    if end - start <= MAX_LIFETIME:
        return None
    note = f"{(end - start).days} days, {_day(start)} to {_day(end)}"
    return Severity.LOW, "Credential lifetime over 180 days", note


def _check_credential(
    res: RuleResult,
    server: str,
    app: EntraApp,
    index: int,
    c: CredentialExpiry,
    now: datetime,
    origin: str,
) -> None:
    key = idmask.show("cred", c.key_id) if c.key_id else index
    detail = f"{c.kind}-{key}"
    subject = app_subject(server, app, detail)
    if c.end_unreadable:
        res.skips.append(skip(RULE_ID, subject, "credential end date (not a date in Graph)"))
        return
    problem = _problem(c, now)
    if problem is None:
        if c.start_date_time is None and _utc(c.end_date_time) >= now:
            res.skips.append(skip(RULE_ID, subject, "credential start date, so no lifetime"))
        return
    severity, title, note = problem
    conf, why = 0.95, "dates read directly from Graph"
    if c.end_date_time is None:
        conf, why = 0.8, "Graph documents endDateTime as optional; read as no expiry"
    res.findings.append(
        make_finding(
            RULE_ID,
            title,
            severity,
            f"{server}/{detail}",
            granted=[f"{c.kind} credential: {note}"],
            required=[f"expiry within {MAX_LIFETIME.days} days, rotated before it ends"],
            evidence=[Evidence(source=origin, pointer=c.pointer, note=note, app=app_ref(app))],
            fix=(
                f"Rotate this {c.kind} credential on '{app.display_name or app.app_id}' to one "
                f"lasting at most {MAX_LIFETIME.days} days and remove the old one, or use a "
                "managed identity."
            ),
            confidence=conf,
            confidence_reason=why,
            mappings=[NHI7],
        )
    )


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    origin = ENTRA_ORIGIN.get(inv.entra_source or "", "entra")
    now = _utc(inv.generated_at)
    for srv in inv.servers:
        apps, skips = entra_targets(inv, srv, RULE_ID, "credential data")
        res.skips.extend(skips)
        for app in apps:
            subject = app_subject(srv.name, app)
            if app.service_principal_type == "ManagedIdentity":
                res.skips.append(
                    skip(RULE_ID, subject, "customer-managed credentials (managed identity)")
                )
                continue
            if app.credentials_gap:
                res.skips.append(
                    skip(RULE_ID, subject, f"credential data ({app.credentials_gap})")
                )
            if app.credentials or not app.credentials_gap:
                res.ran(RULE_ID, subject)
            for index, c in enumerate(app.credentials):
                _check_credential(res, srv.name, app, index, c, now, origin)
    return res
