"""Scan = inventory + optional Entra data + rules. The only network use is a live Entra collector
passed in by the caller. No subprocesses."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel

from apl.collectors.entra import EntraSnapshot
from apl.collectors.link import link_entra, linkable_app_ids
from apl.inventory import build_inventory
from apl.models import Inventory, RuleResult, Severity
from apl.rules import run_rules

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ScanReport(BaseModel):
    inventory: Inventory
    result: RuleResult

    def sorted_findings(self):
        return sorted(
            self.result.findings,
            key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.subject),
        )


def run_scan(
    configs: list[Path],
    agent: Path | None = None,
    tools: list[Path] | None = None,
    entra: Callable[[set[str]], EntraSnapshot] | None = None,
) -> ScanReport:
    inv = build_inventory(configs, agent, tools)
    if entra is not None:
        link_entra(inv, entra(linkable_app_ids(inv)))
    return ScanReport(inventory=inv, result=run_rules(inv))


def exceeds_threshold(report: ScanReport, fail_on: str) -> bool:
    """True if any finding (violation or review) is at or above `fail_on`. 'none' never fails."""
    if fail_on == "none":
        return False
    floor = SEVERITY_ORDER[Severity(fail_on)]
    return any(SEVERITY_ORDER[f.severity] >= floor for f in report.result.findings)
