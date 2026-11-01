"""Phase 2 rules. Each rule is a module with RULE_ID and check(Inventory) -> RuleResult."""

from __future__ import annotations

from apl.models import Inventory, RuleResult
from apl.rules import (
    apl001_overscoped,
    apl002_shared_credential,
    apl004_no_owner,
    apl007_exceeds_purpose,
    apl010_no_approval_gate,
)

RULES = [
    apl001_overscoped,
    apl002_shared_credential,
    apl004_no_owner,
    apl007_exceeds_purpose,
    apl010_no_approval_gate,
]


def run_rules(inv: Inventory) -> RuleResult:
    out = RuleResult()
    for rule in RULES:
        out.extend(rule.check(inv))
    return out
