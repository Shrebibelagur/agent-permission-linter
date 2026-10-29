"""Phase 2 rules. Each rule is a module with RULE_ID and check(Inventory) -> RuleResult."""

from __future__ import annotations

from apl.models import Inventory, RuleResult
from apl.rules import apl001_overscoped, apl002_shared_credential, apl007_exceeds_purpose

RULES = [apl001_overscoped, apl002_shared_credential, apl007_exceeds_purpose]


def run_rules(inv: Inventory) -> RuleResult:
    out = RuleResult()
    for rule in RULES:
        out.extend(rule.check(inv))
    return out
