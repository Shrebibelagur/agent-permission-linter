"""SARIF 2.1.0 output (ASSUMPTION R9).

Levels: critical/high -> error, medium -> warning, low/info -> note. review_required findings are
always "note": they ask for a decision, not a fix. Skipped rules become tool execution
notifications so "not evaluated" stays visible in code-scanning UIs.
"""

from __future__ import annotations

import json
from pathlib import Path

from apl import __version__
from apl.models import Finding, Severity
from apl.redact import redact_obj
from apl.report.common import display_path, outcome
from apl.scan import ScanReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULE_META: dict[str, tuple[str, str]] = {
    "APL-001": ("OverScopedPermission", "Granted scope broader than any tool needs"),
    "APL-002": ("SharedCredential", "One fixed credential serves many invokers"),
    "APL-004": ("NoOwner", "Entra app linked to a server has no owner"),
    "APL-005": ("SecretHygiene", "Entra credential expired, without expiry or long-lived"),
    "APL-007": ("ToolExceedsPurpose", "Tool capability exceeds declared purpose"),
    "APL-010": ("NoApprovalGate", "High-impact tool runs without human approval"),
}
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _uri(source: str) -> str:
    p = Path(source)
    return p.as_uri() if p.is_absolute() else display_path(source)


def _location(f: Finding, report: ScanReport) -> tuple[str | None, str | None]:
    for e in f.evidence:
        if e.source:
            return e.source, e.pointer
    server = f.subject.split("/", 1)[0]
    for s in report.inventory.servers:
        if s.name == server:
            return s.evidence.source, s.evidence.pointer
    return None, None


def _result(f: Finding, report: ScanReport, index: dict[str, int]) -> dict:
    source, pointer = _location(f, report)
    res: dict = {
        "ruleId": f.rule_id,
        "level": "note" if f.status == "review_required" else _LEVEL[f.severity],
        "message": {"text": f"{f.title}: {f.subject}. {f.fix}"},
        "partialFingerprints": {"aplFindingId/v1": f.id},
        "properties": {
            "severity": f.severity.value,
            "status": f.status,
            "confidence": f.confidence,
            "confidenceReason": f.confidence_reason,
            "granted": f.granted,
            "required": f.required,
            "jsonPointer": pointer,
            "suggestedMappings": [m.model_dump(mode="json") for m in f.suggested_mappings],
        },
    }
    if f.rule_id in index:
        res["ruleIndex"] = index[f.rule_id]
    loc: dict = {"logicalLocations": [{"fullyQualifiedName": f.subject, "kind": "object"}]}
    if source:
        loc["physicalLocation"] = {"artifactLocation": {"uri": _uri(source)}}
    res["locations"] = [loc]
    return res


def build_sarif(report: ScanReport) -> dict:
    ids = sorted({f.rule_id for f in report.result.findings} | set(RULE_META))
    rules = []
    for rid in ids:
        name, desc = RULE_META.get(rid, (rid, rid))
        rules.append({"id": rid, "name": name, "shortDescription": {"text": desc}})
    index = {r["id"]: i for i, r in enumerate(rules)}
    notes = [
        {
            "level": "note",
            "message": {"text": f"{s.rule_id} {s.subject}: {s.reason}"},
            "descriptor": {"id": s.rule_id},
        }
        for s in report.result.skips
    ]
    kind, message = outcome(report)
    if message:
        # An empty results array must not read as "clean" when nothing ran.
        level = "warning" if kind == "nothing_evaluated" else "note"
        notes.insert(0, {"level": level, "message": {"text": message}})
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "apl",
                        "fullName": "Agent Permission Linter",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {"executionSuccessful": True, "toolExecutionNotifications": notes}
                ],
                "results": [_result(f, report, index) for f in report.sorted_findings()],
                "properties": {
                    "evaluated": len(report.result.evaluated),
                    "skipped": len(report.result.skips),
                    "outcome": kind,
                },
            }
        ],
    }


def render_sarif(report: ScanReport) -> str:
    return json.dumps(redact_obj(build_sarif(report)), indent=2, ensure_ascii=False) + "\n"
