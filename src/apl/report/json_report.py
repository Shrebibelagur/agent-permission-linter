"""JSON report with a stable, versioned schema.

Bump SCHEMA_VERSION on any breaking change (removed/renamed key or changed type). Adding a key
is a minor change. Top-level keys are pinned by a test.
"""

from __future__ import annotations

import json

from apl import __version__, idmask
from apl.redact import redact_obj, scrub
from apl.report.common import collect_limits, display_path, summary_counts
from apl.scan import ScanReport

SCHEMA_VERSION = "1.0"


def _finding(f) -> dict:
    d = f.model_dump(mode="json")
    for e in d["evidence"]:
        e["source"] = display_path(e["source"])
    return d


def build_json(report: ScanReport) -> dict:
    inv = report.inventory
    data = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "apl", "version": __version__},
        "generated_at": inv.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent": {"name": inv.agent.name} if inv.agent else None,
        "summary": summary_counts(report),
        "findings": [_finding(f) for f in report.sorted_findings()],
        "not_evaluated": [s.model_dump(mode="json") for s in report.result.skips],
        "servers": [
            {
                "name": s.name,
                "transport": s.transport.value,
                "source": display_path(s.evidence.source),
                "source_format": s.source_format,
                "format_status": s.format_status,
                "tools_source": s.tools_source,
                "tools": [
                    {
                        "name": t.name,
                        "capabilities": sorted(c.value for c in t.capabilities),
                        "confidence": t.classification_confidence,
                        "flags": t.classification_flags,
                    }
                    for t in s.tools
                ],
            }
            for s in inv.servers
        ],
        "limits": collect_limits(report).model_dump(mode="json"),
    }
    if idmask.showing_ids():
        data["contains_real_ids"] = True  # absent otherwise; adding a key is minor (R10)
    return data


def render_json(report: ScanReport) -> str:
    text = json.dumps(redact_obj(build_json(report)), indent=2, ensure_ascii=False)
    return scrub(text) + "\n"
