"""Report renderers. Every renderer's output is redacted and has its ids masked."""

from __future__ import annotations

from apl.report.json_report import render_json
from apl.report.markdown import render_markdown
from apl.report.sarif import render_sarif
from apl.scan import ScanReport

RENDERERS = {"md": render_markdown, "json": render_json, "sarif": render_sarif}


def render(report: ScanReport, fmt: str) -> str:
    try:
        return RENDERERS[fmt](report)
    except KeyError:
        raise ValueError(f"unsupported format: {fmt}") from None
