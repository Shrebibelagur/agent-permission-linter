"""Report renderers. Every renderer's output passes through apl.redact before it is returned."""

from __future__ import annotations

from apl.report.markdown import render_markdown
from apl.scan import ScanReport


def render(report: ScanReport, fmt: str) -> str:
    if fmt == "md":
        return render_markdown(report)
    raise ValueError(f"unsupported format: {fmt}")
