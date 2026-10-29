"""Shared helpers for rules. Every finding is built here so every string goes through redact."""

from __future__ import annotations

import hashlib

from apl.models import Capability, Evidence, Finding, MappingRef, RuleSkip, Severity, Tool
from apl.redact import redact

MAX_SUBJECT = 200  # subjects can embed tool names, which are untrusted server output

# Suggested mappings. Only IDs looked up on owasp.org (see docs/ASSUMPTIONS.md, R1).
LLM06 = MappingRef(
    framework="OWASP Top 10 for LLM Applications 2025",
    id="LLM06:2025",
    title="Excessive Agency",
    url="https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
)
ASI03 = MappingRef(
    framework="OWASP Top 10 for Agentic Applications 2026",
    id="ASI03",
    title="Identity & Privilege Abuse",
    url=(
        "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-"
        "the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"
    ),
)

# Tools at or below this classifier confidence cannot support a hard verdict.
LOW_CONFIDENCE = 0.5


def is_uncertain(tool: Tool) -> bool:
    """Unclassified or low-confidence: a rule may ask for review but must not convict."""
    return (
        Capability.UNKNOWN in tool.capabilities
        or tool.classification_confidence <= LOW_CONFIDENCE
    )


def kind_confidence(kind_source: str) -> tuple[float, str]:
    """Confidence penalty for how the credential kind was established (ASSUMPTION A8)."""
    if kind_source == "verified":
        return 1.0, "credential kind verified"
    if kind_source == "inferred":
        return 0.75, "credential kind inferred from env var/header name"
    return 0.6, "credential kind unknown"


def _r(s: str) -> str:
    return redact(s)


def _ev(e: Evidence) -> Evidence:
    return Evidence(
        source=_r(e.source),
        pointer=_r(e.pointer) if e.pointer else None,
        note=_r(e.note) if e.note else None,
    )


def make_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    subject: str,
    *,
    fix: str,
    confidence: float,
    confidence_reason: str,
    granted: list[str] | None = None,
    required: list[str] | None = None,
    evidence: list[Evidence] | None = None,
    mappings: list[MappingRef] | None = None,
    status: str = "violation",
) -> Finding:
    subj = _r(subject)[:MAX_SUBJECT]
    digest = hashlib.sha256(f"{rule_id}|{subj}".encode()).hexdigest()[:12]
    return Finding(
        id=f"{rule_id}:{digest}",
        rule_id=rule_id,
        title=_r(title),
        severity=severity,
        status=status,
        subject=subj,
        granted=[_r(g) for g in granted or []],
        required=[_r(x) for x in required or []],
        evidence=[_ev(e) for e in evidence or []],
        fix=_r(fix),
        confidence=round(max(0.0, min(1.0, confidence)), 2),
        confidence_reason=_r(confidence_reason),
        suggested_mappings=list(mappings or []),
    )


def skip(rule_id: str, subject: str, missing: str) -> RuleSkip:
    return RuleSkip(
        rule_id=rule_id,
        subject=_r(subject)[:MAX_SUBJECT],
        reason=f"not evaluated: missing {_r(missing)}",
    )
