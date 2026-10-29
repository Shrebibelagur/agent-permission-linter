"""Core data models. Everything downstream (rules, reasoning, reporters) consumes these."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Capability(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    UNKNOWN = "unknown"  # name gave no recognised verb; needs human review


# Ordinal used for "granted exceeds required" comparisons. UNKNOWN ranks highest: until someone
# reviews it, an unclassified tool cannot be shown to be less powerful than execute.
CAPABILITY_RISK: dict[Capability, int] = {
    Capability.READ: 1,
    Capability.NETWORK: 2,
    Capability.WRITE: 3,
    Capability.DELETE: 4,
    Capability.EXECUTE: 5,
    Capability.UNKNOWN: 6,
}


class Transport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"  # Streamable HTTP
    SSE = "sse"  # legacy HTTP+SSE (deprecated in MCP 2026-07-28)
    UNKNOWN = "unknown"


class CredentialKind(StrEnum):
    OAUTH_APP = "oauth_app"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    API_KEY = "api_key"
    PAT = "personal_access_token"  # maker-mode: a human's own token
    USER_DELEGATED = "user_delegated"
    NONE = "none"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """Where a fact came from. `source` is a file path or API endpoint; never a secret."""

    source: str
    pointer: str | None = None  # JSON pointer / key path
    note: str | None = None


class CredentialRef(BaseModel):
    """A reference to a credential. Holds the env var NAME, never the value."""

    model_config = ConfigDict(frozen=True)

    kind: CredentialKind = CredentialKind.UNKNOWN
    # ASSUMPTION A8: "inferred" = guessed from an env var/header name; "verified" is reserved for
    # Phase 3 (Entra). "unknown" = no basis for a kind at all.
    kind_source: Literal["inferred", "verified", "unknown"] = "unknown"
    env_var: str | None = None
    header: str | None = None
    inline_secret_detected: bool = False  # a literal secret was in the config (value discarded)
    entra_app_id: str | None = None  # linked later by collector / agent.yaml
    # Scopes/permissions actually granted (Graph permissions, OAuth or PAT scopes). Static configs
    # never contain these; Phase 3 (Entra collector) fills them. None = not known.
    granted_scopes: list[str] | None = None
    evidence: Evidence | None = None


class ToolAnnotations(BaseModel):
    """MCP tool annotations. Per spec these are HINTS from an untrusted server."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    read_only_hint: bool | None = Field(default=None, alias="readOnlyHint")
    destructive_hint: bool | None = Field(default=None, alias="destructiveHint")
    idempotent_hint: bool | None = Field(default=None, alias="idempotentHint")
    open_world_hint: bool | None = Field(default=None, alias="openWorldHint")


class Tool(BaseModel):
    name: str
    description: str | None = None  # UNTRUSTED - wrap before any LLM use
    annotations: ToolAnnotations | None = None
    capabilities: set[Capability] = Field(default_factory=set)
    classification_reasons: list[str] = Field(default_factory=list)
    classification_confidence: float = 0.0
    classification_flags: list[str] = Field(default_factory=list)  # e.g. review required
    # ASSUMPTION S4: spec defaults for hints the server omitted. Reported only, never used to
    # classify (applying destructiveHint=true by default would mark every tool as delete).
    annotation_defaults_unapplied: dict[str, bool] = Field(default_factory=dict)
    annotation_flags: list[str] = Field(default_factory=list)


class MCPServer(BaseModel):
    name: str
    transport: Transport = Transport.UNKNOWN
    command: str | None = None
    args: list[str] = Field(default_factory=list)  # redacted
    url: str | None = None  # redacted (query strings stripped)
    env_keys: list[str] = Field(default_factory=list)  # names only, values dropped
    credentials: list[CredentialRef] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)
    tools_source: str = "none"  # none | fixture | live
    disabled: bool = False
    source_format: str = "unknown"
    # ASSUMPTION A3: "unverified" = we found no current official doc for this config shape.
    format_status: Literal["verified", "unverified"] = "verified"
    evidence: Evidence

    def granted_capabilities(self) -> set[Capability]:
        caps: set[Capability] = set()
        for t in self.tools:
            caps |= t.capabilities
        return caps


class ServerPurpose(BaseModel):
    server: str
    required_capabilities: set[Capability] = Field(default_factory=set)
    justification: str | None = None
    approval_gate: bool = False
    entra_app_id: str | None = None
    required_graph_permissions: list[str] = Field(default_factory=list)


class AgentSpec(BaseModel):
    """User-supplied agent.yaml - the declared task purpose (trusted input)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    purpose: str
    owner: str | None = None
    data_classification: str | None = None
    servers: list[ServerPurpose] = Field(default_factory=list)


class Inventory(BaseModel):
    """Phase-1 output: everything known about an agent before rules run."""

    agent: AgentSpec | None = None
    servers: list[MCPServer] = Field(default_factory=list)
    generated_at: datetime
    warnings: list[str] = Field(default_factory=list)


class MappingRef(BaseModel):
    """A framework reference. Always a SUGGESTED mapping, never a compliance claim."""

    framework: str
    id: str
    title: str
    url: str
    label: Literal["suggested mapping"] = "suggested mapping"


class Finding(BaseModel):
    """One rule result about one subject. Build via apl.rules.base.make_finding (redacts)."""

    id: str  # stable: "<rule_id>:<hash of subject>"
    rule_id: str
    title: str
    severity: Severity
    # violation = rule says granted exceeds required; review_required = the data cannot support
    # a hard verdict (e.g. unclassified tools) and a human must decide.
    status: Literal["violation", "review_required"] = "violation"
    subject: str
    granted: list[str] = Field(default_factory=list)
    required: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    fix: str
    confidence: float
    confidence_reason: str
    suggested_mappings: list[MappingRef] = Field(default_factory=list)


class RuleSkip(BaseModel):
    """A rule that could not be evaluated for a subject. Shown, never silently dropped."""

    rule_id: str
    subject: str
    reason: str  # always starts "not evaluated: missing "


class RuleResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    skips: list[RuleSkip] = Field(default_factory=list)

    def extend(self, other: RuleResult) -> None:
        self.findings.extend(other.findings)
        self.skips.extend(other.skips)
