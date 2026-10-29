"""Core data models. Everything downstream (rules, reasoning, reporters) consumes these."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Capability(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"


# Ordinal used for "granted exceeds required" comparisons.
CAPABILITY_RISK: dict[Capability, int] = {
    Capability.READ: 1,
    Capability.NETWORK: 2,
    Capability.WRITE: 3,
    Capability.DELETE: 4,
    Capability.EXECUTE: 5,
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
    env_var: str | None = None
    header: str | None = None
    inline_secret_detected: bool = False  # a literal secret was in the config (value discarded)
    entra_app_id: str | None = None  # linked later by collector / agent.yaml
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


class Finding(BaseModel):
    """Phase 2 will populate. Defined now so the schema is stable."""

    rule_id: str
    title: str
    severity: Severity
    subject: str
    granted: list[str] = Field(default_factory=list)
    required: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str
