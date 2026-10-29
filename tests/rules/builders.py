"""Builders for rule tests: small in-memory inventories."""

from datetime import UTC, datetime

from apl.classifier import classify_tool
from apl.models import (
    CredentialKind,
    CredentialRef,
    Evidence,
    Inventory,
    MCPServer,
    Tool,
    ToolAnnotations,
)


def tool(name, **ann):
    return classify_tool(Tool(name=name, annotations=ToolAnnotations(**ann) if ann else None))


def cred(env="GITHUB_PERSONAL_ACCESS_TOKEN", kind=CredentialKind.PAT, source="verified", **kw):
    return CredentialRef(
        kind=kind,
        kind_source=source,
        env_var=env,
        evidence=Evidence(source="cfg.json", pointer=f"/mcpServers/x/env/{env}"),
        **kw,
    )


def server(name="github", tools=(), creds=(), **kw):
    return MCPServer(
        name=name,
        tools=list(tools),
        tools_source="fixture" if tools else "none",
        credentials=list(creds),
        evidence=Evidence(source="cfg.json", pointer=f"/mcpServers/{name}"),
        **kw,
    )


def inventory(*servers, agent=None):
    return Inventory(servers=list(servers), agent=agent, generated_at=datetime.now(UTC))
