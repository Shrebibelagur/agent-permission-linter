"""Assemble an Inventory from static inputs. No network, no subprocesses."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from apl import idmask
from apl.classifier import classify_tool
from apl.models import Inventory
from apl.parsers.agent_spec import load_agent_spec
from apl.parsers.mcp_config import parse_config_file
from apl.parsers.tools_list import load_tools_file
from apl.untrusted import injection_suspected


def build_inventory(
    configs: list[Path], agent: Path | None = None, tools: list[Path] | None = None
) -> Inventory:
    servers, warnings = [], []
    for c in configs:
        s, w = parse_config_file(c)
        servers.extend(s)
        warnings.extend(w)

    tool_map: dict[str, list] = {}
    for tf in tools or []:
        tool_map.update(load_tools_file(tf))
    if "*" in tool_map and len(servers) != 1:
        warnings.append("single-server tools file given but config has != 1 server; ignored")
        tool_map.pop("*")

    for srv in servers:
        src = tool_map.get(srv.name) or (tool_map.get("*") if len(servers) == 1 else None)
        if src is None:
            warnings.append(f"{srv.name}: no tool list (offline); capabilities unknown")
            continue
        srv.tools = [classify_tool(t) for t in src]
        srv.tools_source = "fixture"
        for t in srv.tools:
            if (
                injection_suspected(t.description or "")
                or injection_suspected(t.name)
                or t.schema_injection_suspected
            ):
                warnings.append(f"{srv.name}/{t.name}: possible prompt injection in tool metadata")

    spec = load_agent_spec(agent) if agent else None
    if spec:
        known = {s.name for s in servers}
        for sp in spec.servers:
            if sp.server not in known:
                warnings.append(f"agent.yaml declares server {sp.server!r} not present in config")
        declared = {sp.server for sp in spec.servers}
        for s in servers:
            if s.name not in declared:
                warnings.append(f"{s.name}: in config but has no declared purpose in agent.yaml")

    for name in [s.name for s in servers] + [p.server for p in (spec.servers if spec else [])]:
        idmask.register_name("server-name", name)
    if spec:
        idmask.register_name("agent-name", spec.name)
        if spec.owner:  # also reaches free text that quotes it, such as a justification
            idmask.register_name("owner-name", spec.owner)
    return Inventory(agent=spec, servers=servers, generated_at=datetime.now(UTC), warnings=warnings)
