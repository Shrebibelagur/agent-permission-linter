"""Offline tool-list loader.

Loads a saved `tools/list` result (JSON) so tools can be classified WITHOUT connecting.
Accepts either the JSON-RPC envelope {"result": {"tools": [...]}} or {"tools": [...]}
or a mapping {server_name: {"tools": [...]}}. `resultType` must be absent or "complete".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apl.models import Tool, ToolAnnotations
from apl.parsers.mcp_config import ConfigParseError
from apl.schema_signals import extract_parameters


def _check_result_type(obj: dict[str, Any]) -> None:
    # ASSUMPTION S3: 2026-07-28 Result.resultType is required; servers on older versions omit it
    # and clients MUST treat that as "complete". Anything else is not a usable tool list.
    # The value is untrusted server output, so it is not echoed.
    rt = obj.get("resultType", "complete")
    if rt != "complete":
        raise ConfigParseError("tools/list result has resultType other than 'complete'")


def _tools_from(obj: Any) -> list[Tool] | None:
    if isinstance(obj, dict) and "result" in obj:
        obj = obj["result"]
    if isinstance(obj, dict) and isinstance(obj.get("tools"), list):
        _check_result_type(obj)
        out = []
        for t in obj["tools"]:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                continue
            ann = t.get("annotations")
            parameters, suspected = extract_parameters(t.get("inputSchema"))
            out.append(
                Tool(
                    name=t["name"][:200],
                    description=t.get("description")
                    if isinstance(t.get("description"), str)
                    else None,
                    annotations=ToolAnnotations.model_validate(ann)
                    if isinstance(ann, dict)
                    else None,
                    parameters=parameters,
                    schema_injection_suspected=suspected,
                )
            )
        return out
    return None


def load_tools_file(path: Path) -> dict[str, list[Tool]]:
    """Returns {server_name: tools}. Single-server files map to key '*'."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigParseError(f"{path}: cannot load tools file ({type(e).__name__})") from None
    try:
        return _load(data)
    except ConfigParseError as e:
        raise ConfigParseError(f"{path}: {e}") from None


def _load(data: Any) -> dict[str, list[Tool]]:
    single = _tools_from(data)
    if single is not None:
        return {"*": single}
    if isinstance(data, dict):
        out = {k: v for k, v in ((k, _tools_from(v)) for k, v in data.items()) if v is not None}
        if out:
            return out
    raise ConfigParseError("no tools array found")
