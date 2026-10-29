"""Offline tool-list loader.

Loads a saved `tools/list` result (JSON) so tools can be classified WITHOUT connecting.
Accepts either the JSON-RPC envelope {"result": {"tools": [...]}} or {"tools": [...]}
or a mapping {server_name: {"tools": [...]}}.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apl.models import Tool, ToolAnnotations
from apl.parsers.mcp_config import ConfigParseError


def _tools_from(obj: Any) -> list[Tool] | None:
    if isinstance(obj, dict) and "result" in obj:
        obj = obj["result"]
    if isinstance(obj, dict) and isinstance(obj.get("tools"), list):
        out = []
        for t in obj["tools"]:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                continue
            ann = t.get("annotations")
            out.append(
                Tool(
                    name=t["name"][:200],
                    description=t.get("description")
                    if isinstance(t.get("description"), str)
                    else None,
                    annotations=ToolAnnotations.model_validate(ann)
                    if isinstance(ann, dict)
                    else None,
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
    single = _tools_from(data)
    if single is not None:
        return {"*": single}
    if isinstance(data, dict):
        out = {k: v for k, v in ((k, _tools_from(v)) for k, v in data.items()) if v is not None}
        if out:
            return out
    raise ConfigParseError(f"{path}: no tools array found")
