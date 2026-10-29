"""agent.yaml loader (declared purpose). Strict schema: unknown keys are errors."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from apl.models import AgentSpec
from apl.parsers.mcp_config import ConfigParseError


def load_agent_spec(path: Path) -> AgentSpec:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ConfigParseError(f"{path}: cannot load agent spec ({type(e).__name__})") from None
    if not isinstance(data, dict):
        raise ConfigParseError(f"{path}: top level must be a mapping")
    try:
        return AgentSpec.model_validate(data)
    except ValidationError as e:
        locs = "; ".join(".".join(map(str, err["loc"])) + ": " + err["msg"] for err in e.errors())
        raise ConfigParseError(f"{path}: invalid agent spec: {locs}") from None
