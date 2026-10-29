"""CLI. v0.1 is read-only; there is no `apply` command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from apl.inventory import build_inventory
from apl.parsers.mcp_config import ConfigParseError

app = typer.Typer(add_completion=False, help="Agent Permission Linter (read-only).")


@app.callback()
def _root() -> None:
    """Agent Permission Linter."""


@app.command()
def inventory(
    config: Annotated[list[Path], typer.Option("--config", "-c", help="MCP client config JSON")],
    agent: Annotated[Path | None, typer.Option("--agent", "-a", help="agent.yaml")] = None,
    tools: Annotated[
        list[Path] | None, typer.Option("--tools", "-t", help="saved tools/list JSON (offline)")
    ] = None,
    connect: Annotated[
        bool, typer.Option("--connect", help="Connect to MCP servers to list tools (NOT in v0.1)")
    ] = False,
) -> None:
    """Parse configs offline and print the redacted inventory as JSON."""
    if connect:
        typer.secho(
            "WARNING: --connect would launch/contact MCP servers (executes third-party code, "
            "sends credentials). Live connection is not implemented in v0.1. Use --tools with a "
            "saved tools/list result instead.",
            fg="yellow",
            err=True,
        )
        raise typer.Exit(2)
    try:
        inv = build_inventory(config, agent, tools)
    except ConfigParseError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(1) from None
    for w in inv.warnings:
        typer.secho(f"warning: {w}", fg="yellow", err=True)
    typer.echo(inv.model_dump_json(indent=2, exclude_none=True))


if __name__ == "__main__":
    app()
