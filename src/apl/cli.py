"""CLI. v0.1 is read-only; there is no `apply` command."""

from __future__ import annotations

from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Annotated

import typer

from apl.collectors.entra import ENV_VARS, EntraError, collect_live, collect_mock
from apl.inventory import build_inventory
from apl.parsers.mcp_config import ConfigParseError
from apl.redact import redact

# show_locals stays off: a crash must never print a local holding a credential.
app = typer.Typer(
    add_completion=False,
    help="Agent Permission Linter (read-only).",
    pretty_exceptions_show_locals=False,
)

_CONNECT_WARNING = (
    "WARNING: --connect would launch/contact MCP servers (executes third-party code, "
    "sends credentials). Live connection is not implemented in v0.1. Use --tools with a "
    "saved tools/list result instead."
)

_ENTRA_NOTICE = (
    "NOTICE: --entra reads your tenant through Microsoft Graph. Read-only: GET requests only, "
    "nothing in Entra is changed."
)


class Format(StrEnum):
    md = "md"
    json = "json"
    sarif = "sarif"


class FailOn(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"


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
        typer.secho(_CONNECT_WARNING, fg="yellow", err=True)
        raise typer.Exit(2)
    try:
        inv = build_inventory(config, agent, tools)
    except ConfigParseError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(1) from None
    for w in inv.warnings:
        typer.secho(f"warning: {w}", fg="yellow", err=True)
    typer.echo(inv.model_dump_json(indent=2, exclude_none=True))


def render(report, fmt: Format) -> str:
    from apl.report import render as render_report

    return render_report(report, fmt.value)


@app.command()
def scan(
    config: Annotated[list[Path], typer.Option("--config", "-c", help="MCP client config JSON")],
    agent: Annotated[Path | None, typer.Option("--agent", "-a", help="agent.yaml")] = None,
    tools: Annotated[
        list[Path] | None, typer.Option("--tools", "-t", help="saved tools/list JSON (offline)")
    ] = None,
    fmt: Annotated[Format, typer.Option("--format", "-f", help="report format")] = Format.md,
    out: Annotated[Path | None, typer.Option("--out", "-o", help="write report here")] = None,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="exit 1 if a finding is at/above this severity")
    ] = FailOn.none,
    connect: Annotated[
        bool, typer.Option("--connect", help="Connect to MCP servers to list tools (NOT in v0.1)")
    ] = False,
    entra: Annotated[
        bool,
        typer.Option(
            "--entra", help="Read Entra via Graph (GET only). Needs " + ", ".join(ENV_VARS)
        ),
    ] = False,
    entra_mock: Annotated[
        Path | None,
        typer.Option("--entra-mock", help="Use saved Graph responses from this directory"),
    ] = None,
) -> None:
    """Inventory + rules, then a report. Exit 0 ok, 1 findings at/above --fail-on, 2 error."""
    from apl.scan import exceeds_threshold, run_scan

    if connect:
        typer.secho(_CONNECT_WARNING, fg="yellow", err=True)
        raise typer.Exit(2)
    if entra and entra_mock is not None:
        typer.secho("error: use --entra or --entra-mock, not both", fg="red", err=True)
        raise typer.Exit(2)
    collector = None
    if entra:
        typer.secho(_ENTRA_NOTICE, fg="yellow", err=True)
        collector = collect_live
    elif entra_mock is not None:
        collector = partial(collect_mock, entra_mock)
    try:
        report = run_scan(config, agent, tools, entra=collector)
    except (ConfigParseError, EntraError) as e:
        typer.secho(f"error: {redact(str(e))}", fg="red", err=True)
        raise typer.Exit(2) from None
    for w in report.inventory.warnings:
        typer.secho(f"warning: {redact(w)}", fg="yellow", err=True)
    text = render(report, fmt)
    if out is None:
        typer.echo(text)
    else:
        try:
            out.write_text(text, encoding="utf-8")
        except OSError as e:
            typer.secho(f"error: cannot write {out}: {e.strerror}", fg="red", err=True)
            raise typer.Exit(2) from None
        typer.secho(f"report written to {out}", err=True)
    if exceeds_threshold(report, fail_on.value):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
