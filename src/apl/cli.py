"""CLI. v0.1 is read-only; there is no `apply` command."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Annotated

import typer

from apl.collectors.entra import ENV_VARS, EntraError, collect_live, collect_mock
from apl.idmask import SaltError
from apl.inventory import build_inventory
from apl.parsers.mcp_config import ConfigParseError
from apl.redact import scrub

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


class UnexpectedError(RuntimeError):
    """A crash, with its message scrubbed and the original exception and frames dropped."""


def _clean(text: str) -> str:
    try:
        return scrub(text)
    except SaltError:  # no salt means no pseudonyms, so nothing unscrubbed may be shown
        return "message withheld: no identifier salt available"


def _say(text: str, fg: str = "yellow") -> None:
    typer.secho(_clean(text), fg=fg, err=True)


@contextmanager
def _scrubbed() -> Iterator[None]:
    """Nothing raised in here leaves with an unscrubbed message or traceback."""
    try:
        yield
    except (typer.Exit, typer.Abort):
        raise
    except Exception as e:
        raise UnexpectedError(f"{type(e).__name__}: {_clean(str(e))}") from None


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
        _say(_CONNECT_WARNING)
        raise typer.Exit(2)
    with _scrubbed():
        try:
            inv = build_inventory(config, agent, tools)
            text = scrub(inv.model_dump_json(indent=2, exclude_none=True))
        except (ConfigParseError, SaltError) as e:
            _say(f"error: {e}", "red")
            raise typer.Exit(1) from None
        for w in inv.warnings:
            _say(f"warning: {w}")
        typer.echo(text)


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
    with _scrubbed():
        _run_scan(config, agent, tools, fmt, out, fail_on, connect, entra, entra_mock)


def _run_scan(config, agent, tools, fmt, out, fail_on, connect, entra, entra_mock) -> None:
    from apl.scan import exceeds_threshold, run_scan

    if connect:
        _say(_CONNECT_WARNING)
        raise typer.Exit(2)
    if entra and entra_mock is not None:
        _say("error: use --entra or --entra-mock, not both", "red")
        raise typer.Exit(2)
    collector = None
    if entra:
        _say(_ENTRA_NOTICE)
        collector = collect_live
    elif entra_mock is not None:
        collector = partial(collect_mock, entra_mock)
    try:
        report = run_scan(config, agent, tools, entra=collector)
        text = render(report, fmt)
    except (ConfigParseError, EntraError, SaltError) as e:
        _say(f"error: {e}", "red")
        raise typer.Exit(2) from None
    for w in report.inventory.warnings:
        _say(f"warning: {w}")
    if out is None:
        typer.echo(text)
    else:
        try:
            out.write_text(text, encoding="utf-8")
        except OSError as e:
            _say(f"error: cannot write {out}: {e.strerror}", "red")
            raise typer.Exit(2) from None
        _say(f"report written to {out}")
    if exceeds_threshold(report, fail_on.value):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
