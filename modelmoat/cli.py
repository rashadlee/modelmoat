"""modelmoat command line interface."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from . import __version__
from .checks import ALL_CHECKS
from .scanner import SEVERITIES, SEVERITY_RANK, Scanner

app = typer.Typer(
    name="modelmoat",
    help="Static analysis for AI infrastructure security in Terraform.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)

_COLORS = {
    "CRITICAL": "red",
    "HIGH": "bright_red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"modelmoat {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Dig a moat around your models."""


def _validate_severity(value: str, option: str) -> str:
    upper = value.upper()
    if upper not in SEVERITIES:
        error_console.print(
            f"[red]{option} must be one of {', '.join(SEVERITIES)}[/red]"
        )
        raise typer.Exit(code=2)
    return upper


@app.command()
def scan(
    paths: Annotated[
        list[Path],
        typer.Argument(
            exists=True,
            dir_okay=True,
            file_okay=True,
            help="Terraform files or directories to scan.",
        ),
    ],
    json_out: Annotated[
        bool, typer.Option("--json", "-j", help="Emit machine-readable JSON on stdout.")
    ] = False,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            "-s",
            help="Lowest severity to report (LOW, MEDIUM, HIGH, CRITICAL).",
        ),
    ] = "LOW",
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit non-zero when findings at or above this severity exist. "
            "Set to CRITICAL to loosen, LOW to tighten.",
        ),
    ] = "HIGH",
) -> None:
    """Scan Terraform for AI infrastructure security issues."""
    min_severity = _validate_severity(min_severity, "--min-severity")
    fail_on = _validate_severity(fail_on, "--fail-on")

    result = Scanner(ALL_CHECKS).scan(paths)
    exit_code = 1 if result.max_rank() >= SEVERITY_RANK[fail_on] else 0

    minimum = SEVERITY_RANK[min_severity]
    result.findings = [
        f for f in result.findings if SEVERITY_RANK.get(f.severity, 0) >= minimum
    ]

    if json_out:
        sys.stdout.write(result.to_json())
        sys.stdout.write("\n")
        raise typer.Exit(code=exit_code)

    console.print()
    console.print(
        f"[bold]modelmoat[/bold] {__version__} scanned "
        f"[bold]{result.files_scanned}[/bold] Terraform file(s)"
    )
    console.print(
        f"  [red]CRITICAL:[/red] {result.count('CRITICAL')}  "
        f"[bright_red]HIGH:[/bright_red] {result.count('HIGH')}  "
        f"[yellow]MEDIUM:[/yellow] {result.count('MEDIUM')}  "
        f"[blue]LOW:[/blue] {result.count('LOW')}"
    )

    for parse_error in result.parse_errors:
        error_console.print(
            f"[yellow]warning:[/yellow] could not parse "
            f"{parse_error['file']}: {parse_error['error']}"
        )

    console.print()

    if not result.findings:
        console.print("[green]No findings at or above the requested severity.[/green]")
        raise typer.Exit(code=exit_code)

    for finding in result.findings:
        color = _COLORS.get(finding.severity, "white")
        console.print(
            f"[{color}]{finding.severity:<8}[/{color}] [bold]{finding.check_id}[/bold]  "
            f"{finding.resource_type}.{finding.resource_name}"
        )
        console.print(f"         [dim]{finding.file_path}:{finding.line}[/dim]")
        console.print(f"         {finding.message}")
        console.print(f"         [dim]fix:[/dim] {finding.remediation}")
        console.print()

    console.print(
        "[dim]--json for machine-readable output, --min-severity to filter, "
        "--fail-on to tune CI exit codes.[/dim]"
    )
    raise typer.Exit(code=exit_code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
