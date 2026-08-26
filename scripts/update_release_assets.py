"""Regenerate the README's example output for a release.

Run this after bumping the version and before publishing, whenever the
fixtures or a finding's wording has changed. It renders real scan output
(never invented numbers) and writes both the two screenshot SVGs under
assets/screenshots/ and a plain-text block for README.md's "Real output
from the test fixtures in this repo" section.

The SVG and the plain text come from the same render, so they cannot drift
from each other. They can still drift from README.md itself, since nothing
edits the README automatically: paste the printed block in by hand after
running this.

Usage:
    python scripts/update_release_assets.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Findings carry whatever path the scanner was given verbatim, so run from the
# repo root with relative paths - otherwise finding.file_path comes out
# absolute, which is not what the README or the real CLI shows.
os.chdir(REPO_ROOT)

from rich.console import Console

from modelmoat import __version__
from modelmoat.checks import ALL_CHECKS
from modelmoat.scanner import Scanner

OUT_DIR = REPO_ROOT / "assets" / "screenshots"

_COLORS = {
    "CRITICAL": "red",
    "HIGH": "bright_red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def render_scan(paths, out_name, curated_check_ids=None, prompt="modelmoat scan infra/"):
    """Render one scan to a Console, returning it for both SVG and text export."""
    console = Console(record=True, width=100, force_terminal=True, highlight=False)
    result = Scanner(ALL_CHECKS).scan(paths)

    console.print(f"[bold green]$[/bold green] [bold]{prompt}[/bold]")
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
    console.print()

    if not result.findings:
        console.print("[green]No findings at or above the requested severity.[/green]")
    else:
        findings = result.findings
        if curated_check_ids is not None:
            seen = set()
            curated = []
            for cid, resource_name in curated_check_ids:
                for f in findings:
                    if f.check_id == cid and f.resource_name == resource_name and cid not in seen:
                        curated.append(f)
                        seen.add(cid)
                        break
            findings = curated

        for finding in findings:
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

    return console, result


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    insecure_console, _insecure_result = render_scan(
        [Path("tests/fixtures/insecure")],
        "scan-insecure.svg",
        curated_check_ids=[("S3-001", "datasets"), ("IAM-001", "full_access")],
    )
    # Both export_text() and save_svg() clear the recorded buffer by default.
    # Each console here is used once, so there is nothing to protect by
    # clearing - pass clear=False on both or the second call silently exports
    # a near-empty buffer instead of failing loudly.
    text = insecure_console.export_text(clear=False, styles=False).rstrip("\n")
    insecure_console.save_svg(
        str(OUT_DIR / "scan-insecure.svg"),
        title="modelmoat",
        clear=False,
        # A fixed id, not Rich's default random one, so re-running this with
        # unchanged output produces a byte-identical file instead of a
        # spurious diff on every release.
        unique_id="modelmoat-scan-insecure",
    )
    print(f"wrote {OUT_DIR / 'scan-insecure.svg'}")

    secure_console, secure_result = render_scan(
        [Path("tests/fixtures/secure")],
        "scan-secure.svg",
    )
    secure_console.save_svg(
        str(OUT_DIR / "scan-secure.svg"),
        title="modelmoat",
        unique_id="modelmoat-scan-secure",
    )
    print(f"wrote {OUT_DIR / 'scan-secure.svg'}")

    if secure_result.findings:
        print(
            f"\nWARNING: the secure fixture produced {len(secure_result.findings)} "
            "finding(s). That fixture must always be clean; fix this before "
            "releasing, do not just accept the new screenshot.",
            file=sys.stderr,
        )
    print("\n" + "=" * 70)
    print("Paste this into README.md's fenced code block under ## Usage,")
    print("replacing the existing 'Real output from the test fixtures' example:")
    print("=" * 70)
    print(text)
    print("=" * 70)


if __name__ == "__main__":
    main()
