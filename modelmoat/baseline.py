"""Baseline files, so a team can adopt modelmoat without fixing everything first.

A baseline records the findings that already exist in a codebase. Later scans
suppress those and report only what was added afterwards. The file is a list of
accepted risk, so it is written to be readable in a pull request rather than as
an opaque set of hashes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .scanner import SEVERITY_RANK, Finding

BASELINE_FORMAT = 1


class BaselineError(Exception):
    """A baseline file could not be read or understood."""


@dataclass
class BaselineComparison:
    """What a baseline did to a set of findings."""

    active: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    # Findings that are suppressed but are more severe than when recorded.
    # Reported rather than un-suppressed, because silently changing what a
    # baseline hides would be worse than saying so.
    escalated: list[tuple[Finding, str]] = field(default_factory=list)
    # Baseline entries with no matching finding, usually because they were
    # fixed. Worth pruning so the file keeps reflecting real accepted risk.
    stale: list[dict] = field(default_factory=list)


def write_baseline(path: Path, findings: list[Finding]) -> None:
    """Record findings to a baseline file."""
    payload = {
        "tool": "modelmoat",
        "format": BASELINE_FORMAT,
        "tool_version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "check_id": finding.check_id,
                "severity": finding.severity,
                "resource": f"{finding.resource_type}.{finding.resource_name}",
                "file_path": finding.file_path,
            }
            for finding in findings
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict[str, dict]:
    """Read a baseline file into a fingerprint -> entry map."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline file not found: {path}") from exc
    except OSError as exc:
        raise BaselineError(f"could not read baseline file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file is not valid JSON: {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise BaselineError(f"baseline file is not a JSON object: {path}")

    entries = raw.get("findings")
    if not isinstance(entries, list):
        raise BaselineError(f"baseline file has no findings list: {path}")

    by_fingerprint: dict[str, dict] = {}
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str):
            by_fingerprint[entry["fingerprint"]] = entry
    return by_fingerprint


def apply_baseline(
    findings: list[Finding], baseline: dict[str, dict]
) -> BaselineComparison:
    """Split findings into those the baseline covers and those it does not."""
    comparison = BaselineComparison()
    matched: set[str] = set()

    for finding in findings:
        entry = baseline.get(finding.fingerprint)
        if entry is None:
            comparison.active.append(finding)
            continue

        matched.add(finding.fingerprint)
        comparison.suppressed.append(finding)

        recorded = entry.get("severity")
        if isinstance(recorded, str) and SEVERITY_RANK.get(
            finding.severity, 0
        ) > SEVERITY_RANK.get(recorded, 0):
            comparison.escalated.append((finding, recorded))

    comparison.stale = [
        entry for fingerprint, entry in baseline.items() if fingerprint not in matched
    ]
    return comparison
