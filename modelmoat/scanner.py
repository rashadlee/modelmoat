"""Scanner core: findings, results, and the check orchestrator."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from . import __version__
from .graph import ProjectGraph, build_graph

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES, start=1)}


@dataclass(frozen=True)
class Finding:
    """A single security finding."""

    check_id: str
    check_name: str
    severity: str
    resource_type: str
    resource_name: str
    file_path: str
    line: int
    message: str
    remediation: str
    docs_url: str = ""
    # Distinguishes findings when one check reports several problems on the
    # same resource, for example an OpenSearch domain that is both publicly
    # reachable and unencrypted. A short stable token, never prose, because it
    # is part of the fingerprint and must survive rewording.
    detail: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable identity for this finding, deliberately excluding the line.

        Baselines and SARIF alert history both need to recognise the same
        finding across commits. Editing lines above a finding moves its line
        number without changing the finding, so the resource identity is hashed
        instead. Message wording is excluded for the same reason: rewording a
        finding must not orphan its history.

        `detail` is included because without it every finding a check reports
        against one resource collides, and baselining the mildest would silently
        suppress the worst.
        """
        parts = (
            self.check_id,
            Path(self.file_path).as_posix(),
            self.resource_type,
            self.resource_name,
            self.detail,
        )
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "severity": self.severity,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "file_path": self.file_path,
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
            "docs_url": self.docs_url,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    """Aggregated result of a scan, including files that failed to parse."""

    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    parse_errors: list[dict] = field(default_factory=list)

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def files_with_issues(self) -> int:
        return len({f.file_path for f in self.findings})

    def max_rank(self) -> int:
        return max((SEVERITY_RANK.get(f.severity, 0) for f in self.findings), default=0)

    def to_dict(self) -> dict:
        return {
            "tool": "modelmoat",
            "version": __version__,
            "summary": {
                "files_scanned": self.files_scanned,
                "files_with_issues": self.files_with_issues,
                "total_findings": len(self.findings),
                "critical": self.count("CRITICAL"),
                "high": self.count("HIGH"),
                "medium": self.count("MEDIUM"),
                "low": self.count("LOW"),
                "parse_errors": len(self.parse_errors),
            },
            "parse_errors": self.parse_errors,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class Check(Protocol):
    """Every check exposes an id, a name, and a run over the whole project graph."""

    check_id: str
    check_name: str

    def run(self, graph: ProjectGraph) -> list[Finding]: ...


class Scanner:
    """Builds one project graph from the scanned paths and runs every check on it."""

    def __init__(self, checks: Iterable[Check]) -> None:
        self.checks = list(checks)

    def scan(self, paths: Iterable[Path]) -> ScanResult:
        graph = build_graph(paths)

        findings: list[Finding] = []
        for check in self.checks:
            findings.extend(check.run(graph))

        findings.sort(
            key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.file_path, f.line, f.check_id)
        )

        return ScanResult(
            files_scanned=graph.files_scanned,
            findings=findings,
            parse_errors=[
                {"file": str(path), "error": message}
                for path, message in graph.parse_errors
            ],
        )
