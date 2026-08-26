"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__
from .scanner import SEVERITY_RANK

if TYPE_CHECKING:
    from .scanner import Check, Finding, ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/rashadlee/modelmoat"

# SARIF has four levels. CRITICAL and HIGH both map to error because both fail a
# build at the default --fail-on. MEDIUM and LOW are hygiene and should not read
# as failures in a code scanning UI.
_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# GitHub code scanning buckets alerts by this numeric property rather than by
# SARIF level: >= 9.0 critical, >= 7.0 high, >= 4.0 medium, below that low.
_SECURITY_SEVERITY = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "4.0",
    "LOW": "1.0",
}


def _fingerprint(finding: Finding) -> str:
    """Stable identity for a finding, deliberately excluding the line number.

    Consumers use partialFingerprints to match an alert across commits. Editing
    lines above a finding moves its line number without changing the finding, so
    the resource identity is hashed instead.
    """
    parts = (
        finding.check_id,
        Path(finding.file_path).as_posix(),
        finding.resource_type,
        finding.resource_name,
    )
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _build_rules(
    checks: Iterable[Check] | None, findings: list[Finding]
) -> tuple[list[dict], dict[str, int]]:
    """Return the rule catalog and a check_id -> index map.

    The catalog lists every check the tool can run, not only the ones that fired,
    so a consumer sees the full rule set from any single run.
    """
    docs_by_check: dict[str, str] = {}
    for finding in findings:
        if finding.docs_url and finding.check_id not in docs_by_check:
            docs_by_check[finding.check_id] = finding.docs_url

    rules: list[dict] = []
    index: dict[str, int] = {}

    def add(check_id: str, name: str) -> None:
        if check_id in index:
            return
        rule: dict = {
            "id": check_id,
            "name": name,
            "shortDescription": {"text": name},
        }
        docs_url = docs_by_check.get(check_id)
        if docs_url:
            rule["helpUri"] = docs_url
        index[check_id] = len(rules)
        rules.append(rule)

    for check in checks or ():
        add(check.check_id, check.check_name)

    # A finding from a check outside the registry still needs a rule entry,
    # otherwise its ruleIndex would dangle.
    for finding in findings:
        add(finding.check_id, finding.check_name)

    return rules, index


def to_sarif(result: ScanResult, checks: Iterable[Check] | None = None) -> dict:
    """Convert a ScanResult into a SARIF 2.1.0 log."""
    findings = result.findings
    rules, rule_index = _build_rules(checks, findings)

    # A single check spans severities (S3-001 runs CRITICAL to LOW), so the exact
    # value lives on each result. The rule carries the worst severity that check
    # produced in this run, since some consumers read security-severity from the
    # rule rather than the result.
    worst: dict[str, str] = {}
    for finding in findings:
        current = worst.get(finding.check_id)
        if current is None or SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(
            current, 0
        ):
            worst[finding.check_id] = finding.severity

    for rule in rules:
        severity = worst.get(rule["id"], "MEDIUM")
        rule["properties"] = {
            "tags": ["security", "terraform", "ai-infrastructure"],
            "security-severity": _SECURITY_SEVERITY[severity],
        }

    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.check_id,
                "ruleIndex": rule_index[finding.check_id],
                "level": _LEVELS.get(finding.severity, "warning"),
                "message": {"text": f"{finding.message}\n\nFix: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": Path(finding.file_path).as_posix()
                            },
                            # SARIF requires a 1-based line. Line numbers come
                            # from a regex scan of the source, so guard the case
                            # where that finds nothing.
                            "region": {"startLine": max(finding.line, 1)},
                        }
                    }
                ],
                "partialFingerprints": {"modelmoatFindingV1": _fingerprint(finding)},
                "properties": {
                    "severity": finding.severity,
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                    "resource": f"{finding.resource_type}.{finding.resource_name}",
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "modelmoat",
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif_json(result: ScanResult, checks: Iterable[Check] | None = None) -> str:
    return json.dumps(to_sarif(result, checks), indent=2)
