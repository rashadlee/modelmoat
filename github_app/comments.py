"""Turns scan findings into GitHub PR review comments.

modelmoat's whole design rests on scanning the entire project graph, never a
single file - that is what lets it see a bucket in s3.tf and its public
access block in security.tf together. A GitHub App must not weaken that: it
always scans the full Terraform tree at the PR's head commit, in full, using
the exact same Scanner the CLI uses. What changes for a PR is only where a
finding is reported, never whether it is found.

A finding becomes an inline review comment only when it sits on a line the
PR actually added, because that is what a reviewer reads "this PR caused it"
to mean, and it is the placement GitHub's review comment API reliably
accepts. Every other finding - on an unchanged line, or in a file the PR
never touched - goes into one summary comment. Nothing is ever silently
dropped just because it cannot be placed inline.
"""

from __future__ import annotations

from dataclasses import dataclass

from modelmoat.scanner import SEVERITY_RANK, Finding


@dataclass(frozen=True)
class InlineComment:
    file_path: str
    line: int
    body: str


def _format_finding(finding: Finding) -> str:
    return (
        f"**{finding.severity} {finding.check_id}** "
        f"`{finding.resource_type}.{finding.resource_name}`\n\n"
        f"{finding.message}\n\n"
        f"Fix: {finding.remediation}"
    )


def classify_findings(
    findings: list[Finding], added_lines_by_file: dict[str, set[int]]
) -> tuple[list[InlineComment], list[Finding]]:
    """Split findings into what becomes an inline comment and what does not."""
    inline: list[InlineComment] = []
    summary: list[Finding] = []

    for finding in findings:
        added = added_lines_by_file.get(finding.file_path)
        if added and finding.line in added:
            inline.append(InlineComment(finding.file_path, finding.line, _format_finding(finding)))
        else:
            summary.append(finding)

    return inline, summary


def summary_body(summary_findings: list[Finding]) -> str:
    """Body text for the one PR comment covering everything not placed inline.

    Empty string when there is nothing to say, so a caller can skip posting a
    comment entirely rather than post an empty one.
    """
    if not summary_findings:
        return ""

    ordered = sorted(summary_findings, key=lambda f: -SEVERITY_RANK.get(f.severity, 0))
    lines = [
        "modelmoat found additional findings outside the lines this PR changed:",
        "",
    ]
    for finding in ordered:
        lines.append(
            f"- **{finding.severity} {finding.check_id}** "
            f"`{finding.resource_type}.{finding.resource_name}` "
            f"at `{finding.file_path}:{finding.line}`"
        )
    return "\n".join(lines)
