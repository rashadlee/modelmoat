"""Unified diff parsing: which lines did a PR actually add.

GitHub's pull request files API returns a `patch` field per file containing a
unified diff. modelmoat findings carry a line number in the file as it exists
at the PR's head commit. To know whether a finding can become an inline
review comment, we need the set of new-file line numbers the diff added, not
just which lines are visible inside a hunk.
"""

from __future__ import annotations

import re

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(patch: str) -> set[int]:
    """Return the new-file line numbers this patch added.

    Only lines the diff actually introduces count, not unchanged lines a hunk
    happens to show as context. A finding on an added line is something this
    PR introduced; a finding merely visible in a hunk's context was not, and
    should not read as "the PR caused this."
    """
    lines_added: set[int] = set()
    current_line: int | None = None

    for raw in patch.splitlines():
        header = _HUNK_HEADER.match(raw)
        if header:
            current_line = int(header.group(1))
            continue
        if current_line is None:
            continue  # text before the first hunk header, ignore

        if raw.startswith("+") and not raw.startswith("+++"):
            lines_added.add(current_line)
            current_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            pass  # removed line: only existed in the old file, no new line number
        else:
            current_line += 1  # context line: unchanged, still consumes a new-file line

    return lines_added


def added_lines_by_file(pr_files: list[dict]) -> dict[str, set[int]]:
    """Build a file path -> added line numbers map from a PR files API response.

    A renamed-with-no-content-change file, or a binary file, has no `patch`
    key at all. Skip it rather than guess.
    """
    result: dict[str, set[int]] = {}
    for entry in pr_files:
        patch = entry.get("patch")
        filename = entry.get("filename")
        if not patch or not filename:
            continue
        result[filename] = added_lines(patch)
    return result
