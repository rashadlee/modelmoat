"""Posts a scan's results back to a pull request.

Two separate calls, matching how comments.classify_findings already split
the findings: inline review comments for what landed on a line the PR added,
and one summary comment for everything else. Neither call happens if there
is nothing to say - an empty review or an empty comment is noise, not
information.
"""

from __future__ import annotations

import requests

from github_app.comments import InlineComment
from github_app.installation import GitHubAppAPIError

_API_BASE = "https://api.github.com"
_HEADERS_VERSION = "2022-11-28"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _HEADERS_VERSION,
    }


def post_review_comments(
    token: str,
    repo_full_name: str,
    pull_number: int,
    commit_id: str,
    comments: list[InlineComment],
) -> None:
    """Post every inline comment as one review, submitted immediately.

    event="COMMENT" submits the review right away as a plain comment-only
    review - leaving event unset would create a PENDING review nobody but
    the App's own account could see or submit. A comment whose line is not
    part of the diff GitHub computed for this commit makes the whole
    request fail (422): this only matters if the diff GitHub sees at
    review time has drifted from the one added_lines_by_file was built
    from, which callers should treat as a real error, not silently drop.
    """
    if not comments:
        return

    response = requests.post(
        f"{_API_BASE}/repos/{repo_full_name}/pulls/{pull_number}/reviews",
        headers=_headers(token),
        json={
            "commit_id": commit_id,
            "event": "COMMENT",
            "comments": [
                {"path": c.file_path, "line": c.line, "body": c.body} for c in comments
            ],
        },
        timeout=15,
    )
    if response.status_code != 200:
        raise GitHubAppAPIError(
            f"GitHub refused the review for {repo_full_name}#{pull_number} "
            f"(status {response.status_code}): {response.text[:200]}"
        )


def post_summary_comment(
    token: str, repo_full_name: str, pull_number: int, body: str
) -> None:
    """Post one issue comment. A pull request's number is also its issue number."""
    if not body:
        return

    response = requests.post(
        f"{_API_BASE}/repos/{repo_full_name}/issues/{pull_number}/comments",
        headers=_headers(token),
        json={"body": body},
        timeout=15,
    )
    if response.status_code != 201:
        raise GitHubAppAPIError(
            f"GitHub refused the summary comment for {repo_full_name}#{pull_number} "
            f"(status {response.status_code}): {response.text[:200]}"
        )
