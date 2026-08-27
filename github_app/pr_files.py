"""Fetches the list of files a pull request changed.

Feeds github_app.diff.added_lines_by_file() so a finding can be classified as
inline (on a line the PR itself added) or summary (everything else). This is
the only place a diff enters the pipeline - the scan itself still runs
against the full tree tree.py fetched, never against this file list alone.
"""

from __future__ import annotations

import requests

from github_app.installation import GitHubAppAPIError

_API_BASE = "https://api.github.com"
_HEADERS_VERSION = "2022-11-28"
_PER_PAGE = 100


def fetch_pr_files(token: str, repo_full_name: str, pull_number: int) -> list[dict]:
    """GET /repos/{repo}/pulls/{pull_number}/files, following pagination.

    GitHub defaults to 30 results per page and caps per_page at 100, so a PR
    touching more than 30 files silently truncates without this loop. GitHub
    caps the total at 3000 files regardless; nothing here needs to enforce
    that separately.
    """
    files: list[dict] = []
    page = 1
    while True:
        response = requests.get(
            f"{_API_BASE}/repos/{repo_full_name}/pulls/{pull_number}/files",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": _HEADERS_VERSION,
            },
            params={"per_page": _PER_PAGE, "page": page},
            timeout=10,
        )
        if response.status_code != 200:
            raise GitHubAppAPIError(
                f"GitHub refused to list files for {repo_full_name}#{pull_number} "
                f"(status {response.status_code}): {response.text[:200]}"
            )
        batch = response.json()
        files.extend(batch)
        if len(batch) < _PER_PAGE:
            return files
        page += 1
