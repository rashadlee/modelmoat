"""Fetches the full Terraform tree at a PR's head commit.

modelmoat's whole design rests on scanning the entire project graph, never
a single file or a diff - a bucket in s3.tf is only correctly evaluated
because its public access block in security.tf is visible too. This always
downloads the complete repository tree at the given ref, the same files a
full clone would give the CLI, never just the files a PR touched.
"""

from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path

import requests

_API_BASE = "https://api.github.com"


class TreeFetchError(Exception):
    """Raised when the repository tree could not be downloaded or extracted."""


def _safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    """Extract only members that resolve to a path inside destination.

    Blindly calling extractall() on an unvalidated tarball is a well known
    path-traversal risk (a member named like ../../etc/passwd escaping the
    target directory). This is GitHub's own archive of a repository the App
    is installed on, not attacker-controlled input in the usual sense, but a
    security tool should not skip a check this cheap on principle.

    The manual check below runs first so a path-traversal attempt raises
    modelmoat's own clear error rather than tarfile's. filter="data" (the
    behavior Python 3.14 makes the default; see PEP 706) then adds real
    protection this hand check does not cover: device files, unsafe symlink
    or hardlink targets, and setuid/setgid bits.
    """
    destination = destination.resolve()
    for member in tar.getmembers():
        member_path = (destination / member.name).resolve()
        if not member_path.is_relative_to(destination):
            raise TreeFetchError(f"tarball member escapes extraction directory: {member.name}")
    tar.extractall(destination, filter="data")


def fetch_terraform_tree(token: str, repo_full_name: str, ref: str) -> Path:
    """Download the repo tree at ref into a fresh temp directory.

    Returns the path to the single top-level directory GitHub's tarball
    extracts into (named like <owner>-<repo>-<short-sha>) - that directory,
    not the temp dir itself, is what Scanner should be pointed at.
    """
    response = requests.get(
        f"{_API_BASE}/repos/{repo_full_name}/tarball/{ref}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30,
    )
    if response.status_code != 200:
        raise TreeFetchError(
            f"could not download tree for {repo_full_name}@{ref} "
            f"(status {response.status_code}): {response.text[:200]}"
        )

    extract_to = Path(tempfile.mkdtemp(prefix="modelmoat-tree-"))
    try:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            _safe_extract(tar, extract_to)
    except tarfile.TarError as exc:
        raise TreeFetchError(f"downloaded archive is not a valid tarball: {exc}") from exc

    top_level = [p for p in extract_to.iterdir() if p.is_dir()]
    if len(top_level) != 1:
        raise TreeFetchError(
            "expected exactly one top-level directory in the tarball, found "
            f"{len(top_level)}"
        )
    return top_level[0]
