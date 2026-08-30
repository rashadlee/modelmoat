"""Verify every package in the CI lockfile actually supports every Python
version this project claims to support and tests in CI.

Why this exists: `pip-compile` resolves against whatever Python version is
running it, so a lockfile regenerated under 3.12 has no way to notice that
a pinned package's latest version dropped support for 3.10 - it works fine
in the environment that generated it and fails only when CI's 3.10 matrix
leg actually tries to install it. `pip install --require-hashes` catches
this at install time, but by then it is a CI failure, potentially on a
tagged release commit. This catches it before the lockfile is committed,
using PyPI's own requires_python metadata rather than needing every
supported interpreter installed locally.

Run this after any `pip-compile --generate-hashes` regeneration of
.github/requirements-lock.txt, before committing it. Not run as part of
the fast unit test suite, since it makes real network calls to PyPI and
has no place blocking every push on that as a dependency - see
RELEASING.md for where this fits in the release process.

Usage:
    python scripts/check_lockfile_python_support.py
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = REPO_ROOT / ".github" / "requirements-lock.txt"
PYPROJECT = REPO_ROOT / "pyproject.toml"

_PACKAGE_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([0-9A-Za-z.]+)", re.MULTILINE)
_CLASSIFIER = re.compile(r'"Programming Language :: Python :: (3\.\d+)"')


def _supported_python_versions() -> list[str]:
    """The versions this project actually claims to support, read from
    pyproject.toml's own classifiers rather than hardcoded here - so this
    script stays correct if the support matrix ever changes without anyone
    remembering to update it in two places.
    """
    text = PYPROJECT.read_text()
    versions = _CLASSIFIER.findall(text)
    if not versions:
        raise SystemExit("no 'Programming Language :: Python :: 3.x' classifiers found")
    return versions


def _requires_python(name: str, version: str) -> str | None:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=15) as response:
        import json

        data = json.load(response)
    return data["info"].get("requires_python")


def main() -> None:
    targets = _supported_python_versions()
    text = LOCKFILE.read_text()
    packages = _PACKAGE_LINE.findall(text)
    if not packages:
        raise SystemExit(f"no pinned packages found in {LOCKFILE}")

    problems: list[str] = []
    for name, version in packages:
        try:
            requires_python = _requires_python(name, version)
        except (urllib.error.URLError, TimeoutError) as exc:
            problems.append(f"{name}=={version}: could not reach PyPI ({exc})")
            continue

        if not requires_python:
            continue
        spec = SpecifierSet(requires_python)
        for target in targets:
            if not spec.contains(Version(f"{target}.0"), prereleases=True):
                problems.append(
                    f"{name}=={version} requires Python {requires_python}, "
                    f"incompatible with the {target} this project claims to support"
                )

    if problems:
        print(f"{len(problems)} problem(s) found across {len(packages)} pinned packages:")
        for problem in problems:
            print(f"  - {problem}")
        raise SystemExit(1)

    print(f"All {len(packages)} pinned packages support {', '.join(targets)}.")


if __name__ == "__main__":
    main()
