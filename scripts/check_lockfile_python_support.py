"""Verify the CI lockfile actually works on every Python version this project
claims to support - not just the one that generated it.

`pip-compile` resolves against whatever interpreter runs it, and gets this
wrong for other versions in two separate ways. Both have already broken a
real release:

  1. A pinned package's version may not support an older Python at all.
     `rpds-py` was pinned to a release requiring >=3.11 while this project
     supports >=3.10 - fine on the 3.12 that generated it, broken on CI's
     3.10 leg.

  2. A dependency gated behind a `python_version` marker is omitted
     entirely when the marker is false for the generating interpreter.
     `pytest` needs `exceptiongroup` and `tomli` on <3.11 and `build` needs
     `tomli`; a lockfile generated under 3.12 contains none of them, so
     `pip install --require-hashes` on 3.10 fails - it needs a package the
     lockfile has no hash for, and hash mode refuses to install anything
     unhashed.

The second one is why generating this lockfile under the LOWEST supported
Python version is not optional: doing so includes the backports, and their
markers make them inert on newer versions. See RELEASING.md.

This script checks both. It makes real PyPI network calls, so it is not part
of the fast unit test suite - run it after regenerating the lockfile, before
committing it.

Usage:
    python scripts/check_lockfile_python_support.py
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from packaging.markers import UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
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
    versions = _CLASSIFIER.findall(PYPROJECT.read_text())
    if not versions:
        raise SystemExit("no 'Programming Language :: Python :: 3.x' classifiers found")
    return versions


def _metadata(name: str, version: str) -> dict:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=15) as response:
        return json.load(response)


def _marker_applies(requirement: Requirement, python_version: str) -> bool:
    """True when this requirement is needed on the given Python version.

    Requirements gated on an `extra` are skipped: whether an extra is
    installed is a property of how the lockfile was compiled (`--extra=dev`
    here), not of the Python version, and evaluating them without knowing
    the extra raises rather than answering. The marker-gated dependencies
    this check exists to catch (`exceptiongroup`, `tomli`) are gated on
    python_version alone, not behind an extra.
    """
    if requirement.marker is None:
        return True
    if "extra" in str(requirement.marker):
        return False
    try:
        return requirement.marker.evaluate({"python_version": python_version})
    except UndefinedEnvironmentName:
        return False


def main() -> None:
    targets = _supported_python_versions()
    packages = _PACKAGE_LINE.findall(LOCKFILE.read_text())
    if not packages:
        raise SystemExit(f"no pinned packages found in {LOCKFILE}")

    locked = {canonicalize_name(name) for name, _ in packages}
    problems: list[str] = []

    for name, version in packages:
        try:
            data = _metadata(name, version)
        except (urllib.error.URLError, TimeoutError) as exc:
            problems.append(f"{name}=={version}: could not reach PyPI ({exc})")
            continue

        # Check 1: does this pinned version support every target at all?
        requires_python = data["info"].get("requires_python")
        if requires_python:
            spec = SpecifierSet(requires_python)
            for target in targets:
                if not spec.contains(Version(f"{target}.0"), prereleases=True):
                    problems.append(
                        f"{name}=={version} requires Python {requires_python}, "
                        f"incompatible with the {target} this project supports"
                    )

        # Check 2: is every dependency it needs on a target version actually
        # in the lockfile? A marker-gated backport omitted at compile time
        # is invisible to check 1 and fails only at install time.
        for raw in data["info"].get("requires_dist") or []:
            try:
                requirement = Requirement(raw)
            except InvalidRequirement:
                continue
            if canonicalize_name(requirement.name) in locked:
                continue
            for target in targets:
                if _marker_applies(requirement, target):
                    problems.append(
                        f"{name}=={version} needs '{requirement.name}' on Python "
                        f"{target} ({raw}), but it is not in the lockfile - "
                        "regenerate under the lowest supported Python version"
                    )
                    break

    if problems:
        print(f"{len(problems)} problem(s) found across {len(packages)} pinned packages:")
        for problem in problems:
            print(f"  - {problem}")
        raise SystemExit(1)

    print(f"All {len(packages)} pinned packages resolve correctly on {', '.join(targets)}.")


if __name__ == "__main__":
    main()
