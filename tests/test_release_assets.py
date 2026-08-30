"""MM-21 regression: the release-asset generator must not write assets from
an unvalidated scan, and modelmoat's version must be single-sourced from
pyproject.toml rather than an independent hardcoded fallback.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

from modelmoat.scanner import Finding, ScanResult

REPO_ROOT = Path(__file__).parent.parent


def _load_module(relative_path: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_release_assets = _load_module("scripts/update_release_assets.py")

CURATED = [("S3-001", "datasets"), ("IAM-001", "full_access")]


def _finding(check_id: str, resource_name: str, **overrides) -> Finding:
    base = {
        "check_id": check_id,
        "check_name": "x",
        "severity": "CRITICAL",
        "resource_type": "aws_s3_bucket",
        "resource_name": resource_name,
        "file_path": "x.tf",
        "line": 1,
        "message": "m",
        "remediation": "r",
    }
    base.update(overrides)
    return Finding(**base)


def test_validate_passes_when_everything_curated_is_present_and_secure_is_clean():
    insecure = ScanResult(
        findings=[_finding("S3-001", "datasets"), _finding("IAM-001", "full_access")]
    )
    secure = ScanResult(findings=[])
    assert _release_assets.validate_before_writing(insecure, secure, CURATED) == []


def test_validate_fails_when_secure_fixture_has_findings():
    # MM-21 regression: this used to be a warning the run still exited 0
    # after, with the screenshot already written.
    insecure = ScanResult(
        findings=[_finding("S3-001", "datasets"), _finding("IAM-001", "full_access")]
    )
    secure = ScanResult(findings=[_finding("S3-001", "oops")])
    errors = _release_assets.validate_before_writing(insecure, secure, CURATED)
    assert any("secure fixture" in e for e in errors)


def test_validate_fails_when_a_curated_finding_is_missing():
    # MM-21 regression: a check silently no longer firing on the insecure
    # fixture was never asserted at all.
    insecure = ScanResult(findings=[_finding("S3-001", "datasets")])  # IAM-001 missing
    secure = ScanResult(findings=[])
    errors = _release_assets.validate_before_writing(insecure, secure, CURATED)
    assert any("IAM-001" in e for e in errors)


def test_version_is_single_sourced_from_pyproject_toml():
    # MM-21 regression: the "not installed" fallback used to be a hardcoded
    # "0.0.0-dev" string, independent of pyproject.toml's real version.
    import modelmoat

    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text()
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject_text)
    assert match is not None
    assert modelmoat._read_version_from_pyproject() == match.group(1)
