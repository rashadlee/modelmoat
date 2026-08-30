"""modelmoat: static analysis for AI infrastructure security in Terraform."""

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _read_version_from_pyproject() -> str:
    """Fall back to pyproject.toml's own version when the package metadata
    is unavailable - running from an uninstalled source checkout, most often
    a fresh clone or a release script invoked before `pip install -e .`. A
    hardcoded fallback string would silently drift from the real version
    (pyproject.toml is the single source of it) instead of ever failing
    loudly on that drift; reading it directly closes that gap. Only the
    `[project]` table's own `version = "..."` line is expected to match this
    pattern in this file - nothing else in pyproject.toml declares one.
    """
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        text = pyproject.read_text(encoding="utf-8")
    except OSError:
        return "0.0.0-dev"
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "0.0.0-dev"


try:
    __version__ = version("modelmoat")
except PackageNotFoundError:  # running from source without an install
    __version__ = _read_version_from_pyproject()
