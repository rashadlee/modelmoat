"""modelmoat: static analysis for AI infrastructure security in Terraform."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("modelmoat")
except PackageNotFoundError:  # running from source without an install
    __version__ = "0.0.0-dev"
