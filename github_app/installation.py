"""Exchanges a signed App JWT for a short-lived installation access token.

A JWT only proves "this is App <app_id>." An installation access token is
what actually lets the App act on one specific installation - read
repository contents, post PR comments - scoped to whatever repositories and
permissions that installation was granted, and expires about an hour after
issue.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

_API_BASE = "https://api.github.com"
_HEADERS_VERSION = "2022-11-28"


class GitHubAppAPIError(Exception):
    """Raised when GitHub refuses an App-authenticated API request."""


@dataclass(frozen=True)
class InstallationToken:
    token: str
    expires_at: str


def _jwt_headers(jwt_token: str) -> dict:
    return {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _HEADERS_VERSION,
    }


def exchange_installation_token(jwt_token: str, installation_id: int) -> InstallationToken:
    """POST /app/installations/{id}/access_tokens - the token itself, never logged."""
    response = requests.post(
        f"{_API_BASE}/app/installations/{installation_id}/access_tokens",
        headers=_jwt_headers(jwt_token),
        timeout=10,
    )
    if response.status_code != 201:
        raise GitHubAppAPIError(
            f"GitHub refused the installation token request "
            f"(status {response.status_code}): {response.text[:200]}"
        )
    body = response.json()
    return InstallationToken(token=body["token"], expires_at=body["expires_at"])


def list_installations(jwt_token: str) -> list[dict]:
    """GET /app/installations - every account this App is installed on.

    Used to look up an installation_id by account login rather than asking
    a human to go find it in GitHub's UI. Installation IDs are not secret.
    """
    response = requests.get(
        f"{_API_BASE}/app/installations",
        headers=_jwt_headers(jwt_token),
        timeout=10,
    )
    if response.status_code != 200:
        raise GitHubAppAPIError(
            f"GitHub refused to list installations "
            f"(status {response.status_code}): {response.text[:200]}"
        )
    return response.json()
