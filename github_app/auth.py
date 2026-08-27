"""Signs the JWT a GitHub App uses to authenticate to GitHub's API.

A GitHub App does not call the API as itself directly. It signs a short
lived JWT with its own private key, then exchanges that JWT for an
installation-scoped access token (the next piece to build). The JWT alone
only proves "this is App <app_id>" - it cannot act on any specific
repository by itself, and is never sent anywhere except that one token
exchange call.
"""

from __future__ import annotations

import time

import jwt

# GitHub rejects a JWT whose (exp - iat) exceeds 10 minutes. This stays
# comfortably under that with a minute of margin.
_LIFETIME_SECONDS = 9 * 60
# GitHub's own docs recommend backdating iat by 60 seconds to tolerate clock
# drift between this service and GitHub's servers.
_CLOCK_SKEW_SECONDS = 60


def build_jwt(app_id: str, private_key_pem: str, *, now: int | None = None) -> str:
    """Build and sign a GitHub App JWT, valid for the next several minutes.

    now is the current Unix time in seconds, injectable so tests can assert
    exact claim values instead of racing the real clock. Defaults to the
    real current time when omitted.
    """
    if now is None:
        now = int(time.time())

    iat = now - _CLOCK_SKEW_SECONDS
    payload = {
        "iat": iat,
        "exp": iat + _LIFETIME_SECONDS,
        "iss": str(app_id),
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")
