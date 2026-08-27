"""Verifies that a webhook delivery actually came from GitHub.

GitHub signs every delivery with HMAC-SHA256 over the raw request body,
keyed with the webhook secret configured when the App was registered. This
is the only thing standing between "anyone who finds the URL" and "GitHub" -
the webhook endpoint is otherwise a public, unauthenticated HTTP endpoint.
"""

from __future__ import annotations

import hashlib
import hmac

_PREFIX = "sha256="


def verify_signature(payload: bytes, signature_header: str | None, secret: str) -> bool:
    """True only if signature_header is a valid HMAC-SHA256 of payload under secret.

    Compares with hmac.compare_digest, not ==. A naive equality check returns
    as soon as the first byte differs, which leaks how many leading bytes of
    a guess were correct through response timing - a slow but real way to
    forge a valid signature one byte at a time. compare_digest always takes
    the same time regardless of where the mismatch is.
    """
    if not signature_header or not signature_header.startswith(_PREFIX):
        return False

    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    provided = signature_header[len(_PREFIX) :]
    return hmac.compare_digest(expected, provided)
