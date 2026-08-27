"""AWS Lambda Function URL entry point for the GitHub App webhook.

Function URLs use API Gateway payload format version 2.0: the raw body
arrives as event["body"] (base64-encoded when event["isBase64Encoded"] is
true), and headers arrive in event["headers"], lowercased.
"""

from __future__ import annotations

import base64
import json
import os

from github_app.events import relevant_pull_request
from github_app.signature import verify_signature


def _response(status: int, message: str) -> dict:
    return {
        "statusCode": status,
        "headers": {"content-type": "text/plain"},
        "body": message,
        "isBase64Encoded": False,
    }


def lambda_handler(event: dict, context) -> dict:
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    raw_body = event.get("body") or ""
    body_bytes = (
        base64.b64decode(raw_body)
        if event.get("isBase64Encoded")
        else raw_body.encode("utf-8")
    )

    secret = os.environ["GITHUB_WEBHOOK_SECRET"]
    if not verify_signature(body_bytes, headers.get("x-hub-signature-256"), secret):
        return _response(401, "invalid signature")

    try:
        payload = json.loads(body_bytes)
    except json.JSONDecodeError:
        return _response(400, "invalid JSON body")

    target = relevant_pull_request(headers.get("x-github-event"), payload)
    if target is None:
        return _response(200, "ignored")

    # Scanning and comment posting are the next slice, not this one: fetch
    # the full Terraform tree at target.head_sha via an installation token,
    # run the same Scanner the CLI uses (never a diff-only scan), classify
    # findings with github_app.comments, and post them through the GitHub
    # API. Returning 202 here rather than pretending this is done.
    return _response(202, f"accepted pull_request #{target.pr_number}, scan not yet wired up")
