"""Fetches the GitHub App's private key and webhook secret from Secrets Manager.

Plain Lambda environment variables are readable in plaintext by anyone with
lambda:GetFunctionConfiguration on this function. Secrets Manager keeps them
encrypted at rest and logs every read via CloudTrail, at the cost of one
extra API call - cached at module scope so a warm container pays that cost
once, not on every webhook delivery.
"""

from __future__ import annotations

import json
import os

import boto3

_cached: dict | None = None


def get_credentials() -> dict:
    """Return {"GITHUB_APP_PRIVATE_KEY": ..., "GITHUB_WEBHOOK_SECRET": ...}."""
    global _cached
    if _cached is None:
        client = boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=os.environ["GITHUB_CREDENTIALS_SECRET_ARN"])
        _cached = json.loads(response["SecretString"])
    return _cached
