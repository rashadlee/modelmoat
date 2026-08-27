"""AWS Lambda Function URL entry point for the GitHub App webhook.

Function URLs use API Gateway payload format version 2.0: the raw body
arrives as event["body"] (base64-encoded when event["isBase64Encoded"] is
true), and headers arrive in event["headers"], lowercased.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import shutil
from pathlib import Path

from github_app.auth import build_jwt
from github_app.comments import classify_findings, summary_body
from github_app.diff import added_lines_by_file
from github_app.events import relevant_pull_request
from github_app.installation import GitHubAppAPIError, exchange_installation_token
from github_app.post_results import post_review_comments, post_summary_comment
from github_app.pr_files import fetch_pr_files
from github_app.signature import verify_signature
from github_app.tree import TreeFetchError, fetch_terraform_tree
from modelmoat.checks import ALL_CHECKS
from modelmoat.scanner import Scanner


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

    top = None
    try:
        jwt_token = build_jwt(os.environ["GITHUB_APP_ID"], os.environ["GITHUB_APP_PRIVATE_KEY"])
        access = exchange_installation_token(jwt_token, target.installation_id)

        # The full tree at head_sha, never just the files the PR touched -
        # a bucket in s3.tf is only correctly evaluated with security.tf
        # also present.
        top = fetch_terraform_tree(access.token, target.repo_full_name, target.head_sha)
        result = Scanner(ALL_CHECKS).scan([top])
        # Findings carry the path they were scanned from, which is an
        # absolute temp directory here - GitHub's diff paths are relative
        # to the repo root, so findings need the same shape to match.
        findings = [
            dataclasses.replace(f, file_path=Path(f.file_path).relative_to(top).as_posix())
            for f in result.findings
        ]

        pr_files = fetch_pr_files(access.token, target.repo_full_name, target.pr_number)
        inline, summary = classify_findings(findings, added_lines_by_file(pr_files))

        post_review_comments(
            access.token, target.repo_full_name, target.pr_number, target.head_sha, inline
        )
        post_summary_comment(
            access.token, target.repo_full_name, target.pr_number, summary_body(summary)
        )
    except (GitHubAppAPIError, TreeFetchError) as exc:
        return _response(
            502, f"upstream error scanning pull_request #{target.pr_number}: {exc}"
        )
    finally:
        if top is not None:
            shutil.rmtree(top.parent, ignore_errors=True)

    return _response(
        200, f"scanned pull_request #{target.pr_number}: {len(findings)} finding(s)"
    )
