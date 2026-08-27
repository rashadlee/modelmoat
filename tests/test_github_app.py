"""github_app tests.

The whole point of this component is that it must never weaken modelmoat's
own scanning guarantees just because it is diff-aware about comment
placement. These tests exist to prove that in isolation, with synthetic
diffs and findings, before any of it depends on a live webhook or hosting.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import tarfile
import time
from unittest.mock import Mock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from github_app.auth import build_jwt
from github_app.comments import InlineComment, classify_findings, summary_body
from github_app.diff import added_lines, added_lines_by_file
from github_app.events import PullRequestTarget, relevant_pull_request
from github_app.handler import lambda_handler
from github_app.installation import (
    GitHubAppAPIError,
    InstallationToken,
    exchange_installation_token,
    list_installations,
)
from github_app.signature import verify_signature
from github_app.tree import TreeFetchError, fetch_terraform_tree
from modelmoat.scanner import Finding


def _generate_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


# Generated once for the whole test run, not per test - key generation is
# the slow part, and nothing here depends on a fresh key per test case.
# Never the maintainer's real App key: that key is never read by tests.
_TEST_PRIVATE_KEY, _TEST_PUBLIC_KEY = _generate_keypair()

# Old file (3 lines):
#   resource "aws_s3_bucket" "datasets" {
#     bucket = "datasets"
#   }
# New file (5 lines): two lines inserted after the bucket line.
#   resource "aws_s3_bucket" "datasets" {
#     bucket = "datasets"
#     acl    = "public-read"
#   (blank)
#   }
S3_PATCH = (
    "@@ -1,3 +1,5 @@\n"
    ' resource "aws_s3_bucket" "datasets" {\n'
    '   bucket = "datasets"\n'
    '+  acl    = "public-read"\n'
    "+\n"
    " }\n"
)


def _finding(**overrides) -> Finding:
    base = {
        "check_id": "S3-001",
        "check_name": "AI Data Bucket Public Exposure",
        "severity": "CRITICAL",
        "resource_type": "aws_s3_bucket",
        "resource_name": "datasets",
        "file_path": "s3.tf",
        "line": 3,
        "message": "m",
        "remediation": "r",
    }
    base.update(overrides)
    return Finding(**base)


# --------------------------------------------------------------------- #
# diff.added_lines                                                      #
# --------------------------------------------------------------------- #
def test_added_lines_matches_a_hand_traced_diff():
    # Line 3 (acl) and line 4 (blank) are new. Line 1, 2, and 5 are
    # unchanged context that merely shifted position, not additions.
    assert added_lines(S3_PATCH) == {3, 4}


def test_added_lines_ignores_removed_lines():
    patch = "@@ -1,2 +1,1 @@\n resource \"x\" {\n-  old = true\n"
    # The removed line never existed in the new file, so it cannot
    # consume or appear as a new-file line number.
    assert added_lines(patch) == set()


def test_added_lines_handles_multiple_hunks_independently():
    patch = (
        "@@ -1,1 +1,2 @@\n"
        " a\n"
        "+b\n"
        "@@ -10,1 +11,2 @@\n"
        " c\n"
        "+d\n"
    )
    assert added_lines(patch) == {2, 12}


def test_added_lines_by_file_skips_entries_with_no_patch():
    files = [
        {"filename": "s3.tf", "patch": S3_PATCH},
        {"filename": "renamed.tf"},  # rename with no content change: no patch key
        {"filename": "image.png", "patch": None},
    ]
    result = added_lines_by_file(files)
    assert result == {"s3.tf": {3, 4}}


# --------------------------------------------------------------------- #
# comments.classify_findings                                            #
# --------------------------------------------------------------------- #
def test_finding_on_an_added_line_becomes_an_inline_comment():
    added = {"s3.tf": {3, 4}}
    inline, summary = classify_findings([_finding(line=3)], added)
    assert summary == []
    assert inline == [InlineComment("s3.tf", 3, inline[0].body)]
    assert "CRITICAL" in inline[0].body
    assert "S3-001" in inline[0].body


def test_finding_on_an_unchanged_line_goes_to_summary_not_dropped():
    # Line 2 (the bucket line) is real context in the diff, but the PR did
    # not add it, so it must not read as "this PR caused it."
    added = {"s3.tf": {3, 4}}
    inline, summary = classify_findings([_finding(line=2)], added)
    assert inline == []
    assert summary == [_finding(line=2)]


def test_finding_in_a_file_the_pr_never_touched_goes_to_summary():
    added = {"other.tf": {1}}
    inline, summary = classify_findings([_finding(file_path="s3.tf", line=3)], added)
    assert inline == []
    assert len(summary) == 1


# --------------------------------------------------------------------- #
# comments.summary_body                                                 #
# --------------------------------------------------------------------- #
def test_summary_body_is_empty_string_when_nothing_to_summarize():
    # Empty, not a comment that just says "nothing to report" - a caller
    # should treat this as "do not post a summary comment at all."
    assert summary_body([]) == ""


def test_summary_body_orders_worst_finding_first():
    low = _finding(severity="LOW", check_id="S3-001", line=99)
    critical = _finding(severity="CRITICAL", check_id="IAM-001", line=1)
    body = summary_body([low, critical])
    assert body.index("IAM-001") < body.index("S3-001")


def test_summary_body_never_uses_an_em_dash():
    # House style, enforced everywhere else in this project.
    body = summary_body([_finding()])
    assert "—" not in body


# --------------------------------------------------------------------- #
# signature.verify_signature                                            #
# --------------------------------------------------------------------- #
def test_verify_signature_matches_githubs_own_documented_example():
    # This exact secret, payload, and signature are GitHub's own worked
    # example in their webhook validation docs - a real reference
    # implementation, not a value this test made up and could get wrong
    # in the same way twice.
    secret = "It's a Secret to Everybody"
    payload = b"Hello, World!"
    signature = (
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    )
    assert verify_signature(payload, signature, secret) is True


def test_verify_signature_rejects_wrong_secret_and_tampered_payload():
    secret = "It's a Secret to Everybody"
    payload = b"Hello, World!"
    signature = (
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    )
    assert verify_signature(payload, signature, "wrong secret") is False
    assert verify_signature(b"Hello, World?", signature, secret) is False


def test_verify_signature_rejects_missing_or_malformed_header():
    assert verify_signature(b"x", None, "secret") is False
    assert verify_signature(b"x", "", "secret") is False
    # sha1= was GitHub's legacy scheme; accepting it would downgrade security.
    assert verify_signature(b"x", "sha1=deadbeef", "secret") is False


def _sign(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# --------------------------------------------------------------------- #
# events.relevant_pull_request                                          #
# --------------------------------------------------------------------- #
def _pr_payload(action="opened", **overrides):
    payload = {
        "action": action,
        "installation": {"id": 42},
        "repository": {"full_name": "rashadlee/modelmoat"},
        "pull_request": {
            "number": 7,
            "head": {"sha": "abc123"},
            "base": {"sha": "def456"},
        },
    }
    payload.update(overrides)
    return payload


def test_relevant_pull_request_extracts_everything_needed_to_act():
    target = relevant_pull_request("pull_request", _pr_payload())
    assert target == PullRequestTarget(
        installation_id=42,
        repo_full_name="rashadlee/modelmoat",
        pr_number=7,
        head_sha="abc123",
        base_sha="def456",
    )


def test_relevant_pull_request_ignores_non_pull_request_events():
    assert relevant_pull_request("push", _pr_payload()) is None
    assert relevant_pull_request(None, _pr_payload()) is None


def test_relevant_pull_request_ignores_uninteresting_actions():
    # closed/labeled/etc mean nothing changed that needs scanning.
    assert relevant_pull_request("pull_request", _pr_payload(action="closed")) is None
    assert relevant_pull_request("pull_request", _pr_payload(action="labeled")) is None


def test_relevant_pull_request_treats_malformed_payload_as_not_relevant():
    # Missing the installation key entirely, not just an empty one.
    broken = _pr_payload()
    del broken["installation"]
    assert relevant_pull_request("pull_request", broken) is None


# --------------------------------------------------------------------- #
# handler.lambda_handler                                                #
# --------------------------------------------------------------------- #
def _lambda_event(body: dict, secret: str, event_name="pull_request", *, sign=True):
    raw = json.dumps(body).encode()
    headers = {"x-github-event": event_name}
    if sign:
        headers["x-hub-signature-256"] = _sign(raw, secret)
    return {"headers": headers, "body": raw.decode(), "isBase64Encoded": False}


def test_handler_accepts_a_valid_relevant_delivery(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    event = _lambda_event(_pr_payload(), "test-secret")
    result = lambda_handler(event, None)
    assert result["statusCode"] == 202
    assert "#7" in result["body"]


def test_handler_rejects_an_invalid_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    event = _lambda_event(_pr_payload(), "wrong-secret")
    result = lambda_handler(event, None)
    assert result["statusCode"] == 401


def test_handler_acknowledges_but_ignores_irrelevant_events(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    event = _lambda_event(_pr_payload(), "test-secret", event_name="push")
    result = lambda_handler(event, None)
    # 200, not a 4xx or 5xx - GitHub must not see this as a failed delivery
    # and retry it, since nothing about it was actually wrong.
    assert result["statusCode"] == 200


def test_handler_rejects_a_body_that_does_not_match_its_own_signature(monkeypatch):
    # The signature must be verified before the body is trusted enough to
    # even parse as JSON, let alone act on. Simulates a tampered payload.
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    event = _lambda_event(_pr_payload(), "test-secret")
    event["body"] = event["body"].replace("opened", "reopened")
    result = lambda_handler(event, None)
    assert result["statusCode"] == 401


def test_handler_decodes_base64_body_before_verifying(monkeypatch):
    # Lambda base64-encodes the body for some content types; the signature
    # must be checked against the decoded bytes, not the base64 text.
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    raw = json.dumps(_pr_payload()).encode()
    event = {
        "headers": {
            "x-github-event": "pull_request",
            "x-hub-signature-256": _sign(raw, "test-secret"),
        },
        "body": base64.b64encode(raw).decode(),
        "isBase64Encoded": True,
    }
    result = lambda_handler(event, None)
    assert result["statusCode"] == 202


# --------------------------------------------------------------------- #
# auth.build_jwt                                                        #
# --------------------------------------------------------------------- #
def _decode_ignoring_expiry(token: str) -> dict:
    # These tests use a fixed, deliberately-in-the-past `now` so claim
    # values are exact and reproducible. That makes the resulting token
    # genuinely expired by the real clock, which is a property of the test
    # setup, not something build_jwt got wrong - skip PyJWT's own (already
    # well-tested) expiration check and just inspect the claims it computed.
    return jwt.decode(
        token, _TEST_PUBLIC_KEY, algorithms=["RS256"], options={"verify_exp": False}
    )


def test_build_jwt_claims_match_githubs_documented_requirements():
    token = build_jwt("4733233", _TEST_PRIVATE_KEY, now=1_700_000_000)
    decoded = _decode_ignoring_expiry(token)
    assert decoded["iss"] == "4733233"
    # iat backdated 60s per GitHub's own clock-skew guidance.
    assert decoded["iat"] == 1_700_000_000 - 60
    assert decoded["exp"] == decoded["iat"] + 9 * 60


def test_build_jwt_lifetime_stays_under_githubs_ten_minute_cap():
    # The hard requirement, independent of this module's own chosen margin.
    token = build_jwt("4733233", _TEST_PRIVATE_KEY, now=1_700_000_000)
    decoded = _decode_ignoring_expiry(token)
    assert decoded["exp"] - decoded["iat"] <= 600


def test_build_jwt_is_signed_with_rs256():
    token = build_jwt("4733233", _TEST_PRIVATE_KEY, now=1_700_000_000)
    assert jwt.get_unverified_header(token)["alg"] == "RS256"


def test_build_jwt_rejects_verification_with_the_wrong_key():
    _other_private, other_public = _generate_keypair()
    token = build_jwt("4733233", _TEST_PRIVATE_KEY, now=1_700_000_000)
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, other_public, algorithms=["RS256"])


def test_build_jwt_defaults_to_the_real_current_time():
    before = int(time.time())
    token = build_jwt("4733233", _TEST_PRIVATE_KEY)
    after = int(time.time())
    decoded = jwt.decode(token, _TEST_PUBLIC_KEY, algorithms=["RS256"])
    # iat is backdated 60s from "now" by design; assert it lands in a sane
    # window around the real clock rather than an exact second, since the
    # test itself takes some non-zero time to run.
    assert before - 61 <= decoded["iat"] <= after - 59


# --------------------------------------------------------------------- #
# installation.exchange_installation_token / list_installations         #
# --------------------------------------------------------------------- #
def _mock_response(status_code: int, json_body: dict | list, text: str = "") -> Mock:
    response = Mock()
    response.status_code = status_code
    response.json.return_value = json_body
    response.text = text or json.dumps(json_body)
    return response


def test_exchange_installation_token_parses_a_successful_response():
    ok = _mock_response(
        201, {"token": "ghs_fake", "expires_at": "2026-01-01T00:00:00Z"}
    )
    with patch("github_app.installation.requests.post", return_value=ok) as post:
        result = exchange_installation_token("fake.jwt", 987)
    assert result == InstallationToken(token="ghs_fake", expires_at="2026-01-01T00:00:00Z")
    post.assert_called_once()


def test_exchange_installation_token_sends_the_jwt_as_a_bearer_token_and_correct_url():
    ok = _mock_response(201, {"token": "t", "expires_at": "e"})
    with patch("github_app.installation.requests.post", return_value=ok) as post:
        exchange_installation_token("my.jwt.value", 987)
    args, kwargs = post.call_args
    assert args[0] == "https://api.github.com/app/installations/987/access_tokens"
    assert kwargs["headers"]["Authorization"] == "Bearer my.jwt.value"


def test_exchange_installation_token_raises_on_a_non_201_response():
    denied = _mock_response(401, {"message": "Bad credentials"})
    with (
        patch("github_app.installation.requests.post", return_value=denied),
        pytest.raises(GitHubAppAPIError),
    ):
        exchange_installation_token("fake.jwt", 987)


def test_list_installations_returns_the_parsed_json_array():
    ok = _mock_response(200, [{"id": 987, "account": {"login": "rashadlee"}}])
    with patch("github_app.installation.requests.get", return_value=ok):
        result = list_installations("fake.jwt")
    assert result == [{"id": 987, "account": {"login": "rashadlee"}}]


def test_list_installations_raises_on_a_non_200_response():
    denied = _mock_response(403, {"message": "forbidden"})
    with (
        patch("github_app.installation.requests.get", return_value=denied),
        pytest.raises(GitHubAppAPIError),
    ):
        list_installations("fake.jwt")


# --------------------------------------------------------------------- #
# tree.fetch_terraform_tree                                             #
# --------------------------------------------------------------------- #
def _build_tarball(files: dict[str, str]) -> bytes:
    """Build an in-memory .tar.gz from {path: content}, matching GitHub's shape."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_fetch_terraform_tree_extracts_into_the_top_level_directory():
    archive = _build_tarball(
        {
            "rashadlee-modelmoat-abc123/main.tf": 'resource "x" "y" {}',
            "rashadlee-modelmoat-abc123/sub/other.tf": "# nested",
        }
    )
    ok = Mock(status_code=200, content=archive)
    with patch("github_app.tree.requests.get", return_value=ok):
        top = fetch_terraform_tree("fake.token", "rashadlee/modelmoat", "abc123")
    assert top.name == "rashadlee-modelmoat-abc123"
    assert (top / "main.tf").read_text() == 'resource "x" "y" {}'
    assert (top / "sub" / "other.tf").read_text() == "# nested"


def test_fetch_terraform_tree_raises_on_a_non_200_response():
    denied = Mock(status_code=404, text="Not Found")
    with (
        patch("github_app.tree.requests.get", return_value=denied),
        pytest.raises(TreeFetchError),
    ):
        fetch_terraform_tree("fake.token", "rashadlee/modelmoat", "abc123")


def test_fetch_terraform_tree_rejects_a_path_traversal_member():
    # A member the safe _build_tarball helper above cannot express, since it
    # always prefixes with a contained top-level directory name.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        safe = tarfile.TarInfo(name="rashadlee-modelmoat-abc123/main.tf")
        safe.size = 4
        tar.addfile(safe, io.BytesIO(b"safe"))
        evil = tarfile.TarInfo(name="../../etc/evil.tf")
        evil.size = 4
        tar.addfile(evil, io.BytesIO(b"evil"))
    archive = buf.getvalue()

    ok = Mock(status_code=200, content=archive)
    with (
        patch("github_app.tree.requests.get", return_value=ok),
        pytest.raises(TreeFetchError, match="escapes"),
    ):
        fetch_terraform_tree("fake.token", "rashadlee/modelmoat", "abc123")


def test_fetch_terraform_tree_rejects_unexpected_top_level_shape():
    # Two top-level directories is not a shape GitHub's tarball ever
    # actually produces, so it is treated as untrusted rather than guessed
    # at (which one is "the real" root?).
    archive = _build_tarball({"dir-one/a.tf": "a", "dir-two/b.tf": "b"})
    ok = Mock(status_code=200, content=archive)
    with (
        patch("github_app.tree.requests.get", return_value=ok),
        pytest.raises(TreeFetchError),
    ):
        fetch_terraform_tree("fake.token", "rashadlee/modelmoat", "abc123")


def test_fetched_tree_is_directly_usable_by_the_real_scanner():
    # Proves the extracted tree is not just structurally present but is
    # actually readable by modelmoat's real scanning code, end to end.
    archive = _build_tarball(
        {
            "rashadlee-modelmoat-abc123/s3.tf": (
                'resource "aws_s3_bucket" "datasets" {\n'
                '  bucket = "datasets"\n'
                '  acl    = "public-read"\n'
                "}\n"
            ),
        }
    )
    ok = Mock(status_code=200, content=archive)
    with patch("github_app.tree.requests.get", return_value=ok):
        top = fetch_terraform_tree("fake.token", "rashadlee/modelmoat", "abc123")

    from modelmoat.checks import ALL_CHECKS
    from modelmoat.scanner import Scanner

    result = Scanner(ALL_CHECKS).scan([top])
    assert any(f.check_id == "S3-001" for f in result.findings)
