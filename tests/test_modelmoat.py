"""modelmoat test suite.

The two rules every check lives by:
  1. The secure fixture produces zero findings. A scanner that cries wolf on
     correct infrastructure is broken, whatever else it catches.
  2. The insecure fixture triggers every check, including the paths that were
     dead code in the first draft of this tool: managed FullAccess
     attachments, explicitly disabled encryption, and Lambda traffic without
     PrivateLink.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from modelmoat.checks import ALL_CHECKS
from modelmoat.cli import app
from modelmoat.graph import ai_tokens_in, unquote
from modelmoat.policy import (
    parse_policy_document,
    risky_managed_policy,
    wildcard_ai_grants,
)
from modelmoat.scanner import Scanner

FIXTURES = Path(__file__).parent / "fixtures"
SECURE = FIXTURES / "secure"
INSECURE = FIXTURES / "insecure"


def scan(path: Path):
    return Scanner(ALL_CHECKS).scan([path])


# --------------------------------------------------------------------- #
# The gate                                                              #
# --------------------------------------------------------------------- #
def test_secure_stack_yields_zero_findings():
    result = scan(SECURE)
    assert result.files_scanned >= 8
    assert result.parse_errors == []
    details = "\n".join(
        f"{f.severity} {f.check_id} {f.resource_type}.{f.resource_name}: {f.message}"
        for f in result.findings
    )
    assert result.findings == [], f"False positives on secure fixture:\n{details}"


# --------------------------------------------------------------------- #
# Detection coverage                                                    #
# --------------------------------------------------------------------- #
def test_every_check_fires_on_insecure_stack():
    result = scan(INSECURE)
    ids = {f.check_id for f in result.findings}
    assert {"SMK-001", "IAM-001", "S3-001", "VPC-001", "VEC-001"} <= ids


def test_managed_fullaccess_attachment_is_detected():
    result = scan(INSECURE)
    assert any(
        "AmazonBedrockFullAccess" in f.message and f.check_id == "IAM-001"
        for f in result.findings
    )


def test_data_source_policy_document_is_detected():
    result = scan(INSECURE)
    assert any(
        f.check_id == "IAM-001" and f.resource_name == "sagemaker_admin"
        for f in result.findings
    )


def test_explicitly_disabled_encryption_is_detected():
    result = scan(INSECURE)
    assert any(
        f.check_id == "VEC-001"
        and f.resource_name == "open_vectors"
        and "encryption at rest" in f.message
        for f in result.findings
    )


def test_public_opensearch_with_open_policy_is_critical():
    result = scan(INSECURE)
    assert any(
        f.check_id == "VEC-001"
        and f.resource_name == "open_vectors"
        and f.severity == "CRITICAL"
        for f in result.findings
    )


def test_vpc_lambda_without_endpoint_is_flagged():
    result = scan(INSECURE)
    assert any(
        f.check_id == "VPC-001"
        and f.resource_name == "vpc_agent"
        and f.severity == "MEDIUM"
        for f in result.findings
    )


def test_public_acl_on_training_bucket_is_critical():
    result = scan(INSECURE)
    assert any(
        f.check_id == "S3-001"
        and f.resource_name == "training_data"
        and f.severity == "CRITICAL"
        for f in result.findings
    )


def test_public_bucket_policy_is_critical():
    result = scan(INSECURE)
    assert any(
        f.check_id == "S3-001"
        and f.resource_name == "datasets"
        and f.severity == "CRITICAL"
        for f in result.findings
    )


def test_missing_access_block_is_low_not_critical():
    result = scan(INSECURE)
    weights = [f for f in result.findings if f.resource_name == "model_weights"]
    assert weights and all(f.severity == "LOW" for f in weights)


def test_public_postgres_is_critical():
    result = scan(INSECURE)
    assert any(
        f.check_id == "VEC-001"
        and f.resource_name == "embeddings"
        and f.severity == "CRITICAL"
        for f in result.findings
    )


# --------------------------------------------------------------------- #
# Negative controls: staying in our lane                                #
# --------------------------------------------------------------------- #
def test_non_ai_resources_are_never_flagged():
    for fixture in (SECURE, INSECURE):
        result = scan(fixture)
        named = {f.resource_name for f in result.findings}
        assert "email_archive" not in named, "email is not ai"
        assert "html_assets" not in named, "html is not ml"
        assert "legacy_mysql" not in named, "a mysql inventory db is not a vector store"


def test_findings_have_real_line_numbers():
    result = scan(INSECURE)
    assert result.findings
    assert all(f.line >= 1 for f in result.findings)
    assert any(f.line > 1 for f in result.findings)


# --------------------------------------------------------------------- #
# Units                                                                 #
# --------------------------------------------------------------------- #
def test_unquote_strips_hcl2_quote_wrapping():
    assert unquote('"vectors"') == "vectors"
    assert unquote("plain") == "plain"


def test_ai_token_matching_is_whole_token():
    assert ai_tokens_in("corp-email-archive") == set()
    assert ai_tokens_in("corp-html-assets") == set()
    assert "model" in ai_tokens_in("acme-prod-model-artifacts")
    assert "ml" in ai_tokens_in("team: ml-platform")


def test_parse_policy_document_handles_hcl2_jsonencode_serialization():
    raw = (
        '${jsonencode({Version = "2012-10-17", Statement = '
        '[{Effect = "Allow", Action = ["bedrock:*"], Resource = "*"}]})}'
    )
    doc = parse_policy_document(raw)
    assert doc is not None
    assert wildcard_ai_grants(doc) == ["bedrock:*"]


def test_risky_managed_policy_matching_is_case_insensitive():
    assert risky_managed_policy("arn:aws:iam::aws:policy/AmazonBedrockFullAccess")
    assert risky_managed_policy("arn:aws:iam::aws:policy/amazonsagemakerfullaccess")
    assert risky_managed_policy("arn:aws:iam::aws:policy/ReadOnlyAccess") is None


# --------------------------------------------------------------------- #
# CLI exit codes                                                        #
# --------------------------------------------------------------------- #
def test_cli_exit_codes_for_ci():
    runner = CliRunner()
    clean = runner.invoke(app, ["scan", str(SECURE)])
    assert clean.exit_code == 0, clean.output

    dirty = runner.invoke(app, ["scan", str(INSECURE), "--json"])
    assert dirty.exit_code == 1

    loose = runner.invoke(
        app, ["scan", str(SECURE), "--fail-on", "LOW", "--json"]
    )
    assert loose.exit_code == 0
