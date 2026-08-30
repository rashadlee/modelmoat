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

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

import modelmoat.graph as graph_module
from modelmoat.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from modelmoat.checks import ALL_CHECKS
from modelmoat.cli import app
from modelmoat.graph import _read_terraform_file, ai_tokens_in, build_graph, unquote
from modelmoat.policy import (
    parse_policy_document,
    risky_managed_policy,
    wildcard_ai_grants,
)
from modelmoat.sarif import to_sarif
from modelmoat.scanner import Finding, Scanner

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
    assert result.files_scanned >= 11
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
    assert {
        "SMK-001",
        "IAM-001",
        "S3-001",
        "VPC-001",
        "VEC-001",
        "VEC-002",
        "VEC-003",
        "PIN-001",
        "AZR-001",
        "BRK-001",
        "GCP-001",
        "AGW-001",
    } <= ids


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


def test_fargate_service_without_endpoint_is_medium_never_low():
    # ECS Fargate always runs inside a VPC (awsvpc network_mode is mandatory),
    # so unlike a Lambda missing vpc_config there is no LOW "outside a VPC"
    # tier to hit here - only MEDIUM, or nothing.
    hits = [f for f in scan(INSECURE).findings if f.check_id == "VPC-001"]
    fargate = [f for f in hits if f.resource_name == "fargate_agent"]
    assert len(fargate) == 1
    assert fargate[0].severity == "MEDIUM"
    assert fargate[0].detail == "bedrock"


def test_ec2_launch_type_ecs_service_is_not_flagged():
    # Bridge/host networking on EC2 launch type isn't verified by this check,
    # so it must stay silent even with the identical Bedrock signal present.
    named = {f.resource_name for f in scan(INSECURE).findings if f.check_id == "VPC-001"}
    assert "ec2_agent" not in named


def test_fargate_service_with_matching_endpoint_stays_silent():
    # Same Bedrock signal as the insecure fixture, but network.tf's
    # bedrock_runtime interface endpoint covers it - proves endpoint
    # matching applies across resource types, not just Lambda.
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "fargate_agent" not in named


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


def test_bucket_referenced_by_kb_data_source_is_flagged_despite_generic_name():
    # "acme-prod-storage" matches no AI/ML keyword or tag - the only proof
    # this bucket holds AI data is aws_bedrockagent_data_source pointing its
    # s3_configuration.bucket_arn at it. Relevance through that reference
    # must catch what keyword matching alone would miss.
    result = scan(INSECURE)
    hits = [f for f in result.findings if f.resource_name == "generic_storage"]
    assert hits and all(f.check_id == "S3-001" for f in hits)
    assert any(f.severity == "CRITICAL" and f.detail == "public_policy" for f in hits)
    assert any("bedrockagent_data_source" in f.message for f in hits)


def test_bucket_referenced_by_kb_data_source_but_locked_down_stays_silent():
    # Same generic name and the same data source reference as the insecure
    # case, but fully locked down - the new relevance signal must not turn
    # into a false positive on its own.
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "generic_storage" not in named


def test_s3_defects_on_one_bucket_have_distinct_fingerprints():
    # MM-03 regression: a public ACL, a wildcard-principal policy, and a
    # weakened access block on the same bucket must not collapse onto one
    # fingerprint - baselining the mildest would otherwise silently suppress
    # the other two.
    result = scan(INSECURE)
    multi = [f for f in result.findings if f.resource_name == "multi_defect"]
    assert {f.detail for f in multi} == {"public_acl", "public_policy", "weakened_pab"}
    assert len({f.fingerprint for f in multi}) == len(multi) == 3

    # All four S3-001 branches are represented across the fixture with
    # distinct detail tokens.
    s3_details = {f.detail for f in result.findings if f.check_id == "S3-001"}
    assert s3_details == {"public_acl", "public_policy", "weakened_pab", "missing_pab"}

    # SARIF preserves all three as separate results, not deduplicated.
    run = to_sarif(result, ALL_CHECKS)["runs"][0]
    multi_results = [
        r for r in run["results"]
        if r["properties"]["resource"] == "aws_s3_bucket.multi_defect"
    ]
    assert len(multi_results) == 3
    assert len({r["partialFingerprints"]["modelmoatFindingV1"] for r in multi_results}) == 3


def test_deployable_tf_json_is_not_silently_skipped():
    # MM-06 regression: .tf.json is real, deployable Terraform - it must be
    # parsed, not silently treated as an empty, clean target.
    result = scan(INSECURE)
    assert any(
        f.check_id == "S3-001"
        and f.resource_name == "json_training_data"
        and f.severity == "CRITICAL"
        for f in result.findings
    )


def test_module_boundaries_prevent_cross_module_correlation():
    # MM-01 regression: two sibling modules can declare identically labeled
    # resources for entirely different infrastructure. A protected bucket in
    # one module must never suppress a public bucket's finding in another,
    # whether the public module is scanned alone or as part of the whole
    # repository.
    module_boundary = FIXTURES / "module_boundary"
    module_a = module_boundary / "module_a"

    isolated = scan(module_a)
    assert any(
        f.check_id == "S3-001" and f.severity == "CRITICAL" and f.resource_name == "data"
        for f in isolated.findings
    )

    repo_wide = scan(module_boundary)
    critical = [
        f
        for f in repo_wide.findings
        if f.check_id == "S3-001" and f.severity == "CRITICAL" and f.resource_name == "data"
    ]
    assert len(critical) == 1
    assert critical[0].file_path.endswith("module_a/main.tf")
    # module_b's identically labeled bucket is genuinely protected and must
    # stay silent - the fix is about boundaries, not about matching harder.
    assert not any(f.file_path.endswith("module_b/main.tf") for f in repo_wide.findings)


# A risky resource's own unresolved cardinality must not make it invisible:
# modelmoat cannot prove it is NOT deployed, so it stays in the graph and
# gets evaluated as normal - only a literal, provably-zero count/for_each
# excludes it.
_RISKY_RESOURCE_CARDINALITY_CASES = [
    ("count = 0", False),
    ("for_each = {}", False),
    ("for_each = toset([])", False),
    ("count = 3", True),
    ("count = var.enabled ? 1 : 0", True),
]
# A compensating control's unresolved cardinality must not credit it with
# protecting anything: modelmoat cannot prove it exists, so only a
# confirmed-present control (not absent, not unresolved) suppresses the
# finding for the resource it claims to protect.
_CONTROL_CARDINALITY_CASES = [
    ("count = 0", False),
    ("for_each = {}", False),
    ("for_each = toset([])", False),
    ("count = 3", True),
    ("count = var.enabled ? 1 : 0", False),
]
_CARDINALITY_IDS = [
    "count_zero",
    "for_each_empty_map",
    "for_each_empty_toset",
    "count_positive",
    "count_variable_unknown",
]


@pytest.mark.parametrize(
    "clause,instantiated", _RISKY_RESOURCE_CARDINALITY_CASES, ids=_CARDINALITY_IDS
)
def test_cardinality_on_a_risky_resource(tmp_path, clause, instantiated):
    # MM-02 regression: a risky resource Terraform provably creates zero
    # instances of must not be flagged as though it were deployed - but
    # unresolved cardinality (a variable-driven count/for_each) is not proof
    # of absence either, so it must still be evaluated normally, not dropped
    # from the graph.
    (tmp_path / "main.tf").write_text(
        f"""
resource "aws_s3_bucket" "training_data" {{
  bucket = "acme-cardinality-training-data"
}}
resource "aws_s3_bucket_acl" "training_data" {{
  {clause}
  bucket = aws_s3_bucket.training_data.id
  acl    = "public-read"
}}
"""
    )
    fired = any(
        f.check_id == "S3-001" and f.detail == "public_acl" for f in scan(tmp_path).findings
    )
    assert fired == instantiated


@pytest.mark.parametrize(
    "clause,instantiated", _CONTROL_CARDINALITY_CASES, ids=_CARDINALITY_IDS
)
def test_cardinality_on_a_compensating_control(tmp_path, clause, instantiated):
    # MM-02 regression: a compensating control Terraform provably does not
    # create - or whose cardinality is unresolvable - must not suppress the
    # finding for the resource it claims to protect. Unlike the risky-resource
    # case, unresolved here must NOT count as confirmed: modelmoat cannot
    # prove the control exists, so it must not get to prove the bucket safe.
    (tmp_path / "main.tf").write_text(
        f"""
resource "aws_s3_bucket" "training_data" {{
  bucket = "acme-cardinality-training-data"
}}
resource "aws_s3_bucket_acl" "training_data" {{
  bucket = aws_s3_bucket.training_data.id
  acl    = "public-read"
}}
resource "aws_s3_bucket_public_access_block" "training_data" {{
  {clause}
  bucket                  = aws_s3_bucket.training_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
"""
    )
    fired = any(
        f.check_id == "S3-001" and f.detail == "public_acl" for f in scan(tmp_path).findings
    )
    # The control suppresses the finding only when it is confirmed
    # instantiated; otherwise the bucket's real exposure must still surface.
    assert fired == (not instantiated)


def test_unresolved_cardinality_on_the_resource_itself_does_not_erase_it(tmp_path):
    # Direct regression for a bug introduced by an earlier version of the
    # MM-02 fix: a public bucket whose own count is unresolved (not proven
    # zero) must still show up in the graph at all, not disappear as if it
    # were the same as count = 0.
    (tmp_path / "main.tf").write_text(
        """
resource "aws_s3_bucket" "training_data" {
  count  = var.enable_bucket
  bucket = "acme-cardinality-training-data"
}
resource "aws_s3_bucket_acl" "training_data" {
  bucket = aws_s3_bucket.training_data.id
  acl    = "public-read"
}
"""
    )
    graph = build_graph([tmp_path])
    assert graph.parse_errors == []
    assert any(r.type == "aws_s3_bucket" and r.name == "training_data" for r in graph.resources)
    assert any(
        f.check_id == "S3-001" and f.detail == "public_acl" for f in scan(tmp_path).findings
    )


def test_public_postgres_is_critical():
    result = scan(INSECURE)
    assert any(
        f.check_id == "VEC-001"
        and f.resource_name == "embeddings"
        and f.severity == "CRITICAL"
        for f in result.findings
    )


def test_opensearch_serverless_public_network_policy_is_high():
    # HIGH, not CRITICAL: AWS's own docs state that a data access policy and
    # SigV4-signed IAM credentials are still required for every request
    # regardless of AllowFromPublic, so this is network exposure, not the
    # proven-absent-auth case BRK-001 covers.
    hits = [f for f in scan(INSECURE).findings if f.check_id == "VEC-001"]
    serverless = [f for f in hits if f.resource_name == "vectors_network"]
    assert len(serverless) == 1
    assert serverless[0].severity == "HIGH"
    assert serverless[0].detail == "serverless_network_public"


def test_opensearch_serverless_private_and_dashboard_only_stay_silent():
    # A private network policy stays silent, and so does a policy that only
    # grants public access to the Dashboards resource type: AWS's own docs
    # say direct calls to the OpenSearch API still fail in that case, so
    # flagging it would claim more than the configuration proves.
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "vectors_network" not in named
    assert "vectors_dashboard_only" not in named


# --------------------------------------------------------------------- #
# SMK-001: SageMaker Studio domain network access                       #
# --------------------------------------------------------------------- #
def test_studio_domain_missing_access_type_is_high():
    result = scan(INSECURE)
    hits = [
        f
        for f in result.findings
        if f.check_id == "SMK-001" and f.resource_name == "unset_access_type"
    ]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert hits[0].detail == "app_network_access_type"


def test_studio_domain_explicit_public_internet_only_is_high():
    result = scan(INSECURE)
    hits = [
        f
        for f in result.findings
        if f.check_id == "SMK-001" and f.resource_name == "explicit_public"
    ]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert hits[0].detail == "app_network_access_type"


def test_studio_domain_vpc_only_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "studio" not in named


def test_studio_domain_variable_driven_access_type_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "from_variable" not in named


def test_model_finding_detail_is_unchanged_by_domain_addition():
    # detail feeds the fingerprint (see scanner.Finding.fingerprint), so
    # adding the domain method to SMK-001 must not touch the model
    # finding's detail token - that would orphan every baseline entry
    # that referenced it.
    result = scan(INSECURE)
    model_hits = [
        f
        for f in result.findings
        if f.check_id == "SMK-001" and f.resource_name == "exposed_llm"
    ]
    assert len(model_hits) == 1
    assert model_hits[0].detail == ""

    domain_hits = [
        f
        for f in result.findings
        if f.check_id == "SMK-001" and f.resource_type == "aws_sagemaker_domain"
    ]
    assert len(domain_hits) == 2
    assert len({f.fingerprint for f in domain_hits + model_hits}) == 3


# --------------------------------------------------------------------- #
# PIN-001 and VEC-002: vector stores outside AWS                        #
# --------------------------------------------------------------------- #
def test_pinecone_org_owner_on_machine_principal_is_high():
    result = scan(INSECURE)
    hits = [f for f in result.findings if f.check_id == "PIN-001"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert hits[0].resource_name == "indexer_org_owner"


def test_pinecone_org_manager_is_never_flagged():
    # OrgManager only grants viewing organization details and creating
    # projects. Flagging it on the strength of its name would claim more than
    # the role grants. It sits in the secure fixture as a permanent control.
    for fixture in (SECURE, INSECURE):
        named = {f.resource_name for f in scan(fixture).findings}
        assert "provisioner" not in named


def test_pinecone_human_owner_and_unknown_role_stay_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "founder" not in named, "a person owning the organization is ordinary"
    assert "from_variable" not in named, "a role from a variable is unprovable"


def test_weaviate_anonymous_access_detected_in_helm_and_containers():
    hits = {f.resource_name for f in scan(INSECURE).findings if f.check_id == "VEC-002"}
    assert hits == {"weaviate", "weaviate_embeddings"}


def test_weaviate_accepts_every_value_weaviate_itself_treats_as_enabled():
    # Weaviate's entities/config/helpers.go treats on, enabled, 1 and true as
    # enabled. The insecure fixture uses "1" precisely so that matching only
    # "true" would fail this test.
    from modelmoat.checks.weaviate import _explicitly_enabled

    for value in ("true", "True", "1", "on", "enabled"):
        assert _explicitly_enabled(value), value
    for value in ("false", "0", "off", "", "${var.anon}"):
        assert not _explicitly_enabled(value), value


def test_weaviate_absent_setting_is_deliberately_not_flagged():
    # The chart default is insecure, but the value legitimately arrives via
    # values.yaml, a ConfigMap, or a Secret. Absence is unprovable, so this
    # check knowingly misses those rather than guessing.
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "weaviate_from_values_file" not in named


def test_weaviate_matching_is_whole_token_and_chart_scoped():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "unrelated_app" not in named, "another chart is not weaviate"
    assert "lookalike" not in named, "weaviatelike is not weaviate"


# --------------------------------------------------------------------- #
# VEC-003: self-hosted vector databases on ECS                          #
# --------------------------------------------------------------------- #
def test_ecs_vectorstore_public_ip_detected_for_all_three_engines():
    hits = {f.resource_name for f in scan(INSECURE).findings if f.check_id == "VEC-003"}
    assert hits == {"qdrant", "weaviate", "milvus"}


def test_ecs_vectorstore_finding_is_high_and_names_the_engine():
    hits = [f for f in scan(INSECURE).findings if f.check_id == "VEC-003"]
    assert hits
    for finding in hits:
        assert finding.severity == "HIGH"
    messages = "\n".join(f.message for f in hits)
    assert "Qdrant" in messages
    assert "Weaviate" in messages
    assert "Milvus" in messages


def test_ecs_vectorstore_stays_silent_without_public_ip_or_on_ec2():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "qdrant_private" not in named, "assign_public_ip defaults to false"
    assert "weaviate_private" not in named, "assign_public_ip explicitly false"
    assert "milvus_ec2" not in named, "assign_public_ip is not honored on EC2 launch type"


def test_ecs_vectorstore_private_ecr_image_is_unprovable_blind_spot():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "internal_vectordb" not in named


def test_ecs_vectorstore_matching_is_whole_repo_path_not_substring():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "qdrant_lookalike" not in named, "myqdrant-fork is not qdrant/qdrant"
    assert "web_frontend" not in named, "nginx is not a vector database"


# --------------------------------------------------------------------- #
# AZR-001: Azure OpenAI network exposure                                #
# --------------------------------------------------------------------- #
def test_azure_openai_public_by_default_is_flagged():
    hits = [f for f in scan(INSECURE).findings if f.check_id == "AZR-001"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert hits[0].resource_name == "exposed_openai"


def test_azure_openai_private_network_access_stays_silent():
    # public_network_access_enabled = false, the explicit opposite of the
    # provider's own default.
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "openai" not in named


def test_azure_openai_network_acls_deny_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "openai_with_acl" not in named


def test_azure_openai_non_ai_kind_stays_silent():
    # A public ComputerVision account is a real generic-hygiene finding,
    # but this check is specifically about AI service exposure - flagging
    # it here would claim a broader scope than the check actually has.
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "vision" not in named


def test_truthy_or_absent_treats_boolean_false_as_false():
    # Regression: an earlier version fell through every branch for a
    # literal Python False and returned True, which meant an explicitly
    # disabled setting still read as "enabled by default."
    from modelmoat.graph import truthy_or_absent

    assert truthy_or_absent(False) is False
    assert truthy_or_absent(True) is True
    assert truthy_or_absent(None) is True
    assert truthy_or_absent("false") is False
    assert truthy_or_absent("${var.public}") is False


# --------------------------------------------------------------------- #
# BRK-001: Bedrock AgentCore gateway authentication                     #
# --------------------------------------------------------------------- #
def test_agentcore_gateway_with_no_authorizer_is_critical():
    hits = [f for f in scan(INSECURE).findings if f.check_id == "BRK-001"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert hits[0].resource_name == "open_gateway"


def test_agentcore_gateway_with_aws_iam_authorizer_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "authenticated_gateway" not in named


def test_agentcore_gateway_unknown_authorizer_type_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "from_variable" not in named


# --------------------------------------------------------------------- #
# GCP-001: Vertex AI Reasoning Engine security controls                 #
# --------------------------------------------------------------------- #
def test_reasoning_engine_missing_both_controls_reports_two_findings():
    # Independent problems need independent detail tokens, or baselining
    # one would silently suppress the other - the exact bug that shaped
    # VEC-001's fingerprint fix.
    hits = [f for f in scan(INSECURE).findings if f.check_id == "GCP-001"]
    assert len(hits) == 2
    assert all(f.resource_name == "exposed_agent" for f in hits)
    assert all(f.severity == "HIGH" for f in hits)
    details = {f.detail for f in hits}
    assert details == {"no_network_isolation", "no_cmek"}


def test_reasoning_engine_fingerprints_are_distinct():
    hits = [f for f in scan(INSECURE).findings if f.check_id == "GCP-001"]
    assert len({f.fingerprint for f in hits}) == 2


def test_reasoning_engine_with_psc_and_cmek_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "prod_agent" not in named


# --------------------------------------------------------------------- #
# AGW-001: API Gateway REST methods proxying to Bedrock or SageMaker    #
# --------------------------------------------------------------------- #
def test_unauthenticated_ai_proxy_methods_are_critical():
    # predict_post's integration links to its method via a reference to the
    # method's own http_method attribute (runtime.sagemaker); invoke_post
    # and agent_post write http_method as a literal on both sides instead,
    # exercising the (rest_api_id, resource_id, http_method) triple match
    # (bedrock-runtime and bedrock-agent-runtime respectively).
    hits = [f for f in scan(INSECURE).findings if f.check_id == "AGW-001"]
    names = {f.resource_name for f in hits}
    assert names == {"predict_post", "invoke_post", "agent_post"}
    assert all(f.severity == "CRITICAL" for f in hits)


def test_iam_authorization_on_the_same_sagemaker_proxy_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "predict_post" not in named


def test_unauthenticated_lambda_proxy_stays_silent():
    # Generic API security - no proof the backend is an AI service - is out
    # of scope, even though authorization is "NONE".
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "webhook_post" not in named


def test_private_rest_api_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "internal_predict_post" not in named


def test_unknown_authorization_stays_silent():
    named = {f.resource_name for f in scan(SECURE).findings}
    assert "from_variable_post" not in named


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
# MM-07: referenced policy documents                                    #
# --------------------------------------------------------------------- #
def test_referenced_policy_documents_resolve_correctly_for_s3_and_opensearch(tmp_path):
    # MM-07 regression: a bucket policy or OpenSearch access policy expressed
    # as a data.aws_iam_policy_document reference must resolve to the same
    # verdict an inline policy would - public fires Critical, an
    # organization-restricted or VPC-endpoint-restricted document stays
    # silent on public reachability.
    (tmp_path / "main.tf").write_text(
        """
data "aws_iam_policy_document" "public" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "org_restricted" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:root"]
    }
  }
}

data "aws_iam_policy_document" "vpce_restricted" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket" "public_training_data" {
  bucket = "acme-public-referenced-training-data"
}
resource "aws_s3_bucket_policy" "public_training_data" {
  bucket = aws_s3_bucket.public_training_data.id
  policy = data.aws_iam_policy_document.public.json
}

resource "aws_s3_bucket" "org_training_data" {
  bucket = "acme-org-referenced-training-data"
}
resource "aws_s3_bucket_policy" "org_training_data" {
  bucket = aws_s3_bucket.org_training_data.id
  policy = data.aws_iam_policy_document.org_restricted.json
}

resource "aws_s3_bucket" "vpce_training_data" {
  bucket = "acme-vpce-referenced-training-data"
}
resource "aws_s3_bucket_policy" "vpce_training_data" {
  bucket = aws_s3_bucket.vpce_training_data.id
  policy = data.aws_iam_policy_document.vpce_restricted.json
}

resource "aws_opensearch_domain" "public_vectors" {
  domain_name     = "acme-public-vectors"
  access_policies = data.aws_iam_policy_document.public.json
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
}

resource "aws_opensearch_domain" "org_vectors" {
  domain_name     = "acme-org-vectors"
  access_policies = data.aws_iam_policy_document.org_restricted.json
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
}

resource "aws_opensearch_domain" "vpce_vectors" {
  domain_name     = "acme-vpce-vectors"
  access_policies = data.aws_iam_policy_document.vpce_restricted.json
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
}
"""
    )
    result = scan(tmp_path)

    s3_public_policy = {
        f.resource_name: f
        for f in result.findings
        if f.check_id == "S3-001" and f.detail == "public_policy"
    }
    assert "public_training_data" in s3_public_policy
    assert s3_public_policy["public_training_data"].severity == "CRITICAL"
    assert "org_training_data" not in s3_public_policy
    assert "vpce_training_data" not in s3_public_policy

    vec_public_policy = {
        f.resource_name: f
        for f in result.findings
        if f.check_id == "VEC-001" and f.detail == "public_access_policy"
    }
    assert "public_vectors" in vec_public_policy
    assert vec_public_policy["public_vectors"].severity == "CRITICAL"
    assert "org_vectors" not in vec_public_policy
    assert "vpce_vectors" not in vec_public_policy

    # The restricted domains still register as HIGH ("no vpc_options") - the
    # fix must stop overclaiming public reachability, not silence them.
    restricted_details = {
        f.resource_name: f.detail
        for f in result.findings
        if f.check_id == "VEC-001" and f.resource_name in {"org_vectors", "vpce_vectors"}
    }
    assert restricted_details == {"org_vectors": "no_vpc_options", "vpce_vectors": "no_vpc_options"}


# --------------------------------------------------------------------- #
# MM-08: NotAction / NotResource / composed policies                    #
# --------------------------------------------------------------------- #
def test_iam_inverse_and_composed_policies_are_detected(tmp_path):
    # MM-08 regression: an IAM statement using NotAction or NotResource to
    # express a near-blanket grant, a plain global Action wildcard, and an
    # unparseable composed jsonencode() must all still be caught - not just
    # the direct Action + Resource "*" shape.
    (tmp_path / "main.tf").write_text(
        """
resource "aws_iam_role" "not_action_role" {
  name = "not-action-role"
}
resource "aws_iam_role_policy" "not_action_grant" {
  name = "not-action-grant"
  role = aws_iam_role.not_action_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      NotAction = ["iam:DeleteRole"]
      Resource  = "*"
    }]
  })
}

resource "aws_iam_role" "not_resource_role" {
  name = "not-resource-role"
}
resource "aws_iam_role_policy" "not_resource_grant" {
  name = "not-resource-grant"
  role = aws_iam_role.not_resource_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect      = "Allow"
      Action      = ["bedrock:*"]
      NotResource = ["arn:aws:bedrock:us-east-1:123456789012:guardrail/excluded-one"]
    }]
  })
}

resource "aws_iam_role" "global_wildcard_role" {
  name = "global-wildcard-role"
}
resource "aws_iam_role_policy" "global_wildcard_grant" {
  name = "global-wildcard-grant"
  role = aws_iam_role.global_wildcard_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "composed_role" {
  name = "composed-role"
}
resource "aws_iam_role_policy" "composed_grant" {
  name = "composed-grant"
  role = aws_iam_role.composed_role.id
  policy = jsonencode(merge(
    {
      Version = "2012-10-17"
      Statement = [{
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }]
    },
    local.extra_statements
  ))
}
"""
    )
    result = scan(tmp_path)
    flagged = {f.resource_name for f in result.findings if f.check_id == "IAM-001"}
    assert flagged == {
        "not_action_grant",
        "not_resource_grant",
        "global_wildcard_grant",
        "composed_grant",
    }


# --------------------------------------------------------------------- #
# MM-09: symlink and special-file boundaries                           #
# --------------------------------------------------------------------- #
def test_outside_root_symlink_is_never_read(tmp_path):
    # A symlinked .tf file must not let a scan escape the directory the
    # caller actually asked to scan.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text(
        'resource "aws_s3_bucket" "leaked" {\n'
        '  bucket = "acme-leaked-training-data"\n'
        "}\n"
    )
    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    (scan_root / "linked.tf").symlink_to(outside / "secret.tf")

    graph = build_graph([scan_root])
    assert graph.files_scanned == 0
    assert graph.resources == []


def test_regular_file_symlink_inside_root_is_also_rejected(tmp_path):
    # A symlink is rejected on principle, not just when it points outside the
    # scan root - a same-directory symlink to an otherwise ordinary file must
    # not be silently followed either.
    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    real = scan_root / "real.tf"
    real.write_text('resource "aws_s3_bucket" "real" {\n  bucket = "b"\n}\n')
    (scan_root / "linked.tf").symlink_to(real)

    graph = build_graph([scan_root])
    assert graph.files_scanned == 1
    assert {r.file.name for r in graph.resources} == {"real.tf"}


def test_special_file_is_rejected_not_read(tmp_path):
    # A named pipe named like a Terraform file must not be treated as one -
    # opening it for a blocking read with no writer on the other end is
    # exactly the denial of service this guards against.
    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    os.mkfifo(scan_root / "special.tf")

    graph = build_graph([scan_root])
    assert graph.files_scanned == 1
    assert graph.resources == []
    assert len(graph.parse_errors) == 1
    assert "not a regular file" in graph.parse_errors[0][1]


def test_read_terraform_file_refuses_a_symlink_directly(tmp_path):
    # Race attempt: even if some other code path handed a symlink straight to
    # the reader - what a check-then-open race between discovery and read
    # would produce - the open() call itself must still refuse to follow it.
    # This atomicity, not the discovery-time check alone, is what actually
    # closes the race.
    real = tmp_path / "real.tf"
    real.write_text('resource "aws_s3_bucket" "x" {\n  bucket = "y"\n}\n')
    link = tmp_path / "link.tf"
    link.symlink_to(real)

    with pytest.raises(OSError):
        _read_terraform_file(link)


def test_oversized_file_is_rejected_before_full_read(tmp_path, monkeypatch):
    monkeypatch.setattr(graph_module, "_MAX_FILE_BYTES", 10)
    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    (scan_root / "big.tf").write_text('resource "aws_s3_bucket" "x" {\n  bucket = "y"\n}\n')

    graph = build_graph([scan_root])
    assert graph.files_scanned == 1
    assert graph.resources == []
    assert len(graph.parse_errors) == 1
    assert "byte" in graph.parse_errors[0][1]


def test_total_project_byte_quota_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(graph_module, "_MAX_TOTAL_BYTES", 50)
    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    for i in range(5):
        (scan_root / f"file_{i}.tf").write_text(
            f'resource "aws_s3_bucket" "b{i}" {{\n  bucket = "x{i}"\n}}\n'
        )

    graph = build_graph([scan_root])
    assert graph.files_scanned == 5
    assert any("quota" in message for _, message in graph.parse_errors)
    assert len(graph.resources) < 5


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


# --------------------------------------------------------------------- #
# SARIF output                                                          #
# --------------------------------------------------------------------- #
def _finding(**overrides) -> Finding:
    base = {
        "check_id": "S3-001",
        "check_name": "AI Data Bucket Public Exposure",
        "severity": "CRITICAL",
        "resource_type": "aws_s3_bucket",
        "resource_name": "datasets",
        "file_path": "infra/s3.tf",
        "line": 11,
        "message": "m",
        "remediation": "r",
    }
    base.update(overrides)
    return Finding(**base)


def test_sarif_envelope_is_well_formed():
    log = to_sarif(scan(INSECURE), ALL_CHECKS)
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "modelmoat"
    assert driver["informationUri"]


def test_sarif_rule_catalog_lists_every_check_not_just_the_ones_that_fired():
    # The secure fixture fires nothing, but the catalog still describes the
    # full rule set so a consumer can see what the tool covers.
    log = to_sarif(scan(SECURE), ALL_CHECKS)
    ids = {rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]}
    assert {"SMK-001", "IAM-001", "S3-001", "VPC-001", "VEC-001"} <= ids


def test_sarif_rule_index_points_at_the_matching_rule():
    # A wrong ruleIndex silently mislabels a finding as a different check.
    run = to_sarif(scan(INSECURE), ALL_CHECKS)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["results"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_severity_maps_to_level_and_security_severity():
    run = to_sarif(scan(INSECURE), ALL_CHECKS)["runs"][0]
    seen = set()
    for result in run["results"]:
        severity = result["properties"]["severity"]
        seen.add(severity)
        expected = {
            "CRITICAL": ("error", "9.0"),
            "HIGH": ("error", "7.0"),
            "MEDIUM": ("warning", "4.0"),
            "LOW": ("note", "1.0"),
        }[severity]
        assert (result["level"], result["properties"]["security-severity"]) == expected
    assert {"CRITICAL", "HIGH", "MEDIUM", "LOW"} <= seen


def test_sarif_start_line_is_always_positive():
    # SARIF requires a 1-based line. Line numbers come from a regex scan that
    # can miss, and startLine 0 makes the whole log invalid.
    run = to_sarif(scan(INSECURE), ALL_CHECKS)["runs"][0]
    for result in run["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1


def test_sarif_on_secure_fixture_has_zero_results():
    run = to_sarif(scan(SECURE), ALL_CHECKS)["runs"][0]
    assert run["results"] == []


def test_fingerprints_are_unique_across_a_scan():
    # Two findings sharing a fingerprint is a silent security hole: baselining
    # the mildest would suppress the worst, and SARIF consumers dedupe on it.
    # This caught VEC-001 reporting three separate problems against one
    # OpenSearch domain under a single identity.
    findings = scan(INSECURE).findings
    seen: dict[str, str] = {}
    for finding in findings:
        label = f"{finding.severity} {finding.check_id} {finding.message[:60]}"
        clash = seen.get(finding.fingerprint)
        assert clash is None, f"fingerprint collision:\n  {clash}\n  {label}"
        seen[finding.fingerprint] = label
    assert len(seen) == len(findings)


def test_fingerprint_survives_line_and_wording_changes():
    # Editing lines above a finding, or rewording the message, must not orphan
    # its alert history or silently drop it out of a baseline.
    assert _finding().fingerprint == _finding(line=99).fingerprint
    assert _finding().fingerprint == _finding(message="reworded").fingerprint
    assert _finding().fingerprint != _finding(resource_name="other").fingerprint
    assert _finding().fingerprint != _finding(file_path="other.tf").fingerprint
    assert _finding().fingerprint != _finding(check_id="VEC-001").fingerprint


def test_cli_sarif_matches_json_exit_codes_and_emits_valid_json():
    runner = CliRunner()

    dirty = runner.invoke(app, ["scan", str(INSECURE), "--sarif"])
    assert dirty.exit_code == 1
    assert json.loads(dirty.stdout)["version"] == "2.1.0"

    clean = runner.invoke(app, ["scan", str(SECURE), "--sarif"])
    assert clean.exit_code == 0
    assert json.loads(clean.stdout)["runs"][0]["results"] == []


def test_cli_rejects_json_and_sarif_together():
    runner = CliRunner()
    both = runner.invoke(app, ["scan", str(SECURE), "--json", "--sarif"])
    assert both.exit_code == 2


# --------------------------------------------------------------------- #
# Baselines                                                             #
# --------------------------------------------------------------------- #
def test_baseline_roundtrip_suppresses_everything_it_recorded(tmp_path):
    findings = scan(INSECURE).findings
    path = tmp_path / "baseline.json"
    write_baseline(path, findings)

    comparison = apply_baseline(findings, load_baseline(path))
    assert comparison.active == []
    assert len(comparison.suppressed) == len(findings)
    assert comparison.stale == []


def test_baseline_does_not_suppress_a_finding_it_never_recorded(tmp_path):
    findings = scan(INSECURE).findings
    assert len(findings) > 1
    path = tmp_path / "baseline.json"
    # Record everything except the first finding.
    write_baseline(path, findings[1:])

    comparison = apply_baseline(findings, load_baseline(path))
    assert comparison.active == [findings[0]]


def test_baseline_is_readable_rather_than_opaque_hashes(tmp_path):
    # A baseline is a list of accepted risk. It has to be reviewable in a pull
    # request, so each entry names the check and the resource.
    path = tmp_path / "baseline.json"
    write_baseline(path, scan(INSECURE).findings)

    payload = json.loads(path.read_text())
    assert payload["tool"] == "modelmoat"
    entry = payload["findings"][0]
    assert set(entry) == {
        "fingerprint",
        "check_id",
        "severity",
        "resource",
        "file_path",
    }


def test_baseline_reports_stale_entries(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, scan(INSECURE).findings)

    # Nothing in the insecure baseline matches the secure fixture, so every
    # entry is stale and prunable.
    comparison = apply_baseline(scan(SECURE).findings, load_baseline(path))
    assert comparison.active == []
    assert comparison.suppressed == []
    assert len(comparison.stale) == len(scan(INSECURE).findings)


def test_baseline_flags_a_suppressed_finding_that_got_worse():
    # MM-04 regression: a finding that got more severe than its baselined
    # entry is no longer accepted risk, so it must land back in `active`
    # (and therefore back in the exit code) rather than staying suppressed.
    finding = _finding(severity="CRITICAL")
    stale_entry = {finding.fingerprint: {"fingerprint": finding.fingerprint, "severity": "LOW"}}

    comparison = apply_baseline([finding], stale_entry)
    assert comparison.active == [finding]
    assert comparison.suppressed == []
    assert comparison.escalated == [(finding, "LOW")]


def test_baseline_escalation_reenters_active_json_and_sarif(tmp_path):
    # MM-04 regression: a finding baselined as Low/Medium hygiene that later
    # became Critical must fail the build and still show up in JSON and
    # SARIF output, not just print a stderr warning while everything else
    # looks clean.
    findings = scan(INSECURE).findings
    escalated = next(
        f for f in findings if f.check_id == "S3-001" and f.detail == "public_acl"
    )
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "tool": "modelmoat",
                "format": 1,
                "findings": [
                    {
                        "fingerprint": escalated.fingerprint,
                        "check_id": escalated.check_id,
                        "severity": "LOW",
                        "resource": f"{escalated.resource_type}.{escalated.resource_name}",
                        "file_path": escalated.file_path,
                    }
                ],
            }
        )
    )

    runner = CliRunner()

    dirty = runner.invoke(app, ["scan", str(INSECURE), "--baseline", str(path), "--json"])
    assert dirty.exit_code == 1, dirty.output
    payload = json.loads(dirty.stdout)
    assert any(f["fingerprint"] == escalated.fingerprint for f in payload["findings"])

    sarif = runner.invoke(app, ["scan", str(INSECURE), "--baseline", str(path), "--sarif"])
    assert sarif.exit_code == 1
    sarif_payload = json.loads(sarif.stdout)
    fingerprints = {
        r["partialFingerprints"]["modelmoatFindingV1"]
        for r in sarif_payload["runs"][0]["results"]
    }
    assert escalated.fingerprint in fingerprints


def test_baseline_without_severity_recorded_does_not_crash():
    finding = _finding()
    entry = {finding.fingerprint: {"fingerprint": finding.fingerprint}}
    comparison = apply_baseline([finding], entry)
    assert comparison.suppressed == [finding]
    assert comparison.escalated == []


def test_load_baseline_rejects_junk(tmp_path):
    missing = tmp_path / "nope.json"
    try:
        load_baseline(missing)
        raise AssertionError("expected BaselineError for a missing file")
    except BaselineError:
        pass

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json")
    try:
        load_baseline(bad_json)
        raise AssertionError("expected BaselineError for malformed JSON")
    except BaselineError:
        pass

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text('{"findings": "not a list"}')
    try:
        load_baseline(wrong_shape)
        raise AssertionError("expected BaselineError for a bad findings list")
    except BaselineError:
        pass


def test_cli_baseline_adoption_flow(tmp_path):
    runner = CliRunner()
    path = tmp_path / "baseline.json"

    # Recording a baseline exits 0 even though the fixture is full of findings,
    # so switching the tool on does not break that same build.
    write = runner.invoke(
        app, ["scan", str(INSECURE), "--write-baseline", str(path)]
    )
    assert write.exit_code == 0, write.output
    assert path.exists()

    # With that baseline every finding is known, so the build passes.
    clean = runner.invoke(app, ["scan", str(INSECURE), "--baseline", str(path)])
    assert clean.exit_code == 0, clean.output
    assert "suppressed by baseline" in clean.output

    # Without it, the same scan still fails.
    dirty = runner.invoke(app, ["scan", str(INSECURE)])
    assert dirty.exit_code == 1


def test_unparseable_file_warns_but_does_not_fail_by_default(tmp_path):
    # Unsupported HCL should not break a build, but it must be visible.
    bad = tmp_path / "main.tf"
    bad.write_text("this is not terraform {{{ [[[")

    runner = CliRunner()
    default = runner.invoke(app, ["scan", str(tmp_path)])
    assert default.exit_code == 0

    # A file nobody could read must not be silently indistinguishable from
    # clean infrastructure when a team asks for strictness.
    strict = runner.invoke(app, ["scan", str(tmp_path), "--fail-on-parse-error"])
    assert strict.exit_code == 1

    payload = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    assert json.loads(payload.stdout)["summary"]["parse_errors"] == 1


def test_incomplete_scan_fails_closed_for_machine_output_and_baseline(tmp_path):
    # MM-05 regression: malformed and unreadable input must not look like a
    # clean, complete scan to CI, to a SARIF consumer, or to a recorded
    # baseline - across human, JSON, SARIF, and baseline modes.
    malformed = tmp_path / "malformed.tf"
    malformed.write_text("this is not terraform {{{ [[[")
    unreadable = tmp_path / "unreadable.tf"
    unreadable.write_bytes(b"\xff\xfe\x00bad-utf8-\x80\x81")

    runner = CliRunner()

    # Human mode still just warns by default - unsupported HCL should not be
    # a surprise interactive build break.
    human = runner.invoke(app, ["scan", str(tmp_path)])
    assert human.exit_code == 0
    assert "could not parse" in human.output

    # --json is machine output for CI: fails closed by default and still
    # carries the diagnostics.
    json_result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    assert json_result.exit_code == 1
    payload = json.loads(json_result.stdout)
    assert payload["summary"]["parse_errors"] == 2

    # --sarif: fails closed and encodes the failure for any SARIF consumer,
    # not just modelmoat's own exit code.
    sarif_result = runner.invoke(app, ["scan", str(tmp_path), "--sarif"])
    assert sarif_result.exit_code == 1
    sarif_payload = json.loads(sarif_result.stdout)
    invocation = sarif_payload["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert len(invocation["toolExecutionNotifications"]) == 2

    # --allow-partial opts back into the lenient exit code for machine output.
    lenient_json = runner.invoke(app, ["scan", str(tmp_path), "--json", "--allow-partial"])
    assert lenient_json.exit_code == 0

    # A baseline recorded from an incomplete scan would permanently accept
    # whatever was missed as if it had been reviewed - refuse it.
    baseline_path = tmp_path / "baseline.json"
    refused = runner.invoke(
        app, ["scan", str(tmp_path), "--write-baseline", str(baseline_path)]
    )
    assert refused.exit_code == 2
    assert not baseline_path.exists()

    allowed = runner.invoke(
        app,
        ["scan", str(tmp_path), "--write-baseline", str(baseline_path), "--allow-partial"],
    )
    assert allowed.exit_code == 0
    assert baseline_path.exists()


def test_empty_target_is_an_error_unless_allowed(tmp_path):
    # MM-06 regression: a target with nothing to scan must not exit 0 and
    # look like a clean scan by default - most often because .tf.json was
    # missed or the wrong directory was given.
    runner = CliRunner()

    refused = runner.invoke(app, ["scan", str(tmp_path)])
    assert refused.exit_code == 2
    assert "no supported Terraform files" in refused.output

    allowed = runner.invoke(app, ["scan", str(tmp_path), "--allow-empty"])
    assert allowed.exit_code == 0

    # A directory that exists and has files, just none of them Terraform -
    # the wrong-directory case - hits the same gate.
    (tmp_path / "README.md").write_text("# not terraform")
    wrong_dir = runner.invoke(app, ["scan", str(tmp_path)])
    assert wrong_dir.exit_code == 2


def test_cli_baseline_errors_use_exit_code_two(tmp_path):
    runner = CliRunner()

    missing = runner.invoke(
        app, ["scan", str(SECURE), "--baseline", str(tmp_path / "nope.json")]
    )
    assert missing.exit_code == 2

    path = tmp_path / "b.json"
    path.write_text("{}")
    both = runner.invoke(
        app,
        [
            "scan",
            str(SECURE),
            "--baseline",
            str(path),
            "--write-baseline",
            str(tmp_path / "out.json"),
        ],
    )
    assert both.exit_code == 2
