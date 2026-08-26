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
from pathlib import Path

from typer.testing import CliRunner

from modelmoat.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from modelmoat.checks import ALL_CHECKS
from modelmoat.cli import app
from modelmoat.graph import ai_tokens_in, unquote
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
    assert {
        "SMK-001",
        "IAM-001",
        "S3-001",
        "VPC-001",
        "VEC-001",
        "VEC-002",
        "PIN-001",
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
    # The one way a baseline could hide something that now matters.
    finding = _finding(severity="CRITICAL")
    stale_entry = {finding.fingerprint: {"fingerprint": finding.fingerprint, "severity": "LOW"}}

    comparison = apply_baseline([finding], stale_entry)
    assert comparison.active == []
    assert comparison.escalated == [(finding, "LOW")]


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
