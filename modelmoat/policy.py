"""IAM policy document parsing and analysis.

Terraform expresses IAM policies at least four ways: a jsonencode() call
(which python-hcl2 serializes back in HCL syntax, with = instead of :),
a raw JSON heredoc, a reference to a data.aws_iam_policy_document, or an
attached managed policy ARN. modelmoat handles all four, and when a document
cannot be parsed it falls back to a conservative text scan rather than
guessing.
"""

from __future__ import annotations

import json
import re

from .graph import as_list

# Action prefixes that count as AI or ML service access.
AI_ACTION_PREFIXES = (
    "bedrock",
    "bedrock-agent",
    "bedrock-agent-runtime",
    "bedrock-runtime",
    "sagemaker",
    "comprehend",
    "rekognition",
    "textract",
    "translate",
    "polly",
    "lex",
    "personalize",
    "forecast",
    "kendra",
    "qbusiness",
)

# AWS managed policies that grant blanket AI service access. Comparison is
# case-insensitive on both sides.
RISKY_MANAGED_POLICIES = (
    "amazonbedrockfullaccess",
    "amazonsagemakerfullaccess",
)

_HCL_KEY = re.compile(r'("[^"\n=]+"|\b[A-Za-z_][A-Za-z0-9_]*\b)\s*=(?!=)')


def risky_managed_policy(policy_arn) -> str | None:
    """Return the matched risky managed policy name, or None."""
    if not isinstance(policy_arn, str) or not policy_arn:
        return None
    lowered = policy_arn.lower()
    for managed in RISKY_MANAGED_POLICIES:
        if lowered.endswith(("/" + managed, managed)):
            return managed
    return None


def _hcl_object_to_json(text: str) -> str:
    """Best-effort rewrite of an HCL object literal into JSON."""

    def replace(match: re.Match) -> str:
        key = match.group(1)
        if key.startswith('"'):
            return f"{key}:"
        return f'"{key}":'

    return _HCL_KEY.sub(replace, text)


def parse_json_value(value, expected_type: type):
    """Parse a Terraform string attribute into `expected_type` (dict or list).

    Covers all the shapes hcl2 8.x hands back for a jsonencode() call, a raw
    JSON heredoc, or an HCL object/array literal: the whole value wrapped in
    ${...} (every function call gets this treatment, not just ones with real
    unknowns), then jsonencode(...) itself, then either valid JSON or HCL
    syntax using = instead of :. A value that still contains an unresolved
    reference after unwrapping fails both parse attempts and correctly falls
    through to None - modelmoat does not flag what it cannot prove.
    """
    if isinstance(value, expected_type):
        return value
    if not isinstance(value, str):
        return None

    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    if text.startswith("jsonencode(") and text.endswith(")"):
        text = text[len("jsonencode("):-1].strip()

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, expected_type) else None
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        parsed = json.loads(_hcl_object_to_json(text))
        return parsed if isinstance(parsed, expected_type) else None
    except (json.JSONDecodeError, ValueError):
        return None


def parse_policy_document(value) -> dict | None:
    """Parse a policy attribute into a dict, or None when it cannot be resolved."""
    return parse_json_value(value, dict)


def iter_statements(doc: dict):
    for statement in as_list(doc.get("Statement") or doc.get("statement")):
        if isinstance(statement, dict):
            yield statement


def _is_allow(statement: dict) -> bool:
    effect = statement.get("Effect", statement.get("effect", "Allow"))
    return str(effect).strip().lower() == "allow"


def _wildcard_resource(resources) -> bool:
    return any(str(r).strip() == "*" for r in as_list(resources))


def _matched_actions(actions, not_actions, matched: set[str]) -> None:
    """Add wildcard AI grants found in `actions` to `matched` in place.

    `NotAction` grants every action except the ones listed - on a resource
    scope already judged broad enough to matter, that is a near-blanket
    grant no static analyzer can prove excludes every AI service action, so
    it is treated the same as a literal `Action = "*"` rather than silently
    contributing nothing because there is no `Action` key to enumerate.
    """
    if actions is None and not_actions is not None:
        matched.add("*")
        return
    for action in as_list(actions):
        action_str = str(action).strip().lower()
        if action_str == "*":
            matched.add("*")
            continue
        service = action_str.split(":", 1)[0]
        if action_str.endswith(":*") and service in AI_ACTION_PREFIXES:
            matched.add(action_str)


def wildcard_ai_grants(doc: dict) -> list[str]:
    """Actions like bedrock:* or sagemaker:* granted on a resource scope
    broad enough to include them - Resource "*", or NotResource excluding
    only a handful of ARNs from an otherwise universal grant.
    """
    matched: set[str] = set()
    for statement in iter_statements(doc):
        if not _is_allow(statement):
            continue
        resources = statement.get("Resource", statement.get("resource"))
        not_resources = statement.get("NotResource", statement.get("notresource"))
        if not _wildcard_resource(resources) and not_resources is None:
            continue
        _matched_actions(
            statement.get("Action", statement.get("action")),
            statement.get("NotAction", statement.get("notaction")),
            matched,
        )
    return sorted(matched)


def statement_block_grants(data_config: dict) -> list[str]:
    """Same analysis for a data.aws_iam_policy_document config (statement blocks)."""
    matched: set[str] = set()
    from .graph import blocks  # local import avoids a cycle at module load

    for statement in blocks(data_config, "statement"):
        effect = str(statement.get("effect", "Allow")).strip().lower()
        if effect != "allow":
            continue
        not_resources = statement.get("not_resources")
        if not _wildcard_resource(statement.get("resources")) and not_resources is None:
            continue
        _matched_actions(statement.get("actions"), statement.get("not_actions"), matched)
    return sorted(matched)


_RAW_ACTION_WILDCARD = re.compile(r'"?action"?\s*[:=]\s*(\[\s*)?"\*"')


def raw_wildcard_scan(value) -> list[str]:
    """Conservative fallback when a policy string cannot be parsed - most
    often a jsonencode() call composed from merge()/concat() or similar,
    which resolves at apply time but not statically.
    """
    if not isinstance(value, str):
        return []
    lowered = value.lower()
    if '"*"' not in lowered:
        return []

    matched = {
        f"{prefix}:*" for prefix in AI_ACTION_PREFIXES if f"{prefix}:*" in lowered
    }

    # A literal Action = "*" grants everything on its face, regardless of
    # which AI service prefixes also happen to appear - a scan that only
    # looked for those prefixes would miss the single broadest grant there
    # is.
    if _RAW_ACTION_WILDCARD.search(lowered):
        matched.add("*")

    return sorted(matched)


def allows_public_principal(doc: dict) -> bool:
    """True when any Allow statement grants to Principal "*"."""
    for statement in iter_statements(doc):
        if not _is_allow(statement):
            continue
        principal = statement.get("Principal", statement.get("principal"))
        if isinstance(principal, str) and principal.strip() == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS", principal.get("aws"))
            if any(str(p).strip() == "*" for p in as_list(aws)):
                return True
    return False


_VPC_RESTRICTING_CONDITION_KEYS = {"aws:sourcevpce", "aws:sourcevpc"}


def _has_vpc_restricting_condition(statement: dict) -> bool:
    from .graph import blocks  # local import avoids a cycle at module load

    for condition in blocks(statement, "condition"):
        variable = str(condition.get("variable", "")).strip().lower()
        if variable in _VPC_RESTRICTING_CONDITION_KEYS:
            return True
    return False


def statement_block_allows_public_principal(data_config: dict) -> bool:
    """Same check as allows_public_principal, for a data.aws_iam_policy_document
    config expressed as `principals` blocks rather than a JSON Principal key.

    A `principals { identifiers = ["*"] }` statement gated by an
    aws:SourceVpce/aws:SourceVpc condition is the standard way to restrict a
    resource policy to a specific VPC endpoint - there is no principal-only
    way to express that restriction in IAM, so it must be recognized here or
    every VPC-endpoint-restricted document referenced this way would read as
    public. This intentionally does not extend to inline JSON policies via
    allows_public_principal - broader Condition handling there is a separate,
    not-yet-addressed gap.
    """
    from .graph import blocks  # local import avoids a cycle at module load

    for statement in blocks(data_config, "statement"):
        effect = str(statement.get("effect", "Allow")).strip().lower()
        if effect != "allow":
            continue
        if _has_vpc_restricting_condition(statement):
            continue
        for principal_block in blocks(statement, "principals"):
            identifiers = principal_block.get("identifiers")
            if any(str(p).strip() == "*" for p in as_list(identifiers)):
                return True
    return False


def resolve_public_principal(policy_value, data_docs: dict, module) -> bool | None:
    """Resolve a policy attribute to whether it grants a public principal,
    following a reference to a data.aws_iam_policy_document in the same
    module when the value is not inline JSON/jsonencode.

    `data_docs` is keyed by `(module, label)`, matching how IAM-001 already
    resolves data source references - a same-named document in an unrelated
    directory must never stand in for the one actually referenced.

    Returns None when the policy could not be resolved at all: modelmoat
    does not flag what it cannot prove, but a caller must not read None as
    "not public" either, since that would be proving safety it cannot back
    up. Callers should fall back to their own conservative handling for the
    unresolved case, the same way they already do for a policy that fails to
    parse at all.
    """
    doc = parse_policy_document(policy_value)
    if doc is not None:
        return allows_public_principal(doc)

    from .graph import extract_ref  # local import avoids a cycle at module load

    label = extract_ref(policy_value, "data.aws_iam_policy_document") or extract_ref(
        policy_value, "aws_iam_policy_document"
    )
    if not label:
        return None

    entry = data_docs.get((module, label))
    if entry is None:
        return None
    return statement_block_allows_public_principal(entry.config)
