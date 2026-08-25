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


def parse_policy_document(value) -> dict | None:
    """Parse a policy attribute into a dict, or None when it cannot be resolved."""
    if isinstance(value, dict):
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
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        parsed = json.loads(_hcl_object_to_json(text))
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def iter_statements(doc: dict):
    for statement in as_list(doc.get("Statement") or doc.get("statement")):
        if isinstance(statement, dict):
            yield statement


def _is_allow(statement: dict) -> bool:
    effect = statement.get("Effect", statement.get("effect", "Allow"))
    return str(effect).strip().lower() == "allow"


def _wildcard_resource(resources) -> bool:
    return any(str(r).strip() == "*" for r in as_list(resources))


def wildcard_ai_grants(doc: dict) -> list[str]:
    """Actions like bedrock:* or sagemaker:* granted on Resource "*"."""
    matched: set[str] = set()
    for statement in iter_statements(doc):
        if not _is_allow(statement):
            continue
        resources = statement.get("Resource", statement.get("resource"))
        if not _wildcard_resource(resources):
            continue
        for action in as_list(statement.get("Action") or statement.get("action")):
            action_str = str(action).strip().lower()
            if action_str == "*":
                matched.add("*")
                continue
            service = action_str.split(":", 1)[0]
            if action_str.endswith(":*") and service in AI_ACTION_PREFIXES:
                matched.add(action_str)
    return sorted(matched)


def statement_block_grants(data_config: dict) -> list[str]:
    """Same analysis for a data.aws_iam_policy_document config (statement blocks)."""
    matched: set[str] = set()
    from .graph import blocks  # local import avoids a cycle at module load

    for statement in blocks(data_config, "statement"):
        effect = str(statement.get("effect", "Allow")).strip().lower()
        if effect != "allow":
            continue
        if not _wildcard_resource(statement.get("resources")):
            continue
        for action in as_list(statement.get("actions")):
            action_str = str(action).strip().lower()
            if action_str == "*":
                matched.add("*")
                continue
            service = action_str.split(":", 1)[0]
            if action_str.endswith(":*") and service in AI_ACTION_PREFIXES:
                matched.add(action_str)
    return sorted(matched)


def raw_wildcard_scan(value) -> list[str]:
    """Conservative fallback when a policy string cannot be parsed."""
    if not isinstance(value, str):
        return []
    lowered = value.lower()
    if '"*"' not in lowered:
        return []
    return sorted(
        f"{prefix}:*"
        for prefix in AI_ACTION_PREFIXES
        if f"{prefix}:*" in lowered
    )


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
