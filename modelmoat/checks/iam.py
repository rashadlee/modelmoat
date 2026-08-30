"""IAM-001: blanket AI service permissions.

Flags bedrock:* / sagemaker:* style actions granted on Resource "*", wherever
the policy lives: inline aws_iam_role_policy, standalone aws_iam_policy,
data.aws_iam_policy_document, or an attached AWS managed FullAccess policy.
Roles are resolved across files, and findings name the Lambda functions that
use the role so the blast radius is obvious.
"""

from __future__ import annotations

from pathlib import Path

from ..graph import ProjectGraph, Resource, as_list, extract_ref
from ..policy import (
    parse_policy_document,
    raw_wildcard_scan,
    risky_managed_policy,
    statement_block_grants,
    wildcard_ai_grants,
)
from ..scanner import Finding

_DOCS = "https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html"
_REMEDIATION = (
    "Scope the policy to the specific actions and ARNs the workload needs, for "
    "example bedrock:InvokeModel on the exact foundation model ARN. Wildcard "
    "actions on Resource \"*\" let the principal invoke, create, or delete any "
    "AI resource in the account."
)


class AIServiceIAMCheck:
    check_id = "IAM-001"
    check_name = "Blanket AI Service IAM Permissions"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        roles = graph.by_type("aws_iam_role")
        role_labels = {r.name for r in roles}
        role_by_declared_name = {
            str(r.config.get("name")): r.name
            for r in roles
            if isinstance(r.config.get("name"), str)
        }

        lambdas_by_role = self._lambdas_by_role(graph, role_by_declared_name)
        # Keyed by (module, label): a data.aws_iam_policy_document with the
        # same label in an unrelated directory must never resolve a
        # reference here, or the wrong document's grants get checked - or
        # missed - silently.
        data_docs = {
            (d.module, d.name): d for d in graph.data_by_type("aws_iam_policy_document")
        }

        def resolve_role(value) -> str | None:
            label = extract_ref(value, "aws_iam_role")
            if label:
                return label
            if isinstance(value, str):
                if value in role_labels:
                    return value
                if value in role_by_declared_name:
                    return role_by_declared_name[value]
            return None

        def usage(label: str | None) -> str:
            names = lambdas_by_role.get(label or "", [])
            if names:
                return "used by Lambda function(s) " + ", ".join(sorted(names))
            return "not attached to any Lambda function in the scanned files"

        # Inline role policies.
        for policy in graph.by_type("aws_iam_role_policy"):
            matched = self._grants(policy.config.get("policy"), data_docs, policy.module)
            if not matched:
                continue
            label = resolve_role(policy.config.get("role"))
            findings.append(
                self._finding(
                    policy,
                    f"Inline policy '{policy.name}' on role "
                    f"'{label or policy.config.get('role')}' grants "
                    f"{', '.join(matched)} on Resource \"*\". The role is "
                    f"{usage(label)}.",
                )
            )

        # Standalone customer managed policies.
        attachments = graph.by_type(
            "aws_iam_role_policy_attachment", "aws_iam_policy_attachment"
        )
        attached_roles_by_policy: dict[str, set[str]] = {}
        for attachment in attachments:
            policy_label = extract_ref(attachment.config.get("policy_arn"), "aws_iam_policy")
            if not policy_label:
                continue
            # as_list, not list(x or []): a provider-invalid but parser-valid
            # shape like `roles = true` would otherwise reach list(True) and
            # crash the whole scan, or list("a-role") and iterate it character
            # by character instead of treating it as one value.
            role_refs = [attachment.config.get("role")] + as_list(
                attachment.config.get("roles")
            )
            for ref in role_refs:
                label = resolve_role(ref)
                if label:
                    attached_roles_by_policy.setdefault(policy_label, set()).add(label)

        for policy in graph.by_type("aws_iam_policy"):
            matched = self._grants(policy.config.get("policy"), data_docs, policy.module)
            if not matched:
                continue
            attached = sorted(attached_roles_by_policy.get(policy.name, set()))
            lam_names: list[str] = []
            for label in attached:
                lam_names.extend(lambdas_by_role.get(label, []))
            if attached:
                context = f"attached to role(s) {', '.join(attached)}"
                if lam_names:
                    context += f", used by Lambda function(s) {', '.join(sorted(set(lam_names)))}"
            else:
                context = "not attached to any role in the scanned files"
            findings.append(
                self._finding(
                    policy,
                    f"Managed policy '{policy.name}' grants {', '.join(matched)} on "
                    f"Resource \"*\" and is {context}.",
                )
            )

        # AWS managed FullAccess attachments. Matching is case-insensitive on
        # both sides so mixed-case ARNs cannot slip past.
        for attachment in attachments:
            arn = attachment.config.get("policy_arn")
            matched_name = risky_managed_policy(arn)
            if not matched_name:
                continue
            label = resolve_role(attachment.config.get("role"))
            findings.append(
                self._finding(
                    attachment,
                    f"Role '{label or attachment.config.get('role')}' attaches AWS "
                    f"managed policy '{arn}', which grants blanket AI service access. "
                    f"The role is {usage(label)}.",
                )
            )

        return findings

    def _lambdas_by_role(
        self, graph: ProjectGraph, role_by_declared_name: dict[str, str]
    ) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for function in graph.by_type("aws_lambda_function"):
            role_value = function.config.get("role")
            label = extract_ref(role_value, "aws_iam_role")
            if not label and isinstance(role_value, str):
                label = role_by_declared_name.get(role_value)
            if label:
                mapping.setdefault(label, []).append(function.name)
        return mapping

    def _grants(
        self,
        policy_value,
        data_docs: dict[tuple[Path, str], Resource],
        module: Path,
    ) -> list[str]:
        doc = parse_policy_document(policy_value)
        if doc is not None:
            return wildcard_ai_grants(doc)

        data_label = extract_ref(policy_value, "data.aws_iam_policy_document") or extract_ref(
            policy_value, "aws_iam_policy_document"
        )
        if data_label and (module, data_label) in data_docs:
            return statement_block_grants(data_docs[(module, data_label)].config)

        return raw_wildcard_scan(policy_value)

    def _finding(self, resource: Resource, message: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity="HIGH",
            resource_type=resource.type,
            resource_name=resource.name,
            file_path=str(resource.file),
            line=resource.line,
            message=message,
            remediation=_REMEDIATION,
            docs_url=_DOCS,
        )
