"""SMK-002: SageMaker Model Package Group public sharing.

A different mechanism from SMK-001's network checks, so it gets its own
number under the same SageMaker prefix - the same split VEC-001/002/003
already use for vector stores that share a resource family but not a
detection mechanism.

aws_sagemaker_model_package_group_policy attaches a resource-based policy to
a model registry entry, the same shape as an S3 bucket policy. AWS's own
documentation for legitimate cross-account model sharing always names a
specific account as the principal (arn:aws:iam::{account}:root) - never "*".

Unlike an S3 bucket policy, Principal "*" here does not create anonymous,
unauthenticated access: every SageMaker API call requires a SigV4-signed
request from a valid AWS principal regardless of this policy. What "*"
removes is the account-scoping - the policy grants its listed actions
(typically sagemaker:DescribeModelPackage / ListModelPackages, sometimes
CreateModel for cross-account deployment) to any AWS account on the
internet, not the internet itself. That is a real exposure of the model
registry's catalog - what models exist, their lineage and approval status,
and potentially the ability to deploy from the package - but it is a
"broad enough to reach any AI resource" exposure, not a "reachability plus
absent authentication" one, so it is HIGH rather than CRITICAL.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, extract_ref
from ..policy import resolve_public_principal
from ..scanner import Finding

_DOCS_URL = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/"
    "model-registry-deploy-xaccount.html"
)


class ModelPackageGroupPolicyCheck:
    check_id = "SMK-002"
    check_name = "SageMaker Model Registry Public Sharing"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        groups = graph.by_type("aws_sagemaker_model_package_group")
        group_policies = graph.by_type("aws_sagemaker_model_package_group_policy")
        # Keyed by (module, label): a data.aws_iam_policy_document with the
        # same label in an unrelated directory must never resolve a group
        # policy reference here - the same reasoning S3-001 already applies
        # to bucket policies.
        data_docs = {
            (d.module, d.name): d for d in graph.data_by_type("aws_iam_policy_document")
        }

        for policy in group_policies:
            group = self._target_group(policy, groups)
            group_label = group.name if group is not None else policy.config.get(
                "model_package_group_name"
            )

            is_public = resolve_public_principal(
                policy.config.get("resource_policy"), data_docs, policy.module
            )
            if is_public is None:
                is_public = (
                    '"principal": "*"' in str(policy.config.get("resource_policy", "")).lower()
                )
            if not is_public:
                continue

            findings.append(
                self._finding(
                    group if group is not None else policy,
                    (
                        f"Model package group '{group_label}' has a resource "
                        'policy allowing Principal "*". SageMaker API calls '
                        "always require a signed request, so this is not "
                        "anonymous internet access, but it removes the "
                        "account-scoping that cross-account model sharing is "
                        "supposed to have: any AWS account can perform the "
                        "granted actions against this model registry entry, "
                        "not just accounts you named."
                    ),
                    (
                        "Replace Principal \"*\" with specific account "
                        'principals (arn:aws:iam::{account}:root) on '
                        f"aws_sagemaker_model_package_group_policy.{policy.name}, "
                        "matching AWS's documented pattern for cross-account "
                        "model registry sharing."
                    ),
                )
            )

        return findings

    def _target_group(
        self, policy: Resource, groups: list[Resource]
    ) -> Resource | None:
        ref_value = policy.config.get("model_package_group_name")
        label = extract_ref(ref_value, "aws_sagemaker_model_package_group")
        for group in groups:
            if group.module != policy.module:
                continue
            if label == group.name:
                return group
            declared_name = group.config.get("model_package_group_name")
            if isinstance(ref_value, str) and ref_value in (group.name, declared_name):
                return group
        return None

    def _finding(self, resource: Resource, message: str, remediation: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity="HIGH",
            resource_type=resource.type,
            resource_name=resource.name,
            file_path=str(resource.file),
            line=resource.line,
            message=message,
            remediation=remediation,
            docs_url=_DOCS_URL,
            detail="public_resource_policy",
        )
