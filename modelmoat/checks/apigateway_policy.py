"""AGW-002: API Gateway REST API resource policies granting Principal "*".

A different mechanism from AGW-001's method-level authorization check, so
it gets its own number under the same AGW prefix - the same split
VEC-001/002/003 and SMK-001/002 already use within one resource family.

AWS's own authorization-flow documentation gives the exact combining logic
between an IAM policy and a resource policy: when the caller's IAM policy
neither explicitly allows nor denies the request, a resource policy that
allows it wins. A caller with valid AWS credentials but no IAM statement
mentioning this API sits in that "neither" state by default, so a resource
policy with Principal "*" and Effect Allow on execute-api:Invoke makes
every method on the API invokable - including ones whose own
authorization looks safe in isolation ("AWS_IAM"). AWS's own
control-access documentation names this exact failure mode directly:
"Failing to [require IAM auth on every method] will make these API
methods publicly accessible" when a public resource policy is present.

This fires regardless of what any individual method proxies to - the
policy is evaluated once per invocation at the API level, not per
integration type - but it is still gated on this REST API having at least
one method that proves a SageMaker or Bedrock backend, the same
provable-AI-relevance bar AGW-001 already holds to. A public resource
policy on a REST API with no AI-relevant backend at all is a real,
independently valid finding, but it is generic API Gateway security
already covered by general IaC scanners - out of scope for the same
reason AGW-001 itself does not fire on a public method proxying to
something other than Bedrock/SageMaker.

A Condition block (aws:SourceIp, aws:SourceVpce, aws:SourceVpc - all in
AWS's own policy examples) narrows an otherwise-public statement enough
that this check cannot prove it is actually reachable by anyone, so it is
excluded the same way S3-001 and SMK-002 already exclude a conditioned
Principal "*" grant.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, extract_ref
from ..policy import resolve_public_principal
from ..scanner import Finding
from .apigateway import APIGatewayAIProxyAuthCheck

_DOCS_URL = (
    "https://docs.aws.amazon.com/apigateway/latest/developerguide/"
    "apigateway-authorization-flow.html"
)


class APIGatewayPublicResourcePolicyCheck:
    check_id = "AGW-002"
    check_name = "API Gateway Resource Policy Allows Any Principal"

    def __init__(self) -> None:
        # Reuses AGW-001's own AI-backend proof rather than duplicating it -
        # a REST API only counts as AI-relevant here if AGW-001 could have
        # matched at least one integration underneath it.
        self._agw001 = APIGatewayAIProxyAuthCheck()

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        rest_apis = graph.by_type("aws_api_gateway_rest_api")
        integrations = graph.by_type("aws_api_gateway_integration")
        policy_resources = graph.by_type("aws_api_gateway_rest_api_policy")
        data_docs = {
            (d.module, d.name): d for d in graph.data_by_type("aws_iam_policy_document")
        }

        for rest_api in rest_apis:
            if not self._has_ai_backend(rest_api, integrations):
                continue

            policy_value, policy_module = self._effective_policy(
                rest_api, policy_resources
            )
            if policy_value is None:
                continue

            is_public = resolve_public_principal(policy_value, data_docs, policy_module)
            if is_public is None:
                is_public = '"principal": "*"' in str(policy_value).lower()
            if not is_public:
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="CRITICAL",
                    resource_type=rest_api.type,
                    resource_name=rest_api.name,
                    file_path=str(rest_api.file),
                    line=rest_api.line,
                    message=(
                        f"REST API '{rest_api.name}' has at least one method "
                        "proxying to a SageMaker or Bedrock backend, and a "
                        'resource policy allowing Principal "*" with no '
                        "restricting Condition. Per AWS's own authorization-flow "
                        "documentation, this makes every method on the API "
                        "invokable regardless of its own authorization setting - "
                        "a method requiring AWS_IAM is not actually protected "
                        "when the resource policy independently allows the "
                        "caller."
                    ),
                    remediation=(
                        "Restrict the resource policy's Principal to specific "
                        "accounts or roles, or add a Condition such as "
                        "aws:SourceVpce or aws:SourceIp scoped to trusted "
                        "callers only."
                    ),
                    docs_url=_DOCS_URL,
                    detail="public_resource_policy",
                )
            )

        return findings

    def _has_ai_backend(self, rest_api: Resource, integrations: list[Resource]) -> bool:
        for integration in integrations:
            if integration.module != rest_api.module:
                continue
            ref = integration.config.get("rest_api_id")
            label = extract_ref(ref, "aws_api_gateway_rest_api")
            literal_match = isinstance(ref, str) and ref in (
                rest_api.name,
                rest_api.config.get("name"),
            )
            if label != rest_api.name and not literal_match:
                continue
            if self._agw001._ai_service_target(integration) is not None:
                return True
        return False

    def _effective_policy(
        self, rest_api: Resource, policy_resources: list[Resource]
    ):
        """The policy value in effect for this REST API, and the module it
        should be resolved in.

        Terraform expresses this two ways: inline on aws_api_gateway_rest_api
        itself, or as a separate aws_api_gateway_rest_api_policy resource
        referencing the API via rest_api_id. Both set the same underlying
        AWS property, so both are treated as equivalent sources - checked in
        the same module-scoped way every other cross-resource correlation in
        this project already is.
        """
        inline = rest_api.config.get("policy")
        if inline:
            return inline, rest_api.module

        for policy_resource in policy_resources:
            if policy_resource.module != rest_api.module:
                continue
            ref = policy_resource.config.get("rest_api_id")
            label = extract_ref(ref, "aws_api_gateway_rest_api")
            literal_match = isinstance(ref, str) and ref in (
                rest_api.name,
                rest_api.config.get("name"),
            )
            if label == rest_api.name or literal_match:
                return policy_resource.config.get("policy"), policy_resource.module

        return None, rest_api.module
