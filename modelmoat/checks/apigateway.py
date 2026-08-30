"""AGW-001: API Gateway REST methods proxying directly to Bedrock or SageMaker
with no client-side authorization.

This only fires when the method's own integration proves, through the
provider's documented AWS-service-proxy uri format -
arn:aws:apigateway:{region}:{service}:path|action/{...} - that the backend is
a SageMaker or Bedrock runtime invocation. A REST method with
authorization = "NONE" in front of anything else (a Lambda, an HTTP backend,
another AWS service entirely) is generic API security, already covered by
general IaC scanners, and out of scope here.

The uri is matched by regex, not gated on is_unknown for the whole string, the
same way VPC-001 matches a service fragment inside a service_name built from a
region variable: arn:aws:apigateway:${var.region}:runtime.sagemaker:path/...
still proves the target is SageMaker even though the region segment is not
literal. Only a uri that is unprovable at the service segment itself (a
variable, a completely different prefix) fails to match, and the regex's
anchored literal prefix already handles that without a separate check.

API Gateway v2 (aws_apigatewayv2_route / aws_apigatewayv2_integration, i.e.
HTTP and WebSocket APIs) is deliberately not covered. The only way an HTTP API
integration can name a specific AWS service target without a Lambda in the
middle is integration_subtype, and AWS's own integration subtype reference
lists EventBridge, SQS, AppConfig, Kinesis, and Step Functions only - no
SageMaker or Bedrock subtype exists. Every other v2 path to either service
goes through a Lambda AWS_PROXY integration, and what that Lambda's code
calls is invisible to Terraform. modelmoat does not flag what it cannot
prove.
"""

from __future__ import annotations

import re

from ..graph import ProjectGraph, Resource, extract_ref, first_block, is_unknown
from ..scanner import Finding

_DOCS = "https://docs.aws.amazon.com/apigateway/latest/api/API_PutIntegration.html"

# The ARN service segment for AWS/AWS_PROXY service-proxy integrations, e.g.
# arn:aws:apigateway:us-east-1:runtime.sagemaker:path/endpoints/x/invocations.
# runtime.sagemaker is AWS's own documented example for SageMaker realtime
# inference. bedrock-runtime and bedrock-agent-runtime match the actual
# regional service hostnames (bedrock-runtime.<region>.amazonaws.com and
# bedrock-agent-runtime.<region>.amazonaws.com) that this proxy mechanism is
# generic enough to reach, even without an AWS-published worked example of
# that exact pairing.
_AI_SERVICE_SEGMENTS = {"runtime.sagemaker", "bedrock-runtime", "bedrock-agent-runtime"}

_ARN_SERVICE = re.compile(r"^arn:aws:apigateway:[^:]*:([^:]+):(?:path|action)/")


def _identity(value, resource_type: str) -> str | None:
    """A stable identity for a field that is either a resource reference or a literal.

    Returns None when the value can't be resolved to either, so callers treat
    it the same way every other check treats an unprovable value: skip it.
    """
    if not isinstance(value, str):
        return None
    label = extract_ref(value, resource_type)
    if label:
        return f"{resource_type}.{label}"
    if is_unknown(value):
        return None
    return value.strip()


class APIGatewayAIProxyAuthCheck:
    check_id = "AGW-001"
    check_name = "API Gateway AI Service Proxy Without Authorization"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        methods = graph.by_type("aws_api_gateway_method")
        rest_apis = graph.by_type("aws_api_gateway_rest_api")

        for integration in graph.by_type("aws_api_gateway_integration"):
            service = self._ai_service_target(integration)
            if service is None:
                continue

            method = self._matching_method(integration, methods)
            if method is None:
                continue

            authorization = method.config.get("authorization")
            if not isinstance(authorization, str) or is_unknown(authorization):
                continue
            if authorization.strip() != "NONE":
                continue

            if self._is_private(method, rest_apis):
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="CRITICAL",
                    resource_type=method.type,
                    resource_name=method.name,
                    file_path=str(method.file),
                    line=method.line,
                    message=(
                        f"API Gateway method '{method.name}' has authorization = "
                        f'"NONE" and its integration (\'{integration.name}\') proxies '
                        f"directly to {service}, proven by the integration's own uri. "
                        "Any caller who can reach the API's default execute-api "
                        "endpoint gets unauthenticated inference or agent invocation, "
                        "billed to your account, with no IAM or Cognito check on the "
                        "client side. api_key_required does not change this: a usage "
                        "plan key is metering, not authentication."
                    ),
                    remediation=(
                        'Set authorization to "AWS_IAM" or a configured authorizer '
                        f'("CUSTOM" or "COGNITO_USER_POOLS") on '
                        f"aws_api_gateway_method.{method.name}."
                    ),
                    docs_url=_DOCS,
                )
            )

        return findings

    def _ai_service_target(self, integration: Resource) -> str | None:
        itype = integration.config.get("type")
        if not isinstance(itype, str) or is_unknown(itype) or itype.strip() not in (
            "AWS",
            "AWS_PROXY",
        ):
            return None

        uri = integration.config.get("uri")
        if not isinstance(uri, str):
            return None
        match = _ARN_SERVICE.match(uri)
        if not match:
            return None
        segment = match.group(1).lower()
        return segment if segment in _AI_SERVICE_SEGMENTS else None

    def _matching_method(
        self, integration: Resource, methods: list[Resource]
    ) -> Resource | None:
        # The idiomatic Terraform form: the integration's http_method references
        # the method's own attribute, which names the method resource directly.
        label = extract_ref(integration.config.get("http_method"), "aws_api_gateway_method")
        if label:
            for method in methods:
                if method.name == label:
                    return method
            return None

        # Fallback: both sides write http_method as a literal, so the join is
        # the (rest_api_id, resource_id, http_method) triple AWS itself uses.
        key = self._triple(integration)
        if key is None:
            return None
        for method in methods:
            if self._triple(method) == key:
                return method
        return None

    def _triple(self, resource: Resource) -> tuple[str, str, str] | None:
        rest_api = _identity(resource.config.get("rest_api_id"), "aws_api_gateway_rest_api")
        resource_id = _identity(resource.config.get("resource_id"), "aws_api_gateway_resource")
        http_method = resource.config.get("http_method")
        if not isinstance(http_method, str) or is_unknown(http_method):
            return None
        if rest_api is None or resource_id is None:
            return None
        return (rest_api, resource_id, http_method.strip())

    def _is_private(self, method: Resource, rest_apis: list[Resource]) -> bool:
        """True only when endpoint_configuration proves the API isn't public.

        The default execute-api endpoint (EDGE or REGIONAL, and REGIONAL is
        what a REST API gets when endpoint_configuration is omitted entirely)
        is reachable from the internet. Only an explicit PRIVATE type changes
        that, so this is the one case where reachability isn't proven.
        """
        api_label = extract_ref(method.config.get("rest_api_id"), "aws_api_gateway_rest_api")
        if not api_label:
            return False
        api = next((a for a in rest_apis if a.name == api_label), None)
        if api is None:
            return False
        endpoint_config = first_block(api.config, "endpoint_configuration")
        if endpoint_config is None:
            return False
        types = endpoint_config.get("types")
        if isinstance(types, str):
            types = [types]
        if not isinstance(types, list):
            return False
        return any(isinstance(t, str) and t.strip() == "PRIVATE" for t in types)
