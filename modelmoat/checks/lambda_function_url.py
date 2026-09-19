"""LFU-001: Lambda Function URLs with zero authentication calling AI services.

A new mechanism, not an extension of AGW-001/002 - those check API Gateway
sitting in front of Bedrock/SageMaker. Lambda Function URLs are a separate,
simpler AWS feature that bypasses API Gateway entirely, with their own
authorization model.

aws_lambda_function_url's authorization_type is required, not optional,
with two values: "AWS_IAM" or "NONE". AWS's own documentation
(docs.aws.amazon.com/lambda/latest/dg/urls-auth.html) is unusually
explicit about what "NONE" means: "Lambda doesn't perform any
authentication before invoking your function... Choose this option to
allow public, unauthenticated access to your function URL." Unlike almost
every other finding in this project, there is no SigV4 fallback here -
this is a genuine zero-authentication path, not "reachable but still
signed," which is why this joins AGW-001 and BRK-001 as one of the
project's few CRITICAL findings.

A function URL's authorization_type alone does not prove public
reachability, though. AWS's own docs state plainly that "your function's
resource-based policy is always in effect and must grant public access
before your function URL can receive requests" - when a function URL is
created outside the console/SAM, that policy does not exist unless you add
it yourself via a separate aws_lambda_permission resource
(action = "lambda:InvokeFunctionUrl", principal = "*",
function_url_auth_type = "NONE"). Without it, AWS returns 403 regardless
of authorization_type. So this check requires both resources to exist and
agree, the same two-resource-agreement shape AGW-002 already uses for a
REST API's resource policy - modelmoat does not flag what it cannot prove.

Reuses VPC-001's existing IAM-role-to-AI-service correlation
(AIVPCEndpointCheck._function_signals/_role_signals) rather than
duplicating it, the same cross-check reuse pattern AGW-002 already uses
for AGW-001's _ai_service_target. A publicly invokable Lambda with no
AI-service signal at all is a real, independently valid finding, but it
is generic Lambda security already covered by general IaC scanners and by
AWS Security Hub's own "Lambda function policies should prohibit public
access" finding - out of scope for the same reason AGW-001 does not fire
on a public method proxying to something other than Bedrock/SageMaker.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, extract_ref, is_unknown
from ..scanner import Finding
from .network import AIVPCEndpointCheck

_DOCS_URL = "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"


def _is_none_auth(value) -> bool:
    if not isinstance(value, str) or is_unknown(value):
        return False
    return value.strip() == "NONE"


def _grants_public_function_url_invoke(permission: Resource) -> bool:
    action = str(permission.config.get("action", "")).strip()
    if action != "lambda:InvokeFunctionUrl":
        return False

    principal = permission.config.get("principal")
    if not isinstance(principal, str) or is_unknown(principal) or principal.strip() != "*":
        return False

    auth_type = permission.config.get("function_url_auth_type")
    if not isinstance(auth_type, str) or is_unknown(auth_type):
        return False
    return auth_type.strip() == "NONE"


class LambdaFunctionURLPublicAIAccessCheck:
    check_id = "LFU-001"
    check_name = "Lambda Function URL With No Authentication Calling an AI Service"

    def __init__(self) -> None:
        self._vpc001 = AIVPCEndpointCheck()

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        functions_by_module_label = {
            (f.module, f.name): f for f in graph.by_type("aws_lambda_function")
        }
        role_signals = self._vpc001._role_signals(graph)

        public_permission_labels: set[tuple] = set()
        for permission in graph.by_type("aws_lambda_permission"):
            if not _grants_public_function_url_invoke(permission):
                continue
            function_label = extract_ref(permission.config.get("function_name"), "aws_lambda_function")
            if function_label:
                public_permission_labels.add((permission.module, function_label))

        for function_url in graph.by_type("aws_lambda_function_url"):
            if not _is_none_auth(function_url.config.get("authorization_type")):
                continue

            function_label = extract_ref(
                function_url.config.get("function_name"), "aws_lambda_function"
            )
            if not function_label:
                continue
            if (function_url.module, function_label) not in public_permission_labels:
                continue

            function = functions_by_module_label.get((function_url.module, function_label))
            if function is None:
                continue

            signals = self._vpc001._function_signals(function, role_signals)
            for service in sorted(signals):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity="CRITICAL",
                        resource_type=function_url.type,
                        resource_name=function_url.name,
                        file_path=str(function_url.file),
                        line=function_url.line,
                        message=(
                            f"Function URL on '{function.name}' sets "
                            'authorization_type = "NONE" and has a matching '
                            "aws_lambda_permission granting public "
                            "lambda:InvokeFunctionUrl access, and the function "
                            f"shows signals of calling {service}. Lambda "
                            "performs no authentication at all before "
                            "invoking the function - unlike an API Gateway "
                            "or SigV4-signed call, anyone on the internet can "
                            "invoke it directly."
                        ),
                        remediation=(
                            'Set authorization_type = "AWS_IAM" on '
                            f"{function_url.type}.{function_url.name} and "
                            "remove the public aws_lambda_permission, or "
                            "front the function with an authenticated API "
                            "Gateway method instead."
                        ),
                        docs_url=_DOCS_URL,
                        detail=service,
                    )
                )

        return findings
