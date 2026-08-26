"""VPC-001: AI service traffic without PrivateLink.

VPC endpoints only matter for traffic that originates inside a VPC, so the
check distinguishes two situations instead of shouting at both:

  MEDIUM  a VPC-attached Lambda shows signals of calling Bedrock or SageMaker
          and no matching interface endpoint exists anywhere in the project.
          Depending on routing, those calls either fail or leave through a
          NAT gateway to public AWS endpoints.
  LOW     a Lambda with AI signals runs outside any VPC. Its traffic uses
          public AWS endpoints, which are TLS plus IAM authenticated. That is
          acceptable for many workloads and the finding says so.

Endpoint matching is on the service fragment (".bedrock-runtime",
".sagemaker.runtime"), so a service_name built from a region variable still
matches and does not produce a false positive.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, blocks, extract_ref
from ..scanner import Finding

_DOCS = "https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html"

_SERVICES = {
    "bedrock": ".bedrock-runtime",
    "sagemaker": ".sagemaker.runtime",
}


class AIVPCEndpointCheck:
    check_id = "VPC-001"
    check_name = "AI Service Traffic Without PrivateLink"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        endpoint_services = [
            str(endpoint.config.get("service_name", "")).lower()
            for endpoint in graph.by_type("aws_vpc_endpoint")
        ]

        def endpoint_exists(fragment: str) -> bool:
            return any(fragment in service for service in endpoint_services)

        role_signals = self._role_signals(graph)

        for function in graph.by_type("aws_lambda_function"):
            in_vpc = bool(blocks(function.config, "vpc_config"))
            signals = self._function_signals(function, role_signals)

            for service in sorted(signals):
                fragment = _SERVICES[service]
                if in_vpc and not endpoint_exists(fragment):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_name=self.check_name,
                            severity="MEDIUM",
                            resource_type=function.type,
                            resource_name=function.name,
                            file_path=str(function.file),
                            line=function.line,
                            message=(
                                f"Lambda '{function.name}' runs inside a VPC and shows "
                                f"signals of calling {service}, but no interface VPC "
                                f"endpoint matching '{fragment}' exists in the scanned "
                                "files. Depending on routing, calls either fail or exit "
                                "through NAT to public AWS endpoints."
                            ),
                            remediation=(
                                "Add an aws_vpc_endpoint with vpc_endpoint_type "
                                '"Interface" and service_name '
                                f'"com.amazonaws.<region>{fragment}" in the same VPC, '
                                "and allow the Lambda security group to reach it on 443."
                            ),
                            docs_url=_DOCS,
                            detail=service,
                        )
                    )
                elif not in_vpc:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_name=self.check_name,
                            severity="LOW",
                            resource_type=function.type,
                            resource_name=function.name,
                            file_path=str(function.file),
                            line=function.line,
                            message=(
                                f"Lambda '{function.name}' shows signals of calling "
                                f"{service} and is not attached to a VPC, so traffic "
                                "uses public AWS endpoints. Those are TLS and IAM "
                                "authenticated, which many workloads accept. For "
                                "sensitive prompts or regulated data, keep the traffic "
                                "on your private network."
                            ),
                            remediation=(
                                "If this workload handles sensitive data, attach the "
                                "Lambda to a VPC and add an interface endpoint for "
                                f'"com.amazonaws.<region>{fragment}".'
                            ),
                            docs_url=_DOCS,
                            detail=service,
                        )
                    )

        return findings

    def _function_signals(
        self, function: Resource, role_signals: dict[str, set[str]]
    ) -> set[str]:
        signals: set[str] = set()

        for environment in blocks(function.config, "environment"):
            variables = environment.get("variables")
            if isinstance(variables, dict):
                for key, value in variables.items():
                    text = f"{key} {value}".lower()
                    for service in _SERVICES:
                        if service in text:
                            signals.add(service)

        role_label = extract_ref(function.config.get("role"), "aws_iam_role")
        if role_label:
            signals |= role_signals.get(role_label, set())

        return signals

    def _role_signals(self, graph: ProjectGraph) -> dict[str, set[str]]:
        """Which AI services each role's policies mention, resolved cross-file."""
        signals: dict[str, set[str]] = {}

        def note(role_value, text: str) -> None:
            label = extract_ref(role_value, "aws_iam_role")
            if not label:
                return
            lowered = text.lower()
            for service in _SERVICES:
                if service in lowered:
                    signals.setdefault(label, set()).add(service)

        for policy in graph.by_type("aws_iam_role_policy"):
            note(policy.config.get("role"), str(policy.config.get("policy", "")))
        for attachment in graph.by_type("aws_iam_role_policy_attachment"):
            note(attachment.config.get("role"), str(attachment.config.get("policy_arn", "")))

        return signals
