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
matches and does not produce a false positive - but the fragment alone isn't
enough for an endpoint to count as protecting a given Lambda or Fargate task.
It must also share the same module and provider (a same-named alias
elsewhere in the project is not this deployment's provider), be a usable
Interface endpoint (Gateway - the default when vpc_endpoint_type is
omitted - does not support these services at all) with private DNS not
explicitly disabled (without it, code calling the standard AWS hostname
never reaches the endpoint), and - only when both sides are resolvable, via
subnet_ids to aws_subnet.vpc_id to aws_vpc - be in the same VPC. When the
Lambda's or task's VPC cannot be determined from the scanned files (its
subnets are not declared as aws_subnet resources here, which is common when
they come from a data source, a module, or a hardcoded ID), VPC identity is
not used to rule an endpoint out, since that would newly flag configurations
this check cannot actually disprove.

ECS Fargate tasks get only the MEDIUM tier, never LOW: Fargate requires
network_mode = "awsvpc", and an aws_ecs_service using it must set
network_configuration with subnets, so there is no "outside a VPC" state to
report the way a Lambda can lack vpc_config entirely. Scoped to launch_type
= "FARGATE" specifically (never absent, since that defaults to EC2, and
EC2-launch-type networking - bridge/host mode sharing the instance's own
ENI - isn't verified here). Signals come from task_role_arn, the role the
application code actually assumes at runtime, not execution_role_arn, which
only pulls images and writes logs.
"""

from __future__ import annotations

from ..graph import (
    ProjectGraph,
    Resource,
    as_list,
    blocks,
    extract_ref,
    first_block,
    truthy_or_absent,
)
from ..policy import parse_json_value
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

        endpoints = graph.by_type("aws_vpc_endpoint")
        subnets_by_module_label = {(s.module, s.name): s for s in graph.by_type("aws_subnet")}
        role_signals = self._role_signals(graph)

        def usable_endpoint_exists(fragment: str, consumer: Resource, subnet_refs: list) -> bool:
            consumer_vpc_labels = self._resolve_vpc_labels(
                subnets_by_module_label, consumer.module, subnet_refs
            )
            for endpoint in endpoints:
                if endpoint.module != consumer.module:
                    continue
                if endpoint.config.get("provider") != consumer.config.get("provider"):
                    continue
                if not self._is_usable_interface_endpoint(endpoint):
                    continue
                service_name = str(endpoint.config.get("service_name", "")).lower()
                if fragment not in service_name:
                    continue
                endpoint_vpc_label = extract_ref(endpoint.config.get("vpc_id"), "aws_vpc")
                if (
                    consumer_vpc_labels is not None
                    and endpoint_vpc_label is not None
                    and endpoint_vpc_label not in consumer_vpc_labels
                ):
                    continue
                return True
            return False

        for function in graph.by_type("aws_lambda_function"):
            vpc_config = first_block(function.config, "vpc_config")
            in_vpc = vpc_config is not None
            subnet_refs = as_list(vpc_config.get("subnet_ids")) if vpc_config else []
            signals = self._function_signals(function, role_signals)

            for service in sorted(signals):
                fragment = _SERVICES[service]
                if in_vpc and not usable_endpoint_exists(fragment, function, subnet_refs):
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

        findings.extend(self._ecs_fargate(graph, usable_endpoint_exists, role_signals))

        return findings

    def _ecs_fargate(
        self,
        graph: ProjectGraph,
        usable_endpoint_exists,
        role_signals: dict[str, set[str]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        task_defs = {
            (t.module, t.name): t for t in graph.by_type("aws_ecs_task_definition")
        }

        for service in graph.by_type("aws_ecs_service"):
            if str(service.config.get("launch_type", "")).strip().upper() != "FARGATE":
                continue

            task_label = extract_ref(
                service.config.get("task_definition"), "aws_ecs_task_definition"
            )
            task_def = task_defs.get((service.module, task_label)) if task_label else None
            if task_def is None:
                continue

            signals = self._task_definition_signals(task_def, role_signals)

            network_config = first_block(service.config, "network_configuration")
            subnet_refs = as_list(network_config.get("subnets")) if network_config else []

            for ai_service in sorted(signals):
                fragment = _SERVICES[ai_service]
                if usable_endpoint_exists(fragment, service, subnet_refs):
                    continue
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity="MEDIUM",
                        resource_type=service.type,
                        resource_name=service.name,
                        file_path=str(service.file),
                        line=service.line,
                        message=(
                            f"ECS service '{service.name}' runs Fargate task "
                            f"'{task_def.name}', which shows signals of calling "
                            f"{ai_service}, but no interface VPC endpoint matching "
                            f"'{fragment}' exists in the scanned files. Fargate "
                            "tasks always run inside a VPC, so depending on "
                            "routing, calls either fail or exit through NAT to "
                            "public AWS endpoints."
                        ),
                        remediation=(
                            "Add an aws_vpc_endpoint with vpc_endpoint_type "
                            '"Interface" and service_name '
                            f'"com.amazonaws.<region>{fragment}" in the same VPC, '
                            "and allow the task's security group to reach it on "
                            "443."
                        ),
                        docs_url=_DOCS,
                        detail=ai_service,
                    )
                )

        return findings

    def _task_definition_signals(
        self, task_def: Resource, role_signals: dict[tuple, set[str]]
    ) -> set[str]:
        signals: set[str] = set()

        containers = parse_json_value(task_def.config.get("container_definitions"), list) or []
        for container in containers:
            if not isinstance(container, dict):
                continue
            for entry in container.get("environment") or []:
                if not isinstance(entry, dict):
                    continue
                text = f"{entry.get('name', '')} {entry.get('value', '')}".lower()
                for service in _SERVICES:
                    if service in text:
                        signals.add(service)

        role_label = extract_ref(task_def.config.get("task_role_arn"), "aws_iam_role")
        if role_label:
            signals |= role_signals.get((task_def.module, role_label), set())

        return signals

    def _function_signals(
        self, function: Resource, role_signals: dict[tuple, set[str]]
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
            signals |= role_signals.get((function.module, role_label), set())

        return signals

    def _role_signals(self, graph: ProjectGraph) -> dict[tuple, set[str]]:
        """Which AI services each (module, role label)'s policies mention,
        resolved across files within the same module - a same-named role in
        an unrelated directory must never stand in for the real one.
        """
        signals: dict[tuple, set[str]] = {}

        def note(module, role_value, text: str) -> None:
            label = extract_ref(role_value, "aws_iam_role")
            if not label:
                return
            lowered = text.lower()
            for service in _SERVICES:
                if service in lowered:
                    signals.setdefault((module, label), set()).add(service)

        policies_by_module_label = {
            (p.module, p.name): p for p in graph.by_type("aws_iam_policy")
        }

        for policy in graph.by_type("aws_iam_role_policy"):
            note(policy.module, policy.config.get("role"), str(policy.config.get("policy", "")))
        for attachment in graph.by_type("aws_iam_role_policy_attachment"):
            arn_value = attachment.config.get("policy_arn", "")
            note(attachment.module, attachment.config.get("role"), str(arn_value))
            # A customer-managed policy's own document is what actually
            # grants access - the ARN reference string itself rarely
            # mentions the service by name, unlike an AWS-managed policy's
            # ARN (.../AmazonBedrockFullAccess). Resolve it the same way
            # IAM-001 already does for its own inline-vs-referenced policies.
            policy_label = extract_ref(arn_value, "aws_iam_policy")
            if policy_label:
                policy_resource = policies_by_module_label.get(
                    (attachment.module, policy_label)
                )
                if policy_resource is not None:
                    note(
                        attachment.module,
                        attachment.config.get("role"),
                        str(policy_resource.config.get("policy", "")),
                    )

        return signals

    def _resolve_vpc_labels(
        self, subnets_by_module_label: dict[tuple, Resource], module, subnet_refs: list
    ) -> set[str] | None:
        """VPC label(s) these subnet references resolve to, within the same
        module - or None when that cannot be determined at all (none of the
        references resolve to an aws_subnet declared in the scanned files),
        since then VPC identity cannot rule an endpoint in or out. Subnets
        commonly come from a data source, a module, or a hardcoded ID rather
        than a managed aws_subnet resource, and assuming a mismatch in that
        case would newly flag configurations this check cannot actually
        disprove.
        """
        labels: set[str] = set()
        resolved_any = False
        for ref in subnet_refs:
            subnet_label = extract_ref(ref, "aws_subnet")
            if not subnet_label:
                continue
            subnet = subnets_by_module_label.get((module, subnet_label))
            if subnet is None:
                continue
            resolved_any = True
            vpc_label = extract_ref(subnet.config.get("vpc_id"), "aws_vpc")
            if vpc_label:
                labels.add(vpc_label)
        return labels if resolved_any else None

    def _is_usable_interface_endpoint(self, endpoint: Resource) -> bool:
        """True for an Interface endpoint that will actually intercept
        traffic to the standard AWS hostname.

        vpc_endpoint_type defaults to "Gateway" when omitted, and Gateway
        endpoints do not support Bedrock or SageMaker at all - unlike most
        of modelmoat's absent-means-safe conventions, absence here is the
        provider's own documented default, not an unknown modelmoat should
        stay silent on, so it disqualifies exactly like an explicit
        non-Interface value would. private_dns_enabled is the opposite:
        it defaults to true for an Interface endpoint, so only an explicit
        false disqualifies it - without private DNS, code calling the
        standard AWS hostname never actually reaches the endpoint.
        """
        endpoint_type = str(endpoint.config.get("vpc_endpoint_type", "")).strip().lower()
        if endpoint_type != "interface":
            return False
        return truthy_or_absent(endpoint.config.get("private_dns_enabled"))
