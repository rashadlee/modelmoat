"""SMK-001: SageMaker models deployed without VPC network configuration.

In the Terraform AWS provider, vpc_config lives on aws_sagemaker_model, not
on aws_sagemaker_endpoint_configuration. A model without vpc_config runs its
containers on the SageMaker managed network with direct internet egress, and
inference traffic between your applications and the endpoint never touches
your private network. Invoking the endpoint still requires SigV4-signed IAM
requests, so this is exposure of the model runtime environment and its
traffic path, not an unauthenticated open URL, and the finding says so.
"""

from __future__ import annotations

from ..graph import ProjectGraph, blocks
from ..scanner import Finding


class SageMakerNetworkCheck:
    check_id = "SMK-001"
    check_name = "SageMaker Model Missing VPC Config"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for model in graph.by_type("aws_sagemaker_model"):
            if blocks(model.config, "vpc_config"):
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="HIGH",
                    resource_type=model.type,
                    resource_name=model.name,
                    file_path=str(model.file),
                    line=model.line,
                    message=(
                        f"SageMaker model '{model.name}' has no vpc_config. Its containers "
                        "run on the SageMaker managed network with direct internet egress, "
                        "and traffic to the endpoint bypasses your VPC. Invocation still "
                        "requires IAM auth, so this exposes the runtime environment and "
                        "traffic path rather than an open URL."
                    ),
                    remediation=(
                        "Add vpc_config with subnets and security_group_ids to "
                        f"aws_sagemaker_model.{model.name}. For models that should never "
                        "reach the internet, also set enable_network_isolation = true and "
                        "provide VPC endpoints for S3 and ECR so the container can still "
                        "pull images and artifacts."
                    ),
                    docs_url=(
                        "https://docs.aws.amazon.com/sagemaker/latest/dg/host-vpc.html"
                    ),
                )
            )

        return findings
