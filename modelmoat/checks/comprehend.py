"""CMP-001: Comprehend custom-model training jobs with no vpc_config.

A new AWS service family, not an extension of SMK-001 - VPC-001 already
checks a Lambda/ECS caller reaching Comprehend with no matching VPC
endpoint, a completely different mechanism (endpoint existence, not the
training job's own network attachment) on a completely different resource
type. This check looks at Comprehend's own custom-model training
resources, the same way SMK-001 looks at aws_sagemaker_training_job
instead of relying only on VPC-001's caller-side check.

Two resources, the same mechanism, confirmed against the provider source
directly (both have an optional vpc_config block requiring
security_group_ids and subnets when present):

  aws_comprehend_entity_recognizer
  aws_comprehend_document_classifier

AWS's own documentation ("Protect jobs by using an Amazon Virtual Private
Cloud", docs.aws.amazon.com/comprehend/latest/dg/usingVPC.html) states
plainly that without vpc_config, "job containers access AWS resources...
over the internet," and that distributed jobs need explicit security group
rules to let containers communicate with each other - the same
inter-container concern SMK-001 already checks for SageMaker training
jobs. This is AWS's own documented claim, not an inference by analogy.

HIGH, not CRITICAL: invoking a trained custom model (ClassifyDocument,
DetectEntities) is a standard Comprehend service API action requiring a
SigV4-signed request, with no anonymous invocation path - the same
"traffic path exposure, not an open endpoint" framing SMK-001 uses for its
own training job finding.

model_kms_key_id, volume_kms_key_id, and output_data_config.kms_key_id
were investigated and not built into a check: nothing in AWS's
documentation frames a missing key on any of them as a real gap, and S3
output already defaults to SSE-S3 regardless - the same provider-owned-key
dead pattern already excluded for every other AI service in this project.
"""

from __future__ import annotations

from ..graph import ProjectGraph, blocks
from ..scanner import Finding

_DOCS_URL = "https://docs.aws.amazon.com/comprehend/latest/dg/usingVPC.html"

_RESOURCE_LABELS = {
    "aws_comprehend_entity_recognizer": "Comprehend entity recognizer",
    "aws_comprehend_document_classifier": "Comprehend document classifier",
}


class ComprehendTrainingNetworkCheck:
    check_id = "CMP-001"
    check_name = "Comprehend Training Job With No VPC Configuration"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for resource_type, label in _RESOURCE_LABELS.items():
            for job in graph.by_type(resource_type):
                if blocks(job.config, "vpc_config"):
                    continue

                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity="HIGH",
                        resource_type=job.type,
                        resource_name=job.name,
                        file_path=str(job.file),
                        line=job.line,
                        message=(
                            f"{label} '{job.name}' has no vpc_config. Its "
                            "training containers access training data and "
                            "any inter-container traffic over the internet "
                            "rather than inside your VPC, per AWS's own "
                            "Comprehend VPC documentation. Invoking the "
                            "trained model still requires a SigV4-signed "
                            "request, so this is a traffic-path exposure, "
                            "not an open endpoint."
                        ),
                        remediation=(
                            "Add vpc_config with subnets and "
                            f"security_group_ids to {job.type}.{job.name}. "
                            "Provide VPC endpoints for S3 so the job can "
                            "still read training data and write output."
                        ),
                        docs_url=_DOCS_URL,
                        detail="",
                    )
                )

        return findings
