"""S3-001: model artifact buckets and public exposure.

Relevance uses whole-token matching on bucket labels, bucket names, and tag
values, so 'email-archive' never matches 'ai' - plus one reference-based
signal: a bucket named for the business, not the model (`acme-prod-storage`),
is still provably AI-related when an aws_bedrockagent_data_source points its
s3_configuration.bucket_arn at it. That is stronger evidence than a keyword
guess, the same "prove it through the reference" approach AGW-001 uses for
API Gateway integrations, so it is checked first and a match skips the
keyword scan entirely rather than requiring both.

Exposure is evidence-based and resolved across files:

  CRITICAL  a public-read ACL or a bucket policy with Principal "*"
  MEDIUM    an aws_s3_bucket_public_access_block with protections turned off
  LOW       no explicit public access block anywhere in the project

Account-level defaults have blocked public access on new buckets since April
2023, so a missing block is reported as hygiene, never as an exposure. A
bucket with all four protections enabled produces no finding at all, because
Block Public Access overrides ACLs and policies.
"""

from __future__ import annotations

import re

from ..graph import ProjectGraph, Resource, ai_tokens_in, extract_ref, first_block, truthy
from ..policy import resolve_public_principal
from ..scanner import Finding

# aws_bedrockagent_data_source.s3_configuration.bucket_arn is a bucket ARN,
# not a bucket name - arn:aws:s3:::name, no region or account segment. Only
# the partition varies (aws, aws-cn, aws-us-gov).
_ARN_BUCKET_NAME = re.compile(r"^arn:aws[a-z0-9-]*:s3:::([^/]+)")

_DOCS = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
    "access-control-block-public-access.html"
)

_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


class ModelArtifactBucketCheck:
    check_id = "S3-001"
    check_name = "AI Data Bucket Public Exposure"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        buckets = graph.by_type("aws_s3_bucket")
        kb_data_sources = graph.by_type("aws_bedrockagent_data_source")
        # A public access block is a compensating control here - credited
        # with protecting a bucket only when its own cardinality is
        # confirmed, never when count/for_each on the block itself is
        # unresolved. modelmoat cannot prove an unresolved block exists, so
        # it must not get to prove the bucket is safe.
        access_blocks = [
            b
            for b in graph.by_type("aws_s3_bucket_public_access_block")
            if not b.unresolved_cardinality
        ]
        acl_resources = graph.by_type("aws_s3_bucket_acl")
        bucket_policies = graph.by_type("aws_s3_bucket_policy")
        # Keyed by (module, label): a data.aws_iam_policy_document with the
        # same label in an unrelated directory must never resolve a bucket
        # policy reference here.
        data_docs = {
            (d.module, d.name): d for d in graph.data_by_type("aws_iam_policy_document")
        }

        for bucket in buckets:
            kb_refs = self._kb_data_source_refs(bucket, kb_data_sources)
            if kb_refs:
                ref_names = ", ".join(sorted(f"{ds.type}.{ds.name}" for ds in kb_refs))
                relevance = (
                    f"backs an Amazon Bedrock knowledge base as a data source ({ref_names})"
                )
            else:
                tags = bucket.config.get("tags") or {}
                tag_values = [str(v) for v in tags.values()] if isinstance(tags, dict) else []
                matched = ai_tokens_in(
                    bucket.name, str(bucket.config.get("bucket", "")), *tag_values
                )
                if not matched:
                    continue
                relevance = f"looks AI/ML related (matched: {', '.join(sorted(matched))})"

            related_blocks = self._related(bucket, access_blocks)
            fully_blocked = any(
                all(truthy(block.config.get(flag)) for flag in _FLAGS)
                for block in related_blocks
            )
            if fully_blocked:
                continue  # Block Public Access overrides ACLs and policies.

            exposed = False

            # Evidence 1: public ACL, inline or as its own resource.
            acl_values = [bucket.config.get("acl")] + [
                acl.config.get("acl") for acl in self._related(bucket, acl_resources)
            ]
            for acl in acl_values:
                if isinstance(acl, str) and acl in ("public-read", "public-read-write"):
                    exposed = True
                    findings.append(
                        self._finding(
                            bucket,
                            "CRITICAL",
                            f"S3 bucket '{bucket.name}' {relevance} and declares "
                            f"ACL '{acl}'. Objects such as "
                            "training data or model weights would be readable by anyone.",
                            "Remove the public ACL and add an "
                            "aws_s3_bucket_public_access_block with all four protections "
                            "enabled. Serve artifacts through presigned URLs or VPC "
                            "endpoints instead.",
                            "public_acl",
                        )
                    )
                    break

            # Evidence 2: bucket policy granting to Principal "*", inline or
            # via a data.aws_iam_policy_document reference.
            for policy in self._related(bucket, bucket_policies):
                is_public = resolve_public_principal(
                    policy.config.get("policy"), data_docs, bucket.module
                )
                if is_public is None:
                    is_public = (
                        '"principal": "*"' in str(policy.config.get("policy", "")).lower()
                    )
                if is_public:
                    exposed = True
                    findings.append(
                        self._finding(
                            bucket,
                            "CRITICAL",
                            f"S3 bucket '{bucket.name}' {relevance} and its "
                            'bucket policy allows Principal "*". Anyone on the '
                            "internet can perform the granted actions.",
                            "Restrict the policy principal to specific roles or "
                            "accounts and add an aws_s3_bucket_public_access_block "
                            "with all four protections enabled.",
                            "public_policy",
                        )
                    )
                    break

            # Evidence 3: an access block that turns protections off.
            weakened = False
            for block in related_blocks:
                disabled = [
                    flag for flag in _FLAGS if not truthy(block.config.get(flag))
                ]
                if disabled:
                    weakened = True
                    findings.append(
                        self._finding(
                            bucket,
                            "MEDIUM",
                            f"S3 bucket '{bucket.name}' {relevance} and its "
                            f"public access block leaves {', '.join(disabled)} "
                            "disabled, so public ACLs or policies could take effect.",
                            "Set all four public access block arguments to true. They "
                            "default to false when omitted.",
                            "weakened_pab",
                        )
                    )
                    break

            # Hygiene: no explicit block anywhere, and no direct evidence either.
            if not related_blocks and not exposed and not weakened:
                findings.append(
                    self._finding(
                        bucket,
                        "LOW",
                        f"S3 bucket '{bucket.name}' {relevance} but no "
                        "aws_s3_bucket_public_access_block "
                        "exists for it in the scanned files. Account defaults have "
                        "blocked public access on new buckets since April 2023, so "
                        "this is a hygiene gap rather than a confirmed exposure.",
                        "Add an explicit aws_s3_bucket_public_access_block with all "
                        "four protections enabled so the safety net survives account "
                        "setting changes.",
                        "missing_pab",
                    )
                )

        return findings

    def _related(self, bucket: Resource, resources: list[Resource]) -> list[Resource]:
        """Resources whose bucket argument points at this bucket, across files
        but within the same Terraform module. A same-named bucket in a
        different directory is a different resource - correlating across that
        boundary would let an unrelated module's protections silently cover
        for this bucket's real exposure.
        """
        related = []
        declared_name = bucket.config.get("bucket")
        for resource in resources:
            if resource.module != bucket.module:
                continue
            ref = resource.config.get("bucket")
            label = extract_ref(ref, "aws_s3_bucket")
            literal_match = isinstance(ref, str) and ref in (bucket.name, declared_name)
            if label == bucket.name or literal_match:
                related.append(resource)
        return related

    def _kb_data_source_refs(
        self, bucket: Resource, data_sources: list[Resource]
    ) -> list[Resource]:
        """aws_bedrockagent_data_source resources whose
        data_source_configuration.s3_configuration.bucket_arn points at this
        bucket, scoped to the same module the same way _related() is. This is
        direct evidence of AI relevance through a reference, so it does not
        depend on the bucket's name or tags matching anything.
        """
        related = []
        declared_name = bucket.config.get("bucket")
        for data_source in data_sources:
            if data_source.module != bucket.module:
                continue
            s3_config = first_block(
                first_block(data_source.config, "data_source_configuration") or {},
                "s3_configuration",
            )
            if s3_config is None:
                continue
            bucket_arn = s3_config.get("bucket_arn")
            if not isinstance(bucket_arn, str):
                continue
            label = extract_ref(bucket_arn, "aws_s3_bucket")
            arn_match = _ARN_BUCKET_NAME.match(bucket_arn.strip())
            literal_name = arn_match.group(1) if arn_match else None
            literal_match = literal_name is not None and literal_name in (
                bucket.name,
                declared_name,
            )
            if label == bucket.name or literal_match:
                related.append(data_source)
        return related

    def _finding(
        self, bucket: Resource, severity: str, message: str, remediation: str, detail: str
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity=severity,
            resource_type=bucket.type,
            resource_name=bucket.name,
            file_path=str(bucket.file),
            line=bucket.line,
            message=message,
            remediation=remediation,
            docs_url=_DOCS,
            detail=detail,
        )
