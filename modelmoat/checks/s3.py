"""S3-001: model artifact buckets and public exposure.

Relevance uses whole-token matching on bucket labels, bucket names, and tag
values, so 'email-archive' never matches 'ai'. Exposure is evidence-based
and resolved across files:

  CRITICAL  a public-read ACL or a bucket policy with Principal "*"
  MEDIUM    an aws_s3_bucket_public_access_block with protections turned off
  LOW       no explicit public access block anywhere in the project

Account-level defaults have blocked public access on new buckets since April
2023, so a missing block is reported as hygiene, never as an exposure. A
bucket with all four protections enabled produces no finding at all, because
Block Public Access overrides ACLs and policies.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, ai_tokens_in, extract_ref, truthy
from ..policy import allows_public_principal, parse_policy_document
from ..scanner import Finding

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
        access_blocks = graph.by_type("aws_s3_bucket_public_access_block")
        acl_resources = graph.by_type("aws_s3_bucket_acl")
        bucket_policies = graph.by_type("aws_s3_bucket_policy")

        for bucket in buckets:
            tags = bucket.config.get("tags") or {}
            tag_values = [str(v) for v in tags.values()] if isinstance(tags, dict) else []
            matched = ai_tokens_in(
                bucket.name, str(bucket.config.get("bucket", "")), *tag_values
            )
            if not matched:
                continue
            matched_note = f"(matched: {', '.join(sorted(matched))})"

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
                            f"S3 bucket '{bucket.name}' looks AI/ML related "
                            f"{matched_note} and declares ACL '{acl}'. Objects such as "
                            "training data or model weights would be readable by anyone.",
                            "Remove the public ACL and add an "
                            "aws_s3_bucket_public_access_block with all four protections "
                            "enabled. Serve artifacts through presigned URLs or VPC "
                            "endpoints instead.",
                        )
                    )
                    break

            # Evidence 2: bucket policy granting to Principal "*".
            for policy in self._related(bucket, bucket_policies):
                doc = parse_policy_document(policy.config.get("policy"))
                is_public = (
                    allows_public_principal(doc)
                    if doc is not None
                    else '"principal": "*"' in str(policy.config.get("policy", "")).lower()
                )
                if is_public:
                    exposed = True
                    findings.append(
                        self._finding(
                            bucket,
                            "CRITICAL",
                            f"S3 bucket '{bucket.name}' looks AI/ML related "
                            f"{matched_note} and its bucket policy allows "
                            'Principal "*". Anyone on the internet can perform the '
                            "granted actions.",
                            "Restrict the policy principal to specific roles or "
                            "accounts and add an aws_s3_bucket_public_access_block "
                            "with all four protections enabled.",
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
                            f"S3 bucket '{bucket.name}' looks AI/ML related "
                            f"{matched_note} and its public access block leaves "
                            f"{', '.join(disabled)} disabled, so public ACLs or "
                            "policies could take effect.",
                            "Set all four public access block arguments to true. They "
                            "default to false when omitted.",
                        )
                    )
                    break

            # Hygiene: no explicit block anywhere, and no direct evidence either.
            if not related_blocks and not exposed and not weakened:
                findings.append(
                    self._finding(
                        bucket,
                        "LOW",
                        f"S3 bucket '{bucket.name}' looks AI/ML related "
                        f"{matched_note} but no aws_s3_bucket_public_access_block "
                        "exists for it in the scanned files. Account defaults have "
                        "blocked public access on new buckets since April 2023, so "
                        "this is a hygiene gap rather than a confirmed exposure.",
                        "Add an explicit aws_s3_bucket_public_access_block with all "
                        "four protections enabled so the safety net survives account "
                        "setting changes.",
                    )
                )

        return findings

    def _related(self, bucket: Resource, resources: list[Resource]) -> list[Resource]:
        """Resources whose bucket argument points at this bucket, across files."""
        related = []
        declared_name = bucket.config.get("bucket")
        for resource in resources:
            ref = resource.config.get("bucket")
            label = extract_ref(ref, "aws_s3_bucket")
            literal_match = isinstance(ref, str) and ref in (bucket.name, declared_name)
            if label == bucket.name or literal_match:
                related.append(resource)
        return related

    def _finding(
        self, bucket: Resource, severity: str, message: str, remediation: str
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
        )
