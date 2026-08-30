"""VEC-001: vector and embedding data stores.

Lane discipline: general IaC scanners already flag every unencrypted RDS
instance on the internet. modelmoat only speaks up when the data store is
plausibly holding AI data, and its messages never claim more than the
configuration proves:

  OpenSearch domains       always in scope (the managed vector engine)
  OpenSearch Serverless    always in scope (the same engine, opt-in reachable
                            instead of exposed by default - see below)
  RDS instances/clusters   in scope when the engine is Postgres-family
                           (pgvector capable) or the name/tags are AI-related
  ElastiCache              in scope only when the name/tags are AI-related

Explicitly disabled settings (enabled = false) are treated exactly like
missing ones, and values that come from variables are unknown and never
flagged.

OpenSearch Serverless has the opposite default from a classic domain:
AWS requires encryption at rest for every collection (no finding is possible
there) and a collection is unreachable until a network security policy
explicitly grants access, so absence is safe and only an explicit
AllowFromPublic = true on a collection-type rule is flagged. AWS's own docs
state that public network access still leaves data access policies in
control of reads and writes and that every request must be SigV4-signed
regardless of network settings, so this is HIGH network exposure, the same
tier as a classic domain with no vpc_options, never CRITICAL - there is no
serverless equivalent of BRK-001's authorizer_type = "NONE" with no fallback.
"""

from __future__ import annotations

import json

from ..graph import (
    ProjectGraph,
    Resource,
    ai_tokens_in,
    as_list,
    first_block,
    missing_or_false,
    truthy,
)
from ..policy import _hcl_object_to_json, allows_public_principal, parse_policy_document
from ..scanner import Finding


def _parse_network_policy(value) -> list | None:
    """Parse an OpenSearch Serverless network policy into a list of rule objects.

    Unlike an IAM policy document this is a JSON array at the top level, not
    an object, so it mirrors policy.parse_policy_document's unwrapping (the
    ${...} hcl2 wraps every function call in, then jsonencode(...) itself)
    but checks for a list result instead of a dict. A value that still
    contains an unresolved reference after unwrapping fails to parse as JSON
    or as an HCL object literal and correctly falls through to None.
    """
    if isinstance(value, list):
        return value
    if not isinstance(value, str):
        return None

    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    if text.startswith("jsonencode(") and text.endswith(")"):
        text = text[len("jsonencode("):-1].strip()

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else None
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        parsed = json.loads(_hcl_object_to_json(text))
        return parsed if isinstance(parsed, list) else None
    except (json.JSONDecodeError, ValueError):
        return None


class VectorDataStoreCheck:
    check_id = "VEC-001"
    check_name = "Vector Data Store Missing Security Controls"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._opensearch(graph))
        findings.extend(self._opensearch_serverless(graph))
        findings.extend(self._rds(graph))
        findings.extend(self._elasticache(graph))
        return findings

    # ------------------------------------------------------------------ #
    # OpenSearch                                                          #
    # ------------------------------------------------------------------ #
    def _opensearch(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for domain in graph.by_type("aws_opensearch_domain", "aws_elasticsearch_domain"):
            at_rest = first_block(domain.config, "encrypt_at_rest")
            if at_rest is None or missing_or_false(at_rest.get("enabled")):
                state = "explicitly disables" if at_rest is not None else "does not enable"
                findings.append(
                    self._finding(
                        domain,
                        "HIGH",
                        f"OpenSearch domain '{domain.name}' {state} encryption at "
                        "rest. Indexed documents and vector embeddings sit "
                        "unencrypted on disk.",
                        "Set encrypt_at_rest { enabled = true }, ideally with a "
                        "customer managed KMS key.",
                        "https://docs.aws.amazon.com/opensearch-service/latest/"
                        "developerguide/encryption-at-rest.html",
                        detail="encryption_at_rest",
                    )
                )

            node_to_node = first_block(domain.config, "node_to_node_encryption")
            if node_to_node is None or missing_or_false(node_to_node.get("enabled")):
                findings.append(
                    self._finding(
                        domain,
                        "MEDIUM",
                        f"OpenSearch domain '{domain.name}' lacks node-to-node "
                        "encryption, so traffic between cluster nodes travels in "
                        "plaintext.",
                        "Set node_to_node_encryption { enabled = true }.",
                        "https://docs.aws.amazon.com/opensearch-service/latest/"
                        "developerguide/ntn.html",
                        detail="node_to_node_encryption",
                    )
                )

            vpc_options = first_block(domain.config, "vpc_options")
            if vpc_options is None:
                access_doc = parse_policy_document(domain.config.get("access_policies"))
                if access_doc is not None and allows_public_principal(access_doc):
                    findings.append(
                        self._finding(
                            domain,
                            "CRITICAL",
                            f"OpenSearch domain '{domain.name}' has no vpc_options and "
                            'its access policy allows Principal "*". The domain '
                            "endpoint is reachable from the internet with no IAM "
                            "restriction, which is how vector databases end up in "
                            "breach write-ups.",
                            "Move the domain into a VPC with vpc_options, or at "
                            "minimum restrict the access policy to specific "
                            "principals and source conditions.",
                            "https://docs.aws.amazon.com/opensearch-service/latest/"
                            "developerguide/vpc.html",
                            detail="public_access_policy",
                        )
                    )
                else:
                    findings.append(
                        self._finding(
                            domain,
                            "HIGH",
                            f"OpenSearch domain '{domain.name}' has no vpc_options, so "
                            "its endpoint resolves publicly and reachability is "
                            "governed only by the access policy and fine-grained "
                            "access control.",
                            "Add vpc_options with subnet_ids and security_group_ids "
                            "so the domain is only reachable from your network.",
                            "https://docs.aws.amazon.com/opensearch-service/latest/"
                            "developerguide/vpc.html",
                            detail="no_vpc_options",
                        )
                    )
            elif not as_list(vpc_options.get("security_group_ids")):
                findings.append(
                    self._finding(
                        domain,
                        "LOW",
                        f"OpenSearch domain '{domain.name}' is in a VPC but sets no "
                        "security_group_ids, so it silently uses the VPC default "
                        "security group.",
                        "Set security_group_ids explicitly and restrict ingress on "
                        "443 to the application tiers that query the domain.",
                        "https://docs.aws.amazon.com/opensearch-service/latest/"
                        "developerguide/vpc.html",
                        detail="default_security_group",
                    )
                )

        return findings

    # ------------------------------------------------------------------ #
    # OpenSearch Serverless                                               #
    # ------------------------------------------------------------------ #
    def _opensearch_serverless(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for policy in graph.by_type("aws_opensearchserverless_security_policy"):
            if str(policy.config.get("type", "")).strip().lower() != "network":
                continue

            entries = _parse_network_policy(policy.config.get("policy"))
            if entries is None:
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if entry.get("AllowFromPublic") is not True:
                    continue
                resource_types = {
                    str(rule.get("ResourceType", "")).strip().lower()
                    for rule in as_list(entry.get("Rules"))
                    if isinstance(rule, dict)
                }
                if "collection" not in resource_types:
                    continue

                findings.append(
                    self._finding(
                        policy,
                        "HIGH",
                        f"OpenSearch Serverless network policy '{policy.name}' sets "
                        "AllowFromPublic = true for a collection resource, so the "
                        "matching collection's OpenSearch endpoint is reachable "
                        "from the public internet. A data access policy and "
                        "SigV4-signed IAM credentials are still required for "
                        "every request regardless of network settings, so this "
                        "is network exposure, not an unauthenticated endpoint.",
                        "Set AllowFromPublic to false and add SourceVPCEs "
                        "pointing at an OpenSearch Serverless-managed VPC "
                        "endpoint, or SourceServices if only an AWS service "
                        "such as Bedrock needs private access.",
                        "https://docs.aws.amazon.com/opensearch-service/latest/"
                        "developerguide/serverless-network.html",
                        detail="serverless_network_public",
                    )
                )

        return findings

    # ------------------------------------------------------------------ #
    # RDS / Aurora (pgvector)                                             #
    # ------------------------------------------------------------------ #
    def _rds(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        instances = graph.by_type("aws_db_instance", "aws_rds_cluster_instance")
        clusters = graph.by_type("aws_rds_cluster")

        for db in instances + clusters:
            engine = str(db.config.get("engine", "")).lower()
            postgres = "postgres" in engine
            names = " ".join(
                str(db.config.get(key, ""))
                for key in ("identifier", "cluster_identifier", "db_name", "name")
            )
            tags = db.config.get("tags") or {}
            tag_values = [str(v) for v in tags.values()] if isinstance(tags, dict) else []
            relevant = postgres or ai_tokens_in(db.name, names, *tag_values)
            if not relevant:
                continue

            data_note = (
                "a pgvector-capable Postgres database"
                if postgres
                else "a database whose name or tags look AI related"
            )

            if truthy(db.config.get("publicly_accessible")):
                findings.append(
                    self._finding(
                        db,
                        "CRITICAL",
                        f"'{db.name}' sets publicly_accessible = true on {data_note}. "
                        "The instance gets a public IP and is reachable from the "
                        "internet, guarded only by security groups and database "
                        "credentials.",
                        "Set publicly_accessible = false and place the database in "
                        "private subnets. Reach it through VPC-connected "
                        "applications or a bastion.",
                        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                        "USER_VPC.html",
                        detail="publicly_accessible",
                    )
                )

            # storage_encrypted lives on aws_db_instance and aws_rds_cluster,
            # not on cluster instances, which inherit it.
            if db.type != "aws_rds_cluster_instance" and missing_or_false(
                db.config.get("storage_encrypted")
            ):
                findings.append(
                    self._finding(
                        db,
                        "HIGH",
                        f"'{db.name}' does not enable storage_encrypted on "
                        f"{data_note}. Embeddings and their source text would sit "
                        "unencrypted at rest, and encryption cannot be enabled "
                        "in place later.",
                        "Set storage_encrypted = true, optionally with kms_key_id "
                        "for a customer managed key.",
                        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                        "Overview.Encryption.html",
                        detail="storage_encrypted",
                    )
                )

        return findings

    # ------------------------------------------------------------------ #
    # ElastiCache (Redis as a vector or embedding cache)                  #
    # ------------------------------------------------------------------ #
    def _elasticache(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        caches = graph.by_type(
            "aws_elasticache_replication_group", "aws_elasticache_cluster"
        )
        for cache in caches:
            names = " ".join(
                str(cache.config.get(key, ""))
                for key in ("replication_group_id", "cluster_id", "description")
            )
            tags = cache.config.get("tags") or {}
            tag_values = [str(v) for v in tags.values()] if isinstance(tags, dict) else []
            if not ai_tokens_in(cache.name, names, *tag_values):
                continue

            if missing_or_false(cache.config.get("transit_encryption_enabled")):
                findings.append(
                    self._finding(
                        cache,
                        "HIGH",
                        f"ElastiCache '{cache.name}' looks AI related but does not "
                        "enable transit encryption, so embeddings and cached "
                        "completions cross the network in plaintext.",
                        "Set transit_encryption_enabled = true and require an "
                        "auth_token or RBAC users.",
                        "https://docs.aws.amazon.com/AmazonElastiCache/latest/"
                        "red-ug/in-transit-encryption.html",
                        detail="transit_encryption",
                    )
                )

            if missing_or_false(cache.config.get("at_rest_encryption_enabled")):
                findings.append(
                    self._finding(
                        cache,
                        "MEDIUM",
                        f"ElastiCache '{cache.name}' looks AI related but does not "
                        "enable at-rest encryption.",
                        "Set at_rest_encryption_enabled = true.",
                        "https://docs.aws.amazon.com/AmazonElastiCache/latest/"
                        "red-ug/at-rest-encryption.html",
                        detail="at_rest_encryption",
                    )
                )

        return findings

    def _finding(
        self,
        resource: Resource,
        severity: str,
        message: str,
        remediation: str,
        docs_url: str,
        detail: str,
    ) -> Finding:
        # detail has no default on purpose. This check reports several problems
        # against one resource, and two of them sharing a detail would make them
        # share a fingerprint, so baselining the mildest would hide the worst.
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity=severity,
            resource_type=resource.type,
            resource_name=resource.name,
            file_path=str(resource.file),
            line=resource.line,
            message=message,
            remediation=remediation,
            docs_url=docs_url,
            detail=detail,
        )
