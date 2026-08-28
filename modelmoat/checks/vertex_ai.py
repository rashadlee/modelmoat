"""GCP-001: Vertex AI Reasoning Engines missing network isolation or CMEK.

A google_vertex_ai_reasoning_engine (Agent Engine) deploys with public
network access by default. Reaching it still requires standard Google
Cloud IAM authentication - there is no equivalent of Bedrock AgentCore's
authorizer_type = "NONE" anywhere in this resource's schema, so this is
network exposure and attack surface, not an unauthenticated endpoint. That
is HIGH here, the same tier as SMK-001 and AZR-001, not CRITICAL.

Network isolation is opt-in through spec.deployment_spec.psc_interface_config
.network_attachment (Private Service Connect interface), which is optional
at every level of nesting. Encryption is separately opt-in through
encryption_spec, entirely absent by default rather than defaulting to a
Google-managed key that this check could still credit. Both are checked
independently, since a resource can be missing either, both, or neither.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, first_block
from ..scanner import Finding

_ACCESS_DOCS_URL = (
    "https://docs.cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/manage/access"
)
_CMEK_DOCS_URL = "https://docs.cloud.google.com/vertex-ai/docs/general/cmek"


class VertexAIReasoningEngineCheck:
    check_id = "GCP-001"
    check_name = "Vertex AI Reasoning Engine Missing Security Controls"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for engine in graph.by_type("google_vertex_ai_reasoning_engine"):
            spec = first_block(engine.config, "spec")
            deployment_spec = first_block(spec, "deployment_spec") if spec else None
            psc = first_block(deployment_spec, "psc_interface_config") if deployment_spec else None
            network_attachment = psc.get("network_attachment") if psc else None

            if not network_attachment:
                findings.append(
                    self._finding(
                        engine,
                        "HIGH",
                        f"Reasoning engine '{engine.name}' has no "
                        "psc_interface_config.network_attachment, so it keeps the "
                        "default public network access rather than routing "
                        "through Private Service Connect. Invocation still "
                        "requires Google Cloud IAM authentication, so this "
                        "exposes network reachability and attack surface, not an "
                        "unauthenticated endpoint.",
                        "Add spec.deployment_spec.psc_interface_config with a "
                        "network_attachment pointing at a Compute Engine network "
                        "attachment so the engine is only reachable through your "
                        "VPC.",
                        _ACCESS_DOCS_URL,
                        detail="no_network_isolation",
                    )
                )

            if first_block(engine.config, "encryption_spec") is None:
                findings.append(
                    self._finding(
                        engine,
                        "HIGH",
                        f"Reasoning engine '{engine.name}' has no encryption_spec, "
                        "so it has no customer-managed key protecting the code, "
                        "loaded data, or temporary data on its underlying VMs.",
                        "Add an encryption_spec block with kms_key_name set to a "
                        "Cloud KMS key.",
                        _CMEK_DOCS_URL,
                        detail="no_cmek",
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
        # detail has no default on purpose - this check can report two
        # independent problems on one resource, and sharing a detail would
        # give them the same fingerprint.
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
