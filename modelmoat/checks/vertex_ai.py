"""GCP-001: Vertex AI resources missing network isolation or CMEK.

Three resources, not all the same mechanism:

  google_vertex_ai_reasoning_engine (Agent Engine) deploys with public
    network access by default. Reaching it still requires standard Google
    Cloud IAM authentication - there is no equivalent of Bedrock
    AgentCore's authorizer_type = "NONE" anywhere in this resource's
    schema, so this is network exposure and attack surface, not an
    unauthenticated endpoint. That is HIGH here, the same tier as SMK-001
    and AZR-001, not CRITICAL. Network isolation is opt-in through
    spec.deployment_spec.psc_interface_config.network_attachment (Private
    Service Connect interface), optional at every level of nesting.
    Encryption is separately opt-in through encryption_spec, entirely
    absent by default rather than defaulting to a Google-managed key that
    this check could still credit - both are checked independently, since
    a resource can be missing either, both, or neither.
  google_vertex_ai_endpoint (deployed prediction models) has the identical
    public-by-default, IAM-still-required shape as Reasoning Engine, so
    its missing psc_interface_config gets the same HIGH treatment. Its
    encryption_spec is different, though: Google's own docs describe a
    Google-managed key as the default when omitted, the same pattern
    already established for SageMaker/Q Business/Kendra this project has
    checked - so a missing encryption_spec here is not flagged, unlike
    Reasoning Engine's genuinely-unencrypted default.
  google_workbench_instance (Vertex AI Workbench notebooks, the current
    resource - google_notebooks_instance is deprecated in the provider)
    is a VM, not a managed service, so its exposure shape is different
    again: gce_setup.disable_public_ip defaults to false, so an instance
    gets an external IP by default, per Google's own console behavior
    ("An external IP address is assigned to the instance by default").
    Unlike Reasoning Engine/Endpoint's unconditional public data plane,
    an external IP's actual reachability still depends on firewall rules
    this check does not evaluate, so this is MEDIUM, not HIGH. A second,
    independent finding on the same resource:
    gce_setup.metadata["notebook-disable-root"] defaults to "false" per
    Google's own Workbench documentation ("false (default): Enables root
    access"), the same blast-radius shape as SMK-001's root_access
    finding for SageMaker notebooks, and rated the same: LOW. Workbench's
    own disk encryption also defaults to a Google-managed key (GMEK), so
    it is not checked, the same reasoning as Endpoint above.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, first_block, is_unknown
from ..scanner import Finding

_ACCESS_DOCS_URL = (
    "https://docs.cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/manage/access"
)
_CMEK_DOCS_URL = "https://docs.cloud.google.com/vertex-ai/docs/general/cmek"
_ENDPOINT_DOCS_URL = (
    "https://docs.cloud.google.com/vertex-ai/docs/general/vpc-service-controls"
)
_WORKBENCH_NETWORK_DOCS_URL = (
    "https://docs.cloud.google.com/vertex-ai/docs/workbench/instances/create"
)
_WORKBENCH_ROOT_DOCS_URL = (
    "https://docs.cloud.google.com/vertex-ai/docs/workbench/instances/manage-metadata"
)


def _is_root_disabled(metadata) -> bool:
    """True only when notebook-disable-root is explicitly "true".

    Absent metadata or an absent key both mean root access is enabled -
    Google's own docs state "false (default): Enables root access", so
    absence is the risky state, not presence. An unresolved value is
    neither - it is never flagged either way.
    """
    if not isinstance(metadata, dict):
        return False
    value = metadata.get("notebook-disable-root")
    if value is None:
        return False
    if not isinstance(value, str) or is_unknown(value):
        return True
    return value.strip().lower() == "true"


class VertexAIReasoningEngineCheck:
    check_id = "GCP-001"
    check_name = "Vertex AI Missing Security Controls"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._reasoning_engines(graph))
        findings.extend(self._endpoints(graph))
        findings.extend(self._workbench_instances(graph))
        return findings

    # ------------------------------------------------------------------ #
    # google_vertex_ai_reasoning_engine                                   #
    # ------------------------------------------------------------------ #
    def _reasoning_engines(self, graph: ProjectGraph) -> list[Finding]:
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

    # ------------------------------------------------------------------ #
    # google_vertex_ai_endpoint                                           #
    # ------------------------------------------------------------------ #
    def _endpoints(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for endpoint in graph.by_type("google_vertex_ai_endpoint"):
            psc = first_block(endpoint.config, "private_service_connect_config")
            network = endpoint.config.get("network")

            if psc is not None or network:
                continue

            findings.append(
                self._finding(
                    endpoint,
                    "HIGH",
                    f"Endpoint '{endpoint.name}' has no network and no "
                    "private_service_connect_config, so it keeps the default "
                    "public network access rather than routing through a VPC or "
                    "Private Service Connect. Invocation still requires Google "
                    "Cloud IAM authentication, so this exposes network "
                    "reachability and attack surface, not an unauthenticated "
                    "endpoint.",
                    "Set network to a VPC for private connectivity, or add "
                    "private_service_connect_config with "
                    "enable_private_service_connect = true, so predictions are "
                    "only reachable through your network.",
                    _ENDPOINT_DOCS_URL,
                    detail="no_network_isolation",
                )
            )

        return findings

    # ------------------------------------------------------------------ #
    # google_workbench_instance                                           #
    # ------------------------------------------------------------------ #
    def _workbench_instances(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for instance in graph.by_type("google_workbench_instance"):
            gce_setup = first_block(instance.config, "gce_setup")
            disable_public_ip = gce_setup.get("disable_public_ip") if gce_setup else None
            unknown_ip_setting = isinstance(disable_public_ip, str) and is_unknown(
                disable_public_ip
            )

            if disable_public_ip is not True and not unknown_ip_setting:
                state = (
                    "has no gce_setup.disable_public_ip set, which defaults to "
                    "false"
                    if disable_public_ip is None
                    else "sets gce_setup.disable_public_ip = false"
                )
                findings.append(
                    self._finding(
                        instance,
                        "MEDIUM",
                        f"Workbench instance '{instance.name}' {state}, so it is "
                        "assigned an external IP address by default. Whether it "
                        "is actually reachable from the internet also depends on "
                        "firewall rules this check does not evaluate, but an "
                        "external IP is a precondition this check can prove, and "
                        "removing it removes the precondition entirely.",
                        "Set gce_setup.disable_public_ip = true, and provide "
                        "Private Google Access or a NAT gateway if the instance "
                        "needs outbound internet access.",
                        _WORKBENCH_NETWORK_DOCS_URL,
                        detail="disable_public_ip",
                    )
                )

            metadata = gce_setup.get("metadata") if gce_setup else None
            if not _is_root_disabled(metadata):
                findings.append(
                    self._finding(
                        instance,
                        "LOW",
                        f"Workbench instance '{instance.name}' does not set "
                        'gce_setup.metadata["notebook-disable-root"] = "true", '
                        'which defaults to "false" (root access enabled). '
                        "Whoever can open the notebook has root on the "
                        "underlying instance, widening what a compromised or "
                        "careless session can do to it.",
                        'Set gce_setup.metadata["notebook-disable-root"] = '
                        f'"true" on {instance.type}.{instance.name} unless the '
                        "notebook's users specifically need root to install "
                        "system packages.",
                        _WORKBENCH_ROOT_DOCS_URL,
                        detail="notebook_disable_root",
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
