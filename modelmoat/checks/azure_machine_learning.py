"""AML-001: Azure Machine Learning reachable from the public internet.

A new Azure service family, not an extension of AZR-001/002 - those check
azurerm_cognitive_account (OpenAI/Cognitive Services), a completely
different resource type from Azure Machine Learning's own workspace and
compute instance.

Two resources, the same mechanism:

  azurerm_machine_learning_workspace     public_network_access_enabled
                                          defaults to true. Confirmed
                                          against Microsoft's own security
                                          baseline for Machine Learning
                                          Service, and against an actual
                                          Azure Policy built-in definition
                                          ("Azure Machine Learning
                                          Workspaces should disable public
                                          network access") - not a
                                          fabricated concern.
  azurerm_machine_learning_compute_instance
                                          node_public_ip_enabled defaults
                                          to true, assigning the instance a
                                          real external IP (Microsoft's own
                                          docs confirm a public-IP instance
                                          "must allow inbound traffic from
                                          the Azure Machine Learning
                                          service" - genuine network
                                          exposure, not cosmetic).

Both still require Microsoft Entra ID authentication regardless of network
settings - Microsoft's own security baseline confirms Entra auth is
enabled by default for the workspace's data plane, and interactive
Jupyter access on a compute instance requires it the same way. That rules
out CRITICAL (reachability plus absent auth): this is proven network
reachability with authentication still required, the same MEDIUM shape as
AZR-001 and GCP-001's Workbench-notebook finding, not the unconditional
egress-bypass HIGH shape SMK-001 and GCP-001's Reasoning Engine finding
prove for their own resources.

Two things investigated and deliberately not built here, because the
evidence did not support them:
  - A root-access/blast-radius finding to mirror SMK-001's notebook
    root_access or GCP-001's notebook-disable-root. Azure's shape is the
    inverse of both: SSH access on a compute instance is opt-in and off
    by default, not a flag that defaults to enabled. There is no insecure
    default here to catch.
  - workspace.encryption.service_side_encryption_enabled defaults to
    false, but platform-managed encryption at rest still applies
    underneath regardless of this flag - the same "provider-owned key by
    default" pattern already excluded for every other AI service checked
    in this project (SageMaker, Bedrock, Vertex AI, Kendra), just
    expressed as a boolean here instead of an optional key ID.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, truthy_or_absent
from ..scanner import Finding

_WORKSPACE_DOCS_URL = (
    "https://learn.microsoft.com/en-us/azure/machine-learning/"
    "how-to-configure-private-link"
)
_COMPUTE_INSTANCE_DOCS_URL = (
    "https://learn.microsoft.com/en-us/azure/machine-learning/"
    "how-to-create-compute-instance"
)


class AzureMachineLearningNetworkCheck:
    check_id = "AML-001"
    check_name = "Azure Machine Learning Reachable From the Public Internet"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._workspaces(graph))
        findings.extend(self._compute_instances(graph))
        return findings

    # ------------------------------------------------------------------ #
    # azurerm_machine_learning_workspace                                  #
    # ------------------------------------------------------------------ #
    def _workspaces(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for workspace in graph.by_type("azurerm_machine_learning_workspace"):
            value = workspace.config.get("public_network_access_enabled")
            if not truthy_or_absent(value):
                continue

            state = (
                "has no public_network_access_enabled set, which defaults "
                "to true"
                if value is None
                else "sets public_network_access_enabled = true"
            )

            findings.append(
                self._finding(
                    workspace,
                    "MEDIUM",
                    f"Machine Learning workspace '{workspace.name}' {state}. "
                    "Microsoft Entra ID authentication is still required for "
                    "the workspace's data plane regardless of this setting, "
                    "so this exposes the management API's network "
                    "reachability, not an unauthenticated endpoint.",
                    "Set public_network_access_enabled = false on "
                    f"{workspace.type}.{workspace.name}, and configure a "
                    "private endpoint for workspace access from inside your "
                    "VNet.",
                    _WORKSPACE_DOCS_URL,
                    detail="public_network_access",
                )
            )

        return findings

    # ------------------------------------------------------------------ #
    # azurerm_machine_learning_compute_instance                           #
    # ------------------------------------------------------------------ #
    def _compute_instances(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for instance in graph.by_type("azurerm_machine_learning_compute_instance"):
            value = instance.config.get("node_public_ip_enabled")
            if not truthy_or_absent(value):
                continue

            state = (
                "has no node_public_ip_enabled set, which defaults to true"
                if value is None
                else "sets node_public_ip_enabled = true"
            )

            findings.append(
                self._finding(
                    instance,
                    "MEDIUM",
                    f"Compute instance '{instance.name}' {state}, assigning it "
                    "a real external IP address. Microsoft Entra ID "
                    "authentication is still required to reach its Jupyter "
                    "environment regardless of this setting, so this exposes "
                    "network reachability, not an unauthenticated endpoint.",
                    "Set node_public_ip_enabled = false and provide "
                    f"subnet_resource_id on {instance.type}.{instance.name} "
                    "so the instance has no public IP at all.",
                    _COMPUTE_INSTANCE_DOCS_URL,
                    detail="node_public_ip",
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
