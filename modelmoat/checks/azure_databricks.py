"""DBX-001: Azure Databricks workspace reachable from the public internet.

A new service family, not an AI service in the narrow sense, but in scope
for the same reason SMK-001/AML-001 are: Databricks is a common home for
model training and data pipeline workloads, and its workspace exposure
shape is structurally identical to AML-001's classic workspace finding -
same mechanism, same severity, same "reachable but still authenticated"
framing.

azurerm_databricks_workspace's public_network_access_enabled defaults to
true. Confirmed against the provider source directly
(internal/services/databricks/databricks_workspace_resource.go in
hashicorp/terraform-provider-azurerm): a plain bool with Default: true.
Backed by two independent sources, not a fabricated concern:
  - Microsoft's own Azure security baseline for Azure Databricks (control
    NS-2, "Disable Public Network Access"): "Enabled By Default: False,
    Configuration Responsibility: Customer" - i.e. the safe state is not
    what you get by omitting the field.
  - An Azure Policy built-in definition, "Azure Databricks Workspaces
    should disable public network access" (0e7849de-b939-4c50-ab48-
    fc6b0f5eeba2).

MEDIUM, not CRITICAL or HIGH: the same baseline's IM-1 control ("Azure AD
Authentication Required for Data Plane Access") is Enabled By Default:
True, Configuration Responsibility: Microsoft - no field or combination on
this resource produces a genuinely unauthenticated path. This is a
reachable data-plane/API surface finding, the same framing SMK-001 and
AML-001 already use for their own resources, not an open-endpoint claim.

network_security_group_rules_required and custom_parameters.no_public_ip
were investigated and not built into a check: the first only takes effect
once public access is already disabled, and the second's actual
Terraform-level default has known rough edges across provider versions
(Microsoft's own docs warn that touching custom_parameters on an existing
workspace can force a recreate) - not clean enough evidence to state a
default with the same confidence as public_network_access_enabled.
Encryption falls back to a Microsoft-managed key by default (baseline
control DP-4), the same provider-owned-key pattern already excluded for
every other AI service checked in this project; CMEK is available only
through separate opt-in resources, not a gap in this one.
"""

from __future__ import annotations

from ..graph import ProjectGraph, truthy_or_absent
from ..scanner import Finding

_DOCS_URL = (
    "https://learn.microsoft.com/en-us/azure/databricks/security/network/"
    "classic/private-link-standard"
)


class AzureDatabricksNetworkCheck:
    check_id = "DBX-001"
    check_name = "Azure Databricks Workspace Reachable From the Public Internet"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for workspace in graph.by_type("azurerm_databricks_workspace"):
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
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="MEDIUM",
                    resource_type=workspace.type,
                    resource_name=workspace.name,
                    file_path=str(workspace.file),
                    line=workspace.line,
                    message=(
                        f"Databricks workspace '{workspace.name}' {state}, "
                        "making its web application and REST API reachable "
                        "from the public internet. Microsoft Entra ID "
                        "authentication is still required for data-plane "
                        "access regardless of this setting, so this exposes "
                        "network reachability, not an unauthenticated "
                        "endpoint."
                    ),
                    remediation=(
                        "Set public_network_access_enabled = false on "
                        f"{workspace.type}.{workspace.name} and configure a "
                        "private endpoint for workspace access from inside "
                        "your VNet."
                    ),
                    docs_url=_DOCS_URL,
                    detail="public_network_access",
                )
            )

        return findings
