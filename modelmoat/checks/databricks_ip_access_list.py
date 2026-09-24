"""DBX-004: publicly reachable Databricks workspace with no IP allow list.

A different mechanism from DBX-001's own reachability check, so it gets
its own number under the same prefix - the same split SMK-001/002 and
VEC-001/002/003 already use within one resource family. This is not
redundant hardening layered on top of DBX-001: Microsoft's own Azure
security baseline for Databricks lists disabling public network access
(control NS-2) as "Enabled By Default: False," and names IP access lists
directly as the configuration mechanism for it - a publicly reachable
workspace with zero IP access lists is that specific, named,
off-by-default control sitting in its documented default state, not an
optional extra on top of an already-covered finding.

databricks_ip_access_list (the cloud-agnostic databricks provider, so it
applies regardless of which cloud hosts the workspace) has list_type
(ALLOW or BLOCK) and enabled (defaults to true). Per Databricks' own
front-end IP access list documentation: "When the IP access lists feature
is enabled and there are no allow lists ... for the workspace, all IP
addresses are allowed" - so the absence of any active ALLOW-type list
means every IP can reach a public workspace's web application and REST
API, the same fail-open behavior confirmed for AWS and Azure workspaces
alike.

This is a whole-project, not a per-workspace, correlation:
databricks_ip_access_list carries no field linking it to a specific
azurerm_databricks_workspace resource, since the databricks provider is
scoped to one workspace via its own provider block configuration
(typically a host URL), which is not part of the resource graph. A
project with multiple workspaces where only one has an ALLOW list would
understate the gap for the others - the safe failure direction, since
this project does not flag what it cannot prove, the same reasoning
VPC-001 already applies when it cannot resolve a Lambda's VPC identity.

LOW, not MEDIUM: this compounds DBX-001's existing reachability finding
on the same resource rather than proving anything new on its own, and
Databricks' current guidance is already steering customers toward a
newer "context-based ingress" mechanism instead of IP access lists -
this finding names a real, still-documented default gap, not the
vendor's top recommended control.

Gated on the workspace already being publicly reachable (reusing
DBX-001's is_publicly_reachable predicate): a fully private workspace has
no public endpoint for an IP list to filter, so recommending one there
would be a confusing, moot suggestion. Scoped to azurerm_databricks_workspace
only, the same scope DBX-001 itself uses - the AWS/GCP account-level
databricks_mws_workspaces resource is not independently verified with the
same confidence, so it is left out rather than guessed at.
"""

from __future__ import annotations

from ..graph import ProjectGraph, truthy_or_absent
from ..scanner import Finding
from .azure_databricks import is_publicly_reachable

_DOCS_URL = (
    "https://docs.databricks.com/aws/en/security/network/front-end/"
    "ip-access-list-workspace"
)


def _has_active_allow_list(graph: ProjectGraph) -> bool:
    for ip_list in graph.by_type("databricks_ip_access_list"):
        list_type = ip_list.config.get("list_type")
        if not isinstance(list_type, str) or list_type.strip() != "ALLOW":
            continue
        if truthy_or_absent(ip_list.config.get("enabled")):
            return True
    return False


class DatabricksIPAccessListCheck:
    check_id = "DBX-004"
    check_name = "Publicly Reachable Databricks Workspace With No IP Allow List"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        if _has_active_allow_list(graph):
            return findings

        for workspace in graph.by_type("azurerm_databricks_workspace"):
            if not is_publicly_reachable(workspace):
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="LOW",
                    resource_type=workspace.type,
                    resource_name=workspace.name,
                    file_path=str(workspace.file),
                    line=workspace.line,
                    message=(
                        f"Databricks workspace '{workspace.name}' is "
                        "reachable from the public internet with no "
                        "databricks_ip_access_list resource anywhere in "
                        "the project granting ALLOW access. Databricks' "
                        "own front-end IP access list documentation states "
                        "that with no active allow list, all IP addresses "
                        "are permitted to reach the workspace."
                    ),
                    remediation=(
                        "Add a databricks_ip_access_list resource with "
                        'list_type = "ALLOW" scoped to your known egress '
                        "IP ranges, or set public_network_access_enabled = "
                        f"false on {workspace.type}.{workspace.name} "
                        "instead."
                    ),
                    docs_url=_DOCS_URL,
                    detail="no_ip_access_list",
                )
            )

        return findings
