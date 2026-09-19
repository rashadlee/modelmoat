"""DBX-002: Databricks clusters with no user isolation between attached users.

A different mechanism from DBX-001, so it gets its own number under the
same DBX prefix - the same split SMK-001/002 and VEC-001/002/003 already
use within one resource family. DBX-001 checks azurerm_databricks_workspace
(the azurerm provider) for external network reachability. This check looks
at databricks_cluster (the official databricks provider, cloud-agnostic)
for isolation between users who are already authenticated to the
workspace - a completely different resource, provider, and risk shape.

data_security_mode controls cluster isolation. Confirmed against the
provider's own resource docs (docs/resources/cluster.md in
databricks/terraform-provider-databricks): omitting it "enables default
security features" - the safe state is the default, unlike almost every
other check in this project. The insecure state requires an explicit
"NONE" or its legacy alias "NO_ISOLATION" (UI name "No Isolation Shared"),
so this fires only on an explicit value, the same shape VEC-002 already
uses for Weaviate's anonymous_access, never on absence.

Databricks's own admin documentation
(docs.databricks.com/aws/en/admin/account-settings/no-isolation-shared)
states plainly that these clusters "run arbitrary code from multiple
users in the same shared environment," and that when a higher-privileged
user (such as a workspace administrator) runs commands on the cluster,
"their higher-privileged token is visible in the same environment" to
every other attached user. A separate admin doc adds that any user with
CAN ATTACH TO permission can read service account keys out of the
cluster's own log4j file. Databricks ships an account-level "admin
protection" feature and a workspace-level "Enforce User Isolation"
setting specifically to restrict this mode, which is about as close to
"the vendor recommends against this" as it gets from primary
documentation rather than a blog.

HIGH, not CRITICAL: attaching to any cluster still requires a
workspace-scoped token, OAuth, or SSO session regardless of this setting -
the risk is privilege escalation and credential exposure between already-
authenticated users sharing the cluster, not external reachability. That
puts it closer in shape to IAM-001's overly-broad-permissions HIGH than to
SMK-001's network-exposure HIGH.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown
from ..scanner import Finding

_DOCS_URL = "https://docs.databricks.com/aws/en/admin/account-settings/no-isolation-shared"

_INSECURE_VALUES = {"NONE", "NO_ISOLATION"}


def _is_no_isolation(value) -> bool:
    """True only for an explicit "NONE"/"NO_ISOLATION" - never on absence.

    Databricks's own docs state that omitting data_security_mode enables
    default security features, so unlike almost every other check in this
    project, the safe state here is the default. Unknown (variable-driven)
    values are never flagged.
    """
    if not isinstance(value, str) or is_unknown(value):
        return False
    return value.strip() in _INSECURE_VALUES


class DatabricksClusterIsolationCheck:
    check_id = "DBX-002"
    check_name = "Databricks Cluster With No User Isolation"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for cluster in graph.by_type("databricks_cluster"):
            value = cluster.config.get("data_security_mode")
            if not _is_no_isolation(value):
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="HIGH",
                    resource_type=cluster.type,
                    resource_name=cluster.name,
                    file_path=str(cluster.file),
                    line=cluster.line,
                    message=(
                        f"Databricks cluster '{cluster.name}' sets "
                        f'data_security_mode = "{value.strip()}", running '
                        "code from every attached user in the same shared "
                        "environment. A higher-privileged user's token "
                        "becomes visible to every other user attached to "
                        "the cluster, and any user with attach permission "
                        "can read service account keys out of the "
                        "cluster's own logs."
                    ),
                    remediation=(
                        'Set data_security_mode to "USER_ISOLATION" or '
                        f'"SINGLE_USER" on {cluster.type}.{cluster.name}, '
                        "or remove the field entirely to use the "
                        "workspace's default security features."
                    ),
                    docs_url=_DOCS_URL,
                    detail="data_security_mode",
                )
            )

        return findings
