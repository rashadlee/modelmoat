"""DBX-003: Unity Catalog securable objects open to every workspace.

A different mechanism from DBX-001 (workspace network reachability) and
DBX-002 (cluster user isolation), so it gets its own number under the
same prefix - the same split SMK-001/002/... and VEC-001/002/003 already
use within one resource family.

Four Unity Catalog "securable object" resources, all in the official
databricks provider, all sharing the identical isolation_mode field
(ISOLATION_MODE_ISOLATED / ISOLATION_MODE_OPEN) and the identical
documented default:

  databricks_catalog
  databricks_schema
  databricks_storage_credential
  databricks_external_location

Databricks' own docs state the OPEN default in matching, deliberate
phrasing for each - "By default, a storage credential is accessible from
all of the workspaces in the metastore," "By default, an external
location is accessible from all of the workspaces in the metastore" - and
the workspace-catalog-binding guide states the same for catalogs and
schemas, framing the risk explicitly around production/non-production
separation: an unbound (OPEN) object is exercisable from every workspace
attached to the metastore, including non-production ones, not just the
one it was created for.

MEDIUM, not HIGH or CRITICAL: reaching data through an OPEN object still
requires the accessing principal to hold an explicit Unity Catalog GRANT
regardless of isolation_mode - Databricks' own docs confirm "access from
an unbound workspace is denied, even for users with explicit privilege
grants" runs the other direction, meaning isolation_mode is a workspace-
reachability gate layered underneath permission grants, not a substitute
for them. That is the same "reachable, but a real gate still applies"
shape as DBX-001's workspace network exposure, not DBX-002's cross-user
credential exposure among already-authenticated users, which is what
earns DBX-002 its HIGH rating.

read_only was investigated on both databricks_storage_credential and
databricks_external_location and left out: neither resource's docs state
a default value for it, so there is nothing to prove either way.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown
from ..scanner import Finding

_DOCS_URL = (
    "https://docs.databricks.com/aws/en/data-governance/unity-catalog/"
    "access-control/workspace-catalog-binding"
)

_RESOURCE_LABELS = {
    "databricks_catalog": "Unity Catalog catalog",
    "databricks_schema": "Unity Catalog schema",
    "databricks_storage_credential": "Unity Catalog storage credential",
    "databricks_external_location": "Unity Catalog external location",
}


def _is_open(value) -> bool:
    """True when absent (the documented default) or explicitly OPEN."""
    if value is None:
        return True
    if not isinstance(value, str) or is_unknown(value):
        return False
    return value.strip() == "ISOLATION_MODE_OPEN"


class DatabricksUnityCatalogIsolationCheck:
    check_id = "DBX-003"
    check_name = "Unity Catalog Object Open to Every Workspace"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for resource_type, label in _RESOURCE_LABELS.items():
            for obj in graph.by_type(resource_type):
                value = obj.config.get("isolation_mode")
                if not _is_open(value):
                    continue

                state = (
                    "has no isolation_mode set, which defaults to "
                    '"ISOLATION_MODE_OPEN"'
                    if value is None
                    else 'sets isolation_mode = "ISOLATION_MODE_OPEN"'
                )

                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity="MEDIUM",
                        resource_type=obj.type,
                        resource_name=obj.name,
                        file_path=str(obj.file),
                        line=obj.line,
                        message=(
                            f"{label} '{obj.name}' {state}, making it "
                            "accessible from every workspace attached to "
                            "the metastore, including non-production ones. "
                            "Reaching it still requires an explicit Unity "
                            "Catalog GRANT regardless of this setting, so "
                            "this widens which workspaces a grant is "
                            "exercisable from, not who can exercise it."
                        ),
                        remediation=(
                            'Set isolation_mode = "ISOLATION_MODE_ISOLATED" '
                            f"on {obj.type}.{obj.name} and bind it to the "
                            "specific workspace(s) that should reach it."
                        ),
                        docs_url=_DOCS_URL,
                        detail="isolation_mode",
                    )
                )

        return findings
