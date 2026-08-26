"""PIN-001: Pinecone organization ownership granted to a machine principal.

The official Pinecone provider (pinecone-io/pinecone, v4.0.0) exposes no network
configuration on any of its eight resources: no private endpoint, no IP
allowlist, no public access toggle. Pinecone the service does support private
endpoints, but a static Terraform scanner can only check what appears in .tf
files, so the checkable surface here is identity rather than network. That is
why this check is shaped like IAM-001 and not like VEC-001.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown
from ..scanner import Finding

_DOCS = (
    "https://docs.pinecone.io/guides/organizations/understanding-organizations#roles"
)

# Only OrgOwner is flagged. Pinecone documents it as full control over the
# organization, including billing, members, service accounts, security, and
# every project, and it inherits owner access to every project.
#
# OrgManager is deliberately not flagged. Despite the name, it grants only
# viewing organization details and creating projects, and cannot manage
# billing, members, service accounts, or organization settings. Flagging it
# would claim more than the role actually grants.
_FLAGGED_ROLE = "orgowner"

# A person owning the organization is ordinary and is not a finding. The
# finding is a long lived machine credential holding the same role.
_MACHINE_PRINCIPALS = {"service_account", "api_key"}

_PRINCIPAL_WORDING = {
    "service_account": "service account",
    "api_key": "API key",
}


class PineconeOrgRoleCheck:
    check_id = "PIN-001"
    check_name = "Pinecone Organization Owner Granted to a Machine Principal"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for binding in graph.by_type("pinecone_role_binding"):
            role = binding.config.get("role")
            principal_type = binding.config.get("principal_type")
            scope = binding.config.get("resource_type")

            # Values that come from variables or expressions are unknown, and
            # modelmoat does not flag what it cannot prove.
            if any(is_unknown(value) for value in (role, principal_type, scope)):
                continue
            if not all(isinstance(value, str) for value in (role, principal_type, scope)):
                continue

            if role.strip().lower() != _FLAGGED_ROLE:
                continue
            if scope.strip().lower() != "organization":
                continue

            principal = principal_type.strip().lower()
            if principal not in _MACHINE_PRINCIPALS:
                continue

            wording = _PRINCIPAL_WORDING.get(principal, principal)
            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="HIGH",
                    resource_type=binding.type,
                    resource_name=binding.name,
                    file_path=str(binding.file),
                    line=binding.line,
                    message=(
                        f"Role binding '{binding.name}' grants OrgOwner at organization "
                        f"scope to a {wording}. Pinecone documents OrgOwner as full "
                        "control over the organization, including billing, members, "
                        "service accounts, and every project, and it inherits owner "
                        "access to all projects. A credential holding this role can "
                        "read, modify, or delete every index in the organization."
                    ),
                    remediation=(
                        "Grant the narrowest role the workload needs. For data access "
                        "use a project scoped binding with resource_type = \"project\" "
                        "and a role such as DataPlaneEditor or DataPlaneViewer, and "
                        "reserve OrgOwner for human administrators."
                    ),
                    docs_url=_DOCS,
                    detail="org_owner_machine_principal",
                )
            )

        return findings
