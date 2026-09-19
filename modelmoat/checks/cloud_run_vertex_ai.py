"""GCP-002: Cloud Run services publicly invokable and granted Vertex AI access.

A new mechanism from GCP-001, so it gets its own number under the same
GCP prefix - the same split SMK-001/002, VEC-001/002/003, and AGW-001/002
already use within one resource family. GCP-001 checks Vertex AI's own
resources for network isolation; this checks a separate compute layer
(Cloud Run) that can front Vertex AI the way Lambda/API Gateway front
Bedrock and SageMaker elsewhere in this project.

Scoped to google_cloud_run_v2_service and google_cloud_run_v2_service_iam_member/
_iam_binding only - the current, GA resource family with confirmed field
names. The legacy google_cloud_run_service (v1) is not covered here; its
schema was not independently verified with the same confidence and this
project does not guess at field names it has not confirmed.

Google's own IAM documentation
(docs.cloud.google.com/run/docs/authenticating/public) states plainly
that Cloud Run enforces the Invoker IAM check by default - absence of a
public binding is the safe default, an affirmative "roles/run.invoker"
grant to "allUsers" is the only Terraform-visible way to disable it. The
same documentation confirms this is a genuine zero-authentication path
("a valid OIDC identity token" is required for every other caller), not a
"reachable but still authenticated" case - the same rare CRITICAL shape
as LFU-001 and AGW-001, not the usual "still requires a signed request"
framing most of this project's findings use.

google_cloud_run_v2_service.ingress is deliberately not part of this
check's logic: Google's own ingress documentation states "IAM
authentication still applies ... from any of the preceding network
ingress paths," so ingress and IAM are independent layers and neither
substitutes for the other - an allUsers invoker grant is sufficient proof
of reachability plus absent auth on its own.

Vertex AI access is correlated the same way IAM-001/VPC-001 correlate a
Lambda's role to Bedrock/SageMaker: the service's own
template.service_account is resolved and checked against
google_project_iam_member/_iam_binding grants of a roles/aiplatform.*
role to that same account. If service_account is omitted, Cloud Run
falls back to the project's default compute service account, whose grants
this check cannot see or prove - so it stays silent rather than guessing,
the same "does not flag what it cannot prove" discipline used throughout
this project.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, as_list, extract_ref, is_unknown
from ..scanner import Finding

_DOCS_URL = "https://docs.cloud.google.com/run/docs/authenticating/public"


def _grants_public_invoker(resource: Resource) -> bool:
    role = resource.config.get("role")
    if not isinstance(role, str) or role.strip() != "roles/run.invoker":
        return False

    member = resource.config.get("member")
    if isinstance(member, str) and member.strip() == "allUsers":
        return True

    members = as_list(resource.config.get("members"))
    return any(isinstance(m, str) and m.strip() == "allUsers" for m in members)


def _service_account_label(value) -> str | None:
    """Resolve a service-account-shaped value to a comparable label.

    Handles both a google_service_account reference and a raw email
    string, since either is idiomatic HCL for this field. extract_ref is
    tried before is_unknown, not after: a reference embedded inside a
    larger string literal (as member values always are - "serviceAccount:"
    plus an interpolated email) requires "${...}" syntax in valid HCL, so
    is_unknown's "contains ${" test would otherwise reject a fully
    resolvable static reference along with genuinely unprovable ones.
    """
    if not isinstance(value, str):
        return None
    ref = extract_ref(value, "google_service_account")
    if ref:
        return f"ref:{ref}"
    if is_unknown(value):
        return None
    stripped = value.strip()
    return f"email:{stripped.lower()}" if stripped else None


def _member_account_label(value) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped.lower().startswith("serviceaccount:"):
        return None
    return _service_account_label(stripped.split(":", 1)[1])


class CloudRunVertexAIPublicAccessCheck:
    check_id = "GCP-002"
    check_name = "Cloud Run Service Publicly Invokable With Vertex AI Access"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        services_by_module_label = {
            (s.module, s.name): s for s in graph.by_type("google_cloud_run_v2_service")
        }

        vertex_ai_accounts = self._vertex_ai_service_accounts(graph)

        public_grants = [
            g
            for g in (
                graph.by_type("google_cloud_run_v2_service_iam_member")
                + graph.by_type("google_cloud_run_v2_service_iam_binding")
            )
            if _grants_public_invoker(g)
        ]

        for grant in public_grants:
            service_label = extract_ref(grant.config.get("name"), "google_cloud_run_v2_service")
            if not service_label:
                continue
            service = services_by_module_label.get((grant.module, service_label))
            if service is None:
                continue

            template = service.config.get("template")
            service_account_value = None
            if isinstance(template, dict):
                service_account_value = template.get("service_account")
            elif isinstance(template, list):
                for block in template:
                    if isinstance(block, dict) and block.get("service_account") is not None:
                        service_account_value = block.get("service_account")
                        break

            account_label = _service_account_label(service_account_value)
            if account_label is None or account_label not in vertex_ai_accounts:
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="CRITICAL",
                    resource_type=service.type,
                    resource_name=service.name,
                    file_path=str(service.file),
                    line=service.line,
                    message=(
                        f"Cloud Run service '{service.name}' grants "
                        '"roles/run.invoker" to "allUsers" and runs as a '
                        "service account with a Vertex AI role. Google "
                        "enforces the invoker IAM check by default; "
                        "granting it to allUsers removes authentication "
                        "entirely, unlike an internal ingress restriction "
                        "or network setting, which Google's own docs "
                        "confirm do not substitute for this control."
                    ),
                    remediation=(
                        "Remove the \"allUsers\" roles/run.invoker grant on "
                        f"{service.type}.{service.name} and require a "
                        "signed OIDC identity token from specific callers "
                        "instead."
                    ),
                    docs_url=_DOCS_URL,
                    detail="",
                )
            )

        return findings

    def _vertex_ai_service_accounts(self, graph: ProjectGraph) -> set[str]:
        accounts: set[str] = set()
        for resource_type in ("google_project_iam_member", "google_project_iam_binding"):
            for grant in graph.by_type(resource_type):
                role = grant.config.get("role")
                if not isinstance(role, str) or not role.strip().startswith("roles/aiplatform."):
                    continue

                member = grant.config.get("member")
                if member is not None:
                    label = _member_account_label(member)
                    if label:
                        accounts.add(label)

                for member in as_list(grant.config.get("members")):
                    label = _member_account_label(member)
                    if label:
                        accounts.add(label)

        return accounts
