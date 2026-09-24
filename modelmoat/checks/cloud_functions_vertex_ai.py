"""GCF-001: Cloud Functions (2nd gen) publicly invokable with Vertex AI access.

A different resource from GCP-002's google_cloud_run_v2_service, even
though 2nd gen Cloud Functions run on Cloud Run infrastructure
underneath - google_cloudfunctions2_function is its own distinct
Terraform resource with its own IAM member resource
(google_cloudfunctions2_function_iam_member/_iam_binding), and GCP-002's
correlation logic (which resolves a public grant's target against a
declared google_cloud_run_v2_service resource) does not and cannot match
a google_cloudfunctions2_function block - there is no
google_cloud_run_v2_service resource in the configuration for a Gen2
function's implicit backing service to correlate against. Confirmed as a
genuine structural gap, not existing coverage, before building this.
Checkov treats these as separate detection targets too (CKV_GCP_124 is
implemented specifically for google_cloudfunctions2_function, not folded
into its Cloud Run checks).

Scoped to "roles/cloudfunctions.invoker" only, not "roles/run.invoker" -
hashicorp/terraform-provider-google has a long-standing, still-open bug
(issue #21674 and predecessors) where granting roles/run.invoker via
google_cloudfunctions2_function_iam_member fails to apply ("invalid
argument"), which is why real-world Terraform uses the documented,
idiomatic cloudfunctions.invoker role for this resource instead. Google's
own Cloud Functions IAM docs state invocation normally requires "entities
that need to invoke an HTTP function must explicitly present
authentication credentials" - the same zero-authentication-when-granted
-to-allUsers shape already confirmed for GCP-002's Cloud Run finding, not
this project's usual "reachable but still signed" framing. CRITICAL.

service_config.ingress_settings (default "ALLOW_ALL") is deliberately not
part of this check's logic, the same reasoning GCP-002 already applies to
Cloud Run's ingress field: Google documents these as independent layers,
and restricting ingress does not substitute for the IAM invoker check.

Vertex AI access is correlated via service_config.service_account_email
against the same roles/aiplatform.* project-level grants GCP-002 already
resolves - reuses CloudRunVertexAIPublicAccessCheck._vertex_ai_service_accounts
directly rather than duplicating it, the same cross-check reuse pattern
AGW-002/SMK-002/LFU-001 already use elsewhere in this project.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, as_list, extract_ref
from ..scanner import Finding
from .cloud_run_vertex_ai import CloudRunVertexAIPublicAccessCheck, _service_account_label

_DOCS_URL = "https://cloud.google.com/functions/docs/securing/managing-access-iam"


def _grants_public_invoker(resource: Resource) -> bool:
    role = resource.config.get("role")
    if not isinstance(role, str) or role.strip() != "roles/cloudfunctions.invoker":
        return False

    member = resource.config.get("member")
    if isinstance(member, str) and member.strip() == "allUsers":
        return True

    members = as_list(resource.config.get("members"))
    return any(isinstance(m, str) and m.strip() == "allUsers" for m in members)


class CloudFunctionsVertexAIPublicAccessCheck:
    check_id = "GCF-001"
    check_name = "Cloud Function Publicly Invokable With Vertex AI Access"

    def __init__(self) -> None:
        self._gcp002 = CloudRunVertexAIPublicAccessCheck()

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        functions_by_module_label = {
            (f.module, f.name): f for f in graph.by_type("google_cloudfunctions2_function")
        }

        vertex_ai_accounts = self._gcp002._vertex_ai_service_accounts(graph)

        public_grants = [
            g
            for g in (
                graph.by_type("google_cloudfunctions2_function_iam_member")
                + graph.by_type("google_cloudfunctions2_function_iam_binding")
            )
            if _grants_public_invoker(g)
        ]

        for grant in public_grants:
            function_label = extract_ref(
                grant.config.get("cloud_function"), "google_cloudfunctions2_function"
            )
            if not function_label:
                continue
            function = functions_by_module_label.get((grant.module, function_label))
            if function is None:
                continue

            service_config = function.config.get("service_config")
            service_account_value = None
            if isinstance(service_config, dict):
                service_account_value = service_config.get("service_account_email")
            elif isinstance(service_config, list):
                for block in service_config:
                    if isinstance(block, dict) and block.get("service_account_email") is not None:
                        service_account_value = block.get("service_account_email")
                        break

            account_label = _service_account_label(service_account_value)
            if account_label is None or account_label not in vertex_ai_accounts:
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="CRITICAL",
                    resource_type=function.type,
                    resource_name=function.name,
                    file_path=str(function.file),
                    line=function.line,
                    message=(
                        f"Cloud Function '{function.name}' grants "
                        '"roles/cloudfunctions.invoker" to "allUsers" and '
                        "runs as a service account with a Vertex AI role. "
                        "Google requires callers to present authentication "
                        "credentials by default; granting the invoker role "
                        "to allUsers removes that requirement entirely, "
                        "unlike an ingress restriction, which does not "
                        "substitute for this control."
                    ),
                    remediation=(
                        "Remove the \"allUsers\" roles/cloudfunctions.invoker "
                        f"grant on {function.type}.{function.name} and "
                        "require a signed OIDC identity token from specific "
                        "callers instead."
                    ),
                    docs_url=_DOCS_URL,
                    detail="",
                )
            )

        return findings
