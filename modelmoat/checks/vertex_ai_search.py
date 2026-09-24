"""VAS-001: Vertex AI Search data stores that drop source ACLs on import.

A new Google Cloud product, not an extension of GCP-001/002 - Vertex AI
Search (Discovery Engine) is a separate service from the core Vertex AI
ML platform those checks target, the same reasoning that already split
ASR-001 (Azure AI Search) out from AZR (Cognitive Services) rather than
folding it in.

google_discovery_engine_data_store's acl_enabled controls whether source
-system permissions are preserved when documents are imported for
indexing. Optional, no default in the Terraform schema, and Google's own
documentation carries an explicit Caution callout:
"When you import data from Cloud Storage into an Agent Search data store,
Cloud Storage permissions aren't imported with the data. After import,
any user with sufficient Agent Search permissions can view the data, even
if they don't have permission to view the data in Cloud Storage." Unlike
Amazon Kendra's parallel ACL question (investigated and rejected because
AWS has closed Kendra to new customers), Vertex AI Search is an actively
shipping, actively recommended GCP product, so this is real, current
evidence, not a stale one.

HIGH, matching IAM-001's "permissions broad enough to reach [data] in the
account" shape: this needs no additional condition to matter (unlike
DBX-003's isolation_mode, which still requires a separate Unity Catalog
GRANT) - once acl_enabled is off, any principal with search-app access
sees everything, full stop.

Scoped to where Google's own caution actually applies: acl_enabled is
"only supported for GENERIC industry_vertical with non-PUBLIC_WEBSITE
content_config" per the provider docs. industry_vertical is required, so
a MEDIA or HEALTHCARE_FHIR data store is out of scope entirely - the
field wouldn't take effect there regardless of its value, and firing
would claim more than the configuration proves. A PUBLIC_WEBSITE
content_config is excluded too: public web content has no Cloud
Storage-style source permissions to strip in the first place, so the
caution's premise does not apply.

This proves the field is off, not that a given data store is actually
ingesting access-sensitive content - the same "proves a default posture,
not what's behind it" shape ASR-001's two findings already carry.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown, missing_or_false
from ..scanner import Finding

_DOCS_URL = (
    "https://cloud.google.com/generative-ai-app-builder/docs/create-data-store-es"
)


class VertexAISearchACLCheck:
    check_id = "VAS-001"
    check_name = "Vertex AI Search Data Store Drops Source ACLs on Import"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for store in graph.by_type("google_discovery_engine_data_store"):
            industry_vertical = store.config.get("industry_vertical")
            if not isinstance(industry_vertical, str) or is_unknown(industry_vertical):
                continue
            if industry_vertical.strip() != "GENERIC":
                continue

            content_config = store.config.get("content_config")
            if isinstance(content_config, str):
                if is_unknown(content_config):
                    continue
                if content_config.strip() == "PUBLIC_WEBSITE":
                    continue

            value = store.config.get("acl_enabled")
            if not missing_or_false(value):
                continue

            state = (
                "has no acl_enabled set, which defaults to false"
                if value is None
                else "sets acl_enabled = false"
            )

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="HIGH",
                    resource_type=store.type,
                    resource_name=store.name,
                    file_path=str(store.file),
                    line=store.line,
                    message=(
                        f"Data store '{store.name}' {state}. Google's own "
                        "documentation states that without it, source-system "
                        "permissions (for example Cloud Storage ACLs) are "
                        "not imported with the data - any user with "
                        "sufficient Agent Search permissions can view it, "
                        "even without permission to view it at the source."
                    ),
                    remediation=(
                        f"Set acl_enabled = true on {store.type}.{store.name} "
                        "and ensure the source data carries acl_info "
                        "metadata, so indexed documents keep their original "
                        "access restrictions."
                    ),
                    docs_url=_DOCS_URL,
                    detail="acl_enabled",
                )
            )

        return findings
