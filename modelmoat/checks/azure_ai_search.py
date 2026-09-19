"""ASR-001: Azure AI Search reachable or locally authenticated by default.

A new Azure service family, not an extension of AZR (Cognitive Services /
OpenAI) or AML (Machine Learning) - azurerm_search_service is its own
resource type with its own defaults.

Two independent fields, both defaulting to the insecure state, confirmed
against the provider source directly (internal/services/search/
search_service_resource.go in hashicorp/terraform-provider-azurerm):

  public_network_access_enabled   Default: true. Backed by a real Azure
                                   Policy built-in definition, "Azure AI
                                   Search services should disable public
                                   network access"
                                   (ee980b6d-0eca-4501-8d54-f6290fd512c3).
  local_authentication_enabled    Default: true, meaning a static API key
                                   alone authenticates every request.
                                   Backed by a separate Azure Policy
                                   built-in, "Azure AI Search services
                                   should have local authentication
                                   methods disabled"
                                   (6300012e-e9a4-4649-b41f-a85f5c43be91).

Both findings are MEDIUM, never CRITICAL: Microsoft's own security baseline
states that even with public network access enabled, "access to data stored
in your search service ... will still require the caller to present a valid
authorization token." There is no anonymous query mode on this resource -
query keys are read-only scoped credentials, not an unauthenticated path.

customer_managed_key_enforcement_enabled was investigated and not built into
a check: it only blocks non-CMK-encrypted *dependent* resources, it does not
itself enable CMK, and Azure AI Search already encrypts at rest with a
Microsoft-managed key by default - the same "provider-owned key by default"
pattern already excluded for every other AI service checked in this project.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, truthy_or_absent
from ..scanner import Finding

_PUBLIC_NETWORK_DOCS_URL = (
    "https://learn.microsoft.com/en-us/azure/search/service-create-private-endpoint"
)
_LOCAL_AUTH_DOCS_URL = "https://learn.microsoft.com/en-us/azure/search/search-security-rbac"


class AzureAISearchCheck:
    check_id = "ASR-001"
    check_name = "Azure AI Search Reachable or Locally Authenticated by Default"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for service in graph.by_type("azurerm_search_service"):
            findings.extend(self._public_network_access(service))
            findings.extend(self._local_authentication(service))

        return findings

    def _public_network_access(self, service: Resource) -> list[Finding]:
        value = service.config.get("public_network_access_enabled")
        if not truthy_or_absent(value):
            return []

        state = (
            "has no public_network_access_enabled set, which defaults to true"
            if value is None
            else "sets public_network_access_enabled = true"
        )

        return [
            self._finding(
                service,
                f"Search service '{service.name}' {state}, making the search "
                "endpoint reachable from the public internet. A valid API key "
                "or Microsoft Entra ID token is still required for every "
                "request regardless of this setting, so this exposes network "
                "reachability, not an unauthenticated endpoint.",
                "Set public_network_access_enabled = false on "
                f"{service.type}.{service.name} and configure a private "
                "endpoint for access from inside your VNet.",
                _PUBLIC_NETWORK_DOCS_URL,
                detail="public_network_access",
            )
        ]

    def _local_authentication(self, service: Resource) -> list[Finding]:
        value = service.config.get("local_authentication_enabled")
        if not truthy_or_absent(value):
            return []

        state = (
            "has no local_authentication_enabled set, which defaults to true"
            if value is None
            else "sets local_authentication_enabled = true"
        )

        return [
            self._finding(
                service,
                f"Search service '{service.name}' {state}, so a static API "
                "key alone authenticates every request. A leaked key works "
                "with no tie to a real identity and no per-identity "
                "revocation - only rotating the key itself stops it.",
                f"Set local_authentication_enabled = false on {service.type}."
                f"{service.name} and grant callers a role such as "
                '"Search Index Data Reader" via Microsoft Entra ID instead.',
                _LOCAL_AUTH_DOCS_URL,
                detail="local_authentication",
            )
        ]

    def _finding(
        self,
        resource: Resource,
        message: str,
        remediation: str,
        docs_url: str,
        detail: str,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity="MEDIUM",
            resource_type=resource.type,
            resource_name=resource.name,
            file_path=str(resource.file),
            line=resource.line,
            message=message,
            remediation=remediation,
            docs_url=docs_url,
            detail=detail,
        )
