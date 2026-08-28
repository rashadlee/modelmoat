"""AZR-001: Azure OpenAI / Foundry accounts reachable from the public internet.

azurerm_cognitive_account's public_network_access_enabled defaults to true
when omitted, so an account with no explicit setting is publicly reachable
by default - the opposite of most security-relevant Terraform defaults.
network_acls is the only thing that narrows that down, and only when its
default_action is "Deny"; an absent network_acls block, or one left at
"Allow", leaves the account open to the internet.

Azure Cognitive Services still requires an API key or Entra ID credential
for every request regardless of network configuration, so this is exposure
of the account's network reachability and attack surface, not an
unauthenticated open endpoint - the finding says so, matching how SMK-001
frames the equivalent SageMaker case.
"""

from __future__ import annotations

from ..graph import ProjectGraph, first_block, is_unknown, truthy_or_absent
from ..scanner import Finding

_AI_KINDS = {"OpenAI", "AIServices"}
_DOCS_URL = "https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks"


class AzureOpenAINetworkCheck:
    check_id = "AZR-001"
    check_name = "Azure OpenAI Account Reachable From the Public Internet"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for account in graph.by_type("azurerm_cognitive_account"):
            kind = account.config.get("kind")
            if not isinstance(kind, str) or is_unknown(kind) or kind not in _AI_KINDS:
                continue

            if not truthy_or_absent(account.config.get("public_network_access_enabled")):
                continue

            acls = first_block(account.config, "network_acls")
            default_action = acls.get("default_action") if acls else None
            if isinstance(default_action, str) and default_action.strip() == "Deny":
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="HIGH",
                    resource_type=account.type,
                    resource_name=account.name,
                    file_path=str(account.file),
                    line=account.line,
                    message=(
                        f"Cognitive account '{account.name}' (kind = {kind}) has "
                        "public network access enabled, or left unset (which "
                        "defaults to enabled), with no network_acls block set to "
                        "default_action = \"Deny\". Every request still requires an "
                        "API key or Entra ID credential, so this exposes the "
                        "account's network reachability and attack surface, not an "
                        "unauthenticated open endpoint."
                    ),
                    remediation=(
                        "Set public_network_access_enabled = false for a fully "
                        "private account, or add a network_acls block with "
                        "default_action = \"Deny\" plus explicit ip_rules or "
                        "virtual_network_rules for the networks that need access."
                    ),
                    docs_url=_DOCS_URL,
                )
            )

        return findings
