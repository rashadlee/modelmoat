"""AZR-002: Azure OpenAI / Foundry accounts allowing local (API key) auth.

A different mechanism from AZR-001's network-reachability check, so it gets
its own number under the same AZR prefix - the same split VEC-001/002/003
already use within one resource family.

azurerm_cognitive_account's local_auth_enabled defaults to true, meaning a
static API key alone authenticates every request. Microsoft's own guidance
recommends disabling it in favor of Microsoft Entra ID tokens exclusively,
and there is a built-in Azure Policy definition for exactly this
("Cognitive Services accounts should have local authentication methods
disabled") - this is not a fabricated concern.

The account still requires some form of authentication either way - this
is not a reachability finding like AZR-001, and does not claim the account
is currently exposed. It is a blast-radius finding: a leaked API key
(committed to source control, logged accidentally, exposed in a client)
authenticates on its own, with no tie to a real identity, no support for
conditional access or MFA, and no per-identity revocation - only rotating
or deleting the key itself stops it. An Entra ID token is tied to a real
principal, inherits whatever conditional access policies apply to it, and
can be revoked without touching the account's keys at all.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown, truthy_or_absent
from ..scanner import Finding

_AI_KINDS = {"OpenAI", "AIServices"}
_DOCS_URL = (
    "https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/"
    "how-to/configure-entra-id"
)


class AzureOpenAILocalAuthCheck:
    check_id = "AZR-002"
    check_name = "Azure OpenAI Local Authentication Enabled"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for account in graph.by_type("azurerm_cognitive_account"):
            kind = account.config.get("kind")
            if not isinstance(kind, str) or is_unknown(kind) or kind not in _AI_KINDS:
                continue

            if not truthy_or_absent(account.config.get("local_auth_enabled")):
                continue

            value = account.config.get("local_auth_enabled")
            state = (
                "has no local_auth_enabled set, which defaults to true"
                if value is None
                else "sets local_auth_enabled = true"
            )

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="MEDIUM",
                    resource_type=account.type,
                    resource_name=account.name,
                    file_path=str(account.file),
                    line=account.line,
                    message=(
                        f"Cognitive account '{account.name}' (kind = {kind}) "
                        f"{state}, so a static API key alone authenticates every "
                        "request. A leaked key works with no tie to a real "
                        "identity and no per-identity revocation - only "
                        "rotating the key itself stops it."
                    ),
                    remediation=(
                        f"Set local_auth_enabled = false on {account.type}."
                        f"{account.name} and grant callers a role such as "
                        '"Cognitive Services OpenAI User" via Microsoft Entra '
                        "ID instead. Note this breaks Azure OpenAI Studio, "
                        "which requires key access - confirm nothing still "
                        "depends on it before disabling."
                    ),
                    docs_url=_DOCS_URL,
                    detail="local_auth_enabled",
                )
            )

        return findings
