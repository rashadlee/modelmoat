"""BRK-001: Bedrock AgentCore gateways with no client-side authentication.

An AgentCore gateway has two sides of authentication: one governs the
agents (MCP clients) calling in, the other governs how the gateway calls
out to the Lambda functions, APIs, or MCP servers it fronts.
authorizer_type controls the first side. "NONE" is a real, documented
value, and it disables that side entirely - any caller who can reach the
gateway can invoke every tool it exposes.

The gateway's default endpoint (com.amazonaws.region.bedrock-agentcore.gateway)
sits on AWS's standard regional network path; AWS PrivateLink is what you
opt into to keep traffic inside a VPC, not the default. So authorizer_type
= "NONE" combines proven network reachability with proven absent
authentication - unlike SMK-001 or AZR-001, where IAM or an API key is
still required no matter how the network is configured, this resource has
no such fallback when set to NONE. That is the difference between HIGH and
CRITICAL here.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown
from ..scanner import Finding

_DOCS_URL = "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html"


class BedrockAgentCoreGatewayCheck:
    check_id = "BRK-001"
    check_name = "Bedrock AgentCore Gateway Without Client Authentication"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for gateway in graph.by_type("aws_bedrockagentcore_gateway"):
            authorizer_type = gateway.config.get("authorizer_type")
            if not isinstance(authorizer_type, str) or is_unknown(authorizer_type):
                continue
            if authorizer_type.strip() != "NONE":
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="CRITICAL",
                    resource_type=gateway.type,
                    resource_name=gateway.name,
                    file_path=str(gateway.file),
                    line=gateway.line,
                    message=(
                        f"Gateway '{gateway.name}' has authorizer_type = \"NONE\", "
                        "which disables authentication on the side that faces "
                        "calling agents. The gateway's default endpoint is on "
                        "AWS's standard regional network path, not restricted to "
                        "a VPC unless PrivateLink is separately configured, so "
                        "any caller that can reach it can invoke every tool, API, "
                        "or Lambda function it exposes."
                    ),
                    remediation=(
                        "Set authorizer_type to \"AWS_IAM\" or \"CUSTOM_JWT\" so "
                        "callers must authenticate. CUSTOM_JWT also needs an "
                        "authorizer_configuration block. If callers must still be "
                        "restricted after authenticating, add "
                        "policy_engine_configuration and keep traffic inside a "
                        "VPC with AWS PrivateLink."
                    ),
                    docs_url=_DOCS_URL,
                )
            )

        return findings
