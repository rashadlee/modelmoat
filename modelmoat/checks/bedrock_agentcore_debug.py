"""BRK-002: Bedrock AgentCore gateways with exception_level = "DEBUG".

A different mechanism from BRK-001's authentication check, so it gets its
own number under the same BRK prefix - the same split SMK-001/002 and
AZR-001/002 already use within one resource family.

AWS's own documentation states exception messages are sanitized for
end users by default; exception_level = "DEBUG" is an explicit opt-in that
returns granular internal error detail instead - Lambda function errors,
egress authorizer errors, and target specification parameter validation
errors, in AWS's own words. That detail reaches whoever can invoke the
gateway, authenticated or not, so it is an information-disclosure finding
independent of how authorizer_type is set.

MEDIUM, not CRITICAL or HIGH: this requires an additional condition to
matter (a caller invoking the gateway and something in the leaked detail
actually being sensitive), and it does not itself prove reachability or
absent authentication the way BRK-001's authorizer_type = "NONE" does.
"""

from __future__ import annotations

from ..graph import ProjectGraph, is_unknown
from ..scanner import Finding

_DOCS_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "gateway-debugging.html"
)


class BedrockAgentCoreDebugExceptionsCheck:
    check_id = "BRK-002"
    check_name = "Bedrock AgentCore Gateway Debug Exceptions Enabled"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for gateway in graph.by_type("aws_bedrockagentcore_gateway"):
            exception_level = gateway.config.get("exception_level")
            if not isinstance(exception_level, str) or is_unknown(exception_level):
                continue
            if exception_level.strip() != "DEBUG":
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity="MEDIUM",
                    resource_type=gateway.type,
                    resource_name=gateway.name,
                    file_path=str(gateway.file),
                    line=gateway.line,
                    message=(
                        f"Gateway '{gateway.name}' sets exception_level = "
                        '"DEBUG". AWS sanitizes exception messages for end users '
                        "by default; DEBUG mode instead returns granular internal "
                        "detail to callers - Lambda function errors, egress "
                        "authorizer errors, and target specification parameter "
                        "validation errors."
                    ),
                    remediation=(
                        f"Remove exception_level from "
                        f"{gateway.type}.{gateway.name} so AWS's default "
                        "sanitized exception behavior applies, and internal "
                        "error detail does not reach callers."
                    ),
                    docs_url=_DOCS_URL,
                    detail="exception_level_debug",
                )
            )

        return findings
