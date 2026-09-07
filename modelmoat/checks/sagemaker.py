"""SMK-001: SageMaker networking - traffic paths that bypass the VPC.

Three distinct resources, one theme:

  aws_sagemaker_model    vpc_config lives here, not on
                          aws_sagemaker_endpoint_configuration. A model
                          without vpc_config runs its containers on the
                          SageMaker managed network with direct internet
                          egress, and inference traffic between your
                          applications and the endpoint never touches your
                          private network.
  aws_sagemaker_domain   vpc_id and subnet_ids are required, so a Studio
                          domain always sits in a VPC for EFS traffic. But
                          app_network_access_type (default
                          "PublicInternetOnly") controls non-EFS app traffic
                          separately: SageMaker API/runtime calls, package
                          installs, and other outbound requests from a
                          running Studio app exit through a SageMaker-managed
                          network interface unless this is set to "VpcOnly".
                          This does not control whether Studio itself is
                          reachable - access always requires IAM or SSO
                          authentication and a presigned domain URL regardless
                          of this setting.
  aws_sagemaker_notebook_instance
                          direct_internet_access defaults to "Enabled", and
                          specifying subnet_id does not turn this off by
                          itself: per AWS's own documentation, traffic within
                          the VPC's CIDR goes through the VPC's network
                          interface, but "all other traffic" - including
                          calls to the SageMaker API and training/hosting
                          endpoints unless VPC endpoints exist - goes through
                          a second, SageMaker-managed interface, "essentially
                          through the public internet." Disabling it requires
                          setting the attribute explicitly (and then requires
                          subnet_id and security_groups too), the same
                          "explicit VpcOnly required" shape as the Studio
                          domain check above.
                          root_access also defaults to "Enabled" and is
                          judged separately: it grants the notebook's user
                          root on the underlying instance, which is a
                          blast-radius question (what a compromised or
                          careless session can do to the instance and the
                          IAM role attached to it), not a network traffic
                          path, so it does not share the network finding's
                          severity.

In all three cases invoking or reaching the resource still requires an
authenticated request (SigV4-signed IAM for a model endpoint, IAM/SSO for
Studio, a presigned URL for a notebook instance), so these are exposures of
the runtime traffic path or blast radius, not open URLs, and the findings
say so.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, blocks, is_unknown
from ..scanner import Finding

_MODEL_DOCS_URL = "https://docs.aws.amazon.com/sagemaker/latest/dg/host-vpc.html"
_DOMAIN_DOCS_URL = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/"
    "studio-notebooks-and-internet-access.html"
)
_NOTEBOOK_DOCS_URL = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/"
    "appendix-notebook-and-internet-access.html"
)


def _is_public_internet_only(value) -> bool:
    """True when absent (the provider default) or explicitly "PublicInternetOnly".

    Unknown values (variables/expressions) are never flagged.
    """
    if value is None:
        return True
    if not isinstance(value, str) or is_unknown(value):
        return False
    return value.strip() == "PublicInternetOnly"


def _is_enabled(value) -> bool:
    """True when absent (the provider default) or explicitly "Enabled".

    Shared by direct_internet_access and root_access on
    aws_sagemaker_notebook_instance - both default to "Enabled" and use the
    same Enabled/Disabled vocabulary. Unknown values are never flagged.
    """
    if value is None:
        return True
    if not isinstance(value, str) or is_unknown(value):
        return False
    return value.strip() == "Enabled"


class SageMakerNetworkCheck:
    check_id = "SMK-001"
    check_name = "SageMaker Missing Network Isolation"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._models(graph))
        findings.extend(self._domains(graph))
        findings.extend(self._notebook_instances(graph))
        return findings

    # ------------------------------------------------------------------ #
    # aws_sagemaker_model                                                 #
    # ------------------------------------------------------------------ #
    def _models(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for model in graph.by_type("aws_sagemaker_model"):
            if blocks(model.config, "vpc_config"):
                continue

            findings.append(
                self._finding(
                    model,
                    "HIGH",
                    (
                        f"SageMaker model '{model.name}' has no vpc_config. Its "
                        "containers run on the SageMaker managed network with "
                        "direct internet egress, and traffic to the endpoint "
                        "bypasses your VPC. Invocation still requires IAM auth, "
                        "so this exposes the runtime environment and traffic "
                        "path rather than an open URL."
                    ),
                    (
                        "Add vpc_config with subnets and security_group_ids to "
                        f"aws_sagemaker_model.{model.name}. For models that should "
                        "never reach the internet, also set "
                        "enable_network_isolation = true and provide VPC "
                        "endpoints for S3 and ECR so the container can still pull "
                        "images and artifacts."
                    ),
                    _MODEL_DOCS_URL,
                    detail="",
                )
            )

        return findings

    # ------------------------------------------------------------------ #
    # aws_sagemaker_domain                                                #
    # ------------------------------------------------------------------ #
    def _domains(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for domain in graph.by_type("aws_sagemaker_domain"):
            value = domain.config.get("app_network_access_type")
            if not _is_public_internet_only(value):
                continue

            state = (
                'has no app_network_access_type set, which defaults to '
                '"PublicInternetOnly"'
                if value is None
                else 'sets app_network_access_type = "PublicInternetOnly"'
            )

            findings.append(
                self._finding(
                    domain,
                    "HIGH",
                    (
                        f"SageMaker Studio domain '{domain.name}' {state}. "
                        "Non-EFS app traffic - SageMaker API/runtime calls, "
                        "package installs, and other outbound requests from a "
                        "running Studio app - exits through a SageMaker-managed "
                        "network interface rather than your VPC. Studio access "
                        "itself still requires IAM or SSO authentication "
                        "regardless of this setting, so this exposes the app "
                        "traffic path, not the Studio UI."
                    ),
                    (
                        "Set app_network_access_type = \"VpcOnly\" on "
                        f"aws_sagemaker_domain.{domain.name}, and provide either "
                        "a NAT gateway or interface VPC endpoints for the "
                        "SageMaker API and runtime (and any other AWS services "
                        "Studio apps call) so app traffic stays inside your VPC."
                    ),
                    _DOMAIN_DOCS_URL,
                    detail="app_network_access_type",
                )
            )

        return findings

    # ------------------------------------------------------------------ #
    # aws_sagemaker_notebook_instance                                     #
    # ------------------------------------------------------------------ #
    def _notebook_instances(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for notebook in graph.by_type("aws_sagemaker_notebook_instance"):
            direct_internet = notebook.config.get("direct_internet_access")
            if _is_enabled(direct_internet):
                state = (
                    'has no direct_internet_access set, which defaults to '
                    '"Enabled"'
                    if direct_internet is None
                    else 'sets direct_internet_access = "Enabled"'
                )
                findings.append(
                    self._finding(
                        notebook,
                        "HIGH",
                        (
                            f"SageMaker notebook instance '{notebook.name}' "
                            f"{state}. Traffic within your VPC's CIDR goes "
                            "through your VPC's network interface, but all "
                            "other traffic - including SageMaker API and "
                            "training/hosting calls unless VPC endpoints "
                            "exist - goes through a second, SageMaker-managed "
                            "interface, bypassing your VPC's egress controls "
                            "regardless of whether subnet_id is also set. "
                            "Reaching the notebook itself still requires a "
                            "presigned URL and IAM authorization, so this "
                            "exposes the traffic path, not the notebook UI."
                        ),
                        (
                            "Set direct_internet_access = \"Disabled\" on "
                            f"aws_sagemaker_notebook_instance.{notebook.name}, "
                            "and provide subnet_id and security_groups plus "
                            "either a NAT gateway or interface VPC endpoints "
                            "for the services the notebook needs, so its "
                            "traffic stays inside your VPC."
                        ),
                        _NOTEBOOK_DOCS_URL,
                        detail="direct_internet_access",
                    )
                )

            root_access = notebook.config.get("root_access")
            if _is_enabled(root_access):
                state = (
                    'has no root_access set, which defaults to "Enabled"'
                    if root_access is None
                    else 'sets root_access = "Enabled"'
                )
                findings.append(
                    self._finding(
                        notebook,
                        "LOW",
                        (
                            f"SageMaker notebook instance '{notebook.name}' "
                            f"{state}. Whoever can open the notebook has root "
                            "on the underlying instance, widening what a "
                            "compromised or careless session can do to it "
                            "and to the IAM role attached to it. This is a "
                            "blast-radius setting on the instance, not a "
                            "network exposure."
                        ),
                        (
                            "Set root_access = \"Disabled\" on "
                            f"aws_sagemaker_notebook_instance.{notebook.name} "
                            "unless the notebook's users specifically need "
                            "root to install system packages."
                        ),
                        _NOTEBOOK_DOCS_URL,
                        detail="root_access",
                    )
                )

        return findings

    def _finding(
        self,
        resource: Resource,
        severity: str,
        message: str,
        remediation: str,
        docs_url: str,
        detail: str,
    ) -> Finding:
        # detail has no default on purpose. This check reports against two
        # different resource types, and reusing one detail token across them
        # would make an unrelated finding share a fingerprint if a future
        # change ever let both fire on the same resource address.
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity=severity,
            resource_type=resource.type,
            resource_name=resource.name,
            file_path=str(resource.file),
            line=resource.line,
            message=message,
            remediation=remediation,
            docs_url=docs_url,
            detail=detail,
        )
