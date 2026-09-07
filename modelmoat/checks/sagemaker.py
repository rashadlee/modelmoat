"""SMK-001: SageMaker networking - traffic paths that bypass the VPC.

Four distinct resources, one theme:

  aws_sagemaker_model    vpc_config lives here, not on
                          aws_sagemaker_endpoint_configuration. A model
                          without vpc_config runs its containers on the
                          SageMaker managed network with direct internet
                          egress, and inference traffic between your
                          applications and the endpoint never touches your
                          private network.
  aws_sagemaker_training_job
                          Same vpc_config shape and the same "has no
                          vpc_config" check as the model above - training
                          data channels and inter-container traffic run on
                          the SageMaker managed network instead of the VPC
                          when it is absent. There is no invocation endpoint
                          to authenticate against here at all, unlike a
                          model or a domain, so the message says so rather
                          than reusing the "still requires IAM auth" framing
                          that does not apply to this resource.
                          A second, independent finding on this same
                          resource: enable_inter_container_traffic_encryption
                          (default false) protects model weights and
                          gradients moving between compute instances during
                          distributed training, not the raw dataset, and it
                          is meaningless below two instances - AWS's own
                          docs say it "doesn't affect training jobs with a
                          single compute instance" - so it is only checked
                          once instance_count is provably greater than one.
                          MEDIUM rather than HIGH: this traffic stays inside
                          the job's own network, so observing it needs a
                          foothold there, unlike the internet-facing shape
                          of this check's other HIGH findings.
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

In the model, domain, and notebook cases, invoking or reaching the resource
still requires an authenticated request (SigV4-signed IAM for a model
endpoint, IAM/SSO for Studio, a presigned URL for a notebook instance), so
those are exposures of the runtime traffic path or blast radius, not open
URLs, and the findings say so. A training job has no invocation endpoint at
all to authenticate against - its exposure is the training data and
inter-container traffic on the wire, not a reachable interface - so its
message does not borrow that framing.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, blocks, first_block, is_unknown, missing_or_false
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
_TRAINING_ENCRYPTION_DOCS_URL = (
    "https://docs.aws.amazon.com/sagemaker/latest/dg/train-encrypt.html"
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


def _instance_count(resource_config: dict | None) -> int | None:
    """Resolve resource_config.instance_count to an int, or None when it
    cannot be proven - missing block, missing field, or a variable-driven
    value. enable_inter_container_traffic_encryption "doesn't affect
    training jobs with a single compute instance" per AWS's own docs, so a
    caller must know this is genuinely greater than one before treating the
    setting as meaningful.
    """
    if resource_config is None:
        return None
    value = resource_config.get("instance_count")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and not is_unknown(value):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


class SageMakerNetworkCheck:
    check_id = "SMK-001"
    check_name = "SageMaker Missing Network Isolation"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._models(graph))
        findings.extend(self._domains(graph))
        findings.extend(self._notebook_instances(graph))
        findings.extend(self._training_jobs(graph))
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
    # aws_sagemaker_training_job                                          #
    # ------------------------------------------------------------------ #
    def _training_jobs(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for job in graph.by_type("aws_sagemaker_training_job"):
            if not blocks(job.config, "vpc_config"):
                findings.append(
                    self._finding(
                        job,
                        "HIGH",
                        (
                            f"SageMaker training job '{job.name}' has no "
                            "vpc_config. Its training containers run on the "
                            "SageMaker managed network with direct internet "
                            "egress, and data channel and inter-container "
                            "traffic bypasses your VPC. The training data and "
                            "any credentials the job assumes are exposed to "
                            "that traffic path, not to an open URL - there is "
                            "no invocation endpoint here at all."
                        ),
                        (
                            "Add vpc_config with subnets and security_group_ids "
                            f"to aws_sagemaker_training_job.{job.name}. For jobs "
                            "that should never reach the internet, also set "
                            "enable_network_isolation = true and provide VPC "
                            "endpoints for S3 and ECR so the job can still pull "
                            "training data and images."
                        ),
                        _MODEL_DOCS_URL,
                        detail="",
                    )
                )

            # enable_inter_container_traffic_encryption is independent of
            # vpc_config - a job can be fully VPC-attached and still leave
            # inter-node weight/gradient traffic unencrypted - and it is
            # meaningless below two instances, so it is only evaluated once
            # instance_count is provably greater than one.
            instance_count = _instance_count(first_block(job.config, "resource_config"))
            if instance_count is not None and instance_count > 1:
                encryption = job.config.get("enable_inter_container_traffic_encryption")
                if missing_or_false(encryption):
                    state = (
                        "has no enable_inter_container_traffic_encryption set, "
                        "which defaults to false"
                        if encryption is None
                        else "sets enable_inter_container_traffic_encryption = false"
                    )
                    findings.append(
                        self._finding(
                            job,
                            "MEDIUM",
                            (
                                f"SageMaker training job '{job.name}' runs "
                                f"{instance_count} compute instances and {state}. "
                                "Distributed training transmits model weights "
                                "and gradients - not the raw training dataset - "
                                "between those instances unencrypted. This "
                                "traffic stays within the job's own network "
                                "rather than the internet, so observing it "
                                "requires a foothold on that network, but AWS's "
                                "own guidance recommends this control "
                                "specifically for regulated workloads."
                            ),
                            (
                                "Set enable_inter_container_traffic_encryption = "
                                "true on "
                                f"aws_sagemaker_training_job.{job.name}. This can "
                                "increase training time for communication-heavy "
                                "distributed algorithms."
                            ),
                            _TRAINING_ENCRYPTION_DOCS_URL,
                            detail="enable_inter_container_traffic_encryption",
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
