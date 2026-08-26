"""VEC-002: self-hosted Weaviate reachable without authentication.

There is no Terraform provider for Weaviate, and this is structural rather than
an oversight: Weaviate Cloud has no public cluster provisioning API, so there is
no control plane for a provider to wrap. Teams deploy Weaviate with the official
Helm chart or as a container on Kubernetes, and that is where its security
configuration becomes visible to a Terraform scanner.

The chart ships `authentication.anonymous_access.enabled: true` as its default,
so the tempting check is to fire whenever the setting is absent. This check
deliberately does not do that. Absence is unprovable here: the value legitimately
arrives through a values.yaml passed to helm_release, a ConfigMap, a Secret, or a
chart default, none of which the scanner can see. Firing only on an explicit
enabled value means knowingly missing real insecure deployments, which is the
correct trade for a tool whose false positive rate is the product.
"""

from __future__ import annotations

import re

from ..graph import ProjectGraph, Resource, blocks, is_unknown
from ..scanner import Finding

_DOCS = "https://docs.weaviate.io/deploy/configuration/authentication"

_HELM_VALUE = "authentication.anonymous_access.enabled"
_ENV_VAR = "AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED"

# Weaviate's own truthiness helper, entities/config/helpers.go, treats exactly
# these as enabled. Matching only "true" would miss a deployment that sets the
# variable to "1", which really does enable anonymous access.
_ENABLED_VALUES = {"on", "enabled", "1", "true"}

_WORKLOAD_TYPES = ("kubernetes_deployment", "kubernetes_stateful_set")

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _mentions_weaviate(*texts) -> bool:
    """Whole-token match on 'weaviate', never a substring match."""
    for text in texts:
        if not isinstance(text, str) or not text:
            continue
        if "weaviate" in {t for t in _TOKEN_SPLIT.split(text.lower()) if t}:
            return True
    return False


def _explicitly_enabled(value) -> bool:
    """True only when the configuration literally enables anonymous access."""
    if value is True:
        return True
    if not isinstance(value, str):
        return False
    if is_unknown(value):
        return False
    return value.strip().lower() in _ENABLED_VALUES


def _containers(resource: Resource) -> list[dict]:
    """Walk kubernetes_deployment / stateful_set down to its container blocks."""
    found: list[dict] = []
    for spec in blocks(resource.config, "spec"):
        for template in blocks(spec, "template"):
            for pod_spec in blocks(template, "spec"):
                found.extend(blocks(pod_spec, "container"))
    return found


class WeaviateAnonymousAccessCheck:
    check_id = "VEC-002"
    check_name = "Self-Hosted Weaviate Without Authentication"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._helm(graph))
        findings.extend(self._workloads(graph))
        return findings

    def _helm(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for release in graph.by_type("helm_release"):
            chart = release.config.get("chart")
            name = release.config.get("name")
            if not _mentions_weaviate(chart, name, release.name):
                continue

            for entry in blocks(release.config, "set"):
                if entry.get("name") != _HELM_VALUE:
                    continue
                if not _explicitly_enabled(entry.get("value")):
                    continue

                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity="HIGH",
                        resource_type=release.type,
                        resource_name=release.name,
                        file_path=str(release.file),
                        line=release.line,
                        message=(
                            f"Weaviate release '{release.name}' sets "
                            f"{_HELM_VALUE} to true, so the vector store accepts "
                            "unauthenticated requests. Anyone able to reach the "
                            "service can read and delete the embeddings and the "
                            "source text stored alongside them. This says nothing "
                            "about whether the service is reachable from the "
                            "internet, only that no credential is required."
                        ),
                        remediation=(
                            "Set authentication.anonymous_access.enabled to false and "
                            "enable an authentication method, for example "
                            "authentication.apikey.enabled with keys supplied from a "
                            "Kubernetes secret. Weaviate rejects a configuration that "
                            "enables both anonymous access and RBAC."
                        ),
                        docs_url=_DOCS,
                        detail="helm_anonymous_access",
                    )
                )

        return findings

    def _workloads(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for workload in graph.by_type(*_WORKLOAD_TYPES):
            for container in _containers(workload):
                image = container.get("image")
                container_name = container.get("name")
                if not _mentions_weaviate(image, container_name):
                    continue

                for env in blocks(container, "env"):
                    if env.get("name") != _ENV_VAR:
                        continue
                    if not _explicitly_enabled(env.get("value")):
                        continue

                    label = container_name if isinstance(container_name, str) else "container"
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_name=self.check_name,
                            severity="HIGH",
                            resource_type=workload.type,
                            resource_name=workload.name,
                            file_path=str(workload.file),
                            line=workload.line,
                            message=(
                                f"Weaviate container '{label}' in '{workload.name}' "
                                f"sets {_ENV_VAR} to an enabled value, so the vector "
                                "store accepts unauthenticated requests. Anyone able "
                                "to reach the service can read and delete the "
                                "embeddings and the source text stored alongside "
                                "them. This says nothing about whether the service is "
                                "reachable from the internet, only that no credential "
                                "is required."
                            ),
                            remediation=(
                                f"Set {_ENV_VAR} to false and configure an "
                                "authentication method, for example "
                                "AUTHENTICATION_APIKEY_ENABLED with keys supplied "
                                "from a Kubernetes secret rather than a literal in "
                                "the manifest."
                            ),
                            docs_url=_DOCS,
                            detail=f"env_anonymous_access:{label}",
                        )
                    )

        return findings
