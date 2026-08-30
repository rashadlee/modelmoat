"""VEC-003: self-hosted vector database on ECS reachable from the internet.

Terraform expresses container definitions as a JSON string on
aws_ecs_task_definition.container_definitions, not a native block - the same
jsonencode() shape modelmoat already unwraps for IAM policy documents in
policy.py, just with a list at the root instead of a dict.

This check proves reachability only, never authentication. Qdrant and Milvus
both ship with authentication disabled by default (QDRANT__SERVICE__API_KEY
unset, common.security.authorizationEnabled false), but neither exposes a
Terraform-visible setting whose *absence* is safe to flag: the real value can
arrive through the container's `secrets` field (Secrets Manager or SSM),
which is opaque to modelmoat by design. That is the same trap VEC-002 already
avoids for Weaviate's anonymous_access setting, and neither Qdrant nor Milvus
even has VEC-002's fallback: an explicit "enabled" value to fire on instead of
absence. So this check reports only what assign_public_ip on the ECS service
literally proves - the task gets a public IP - and its message says nothing
about whether a credential is required to reach it.

assign_public_ip only takes effect on the Fargate launch type; the ECS API
does not honor it for the EC2 launch type, where a task's reachability comes
from the underlying instance instead. The check only fires when launch_type
is explicitly "FARGATE", so it says nothing about EC2-launched services.

Matching is on an exact image repository path (qdrant/qdrant,
semitechnologies/weaviate, milvusdb/milvus), any registry host and tag or
digest stripped off first, never a substring - "myqdrant/qdrant" and
"qdrant/qdrant-proxy" must not match. Private ECR images with custom
repository names are unprovable either way, the same blind spot PIN-001 and
VEC-002 already accept for images and charts modelmoat cannot identify.
"""

from __future__ import annotations

from ..graph import ProjectGraph, Resource, extract_ref, first_block, truthy
from ..policy import parse_json_value
from ..scanner import Finding

_DOCS = (
    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/"
    "task-networking-awsvpc.html"
)

_KNOWN_IMAGES = {
    "qdrant/qdrant": "Qdrant",
    "semitechnologies/weaviate": "Weaviate",
    "milvusdb/milvus": "Milvus",
}


def _strip_tag(ref: str) -> str:
    """Drop a trailing :tag or @digest, without mistaking a registry host:port for one."""
    ref = ref.split("@", 1)[0]
    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    if last_colon > last_slash:
        ref = ref[:last_colon]
    return ref


def _matched_engine(image) -> str | None:
    """Exact repository path match against a known vector-DB image, never a substring."""
    if not isinstance(image, str) or not image.strip():
        return None
    if "${" in image:
        return None

    ref = _strip_tag(image.strip())
    for repo, engine in _KNOWN_IMAGES.items():
        if ref == repo or ref.endswith("/" + repo):
            return engine
    return None


def _matched_containers(task_def: Resource) -> list[tuple[str, str]]:
    """(container_name, engine) pairs for known vector-DB images in a task definition."""
    parsed = parse_json_value(task_def.config.get("container_definitions"), list)
    if parsed is None:
        return []

    matches: list[tuple[str, str]] = []
    for container in parsed:
        if not isinstance(container, dict):
            continue
        engine = _matched_engine(container.get("image"))
        if engine is None:
            continue
        name = container.get("name")
        matches.append((name if isinstance(name, str) and name else "container", engine))
    return matches


def _resolve_task_definition(graph: ProjectGraph, service: Resource) -> Resource | None:
    label = extract_ref(service.config.get("task_definition"), "aws_ecs_task_definition")
    if label is None:
        return None
    for task_def in graph.by_type("aws_ecs_task_definition"):
        if task_def.name == label:
            return task_def
    return None


class ECSVectorStoreReachabilityCheck:
    check_id = "VEC-003"
    check_name = "Self-Hosted Vector Database Publicly Reachable on ECS"

    def run(self, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []

        for service in graph.by_type("aws_ecs_service"):
            launch_type = service.config.get("launch_type")
            if not isinstance(launch_type, str) or launch_type.strip() != "FARGATE":
                continue

            net_config = first_block(service.config, "network_configuration")
            if net_config is None or not truthy(net_config.get("assign_public_ip")):
                continue

            task_def = _resolve_task_definition(graph, service)
            if task_def is None:
                continue

            for container_name, engine in _matched_containers(task_def):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity="HIGH",
                        resource_type=service.type,
                        resource_name=service.name,
                        file_path=str(service.file),
                        line=service.line,
                        message=(
                            f"ECS service '{service.name}' runs {engine} "
                            f"(container '{container_name}' in task definition "
                            f"'{task_def.name}') on the Fargate launch type with "
                            "assign_public_ip = true, so the task gets a public IP "
                            "address and is reachable directly from the internet. "
                            "This says nothing about whether the vector database "
                            "itself requires a credential, only that reaching it "
                            "no longer depends on being inside the VPC."
                        ),
                        remediation=(
                            "Set assign_public_ip = false and put the service "
                            "behind a load balancer or reach it only from other "
                            "resources inside the VPC. If a public endpoint is "
                            "genuinely required, put authentication in front of it "
                            "that the vector database itself enforces."
                        ),
                        docs_url=_DOCS,
                        detail=f"public_ip:{container_name}",
                    )
                )

        return findings
