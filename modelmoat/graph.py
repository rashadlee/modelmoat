"""Project-wide Terraform parsing.

Every check in modelmoat runs against a ProjectGraph built from all .tf files
in the scanned paths, because Terraform spreads related resources across
files. A bucket in s3.tf, its public access block in security.tf, and a VPC
endpoint in network.tf must all be visible to the same check at once.

This module also normalizes two quirks of python-hcl2 8.x:
  1. String literals and block labels come back wrapped in literal quote
     characters ('"my_bucket"').
  2. Nested blocks (vpc_config, environment, encrypt_at_rest) come back as
     lists of dicts, tagged with an __is_block__ marker.
"""

from __future__ import annotations

import io
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

_META_KEYS = {"__is_block__", "__start_line__", "__end_line__"}

# Tokens that mark a resource as AI or ML related. Matching is on whole
# tokens after splitting on non-alphanumeric characters, never on
# substrings, so "email" does not match "ai" and "html" does not match "ml".
AI_TOKENS = {
    "ai", "ml", "genai", "llm", "llms", "rag",
    "model", "models", "training", "dataset", "datasets",
    "artifact", "artifacts", "checkpoint", "checkpoints",
    "weight", "weights", "embedding", "embeddings",
    "vector", "vectors", "inference",
    "sagemaker", "bedrock", "huggingface", "lora",
    "finetune", "finetuned", "anthropic", "openai",
}

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def unquote(value: str) -> str:
    """Strip one layer of literal surrounding quotes that hcl2 8.x leaves on strings."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def normalize(node):
    """Recursively strip quote wrapping and parser metadata from a parse tree."""
    if isinstance(node, dict):
        return {
            (unquote(k) if isinstance(k, str) else k): normalize(v)
            for k, v in node.items()
            if k not in _META_KEYS
        }
    if isinstance(node, list):
        return [normalize(item) for item in node]
    if isinstance(node, str):
        return unquote(node)
    return node


def blocks(config: dict, key: str) -> list[dict]:
    """Return nested blocks under a key as a list of dicts, however hcl2 shaped them."""
    value = config.get(key)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def first_block(config: dict, key: str) -> dict | None:
    found = blocks(config, key)
    return found[0] if found else None


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_unknown(value) -> bool:
    """True when the value comes from a variable or expression we cannot resolve."""
    return isinstance(value, str) and "${" in value


def truthy(value) -> bool:
    """True only for a literal true. Unknown expressions are not treated as true."""
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() == "true"


def missing_or_false(value) -> bool:
    """True when a setting is absent or literally false.

    Values coming from variables are unknown, and modelmoat does not flag
    what it cannot prove, so unknowns return False here.
    """
    if value is None:
        return True
    if value is False:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        if "${" in stripped:
            return False
        return stripped.lower() == "false"
    return False


def truthy_or_absent(value) -> bool:
    """True when a setting is absent or true - the inverse of missing_or_false.

    Some provider arguments default to enabled when omitted, for example
    azurerm_cognitive_account's public_network_access_enabled (defaults to
    true per the azurerm provider docs). For those, absence is the risky
    state, not presence. Unknowns still return False: modelmoat does not
    flag what it cannot prove either way.
    """
    if value is None:
        return True
    if value is False:
        return False
    if value is True:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        if "${" in stripped:
            return False
        return stripped.lower() != "false"
    return True


def ai_tokens_in(*texts: str) -> set[str]:
    """Whole-token AI/ML keyword matches across the given strings."""
    matched: set[str] = set()
    for text in texts:
        if not text:
            continue
        tokens = {t for t in _TOKEN_SPLIT.split(str(text).lower()) if t}
        matched |= AI_TOKENS & tokens
    return matched


def extract_ref(value, resource_type: str) -> str | None:
    """Pull the resource label out of a Terraform reference string.

    extract_ref('${aws_iam_role.lambda_ai.arn}', 'aws_iam_role') -> 'lambda_ai'
    """
    if not isinstance(value, str):
        return None
    match = re.search(rf"{re.escape(resource_type)}\.([A-Za-z0-9_-]+)", value)
    return match.group(1) if match else None


@dataclass(frozen=True)
class Resource:
    """One resource or data block, with its location."""

    kind: str  # "resource" or "data"
    type: str
    name: str
    config: dict
    file: Path
    line: int

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"


@dataclass
class ProjectGraph:
    """Everything modelmoat knows about the scanned Terraform project."""

    resources: list[Resource] = field(default_factory=list)
    data_sources: list[Resource] = field(default_factory=list)
    parse_errors: list[tuple[Path, str]] = field(default_factory=list)
    files_scanned: int = 0

    def by_type(self, *types: str) -> list[Resource]:
        wanted = set(types)
        return [r for r in self.resources if r.type in wanted]

    def data_by_type(self, *types: str) -> list[Resource]:
        wanted = set(types)
        return [d for d in self.data_sources if d.type in wanted]


def _find_line(lines: list[str], kind: str, rtype: str, name: str) -> int:
    pattern = re.compile(
        rf'^\s*{kind}\s+"{re.escape(rtype)}"\s+"{re.escape(name)}"'
    )
    for number, text in enumerate(lines, start=1):
        if pattern.match(text):
            return number
    return 1


def _collect_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        path = Path(path)
        if path.is_file() and path.suffix == ".tf":
            files.append(path)
        elif path.is_dir():
            for tf in path.rglob("*.tf"):
                if ".terraform" in tf.parts:
                    continue
                files.append(tf)
    return sorted(set(files))


def build_graph(paths: Iterable[Path]) -> ProjectGraph:
    graph = ProjectGraph()
    files = _collect_files(paths)
    graph.files_scanned = len(files)

    for tf_file in files:
        try:
            text = tf_file.read_text(encoding="utf-8")
            parsed = hcl2.load(io.StringIO(text))
        except Exception as exc:  # noqa: BLE001 - any parse failure is reported, never swallowed
            first_line = str(exc).splitlines()[0][:160] if str(exc) else type(exc).__name__
            graph.parse_errors.append((tf_file, first_line))
            continue

        lines = text.splitlines()
        for kind, bucket in (("resource", graph.resources), ("data", graph.data_sources)):
            for block in parsed.get(kind, []) or []:
                if not isinstance(block, dict):
                    continue
                for rtype_raw, name_map in block.items():
                    if not isinstance(name_map, dict):
                        continue
                    rtype = unquote(rtype_raw)
                    for name_raw, config in name_map.items():
                        name = unquote(name_raw)
                        clean = normalize(config) if isinstance(config, dict) else {}
                        bucket.append(
                            Resource(
                                kind=kind,
                                type=rtype,
                                name=name,
                                config=clean,
                                file=tf_file,
                                line=_find_line(lines, kind, rtype, name),
                            )
                        )

    return graph
