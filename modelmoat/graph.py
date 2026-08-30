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
import json
import os
import re
import stat
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
    """One resource or data block, with its location.

    `module` is the directory the resource's file lives in - modelmoat does
    not resolve `module "x" { source = ... }` call sites, so a directory is
    the closest available proxy for a Terraform module boundary. Terraform
    itself merges every .tf/.tf.json file within one directory into a single
    scope, but a resource label in one directory is never implicitly visible
    to another: two sibling directories can each declare
    `resource "aws_s3_bucket" "data" {}` and refer to two unrelated buckets.
    Cross-resource correlation (a bucket to its access block, a policy
    document to the statement that references it) must stay inside one
    module, or an identically labeled resource in an unrelated directory can
    silently stand in for the real one.

    `unresolved_cardinality` is True when `count`/`for_each` could not be
    resolved to a definite positive value (a variable-driven expression, for
    example) - the resource is neither provably created nor provably absent,
    so it still belongs in the graph (a resource that IS provably absent is
    excluded entirely in build_graph, never reaching Resource at all). What
    to do with that uncertainty is a per-check, per-role decision the graph
    itself cannot make: evaluating this resource for the risk it might pose
    should proceed as normal, since modelmoat cannot prove it is absent
    either, but crediting it as a compensating control protecting some other
    resource should not, since modelmoat cannot prove it exists.
    """

    kind: str  # "resource" or "data"
    type: str
    name: str
    config: dict
    file: Path
    line: int
    module: Path
    unresolved_cardinality: bool = False

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


def _parse_tf_json(text: str) -> dict:
    """Load a .tf.json file into the same shape build_graph expects from hcl2:
    each top-level block type (`resource`, `data`, ...) maps to a list of
    {type: {name: config}} dicts.

    Terraform's JSON syntax normally nests a top-level block type straight to
    an object (`{"resource": {"aws_s3_bucket": {"a": {...}}}}`), only using a
    JSON array where the same block type/labels repeat. hcl2 always gives a
    list at this level, so wrap the common single-object case to match -
    downstream code already tolerates a list (repeats) or skips a shape it
    doesn't recognise, the same as it does for hcl2 output.
    """
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise TypeError("root of a .tf.json file must be a JSON object")
    return {
        key: [value] if isinstance(value, dict) else value
        for key, value in parsed.items()
    }


_EMPTY_TOSET = re.compile(r"^\$\{\s*toset\(\s*\[\s*\]\s*\)\s*\}$")


def _cardinality(config: dict) -> bool | None:
    """Whether `count`/`for_each` proves this block is created (True), proves
    it is not (False), or leaves that unresolved (None).

    A literal `count = 0` or an empty `for_each` (`{}`, `[]`, or the common
    `toset([])` idiom) means Terraform creates no instance at all - build_graph
    excludes that block from the graph entirely, whether it is the resource
    being checked for risk or a compensating control, since nothing exists
    either way.

    A variable-driven count/for_each is unresolved rather than provably zero
    or provably nonzero. Collapsing that to "absent" would make a risky
    resource with unresolved cardinality invisible to every check - a false
    negative, not a fix, since modelmoat cannot prove it is NOT deployed
    either. Collapsing it to "present" would let a compensating control with
    unresolved cardinality prove safety again, the same bug through a
    different door. So None stays in the graph rather than being excluded -
    see Resource.unresolved_cardinality for what a check is expected to do
    with it. hcl2 serializes any function call - `toset([])` included - back
    as an opaque `${...}` string, so `toset([])` needs its own literal check;
    any other for_each expression (a variable, local, or a non-empty
    toset(...) call) is unresolved rather than parsed as an expression.
    """
    if "count" in config:
        count = config["count"]
        if isinstance(count, bool) or is_unknown(count):
            return None
        try:
            return int(count) > 0
        except (TypeError, ValueError):
            return None

    if "for_each" in config:
        for_each = config["for_each"]
        if isinstance(for_each, (dict, list)):
            return bool(for_each)
        if isinstance(for_each, str) and _EMPTY_TOSET.match(for_each.strip()):
            return False
        return None

    return True


def _is_terraform_file(path: Path) -> bool:
    """True for both HCL (.tf) and JSON-syntax (.tf.json) Terraform files.

    Terraform loads both from the same directory, and .tf.json is real,
    deployable Terraform - a generated file, an override, or a directory
    migrated to JSON syntax must not scan as if it were empty.
    """
    return path.name.endswith(".tf") or path.name.endswith(".tf.json")


_MAX_FILE_BYTES = 5_000_000
_MAX_TOTAL_BYTES = 50_000_000
_MAX_FILES = 20_000


def _walk_terraform_files(root: Path) -> list[Path]:
    """Find .tf/.tf.json files under root without ever following a symlink.

    os.walk's followlinks=False already refuses to descend into a symlinked
    subdirectory - a symlinked directory nested in the scan root cannot walk
    modelmoat out to somewhere else on disk. Symlinked files are still listed
    by os.walk even with followlinks=False, so each one is checked and
    skipped explicitly here too.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".terraform"]
        current = Path(dirpath)
        for name in filenames:
            candidate = current / name
            if not _is_terraform_file(candidate) or candidate.is_symlink():
                continue
            found.append(candidate)
    return found


def _collect_files(paths: Iterable[Path]) -> list[Path]:
    """Discover scan targets.

    A symlink is never scanned, whether passed directly or found during
    traversal, regardless of where it points - reading through it could pull
    in a file outside every path the caller actually asked to scan, and
    modelmoat's untrusted-checkout use case (a PR's changed files) makes that
    a real boundary, not a hypothetical one.
    """
    files: list[Path] = []
    for path in paths:
        path = Path(path)
        if path.is_symlink():
            continue
        if path.is_file() and _is_terraform_file(path):
            files.append(path)
        elif path.is_dir():
            files.extend(_walk_terraform_files(path))
    return sorted(set(files))


def _read_terraform_file(path: Path) -> str:
    """Read a Terraform file with no-follow, regular-file-only, size-capped
    semantics.

    Opening the path directly with O_NOFOLLOW - rather than checking
    is_symlink()/is_file() and opening separately - closes the race where the
    path is swapped for a symlink or a special file between an earlier check
    and the read: the open() call itself fails atomically instead of trusting
    a check that already happened. fstat (not stat on the path) confirms what
    was actually opened is a regular file before any content is read, and the
    size is capped before that read rather than after, so a device or an
    oversized file cannot be read in full first and rejected second.
    """
    # O_NONBLOCK matters as much as the regular-file check that follows it: a
    # FIFO opened O_RDONLY without it blocks the whole scan until something
    # writes to the other end, which is itself the denial of service this
    # function exists to prevent. It is a no-op for a regular file, so it
    # never changes how an actual Terraform file is read.
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"{path} is not a regular file")
        if info.st_size > _MAX_FILE_BYTES:
            raise OSError(
                f"{path} is {info.st_size} bytes, over modelmoat's "
                f"{_MAX_FILE_BYTES}-byte per-file limit"
            )
        raw = os.read(fd, info.st_size)
    finally:
        os.close(fd)
    return raw.decode("utf-8")


def build_graph(paths: Iterable[Path]) -> ProjectGraph:
    graph = ProjectGraph()
    files = _collect_files(paths)

    # A directory containing an adversarial number of files is its own denial
    # of service before a single one is even opened - cap the file count
    # discovery itself can act on, the same way each file's own read is
    # capped by size.
    if len(files) > _MAX_FILES:
        graph.parse_errors.append(
            (files[_MAX_FILES], f"scan truncated at modelmoat's {_MAX_FILES}-file limit")
        )
        files = files[:_MAX_FILES]

    graph.files_scanned = len(files)
    total_bytes = 0

    for tf_file in files:
        try:
            text = _read_terraform_file(tf_file)
        except Exception as exc:  # noqa: BLE001 - any read failure is reported, never swallowed
            first_line = str(exc).splitlines()[0][:160] if str(exc) else type(exc).__name__
            graph.parse_errors.append((tf_file, first_line))
            continue

        total_bytes += len(text.encode("utf-8"))
        if total_bytes > _MAX_TOTAL_BYTES:
            graph.parse_errors.append(
                (
                    tf_file,
                    f"skipped: total project byte quota ({_MAX_TOTAL_BYTES} bytes) exceeded",
                )
            )
            continue

        try:
            if tf_file.name.endswith(".tf.json"):
                parsed = _parse_tf_json(text)
            else:
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
                        unresolved_cardinality = False
                        if isinstance(config, dict):
                            cardinality = _cardinality(config)
                            if cardinality is False:
                                continue
                            unresolved_cardinality = cardinality is None
                        clean = normalize(config) if isinstance(config, dict) else {}
                        bucket.append(
                            Resource(
                                kind=kind,
                                type=rtype,
                                name=name,
                                config=clean,
                                file=tf_file,
                                line=_find_line(lines, kind, rtype, name),
                                module=tf_file.parent,
                                unresolved_cardinality=unresolved_cardinality,
                            )
                        )

    return graph
