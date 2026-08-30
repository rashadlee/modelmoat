"""MM-13/MM-14/MM-15 regression: policy checks on the GitHub Actions
workflows and their locked dependencies, not on modelmoat itself.

An authenticated push from CI failing is not checked here - that is a
property of `permissions: contents: read` granting no write scope at all,
provable only by an actual GitHub Actions run against the real GITHUB_TOKEN,
not by anything this repository's own test suite can execute. Likewise,
whether PyPI Trusted Publishing and the `pypi` environment's protection
rules are actually configured is PyPI- and GitHub-settings state this suite
cannot see - it can only check that the workflow is written to use them
correctly.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOWS_DIR / "ci.yml"
RELEASE_WORKFLOW = WORKFLOWS_DIR / "release.yml"
LOCKFILE = REPO_ROOT / ".github" / "requirements-lock.txt"

_USES_LINE = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)
_PACKAGE_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==\S+ \\$", re.MULTILINE)
_WRITE_PERMISSION = re.compile(r"^\s*([a-z-]+):\s*write\s*$", re.MULTILINE)

# The only write scopes any workflow in this repo may request: OIDC token
# issuance for PyPI Trusted Publishing and build provenance attestation, and
# persisting that attestation via Sigstore - neither is a repository content
# mutation.
_ALLOWED_WRITE_PERMISSIONS = {"id-token", "attestations"}


def _all_workflows() -> list[Path]:
    files = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert files, "expected at least one workflow file"
    return files


def test_ci_actions_are_pinned_to_a_full_commit_sha():
    # A mutable tag (v5, v5.1.0, main) can be repointed by the action's own
    # maintainers - accidentally, or via a compromised account - without
    # this workflow's approval ever running again. Only a full 40-character
    # commit SHA closes that.
    for workflow in _all_workflows():
        text = workflow.read_text()
        uses_refs = _USES_LINE.findall(text)
        assert uses_refs, f"expected at least one `uses:` step in {workflow.name}"
        for ref in uses_refs:
            action, _, version = ref.partition("@")
            assert version, f"{workflow.name}: {ref} has no @version pin at all"
            assert re.fullmatch(r"[0-9a-f]{40}", version), (
                f"{workflow.name}: {action} is pinned to '{version}', not a full "
                "40-character commit SHA"
            )


def test_ci_declares_restrictive_permissions():
    # Every workflow must declare contents: read explicitly rather than
    # running under the implicit default GITHUB_TOKEN, which historically
    # defaults to read-write, and none may request contents: write. The one
    # write scope allowed anywhere is id-token: write, which release.yml
    # needs for PyPI Trusted Publishing - it grants OIDC token issuance, not
    # any ability to modify this repository.
    for workflow in _all_workflows():
        text = workflow.read_text()
        assert "permissions:\n  contents: read\n" in text, (
            f"{workflow.name} has no top-level `contents: read` permissions block"
        )
        for match in _WRITE_PERMISSION.finditer(text):
            scope = match.group(1)
            assert scope in _ALLOWED_WRITE_PERMISSIONS, (
                f"{workflow.name} requests disallowed write scope '{scope}: write'"
            )


def test_release_workflow_only_triggers_on_version_tags():
    # A release must not be publishable from an arbitrary branch push.
    text = RELEASE_WORKFLOW.read_text()
    assert "tags:" in text
    assert "branches:" not in text


def test_release_workflow_builds_once_and_publishes_the_same_artifact():
    # Rebuilding in the publish job would mean the attested provenance and
    # the artifact actually uploaded to PyPI are not provably the same
    # bytes - build must happen exactly once, with publish downloading that
    # output rather than re-running `python -m build`.
    text = RELEASE_WORKFLOW.read_text()
    assert text.count("python -m build") == 1
    assert "upload-artifact" in text
    assert "download-artifact" in text


def test_release_workflow_uses_trusted_publishing_not_a_stored_token():
    text = RELEASE_WORKFLOW.read_text()
    assert "gh-action-pypi-publish" in text
    assert "id-token: write" in text
    # No PyPI API token secret anywhere - Trusted Publishing needs none.
    assert "PYPI_API_TOKEN" not in text
    assert "TWINE_PASSWORD" not in text
    assert "password:" not in text.lower()


def test_release_workflow_attests_build_provenance():
    text = RELEASE_WORKFLOW.read_text()
    assert "attest-build-provenance" in text


def test_release_workflow_gates_publish_behind_a_protected_environment():
    text = RELEASE_WORKFLOW.read_text()
    assert re.search(r"^\s*environment:\s*\S+", text, re.MULTILINE), (
        "publish job has no `environment:` - that's what a required-reviewer "
        "protection rule attaches to"
    )


def test_release_workflow_verifies_the_tag_matches_the_package_version():
    text = RELEASE_WORKFLOW.read_text()
    assert "pyproject.toml" in text
    assert "GITHUB_REF_NAME" in text


def test_dependency_lockfile_hashes_every_pinned_package():
    # Two clean installs from the same commit resolving identically is
    # guaranteed by pip's --require-hashes mode, which refuses to install
    # anything the lockfile does not hash - this checks that guarantee
    # actually covers every pinned package, not just some of them, and that
    # ci.yml actually enforces it rather than leaving the hashes unused.
    text = LOCKFILE.read_text()
    lines = text.splitlines()
    package_line_indices = [i for i, line in enumerate(lines) if _PACKAGE_LINE.match(line)]
    assert len(package_line_indices) >= 5, "expected the runtime and dev dependencies to be pinned"
    for i in package_line_indices:
        assert lines[i + 1].strip().startswith("--hash=sha256:"), (
            f"{lines[i]} has no --hash entry immediately following it"
        )

    ci_text = CI_WORKFLOW.read_text()
    assert "--require-hashes" in ci_text
    assert "requirements-lock.txt" in ci_text
