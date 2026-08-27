"""Decides which GitHub webhook deliveries modelmoat's App should act on.

Only pull_request events matter, and only the actions that mean "there is
new or changed code to scan": a PR just opened, reopened, or given new
commits. Every other event and action is acknowledged, so GitHub does not
treat it as a failed delivery and retry it, but otherwise ignored.
"""

from __future__ import annotations

from dataclasses import dataclass

_RELEVANT_ACTIONS = {"opened", "synchronize", "reopened"}


@dataclass(frozen=True)
class PullRequestTarget:
    """Everything needed to fetch the tree and post comments for one PR."""

    installation_id: int
    repo_full_name: str
    pr_number: int
    head_sha: str
    base_sha: str


def relevant_pull_request(event_name: str | None, payload: dict) -> PullRequestTarget | None:
    """Return the PR to scan, or None if this delivery should be ignored.

    A malformed or unexpectedly-shaped payload is treated the same as "not
    relevant" rather than raised as an error - a delivery modelmoat cannot
    understand is not one it should act on, and GitHub still gets a normal
    acknowledgement instead of a 500.
    """
    if event_name != "pull_request":
        return None
    if payload.get("action") not in _RELEVANT_ACTIONS:
        return None

    try:
        pull_request = payload["pull_request"]
        return PullRequestTarget(
            installation_id=payload["installation"]["id"],
            repo_full_name=payload["repository"]["full_name"],
            pr_number=pull_request["number"],
            head_sha=pull_request["head"]["sha"],
            base_sha=pull_request["base"]["sha"],
        )
    except (KeyError, TypeError):
        return None
