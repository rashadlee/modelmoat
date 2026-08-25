# Contributing

Contributions are welcome, especially new checks and false positive reports.

## Setup

    pip install -e ".[dev]"
    pytest

## Rules for checks

1. Every check runs against the whole project graph, not a single file.
   Terraform spreads related resources across files and so do we.
2. Every check needs two fixtures: one that triggers it and one that looks
   similar but must not. The secure fixture returning zero findings is a hard
   CI gate.
3. Severity is calibrated to real exposure. Reachable-from-internet with weak
   or no auth is CRITICAL. Missing encryption or broad IAM is HIGH. Hygiene
   gaps are MEDIUM or LOW. A finding message must never claim more than the
   configuration proves.
4. Values that come from variables or expressions we cannot resolve are
   treated as unknown and are not flagged.

## Adding a check

Create a module in `modelmoat/checks/`, implement a class with `check_id`,
`check_name`, and `run(graph) -> list[Finding]`, register it in
`modelmoat/checks/__init__.py`, and add both fixtures plus assertions in
`tests/`.
