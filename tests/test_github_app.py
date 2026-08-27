"""github_app tests.

The whole point of this component is that it must never weaken modelmoat's
own scanning guarantees just because it is diff-aware about comment
placement. These tests exist to prove that in isolation, with synthetic
diffs and findings, before any of it depends on a live webhook or hosting.
"""

from __future__ import annotations

from github_app.comments import InlineComment, classify_findings, summary_body
from github_app.diff import added_lines, added_lines_by_file
from modelmoat.scanner import Finding

# Old file (3 lines):
#   resource "aws_s3_bucket" "datasets" {
#     bucket = "datasets"
#   }
# New file (5 lines): two lines inserted after the bucket line.
#   resource "aws_s3_bucket" "datasets" {
#     bucket = "datasets"
#     acl    = "public-read"
#   (blank)
#   }
S3_PATCH = (
    "@@ -1,3 +1,5 @@\n"
    ' resource "aws_s3_bucket" "datasets" {\n'
    '   bucket = "datasets"\n'
    '+  acl    = "public-read"\n'
    "+\n"
    " }\n"
)


def _finding(**overrides) -> Finding:
    base = {
        "check_id": "S3-001",
        "check_name": "AI Data Bucket Public Exposure",
        "severity": "CRITICAL",
        "resource_type": "aws_s3_bucket",
        "resource_name": "datasets",
        "file_path": "s3.tf",
        "line": 3,
        "message": "m",
        "remediation": "r",
    }
    base.update(overrides)
    return Finding(**base)


# --------------------------------------------------------------------- #
# diff.added_lines                                                      #
# --------------------------------------------------------------------- #
def test_added_lines_matches_a_hand_traced_diff():
    # Line 3 (acl) and line 4 (blank) are new. Line 1, 2, and 5 are
    # unchanged context that merely shifted position, not additions.
    assert added_lines(S3_PATCH) == {3, 4}


def test_added_lines_ignores_removed_lines():
    patch = "@@ -1,2 +1,1 @@\n resource \"x\" {\n-  old = true\n"
    # The removed line never existed in the new file, so it cannot
    # consume or appear as a new-file line number.
    assert added_lines(patch) == set()


def test_added_lines_handles_multiple_hunks_independently():
    patch = (
        "@@ -1,1 +1,2 @@\n"
        " a\n"
        "+b\n"
        "@@ -10,1 +11,2 @@\n"
        " c\n"
        "+d\n"
    )
    assert added_lines(patch) == {2, 12}


def test_added_lines_by_file_skips_entries_with_no_patch():
    files = [
        {"filename": "s3.tf", "patch": S3_PATCH},
        {"filename": "renamed.tf"},  # rename with no content change: no patch key
        {"filename": "image.png", "patch": None},
    ]
    result = added_lines_by_file(files)
    assert result == {"s3.tf": {3, 4}}


# --------------------------------------------------------------------- #
# comments.classify_findings                                            #
# --------------------------------------------------------------------- #
def test_finding_on_an_added_line_becomes_an_inline_comment():
    added = {"s3.tf": {3, 4}}
    inline, summary = classify_findings([_finding(line=3)], added)
    assert summary == []
    assert inline == [InlineComment("s3.tf", 3, inline[0].body)]
    assert "CRITICAL" in inline[0].body
    assert "S3-001" in inline[0].body


def test_finding_on_an_unchanged_line_goes_to_summary_not_dropped():
    # Line 2 (the bucket line) is real context in the diff, but the PR did
    # not add it, so it must not read as "this PR caused it."
    added = {"s3.tf": {3, 4}}
    inline, summary = classify_findings([_finding(line=2)], added)
    assert inline == []
    assert summary == [_finding(line=2)]


def test_finding_in_a_file_the_pr_never_touched_goes_to_summary():
    added = {"other.tf": {1}}
    inline, summary = classify_findings([_finding(file_path="s3.tf", line=3)], added)
    assert inline == []
    assert len(summary) == 1


# --------------------------------------------------------------------- #
# comments.summary_body                                                 #
# --------------------------------------------------------------------- #
def test_summary_body_is_empty_string_when_nothing_to_summarize():
    # Empty, not a comment that just says "nothing to report" - a caller
    # should treat this as "do not post a summary comment at all."
    assert summary_body([]) == ""


def test_summary_body_orders_worst_finding_first():
    low = _finding(severity="LOW", check_id="S3-001", line=99)
    critical = _finding(severity="CRITICAL", check_id="IAM-001", line=1)
    body = summary_body([low, critical])
    assert body.index("IAM-001") < body.index("S3-001")


def test_summary_body_never_uses_an_em_dash():
    # House style, enforced everywhere else in this project.
    body = summary_body([_finding()])
    assert "—" not in body
