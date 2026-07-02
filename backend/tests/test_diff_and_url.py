"""Tests for the PR diff parser and URL parser (pure functions, no network)."""

import pytest
from github_pr import _added_lines, _parse_pr_url


@pytest.mark.parametrize("patch, expected", [
    ("@@ -1,2 +1,3 @@\n a\n+b\n c", {2}),                       # one added line mid-hunk
    ("@@ -10,3 +10,3 @@\n ctx\n-old\n+new\n ctx2", {11}),       # removed line doesn't advance
    ("@@ -1,1 +1,1 @@\n unchanged", set()),                     # no additions
])
def test_added_lines(patch, expected):
    assert _added_lines(patch) == expected


def test_parse_pr_url_ok():
    assert _parse_pr_url("https://github.com/o/r/pull/42") == ("o", "r", 42)


def test_parse_pr_url_rejects_non_pr():
    with pytest.raises(ValueError):
        _parse_pr_url("https://github.com/o/r")
