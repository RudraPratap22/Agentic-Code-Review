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


# ── Pagination: PRs with >100 changed files must not be silently truncated ──

class _FakeResp:
    def __init__(self, payload, next_url=None):
        self._payload = payload
        self.links = {"next": {"url": next_url}} if next_url else {}

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_paginated_follows_link_next(monkeypatch):
    from github_pr import _paginated
    pages = {
        "page1": _FakeResp([{"filename": "a.py"}], next_url="page2"),
        "page2": _FakeResp([{"filename": "b.py"}], next_url="page3"),
        "page3": _FakeResp([{"filename": "c.py"}]),          # no next → stop
    }
    monkeypatch.setattr("github_pr.requests.get", lambda url, **kw: pages[url])
    assert [f["filename"] for f in _paginated("page1")] == ["a.py", "b.py", "c.py"]


def test_paginated_single_page(monkeypatch):
    from github_pr import _paginated
    monkeypatch.setattr("github_pr.requests.get",
                        lambda url, **kw: _FakeResp([{"filename": "only.py"}]))
    assert [f["filename"] for f in _paginated("u")] == ["only.py"]
