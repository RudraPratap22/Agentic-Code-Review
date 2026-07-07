"""Tests for private-repo clone auth: token injection + redaction (no network)."""

from pipeline import _clone_url, _redact


def test_clone_url_injects_token_for_github_https(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret123")
    out = _clone_url("https://github.com/owner/repo")
    assert out == "https://x-access-token:secret123@github.com/owner/repo"


def test_clone_url_unchanged_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    url = "https://github.com/owner/repo"
    assert _clone_url(url) == url                       # public path untouched


def test_clone_url_ignores_non_github(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret123")
    url = "https://gitlab.com/owner/repo"
    assert _clone_url(url) == url                       # only rewrites github.com https


def test_redact_scrubs_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret123")
    err = "fatal: could not read from https://x-access-token:secret123@github.com/o/r"
    scrubbed = _redact(err)
    assert "secret123" not in scrubbed and "***" in scrubbed


def test_redact_noop_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert _redact("some error") == "some error"
