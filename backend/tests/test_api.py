"""Tests for the FastAPI endpoints, using TestClient (no real server, no real reviews)."""

from fastapi.testclient import TestClient
from models.state import Issue, Severity
from api import app

client = TestClient(app)


def _fake_issue():
    return Issue(agent="security", severity=Severity.CRITICAL, category="sql-injection",
                 description="d", suggestion="s", tier="verified", source="custom-ast",
                 filename="a.py", line_number=1)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_review_repo_returns_structured(monkeypatch):
    monkeypatch.setattr("api.collect_github_findings", lambda t: ("repo (1 files)", [_fake_issue()]))
    monkeypatch.setattr("api.render_report", lambda issues, title: "# md")   # avoid real LLM
    r = client.post("/review", json={"target": "https://github.com/o/r"})
    assert r.status_code == 200
    d = r.json()
    assert d["title"] == "repo (1 files)"
    assert d["summary"]["total"] == 1 and d["summary"]["verified"] == 1
    assert d["findings"][0]["category"] == "sql-injection"
    assert d["findings"][0]["corroborated_by"] == []
    assert d["report_markdown"] == "# md"


def test_review_pr_returns_structured(monkeypatch):
    monkeypatch.setattr("api._collect_pr_findings", lambda t: ("o", "r", 1, [_fake_issue()]))
    monkeypatch.setattr("api.render_report", lambda issues, title: "# pr md")
    r = client.post("/review", json={"target": "https://github.com/o/r/pull/1"})
    d = r.json()
    assert d["title"] == "PR #1 — o/r"
    assert d["summary"]["total"] == 1


def test_review_error_returns_400(monkeypatch):
    def boom(t):
        raise RuntimeError("bad url")
    monkeypatch.setattr("api.collect_github_findings", boom)
    r = client.post("/review", json={"target": "https://github.com/o/r"})
    assert r.status_code == 400


def test_review_rejects_missing_target():
    r = client.post("/review", json={})     # no 'target' → FastAPI validation error
    assert r.status_code == 422
