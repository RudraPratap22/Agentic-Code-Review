"""Tests for the FastAPI endpoints, using TestClient (no real server, no real reviews).

/review is async now: POST returns a job_id, and the result/error is polled from
/jobs/{id}. These tests submit, then poll the job until it settles.
"""

import time
from fastapi.testclient import TestClient
from models.state import Issue, Severity
from agents.supervisor_agent import ReportParts
from api import app

client = TestClient(app)


def _fake_issue():
    return Issue(agent="security", severity=Severity.CRITICAL, category="sql-injection",
                 description="d", suggestion="s", tier="verified", source="custom-ast",
                 filename="a.py", line_number=1)


def _poll(job_id, timeout=2.0):
    """Poll /jobs/{id} until the job leaves queued/running, then return its final state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/jobs/{job_id}").json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never settled: {job}")


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_review_returns_job_id():
    r = client.post("/review", json={"target": "https://github.com/o/r"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "queued" and isinstance(d["job_id"], str) and d["job_id"]


def _fake_report(issues, title):
    """Stand-in for build_report so tests never hit the LLM."""
    return ReportParts(markdown="# md", executive_summary="All good.",
                       top_priority_fixes="1. Fix the SQL injection.")


def test_review_repo_completes_with_structured_result(monkeypatch):
    monkeypatch.setattr("api.collect_github_findings", lambda t: ("repo (1 files)", [_fake_issue()]))
    monkeypatch.setattr("api.build_report", _fake_report)          # avoid real LLM
    job_id = client.post("/review", json={"target": "https://github.com/o/r"}).json()["job_id"]
    job = _poll(job_id)
    assert job["status"] == "done"
    d = job["result"]
    assert d["title"] == "repo (1 files)"
    assert d["summary"]["total"] == 1 and d["summary"]["verified"] == 1
    assert d["findings"][0]["category"] == "sql-injection"
    assert d["report_markdown"] == "# md"
    # the narrative is now exposed as structured fields for the frontend
    assert d["executive_summary"] == "All good."
    assert d["top_priority_fixes"] == "1. Fix the SQL injection."


def test_review_pr_completes_with_structured_result(monkeypatch):
    monkeypatch.setattr("api._collect_pr_findings", lambda t: ("o", "r", 1, [_fake_issue()]))
    monkeypatch.setattr("api.build_report", _fake_report)
    job_id = client.post("/review", json={"target": "https://github.com/o/r/pull/1"}).json()["job_id"]
    job = _poll(job_id)
    assert job["status"] == "done"
    assert job["result"]["title"] == "PR #1 — o/r"


def test_review_error_surfaces_in_job(monkeypatch):
    def boom(t):
        raise RuntimeError("bad url")
    monkeypatch.setattr("api.collect_github_findings", boom)
    job_id = client.post("/review", json={"target": "https://github.com/o/r"}).json()["job_id"]
    job = _poll(job_id)
    assert job["status"] == "error"
    assert "bad url" in job["error"]


def test_unknown_job_returns_404():
    assert client.get("/jobs/nope").status_code == 404


def test_review_rejects_missing_target():
    r = client.post("/review", json={})     # no 'target' → FastAPI validation error
    assert r.status_code == 422
