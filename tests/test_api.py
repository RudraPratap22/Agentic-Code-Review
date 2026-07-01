"""Tests for the FastAPI endpoints, using TestClient (no real server, no real reviews)."""

from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_review_repo(monkeypatch):
    monkeypatch.setattr("api.review_github", lambda target: "# fake report")
    r = client.post("/review", json={"target": "https://github.com/o/r"})
    assert r.status_code == 200
    assert r.json()["report"] == "# fake report"


def test_review_pr(monkeypatch):
    monkeypatch.setattr("api.review_pr", lambda target: "# pr report")
    r = client.post("/review", json={"target": "https://github.com/o/r/pull/1"})
    assert r.json()["report"] == "# pr report"


def test_review_error_returns_400(monkeypatch):
    def boom(target):
        raise RuntimeError("bad url")
    monkeypatch.setattr("api.review_github", boom)
    r = client.post("/review", json={"target": "https://github.com/o/r"})
    assert r.status_code == 400


def test_review_rejects_missing_target():
    r = client.post("/review", json={})     # no 'target' → FastAPI validation error
    assert r.status_code == 422
