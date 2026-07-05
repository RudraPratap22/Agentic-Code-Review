"""Mock-based tests for a tool->Issue mapper (the real Ruff run is replaced).

We target the Ruff mapper because it goes through the shared `run_json_tool` helper,
which is the clean seam to mock. (Bandit/Semgrep call subprocess directly — older code.)
"""

from agents.quality_agent import _run_ruff_quality, _RUFF_QUALITY_SELECT
from agents.external_tools import run_ruff_repo


def test_ruff_mapping(monkeypatch):
    fake_json = [{"code": "PLR0913", "message": "too many args", "location": {"row": 5}}]
    # Replace the real subprocess+JSON call with one that returns canned data:
    monkeypatch.setattr("agents.quality_agent.run_json_tool", lambda *a, **k: fake_json)

    issues = _run_ruff_quality("def f(a, b, c, d, e, g): ...")
    assert len(issues) == 1
    assert issues[0].source == "ruff"
    assert issues[0].rule_id == "PLR0913"
    assert issues[0].line_number == 5
    assert issues[0].severity.value == "medium"


def test_ruff_degrades_when_tool_missing(monkeypatch):
    monkeypatch.setattr("agents.quality_agent.run_json_tool", lambda *a, **k: None)
    assert _run_ruff_quality("x = 1") == []     # no tool / bad output → no crash, just []


# ── Real-Ruff integration checks for the FastAPI false-positive fix ──

def test_ruff_allows_fastapi_default_calls():
    code = "from fastapi import File, UploadFile\ndef f(x: UploadFile = File(...)):\n    return x\n"
    assert "B008" not in [i.rule_id for i in _run_ruff_quality(code)]   # idiomatic → not flagged


def test_ruff_still_flags_real_mutable_default():
    assert "B006" in [i.rule_id for i in _run_ruff_quality("def g(y=[]):\n    return y\n")]


# ── Batched repo-level runner + precomputed-slice path ──

def test_ruff_uses_precomputed_without_spawning(monkeypatch):
    # If a slice is injected, the mapper must NOT call the subprocess helper at all.
    def _boom(*a, **k):
        raise AssertionError("run_json_tool should not be called when precomputed is given")
    monkeypatch.setattr("agents.quality_agent.run_json_tool", _boom)
    precomputed = [{"code": "PLR0913", "message": "too many args", "location": {"row": 3}}]
    issues = _run_ruff_quality("irrelevant", precomputed)
    assert [i.rule_id for i in issues] == ["PLR0913"]


def test_ruff_repo_groups_findings_by_file(tmp_path):
    # Real batched Ruff over a 2-file dir: findings come back keyed by relative path.
    (tmp_path / "a.py").write_text("def f(y=[]):\n    return y\n")   # B006 mutable default
    (tmp_path / "b.py").write_text("x = 1\n")                        # clean
    by_file = run_ruff_repo(str(tmp_path), _RUFF_QUALITY_SELECT)
    assert "a.py" in by_file and by_file["a.py"]     # a.py has at least one finding
    assert "b.py" not in by_file                     # clean file → no entry at all
