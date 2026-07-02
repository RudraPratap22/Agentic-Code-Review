"""Mock-based tests for a tool->Issue mapper (the real Ruff run is replaced).

We target the Ruff mapper because it goes through the shared `run_json_tool` helper,
which is the clean seam to mock. (Bandit/Semgrep call subprocess directly — older code.)
"""

from agents.quality_agent import _run_ruff_quality


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
