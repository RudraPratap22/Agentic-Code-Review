"""Tests for the supervisor's structured report parts (no LLM)."""

from agents.supervisor_agent import build_report, _normalize_numbered_list
from models.state import Issue, Severity


def _issue():
    return Issue(agent="security", severity=Severity.HIGH, category="command-injection",
                 description="d", suggestion="s", filename="a.py", line_number=1)


def test_normalize_numbered_list_splits_inline_items():
    # The LLM often returns all items on one line; each must get its own line.
    text = "1. Do x. 2. Do y. 3. Do z."
    assert _normalize_numbered_list(text) == "1. Do x.\n2. Do y.\n3. Do z."


def test_normalize_ignores_numbers_that_are_not_list_markers():
    # "line 3." must NOT start a new item — only numbers continuing the sequence do.
    text = "1. Fix the os.system call on line 3. 2. Add a tests/ suite. 3. Add CI."
    assert _normalize_numbered_list(text) == (
        "1. Fix the os.system call on line 3.\n2. Add a tests/ suite.\n3. Add CI.")


def test_normalize_leaves_already_formatted_text_alone():
    text = "1. Do x.\n2. Do y."
    assert _normalize_numbered_list(text) == text


def test_normalize_leaves_prose_without_a_list_alone():
    text = "Refactor the parser; it is far too long."
    assert _normalize_numbered_list(text) == text


def test_clean_code_needs_no_llm_and_has_summary():
    parts = build_report([], "empty-repo")
    assert "No issues detected" in parts.markdown
    assert parts.executive_summary == "No issues detected by any agent."
    assert parts.top_priority_fixes is None


def test_narrative_failure_degrades_to_none_but_keeps_findings(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no LLM")
    monkeypatch.setattr("agents.supervisor_agent._write_narrative", boom)

    parts = build_report([_issue()], "repo")
    assert parts.executive_summary is None          # UI hides the section
    assert parts.top_priority_fixes is None
    assert "command-injection" in parts.markdown    # deterministic findings still render
    assert "Executive summary unavailable" in parts.markdown


def test_narrative_fields_populated(monkeypatch):
    class _N:
        executive_summary = "Looks risky."
        top_priority_fixes = "1. Fix a. 2. Fix b."
    monkeypatch.setattr("agents.supervisor_agent._write_narrative", lambda *a, **k: _N())

    parts = build_report([_issue()], "repo")
    assert parts.executive_summary == "Looks risky."
    assert parts.top_priority_fixes == "1. Fix a.\n2. Fix b."   # normalized
