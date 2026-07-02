"""Tests for the deterministic dedupe + corroboration logic."""

from models.state import Issue, Severity
from agents.external_tools import dedupe


def _issue(line, category, source, severity=Severity.LOW, rule_id=None):
    return Issue(agent="x", severity=severity, category=category, description="d",
                 line_number=line, suggestion="s", source=source, rule_id=rule_id)


def _key(issue):                       # the "same bug" rule for these tests
    return (issue.line_number, issue.category)


def test_duplicate_across_tools_is_corroborated():
    issues = [_issue(5, "sql", "custom-ast"), _issue(5, "sql", "bandit", rule_id="B608")]
    merged = dedupe(issues, _key)
    assert len(merged) == 1                          # collapsed to one
    assert merged[0].corroborated_by == ["bandit"]   # the other tool recorded
    assert merged[0].rule_id == "B608"               # evidence preserved


def test_highest_severity_wins():
    issues = [_issue(5, "sql", "bandit", Severity.MEDIUM),
              _issue(5, "sql", "custom-ast", Severity.CRITICAL)]
    assert dedupe(issues, _key)[0].severity == Severity.CRITICAL


def test_distinct_issues_not_merged():
    issues = [_issue(5, "sql", "custom-ast"), _issue(6, "eval", "custom-ast")]
    assert len(dedupe(issues, _key)) == 2


def test_same_source_not_self_corroborated():
    issues = [_issue(5, "sql", "ruff"), _issue(5, "sql", "ruff")]
    assert dedupe(issues, _key)[0].corroborated_by == []   # ruff doesn't corroborate ruff
