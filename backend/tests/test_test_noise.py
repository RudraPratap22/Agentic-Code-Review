"""Tests for test-file noise suppression (is_test_file / drop_test_noise)."""

from agents.external_tools import is_test_file, drop_test_noise, clean_findings
from models.state import Issue, Severity


def _issue(filename, category="c", rule_id=None, tier="verified", severity=Severity.LOW, agent="quality"):
    return Issue(agent=agent, severity=severity, category=category,
                 description="d", suggestion="s", filename=filename, rule_id=rule_id, tier=tier)


def test_is_test_file():
    assert is_test_file("backend/tests/test_api.py")
    assert is_test_file("test_jobs.py")
    assert is_test_file("pkg/foo_test.py")
    assert not is_test_file("backend/jobs.py")
    assert not is_test_file("api.py")
    assert not is_test_file(None)


def test_drops_noise_rules_only_on_test_files():
    issues = [
        _issue("tests/test_x.py", rule_id="B101"),                     # noise on test → drop
        _issue("tests/test_x.py", category="missing-docstring"),       # noise on test → drop
        _issue("tests/test_x.py", rule_id="PLR2004"),                  # noise on test → drop
        _issue("jobs.py", rule_id="B101"),                             # production → keep
        _issue("tests/test_x.py", category="command-injection"),       # real bug on test → keep
    ]
    kept = drop_test_noise(issues)
    assert len(kept) == 2
    kept_desc = {(i.filename, i.rule_id or i.category) for i in kept}
    assert kept_desc == {("jobs.py", "B101"), ("tests/test_x.py", "command-injection")}


def test_no_op_when_no_test_files():
    issues = [_issue("api.py", rule_id="B101"), _issue("jobs.py", category="missing-docstring")]
    assert drop_test_noise(issues) == issues     # production findings untouched


def test_clean_findings_drops_suggested_on_test_files():
    issues = [
        _issue("tests/test_x.py", tier="suggested", agent="performance"),   # LLM on test → drop
        _issue("tests/test_x.py", tier="suggested", agent="quality"),        # LLM on test → drop
        _issue("tests/test_x.py", tier="verified", category="command-injection"),  # real → keep
        _issue("api.py", tier="suggested", agent="quality"),                 # LLM on prod → keep
    ]
    kept = clean_findings(issues)
    assert len(kept) == 2
    assert {(i.filename, i.tier) for i in kept} == {
        ("tests/test_x.py", "verified"), ("api.py", "suggested")}


def test_clean_findings_caps_suggested_severity_at_medium():
    issues = [
        _issue("api.py", tier="suggested", severity=Severity.HIGH, agent="performance"),
        _issue("api.py", tier="verified", severity=Severity.CRITICAL, agent="security"),  # not capped
    ]
    kept = clean_findings(issues)
    by_tier = {i.tier: i.severity for i in kept}
    assert by_tier["suggested"] == Severity.MEDIUM     # HIGH suggested → capped to MEDIUM
    assert by_tier["verified"] == Severity.CRITICAL    # verified severity untouched
