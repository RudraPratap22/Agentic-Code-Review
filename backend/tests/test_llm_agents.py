"""Mock-based tests for the LLM agents (no real API calls)."""

from agents.quality_agent import _run_llm_checks, LLMQualityResponse, LLMIssue


def test_llm_evidence_guard_and_dedupe(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-dummy")     # so ChatGroq constructs (no network)
    fake = LLMQualityResponse(issues=[
        LLMIssue(category="naming", severity="low", description="bad", suggestion="x", evidence=""),    # dropped: no evidence
        LLMIssue(category="naming", severity="low", description="d", suggestion="x", evidence="y=1"),   # kept
        LLMIssue(category="naming", severity="low", description="d", suggestion="x", evidence="y=1"),   # dropped: duplicate
    ])
    monkeypatch.setattr("agents.quality_agent.llm_invoke", lambda *a, **k: fake)

    issues = _run_llm_checks("y = 1")
    assert len(issues) == 1                              # evidence-guard + dedupe both worked
    assert issues[0].tier == "suggested" and issues[0].source == "llm"


def test_llm_degrades_on_failure(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-dummy")
    monkeypatch.setattr("agents.quality_agent.llm_invoke", lambda *a, **k: None)  # simulate total failure
    assert _run_llm_checks("y = 1") == []                # degraded, no crash


def test_naming_srp_severity_capped_to_low(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-dummy")
    # The LLM over-rates a naming nit as 'high' — we must force it down to 'low'.
    fake = LLMQualityResponse(issues=[
        LLMIssue(category="naming", severity="high", description="d", suggestion="x", evidence="job=1"),
    ])
    monkeypatch.setattr("agents.quality_agent.llm_invoke", lambda *a, **k: fake)
    issues = _run_llm_checks("job = 1")
    assert len(issues) == 1
    assert issues[0].severity.value == "low"             # inflated 'high' capped to 'low'
