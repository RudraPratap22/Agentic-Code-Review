"""
Supervisor Agent — assembles the final report from all agent outputs.

Design (the anti-circularity principle applied to the report itself):
- CODE renders the findings deterministically, split into a VERIFIED section
  (deterministic tools/AST — facts) and a SUGGESTED section (LLM — lower trust,
  evidence-cited). The LLM cannot invent or drop a finding because it does not
  build this list.
- The LLM writes ONLY the prose that genuinely needs judgement: a one-paragraph
  executive summary and the top priority fixes — chosen strictly from the findings
  it is given.

If the LLM call fails, the deterministic findings are still returned in full.
"""

import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field
from models.state import ReviewState, Issue, Severity

load_dotenv()

# Severity ordering for sorting/grouping (most severe first).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _collect_issues(state: ReviewState) -> list[Issue]:
    """Gather every issue from every agent into one flat list."""
    issues: list[Issue] = []
    for output in [
        state.security_output,
        state.quality_output,
        state.performance_output,
        state.documentation_output,
        state.architecture_output,
    ]:
        if output and output.issues:
            issues.extend(output.issues)
    return issues


def _render_issue(issue: Issue) -> str:
    """Render a single issue as one markdown bullet, including its evidence trail."""
    line = f"L{issue.line_number}" if issue.line_number else "L?"
    rule = f" `{issue.rule_id}`" if issue.rule_id else ""
    corro = f" ✓ corroborated by {', '.join(issue.corroborated_by)}" if issue.corroborated_by else ""
    parts = [
        f"- **[{issue.severity.value.upper()}]** {line} ({issue.agent}{rule}) — "
        f"{issue.category}: {issue.description}{corro}"
    ]
    if issue.evidence:
        parts.append(f"  - cites: `{issue.evidence.strip()}`")
    parts.append(f"  - fix: {issue.suggestion}")
    return "\n".join(parts)


def _render_tier(issues: list[Issue]) -> str:
    """Render a list of issues grouped by severity (most severe first)."""
    if not issues:
        return "_None._"
    ordered = sorted(issues, key=lambda i: _SEVERITY_ORDER.get(i.severity, 99))
    return "\n".join(_render_issue(i) for i in ordered)


def _digest(issues: list[Issue]) -> str:
    """A compact one-line-per-issue digest the LLM summarises from (cannot add to)."""
    lines = []
    for i in sorted(issues, key=lambda i: _SEVERITY_ORDER.get(i.severity, 99)):
        line = f"L{i.line_number}" if i.line_number else "L?"
        lines.append(f"[{i.tier.upper()}][{i.severity.value.upper()}] {i.agent} {line}: "
                     f"{i.category} — {i.description}")
    return "\n".join(lines)


# ── LLM writes ONLY the narrative (structured so code controls placement) ──

class SupervisorNarrative(BaseModel):
    executive_summary: str = Field(description="One paragraph on overall code health.")
    top_priority_fixes: str = Field(description="Markdown list of the 3 most important fixes.")


def _write_narrative(filename: str, digest: str, count_str: str) -> SupervisorNarrative:
    """Ask the LLM for the summary + priorities ONLY, strictly from the given findings."""
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"))
    structured = llm.with_structured_output(SupervisorNarrative)
    prompt = f"""You are a senior code-review supervisor writing the narrative for a report on `{filename}`.

You are given a fixed list of findings already detected by other agents. You must NOT
invent new issues, and you must NOT restate the whole list — the report renders it
separately. Work ONLY from these findings:

{digest}

Totals: {count_str}

Produce:
1. executive_summary: ONE paragraph on overall code health, grounded in the findings above.
2. top_priority_fixes: a numbered markdown list (1., 2., 3.) of the 3 most important fixes
   to do first. Write each in your own words as a short actionable sentence with its
   severity and line number — do NOT copy the bracketed `[TIER][SEVERITY]` digest format
   above. Choose only from the findings above; if fewer than 3 exist, list what exists.
"""
    return structured.invoke(prompt)


def run_supervisor_agent(state: ReviewState) -> dict:
    """
    LangGraph node. Runs AFTER all agents finish. Returns {"final_report": markdown}.
    Facts are rendered by code; only the summary/priorities come from the LLM.
    """
    all_issues = _collect_issues(state)
    verified = [i for i in all_issues if i.tier == "verified"]
    suggested = [i for i in all_issues if i.tier == "suggested"]

    # Clean code → simple deterministic report, no LLM call needed.
    if not all_issues:
        return {"final_report": f"# Code Review Report — {state.filename}\n\n"
                                f"No issues detected by any agent. ✅"}

    # Severity counts for context.
    counts: dict[str, int] = {}
    for i in all_issues:
        counts[i.severity.value] = counts.get(i.severity.value, 0) + 1
    count_str = (f"{len(all_issues)} total ({len(verified)} verified, {len(suggested)} suggested) — "
                 + ", ".join(f"{v} {k}" for k, v in counts.items()))

    # LLM narrative — degrade gracefully if it fails.
    try:
        narrative = _write_narrative(state.filename, _digest(all_issues), count_str)
        exec_summary = narrative.executive_summary
        top_fixes = f"## Top Priority Fixes\n\n{narrative.top_priority_fixes}"
    except Exception as e:
        exec_summary = f"_(Executive summary unavailable — LLM error: {e})_"
        top_fixes = ""

    report = f"""# Code Review Report — {state.filename}

{exec_summary}

**Findings:** {count_str}

## ✅ Verified findings — deterministic tools/AST ({len(verified)})

{_render_tier(verified)}

## 🤖 Suggested findings — LLM, lower confidence, evidence-cited ({len(suggested)})

{_render_tier(suggested)}

{top_fixes}"""

    return {"final_report": report}
