"""
Supervisor Agent — reads all 4 agent outputs, uses LLM to:
1. Deduplicate overlapping issues across agents
2. Prioritize by severity (critical → high → medium → low)
3. Generate a final structured report with actionable summary
"""

import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from models.state import ReviewState, AgentOutput, Severity

load_dotenv()

# Severity ordering for sorting
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _format_agent_output(output: AgentOutput | None) -> str:
    """Format a single agent's output into a readable string for the LLM."""
    if output is None:
        return "  (agent did not run)\n"
    if not output.issues:
        return f"  Summary: {output.summary}\n  No issues found.\n"

    lines = [f"  Summary: {output.summary}"]
    for issue in output.issues:
        lines.append(
            f"  - [{issue.severity.value.upper()}] Line {issue.line_number}: "
            f"{issue.category} — {issue.description} | Fix: {issue.suggestion}"
        )
    return "\n".join(lines) + "\n"


def run_supervisor_agent(state: ReviewState) -> dict:
    """
    LangGraph node. Runs AFTER all 4 agents finish.
    Collects their outputs, sorts issues, and asks the LLM for a final report.
    """
    # ── Collect all issues from all agents ──
    all_issues = []
    for output in [
        state.security_output,
        state.quality_output,
        state.performance_output,
        state.documentation_output,
    ]:
        if output and output.issues:
            all_issues.extend(output.issues)

    # ── Sort by severity ──
    all_issues.sort(key=lambda i: _SEVERITY_ORDER.get(i.severity, 99))

    # ── Build context for LLM ──
    agent_context = f"""## Security Agent
{_format_agent_output(state.security_output)}
## Code Quality Agent
{_format_agent_output(state.quality_output)}
## Performance Agent
{_format_agent_output(state.performance_output)}
## Documentation Agent
{_format_agent_output(state.documentation_output)}"""

    # ── Count by severity ──
    counts = {}
    for issue in all_issues:
        counts[issue.severity.value] = counts.get(issue.severity.value, 0) + 1
    count_str = ", ".join(f"{v} {k}" for k, v in counts.items())

    # ── Ask LLM for final synthesis ──
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
    )

    prompt = f"""You are a senior code review supervisor. Four specialized agents have reviewed the code below.
Your job is to write a FINAL CODE REVIEW REPORT.

FILE: {state.filename}

AGENT FINDINGS:
{agent_context}

INSTRUCTIONS:
1. Start with a one-paragraph executive summary of overall code health.
2. List ALL issues grouped by severity (CRITICAL first, then HIGH, MEDIUM, LOW).
3. For each issue, include: severity, line number, what's wrong, and how to fix it.
4. If two agents flagged the same issue, mention it only once but note both agents found it.
5. End with a "Top 3 Priority Fixes" section — the 3 most important things to fix first.
6. Keep the tone professional but direct. No fluff.

Total issues found: {len(all_issues)} ({count_str})

Write the report in markdown format."""

    response = llm.invoke(prompt)

    return {"final_report": response.content}
