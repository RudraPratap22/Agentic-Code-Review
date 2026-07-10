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
import re
from dataclasses import dataclass
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
    loc = f"{issue.filename}:{line}" if issue.filename else line
    rule = f" `{issue.rule_id}`" if issue.rule_id else ""
    corro = f" ✓ corroborated by {', '.join(issue.corroborated_by)}" if issue.corroborated_by else ""
    parts = [
        f"- **[{issue.severity.value.upper()}]** {loc} ({issue.agent}{rule}) — "
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
        loc = f"{i.filename}:{line}" if i.filename else line
        lines.append(f"[{i.tier.upper()}][{i.severity.value.upper()}] {i.agent} {loc}: "
                     f"{i.category} — {i.description}")
    return "\n".join(lines)


# ── LLM writes ONLY the narrative (structured so code controls placement) ──

class SupervisorNarrative(BaseModel):
    executive_summary: str = Field(description="One paragraph on overall code health.")
    top_priority_fixes: str = Field(description="Markdown list of the 3 most important fixes.")


def _write_narrative(filename: str, digest: str, count_str: str) -> SupervisorNarrative:
    """Ask the LLM for the summary + priorities ONLY, strictly from the given findings."""
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"), temperature=0)
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


@dataclass(frozen=True)
class ReportParts:
    """The rendered report plus its narrative as structured fields.

    The API surfaces `executive_summary` / `top_priority_fixes` separately so the frontend
    can render them as first-class UI instead of parsing them back out of the markdown.
    Both are None when the LLM tier was unavailable — callers just hide the section.
    """
    markdown: str
    executive_summary: str | None
    top_priority_fixes: str | None


_LIST_MARKER_RE = re.compile(r"(?:^|(?<=\s))(\d+)\.\s")


def _normalize_numbered_list(text: str) -> str:
    """Put each `N.` item on its own line.

    The LLM tends to return "1. do x 2. do y 3. do z" on a single line, which renders as one
    run-on paragraph in both markdown and the UI.

    We only split on a number that CONTINUES the sequence (1, then 2, then 3...). Splitting
    on every `\\d+\\.` would break "...the os.system call on line 3." into a bogus item.
    """
    text = text.strip()
    if "\n" in text:
        return text                       # the LLM already formatted it

    starts, expected = [], 1
    for match in _LIST_MARKER_RE.finditer(text):
        if int(match.group(1)) == expected:
            starts.append(match.start())
            expected += 1
    if len(starts) < 2:
        return text                       # not actually a numbered list

    items = [text[begin:end].strip()
             for begin, end in zip(starts, starts[1:] + [len(text)])]
    preamble = text[:starts[0]].strip()
    return "\n".join(([preamble] if preamble else []) + items)


def build_report(all_issues: list[Issue], title: str) -> ReportParts:
    """
    Build the final report from a flat list of issues (from one file OR a whole repo).
    Facts are rendered by code; only the summary/priorities come from the LLM, and they are
    returned separately so no consumer has to scrape them out of the markdown.
    """
    verified = [i for i in all_issues if i.tier == "verified"]
    suggested = [i for i in all_issues if i.tier == "suggested"]

    # Clean code → simple deterministic report, no LLM call needed.
    if not all_issues:
        return ReportParts(
            markdown=f"# Code Review Report — {title}\n\nNo issues detected by any agent. ✅",
            executive_summary="No issues detected by any agent.",
            top_priority_fixes=None,
        )

    # Severity counts for context.
    counts: dict[str, int] = {}
    for i in all_issues:
        counts[i.severity.value] = counts.get(i.severity.value, 0) + 1
    count_str = (f"{len(all_issues)} total ({len(verified)} verified, {len(suggested)} suggested) — "
                 + ", ".join(f"{v} {k}" for k, v in counts.items()))

    # LLM narrative — degrade gracefully if it fails (the findings still render in full).
    try:
        narrative = _write_narrative(title, _digest(all_issues), count_str)
        exec_summary = narrative.executive_summary
        top_fixes = _normalize_numbered_list(narrative.top_priority_fixes)
    except Exception:
        exec_summary = None
        top_fixes = None

    exec_md = exec_summary or "_(Executive summary unavailable — the LLM tier was skipped.)_"
    top_md = f"## Top Priority Fixes\n\n{top_fixes}" if top_fixes else ""

    markdown = f"""# Code Review Report — {title}

{exec_md}

**Findings:** {count_str}

## ✅ Verified findings — deterministic tools/AST ({len(verified)})

{_render_tier(verified)}

## 🤖 Suggested findings — LLM, lower confidence, evidence-cited ({len(suggested)})

{_render_tier(suggested)}

{top_md}"""
    return ReportParts(markdown=markdown, executive_summary=exec_summary,
                       top_priority_fixes=top_fixes)


def render_report(all_issues: list[Issue], title: str) -> str:
    """Markdown-only view of build_report (CLI + PR-comment paths)."""
    return build_report(all_issues, title).markdown


def run_supervisor_agent(state: ReviewState) -> dict:
    """Thin wrapper kept for single-file/graph use: collect from state, then render."""
    return {"final_report": render_report(_collect_issues(state), state.filename)}
