"""
Code Quality Agent — hybrid approach:
- AST for mechanical checks (docstrings, function length, arg count)
- LLM for semantic checks (naming quality, SRP violations)
"""

import ast
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field
from models.state import ReviewState, AgentOutput, Issue, Severity
from agents.external_tools import (tool_bin, run_json_tool, dedupe, llm_invoke,
                                    drop_duplicate_suggestions, ruff_suggestion)

load_dotenv()

MAX_FUNCTION_LINES = 50
MAX_FUNCTION_ARGS = 5


# ── AST checks ────────────────────────────────────────────────────────────────

class QualityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues: list[Issue] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Missing docstring
        if not (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)):
            self.issues.append(Issue(
                agent="quality",
                severity=Severity.LOW,
                category="missing-docstring",
                description=f"Function '{node.name}' has no docstring",
                line_number=node.lineno,
                suggestion=f"Add a docstring explaining what '{node.name}' does.",
            ))

        # Function too long
        length = node.end_lineno - node.lineno
        if length > MAX_FUNCTION_LINES:
            self.issues.append(Issue(
                agent="quality",
                severity=Severity.MEDIUM,
                category="function-too-long",
                description=f"Function '{node.name}' is {length} lines (limit: {MAX_FUNCTION_LINES})",
                line_number=node.lineno,
                suggestion="Break this into smaller, focused functions.",
            ))

        # Too many arguments
        arg_count = len(node.args.args)
        if arg_count > MAX_FUNCTION_ARGS:
            self.issues.append(Issue(
                agent="quality",
                severity=Severity.MEDIUM,
                category="too-many-arguments",
                description=f"Function '{node.name}' has {arg_count} arguments (limit: {MAX_FUNCTION_ARGS})",
                line_number=node.lineno,
                suggestion="Group related arguments into a dataclass or config object.",
            ))

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # same checks for async def


# ── LLM checks ────────────────────────────────────────────────────────────────

class LLMIssue(BaseModel):
    category: str
    severity: str = Field(description="one of: critical, high, medium, low")
    description: str
    line_number: int | None = None
    suggestion: str
    evidence: str = Field(
        description="The EXACT line of code this issue refers to, copied verbatim. "
                    "Required — if you cannot quote a specific line, do not report the issue."
    )


class LLMQualityResponse(BaseModel):
    issues: list[LLMIssue] = Field(default_factory=list)


def _run_llm_checks(code: str) -> list[Issue]:
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0,
    )
    structured_llm = llm.with_structured_output(LLMQualityResponse)

    prompt = f"""You are a code quality reviewer. Analyze the following Python code ONLY for:
1. Poor variable/function naming (e.g. single-letter names, non-descriptive names like 'data', 'result', 'tmp')
2. Single Responsibility Principle violations (a function doing more than one thing)

Do NOT flag missing docstrings or function length — those are handled separately.
Do NOT flag security, performance, or any other category — only naming and SRP.
Do NOT flag names that follow a normal Python convention — these are correct, never flag them:
  loop/temp vars (a, b, i, j, x, n, _, e, tmp, ctx),
  a generic callable (fn, cb, func), a response/result (r, res, resp, ret), data/dict (d),
  UPPERCASE constants (JOBS, MAX_WORKERS — the caps ARE the meaning),
  _underscore-prefixed private names (_pool, _run — privacy is the signal, not the length),
  and ANY name inside a test file (test_*.py or a tests/ directory).
Only flag genuinely unclear names in meaningful production scopes (public function
params, module-level names, class attributes) where a reader truly can't tell the intent.
Prefer returning an empty list over a nitpick — most code names are fine.
For EVERY issue you MUST quote the exact offending line verbatim in the `evidence` field.
If you cannot point to a specific line of code, DO NOT report the issue.
Return only real issues, not nitpicks. If the code is clean, return an empty list.

CODE:
```python
{code}
```"""

    response = llm_invoke(structured_llm, prompt)
    if response is None:
        return []                      # LLM unavailable → degrade (no suggested findings)

    issues = []
    for item in response.issues:
        # Enforce grounding in CODE, not by trusting the prompt: an LLM finding with no
        # cited evidence is dropped. This kills "no issue found"-style hallucinations.
        if not (item.evidence and item.evidence.strip()):
            continue
        # This agent only surfaces naming + SRP — both are style preferences, never real
        # defects. Force them to LOW (ignoring the LLM's self-rating, which tends to
        # inflate these to medium/high) so a rename never looks as urgent as a real bug.
        sev = Severity.LOW
        issues.append(Issue(
            agent="quality",
            severity=sev,
            category=item.category,
            description=item.description,
            line_number=item.line_number,
            suggestion=item.suggestion,
            tier="suggested",   # LLM judgment — lower trust than deterministic checks
            source="llm",
            evidence=item.evidence,
        ))
    return drop_duplicate_suggestions(issues)


# ── Ruff checks (verified tier) ────────────────────────────────────────────────

# Quality-relevant rule families (we exclude S=security, owned by the security agent,
# and ANN=type-annotations which is too noisy for now).
_RUFF_QUALITY_SELECT = "ARG,PLR,B,SIM,RET,PIE,C90"

# FastAPI (and similar) use `= Depends(...)` / `= File(...)` etc. as argument defaults —
# that's idiomatic, so whitelist those calls for Ruff's B008 (function-call-in-default).
# B008 still fires on genuinely-bad defaults like `def f(x=list())`.
_IMMUTABLE_CALLS = [
    "fastapi.File", "fastapi.Form", "fastapi.Body", "fastapi.Depends",
    "fastapi.Query", "fastapi.Path", "fastapi.Header", "fastapi.Cookie", "fastapi.Security",
]
_RUFF_CONFIG = ("lint.flake8-bugbear.extend-immutable-calls=["
                + ", ".join(f'"{c}"' for c in _IMMUTABLE_CALLS) + "]")


def _ruff_quality_severity(code_id: str) -> Severity:
    """Ruff has no severities; assign one by rule family."""
    if code_id.startswith(("PLR0913", "C901", "B")):
        return Severity.MEDIUM
    return Severity.LOW


# Map Ruff rule ids onto the canonical category our AST checks already use, so an
# overlap (e.g. Ruff PLR0913 vs our 'too-many-arguments') becomes corroboration.
_RUFF_QUALITY_CANONICAL = {
    "PLR0913": "too-many-arguments",
}


def _quality_canonical(issue: Issue):
    """Key for dedupe: same underlying issue → same key across AST and Ruff."""
    if issue.source == "ruff":
        return (issue.line_number, _RUFF_QUALITY_CANONICAL.get(issue.rule_id, f"ruff:{issue.rule_id}"))
    return (issue.line_number, issue.category)


def _run_ruff_quality(code: str, precomputed: list | None = None) -> list[Issue]:
    # precomputed (this file's slice from the repo-level batched Ruff run) is used when
    # given; otherwise fall back to spawning Ruff on this one string (tests / lone code).
    if precomputed is not None:
        data = precomputed
    else:
        data = run_json_tool(
            [tool_bin("ruff"), "check", "--select", _RUFF_QUALITY_SELECT,
             "--config", _RUFF_CONFIG, "--output-format", "json", "--no-cache"],
            code,
        )
    if not data:
        return []
    issues = []
    for r in data:
        code_id = r.get("code") or "RUFF"
        issues.append(Issue(
            agent="quality",
            severity=_ruff_quality_severity(code_id),
            category=code_id,
            description=(r.get("message") or "").strip(),
            line_number=r.get("location", {}).get("row"),
            suggestion=ruff_suggestion(r),
            tier="verified",
            source="ruff",
            rule_id=code_id,
        ))
    return issues


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_quality_agent(state: ReviewState) -> dict:
    try:
        tree = ast.parse(state.code)
    except SyntaxError as e:
        return {"quality_output": AgentOutput(
            agent_name="quality",
            summary=f"Could not parse code: {e}",
        )}

    visitor = QualityVisitor()
    visitor.visit(tree)
    ast_issues = visitor.issues

    # Verified tier: AST + Ruff, deduped so overlaps become corroboration.
    ruff_issues = _run_ruff_quality(state.code, (state.tool_findings or {}).get("ruff"))
    verified = dedupe(ast_issues + ruff_issues, _quality_canonical)

    # Suggested tier: LLM (kept separate from the verified dedupe).
    llm_issues = _run_llm_checks(state.code)

    all_issues = verified + llm_issues
    corroborated = sum(1 for i in verified if i.corroborated_by)
    summary = (
        f"Found {len(all_issues)} quality issue(s) "
        f"({len(verified)} verified [AST+Ruff], {len(llm_issues)} suggested [LLM], {corroborated} corroborated)."
        if all_issues else "No quality issues detected."
    )

    return {"quality_output": AgentOutput(
        agent_name="quality",
        issues=all_issues,
        summary=summary,
    )}
