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

load_dotenv()

MAX_FUNCTION_LINES = 20
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
    )
    structured_llm = llm.with_structured_output(LLMQualityResponse)

    prompt = f"""You are a code quality reviewer. Analyze the following Python code ONLY for:
1. Poor variable/function naming (e.g. single-letter names, non-descriptive names like 'data', 'result', 'tmp')
2. Single Responsibility Principle violations (a function doing more than one thing)

Do NOT flag missing docstrings or function length — those are handled separately.
Do NOT flag security, performance, or any other category — only naming and SRP.
For EVERY issue you MUST quote the exact offending line verbatim in the `evidence` field.
If you cannot point to a specific line of code, DO NOT report the issue.
Return only real issues, not nitpicks. If the code is clean, return an empty list.

CODE:
```python
{code}
```"""

    response: LLMQualityResponse = structured_llm.invoke(prompt)

    issues = []
    for item in response.issues:
        try:
            sev = Severity(item.severity.lower())
        except ValueError:
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

    llm_issues = _run_llm_checks(state.code)

    all_issues = ast_issues + llm_issues
    summary = (
        f"Found {len(all_issues)} quality issue(s) ({len(ast_issues)} structural, {len(llm_issues)} semantic)."
        if all_issues else "No quality issues detected."
    )

    return {"quality_output": AgentOutput(
        agent_name="quality",
        issues=all_issues,
        summary=summary,
    )}
