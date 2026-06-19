"""
Documentation Agent — hybrid approach:
- AST for mechanical checks (missing docstrings on modules/classes/functions)
- LLM for semantic checks (outdated/misleading comments, unclear naming in docs)
"""

import ast
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field
from models.state import ReviewState, AgentOutput, Issue, Severity

load_dotenv()


class DocVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues: list[Issue] = []
        self.has_module_docstring = False
        self.total_functions = 0
        self.documented_functions = 0

    def _has_docstring(self, node) -> bool:
        return (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        )

    def visit_Module(self, node):
        if not self._has_docstring(node):
            self.issues.append(Issue(
                agent="documentation",
                severity=Severity.LOW,
                category="missing-module-docstring",
                description="Module has no docstring",
                line_number=1,
                suggestion="Add a module-level docstring explaining the file's purpose.",
            ))
        else:
            self.has_module_docstring = True
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        if not self._has_docstring(node):
            self.issues.append(Issue(
                agent="documentation",
                severity=Severity.MEDIUM,
                category="missing-class-docstring",
                description=f"Class '{node.name}' has no docstring",
                line_number=node.lineno,
                suggestion=f"Add a docstring explaining what '{node.name}' represents and its responsibilities.",
            ))
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.total_functions += 1
        # Skip private/dunder methods for docstring checks
        if node.name.startswith("_") and not node.name.startswith("__"):
            self.generic_visit(node)
            return

        if self._has_docstring(node):
            self.documented_functions += 1
        else:
            self.issues.append(Issue(
                agent="documentation",
                severity=Severity.LOW,
                category="missing-function-docstring",
                description=f"Function '{node.name}' has no docstring",
                line_number=node.lineno,
                suggestion=f"Add a docstring with a brief description, args, and return value.",
            ))
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


# ── LLM checks ────────────────────────────────────────────────────────────────

class LLMDocIssue(BaseModel):
    category: str
    severity: str = Field(description="one of: critical, high, medium, low")
    description: str
    line_number: int | None = None
    suggestion: str
    evidence: str = Field(
        description="The EXACT comment or line this issue refers to, copied verbatim. "
                    "Required — if you cannot quote a specific line, do not report the issue."
    )


class LLMDocResponse(BaseModel):
    issues: list[LLMDocIssue] = Field(default_factory=list)


def _run_llm_doc_checks(code: str) -> list[Issue]:
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
    )
    structured_llm = llm.with_structured_output(LLMDocResponse)

    prompt = f"""You are a documentation reviewer. Analyze the following Python code ONLY for:
1. Comments that are outdated or misleading (say one thing but the code does another)
2. Comments that just restate the code instead of explaining WHY
3. TODO/FIXME/HACK comments that indicate unfinished work

Do NOT flag missing docstrings — those are handled separately.
Do NOT flag security, performance, naming, or any other category — only the three above.
Only flag comments that ACTUALLY EXIST in the code. The absence of comments is NOT an issue.
For EVERY issue you MUST quote the exact existing comment/line verbatim in the `evidence` field.
If you cannot point to a specific comment that exists, DO NOT report the issue.
Return only real issues. If comments are fine, return an empty list.

CODE:
```python
{code}
```"""

    response: LLMDocResponse = structured_llm.invoke(prompt)

    issues = []
    for item in response.issues:
        try:
            sev = Severity(item.severity.lower())
        except ValueError:
            sev = Severity.LOW
        issues.append(Issue(
            agent="documentation",
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

def run_documentation_agent(state: ReviewState) -> dict:
    try:
        tree = ast.parse(state.code)
    except SyntaxError as e:
        return {"documentation_output": AgentOutput(
            agent_name="documentation",
            summary=f"Could not parse code: {e}",
        )}

    visitor = DocVisitor()
    visitor.visit(tree)
    ast_issues = visitor.issues

    llm_issues = _run_llm_doc_checks(state.code)

    all_issues = ast_issues + llm_issues

    # Include a doc coverage metric in the summary
    if visitor.total_functions > 0:
        coverage = round(visitor.documented_functions / visitor.total_functions * 100)
        coverage_str = f" Documentation coverage: {coverage}%."
    else:
        coverage_str = ""

    summary = (
        f"Found {len(all_issues)} documentation issue(s).{coverage_str}"
        if all_issues else f"No documentation issues detected.{coverage_str}"
    )

    return {"documentation_output": AgentOutput(
        agent_name="documentation",
        issues=all_issues,
        summary=summary,
    )}
