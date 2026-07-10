"""
Performance Agent — hybrid:
- Verified tier (deterministic): our AST anti-pattern checks + Ruff's PERF/ASYNC rules,
  deduped so overlaps become corroboration. Detects:
    * DB/network calls inside loops (N+1 pattern)
    * Blocking calls inside async functions
    * Inefficient list building with += inside loops
- Suggested tier (LLM): a code-grounded "scalability lens" (queue-offload, pagination,
  caching, ...). It MUST cite a line; it never proposes infra/capacity changes.
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


# N+1 detection matches the FULL dotted call path, never a bare method name. Matching bare
# names flagged every `dict.get()`, `headers.get()` and `os.environ.get()` inside a loop as
# a database query — `get`, `all`, `first`, `read` and `write` are far too common.

# DB cursor methods — unambiguous once we require a receiver (`cursor.execute`, not `execute`).
_DB_METHOD_SUFFIXES = (".execute", ".executemany", ".fetchone", ".fetchall", ".fetchmany")

# ORM access paths: Django `Model.objects.get(...)`, SQLAlchemy `session.query(...)`.
_ORM_PATH_MARKERS = (".objects.", "session.query", ".query.filter", ".query.get",
                     ".query.all", ".query.first")

# HTTP clients. A receiver is required, so `resp.links.get(...)` can never match.
_HTTP_CALL_SUFFIXES = ("requests.get", "requests.post", "requests.put", "requests.patch",
                       "requests.delete", "httpx.get", "httpx.post")


def _is_db_call(path: str) -> bool:
    """True for a database/ORM read, judged from the whole call path."""
    return path.endswith(_DB_METHOD_SUFFIXES) or any(m in path for m in _ORM_PATH_MARKERS)


def _is_http_call(path: str) -> bool:
    return path == "urlopen" or path.endswith(_HTTP_CALL_SUFFIXES)

# Blocking calls that should never appear inside async def
_BLOCKING_CALLS = {
    "time.sleep": "Use asyncio.sleep() instead.",
    "requests.get": "Use httpx.AsyncClient or aiohttp instead.",
    "requests.post": "Use httpx.AsyncClient or aiohttp instead.",
    "requests.put": "Use httpx.AsyncClient or aiohttp instead.",
    "requests.delete": "Use httpx.AsyncClient or aiohttp instead.",
    "open": "Use aiofiles.open() instead.",
    "input": "input() blocks the event loop. Redesign the async flow.",
}


class PerformanceVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues: list[Issue] = []
        self._loop_kind: str | None = None       # None | "for" | "while"
        self._in_async = False

    @property
    def _in_loop(self) -> bool:
        return self._loop_kind is not None

    def _add(self, node, severity, category, description, suggestion):
        self.issues.append(Issue(
            agent="performance",
            severity=severity,
            category=category,
            description=description,
            line_number=getattr(node, "lineno", None),
            suggestion=suggestion,
        ))

    # ── Track context: are we inside a loop? inside async? ─────────────

    def visit_For(self, node):
        old = self._loop_kind
        self._loop_kind = "for"
        self.generic_visit(node)
        self._loop_kind = old

    def visit_While(self, node):
        old = self._loop_kind
        self._loop_kind = "while"
        self.generic_visit(node)
        self._loop_kind = old

    def visit_AsyncFunctionDef(self, node):
        old = self._in_async
        self._in_async = True
        self.generic_visit(node)
        self._in_async = old

    # ── Check function calls ──────────────────────────────────────────

    def visit_Call(self, node):
        call_path = self._call_path(node)
        if call_path and self._in_loop:
            if _is_db_call(call_path):
                self._add(
                    node, Severity.HIGH, "n-plus-one",
                    f"Database call '{call_path}()' inside a loop — N+1 query pattern",
                    "Batch the query before the loop, e.g. fetch all records with one WHERE...IN query.",
                )
            # An HTTP call in a `for` loop fetches once per item — a real N+1. In a `while`
            # loop it is almost always pagination or retry, where each request depends on the
            # previous response and cannot be batched, so we do not flag it.
            elif self._loop_kind == "for" and _is_http_call(call_path):
                self._add(
                    node, Severity.MEDIUM, "n-plus-one",
                    f"HTTP call '{call_path}()' inside a for-loop — one request per item",
                    "Fetch in one batched request, or issue the requests concurrently.",
                )

        call_name = self._get_call_name(node)
        if call_name:
            # Blocking call inside async
            if self._in_async and call_name in _BLOCKING_CALLS:
                self._add(
                    node, Severity.HIGH, "blocking-in-async",
                    f"Blocking call '{call_name}()' inside an async function",
                    _BLOCKING_CALLS[call_name],
                )

        self.generic_visit(node)

    # ── List concatenation in loops ───────────────────────────────────

    def visit_AugAssign(self, node):
        """Detect `some_list += [item]` inside a loop."""
        if (
            self._in_loop
            and isinstance(node.op, ast.Add)
            and isinstance(node.value, ast.List)
        ):
            self._add(
                node, Severity.LOW, "inefficient-list-building",
                "Using `+=` to extend a list inside a loop",
                "Use list.append() for single items or list.extend() for multiple.",
            )
        self.generic_visit(node)

    @staticmethod
    def _call_path(node: ast.Call) -> str | None:
        """The full dotted source of the callee, e.g. 'self.cursor.execute', 'resp.links.get'.

        Unlike _get_call_name this never collapses to a bare method name, so a receiver is
        always available to disambiguate `dict.get` from `Model.objects.get`.
        """
        try:
            return ast.unparse(node.func)
        except Exception:
            return None

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr  # e.g. self.cursor.execute → "execute"
        return None


# ── Ruff PERF/ASYNC checks (verified tier) ──────────────────────────────────────

_RUFF_PERF_SELECT = "PERF,ASYNC"

# Ruff's async-blocking rules map onto our AST 'blocking-in-async' category, so an
# overlap becomes corroboration instead of a duplicate.
_RUFF_PERF_CANONICAL = {
    "ASYNC210": "blocking-in-async",
    "ASYNC251": "blocking-in-async",
}


def _perf_canonical(issue: Issue):
    if issue.source == "ruff":
        return (issue.line_number, _RUFF_PERF_CANONICAL.get(issue.rule_id, f"ruff:{issue.rule_id}"))
    return (issue.line_number, issue.category)


def _run_ruff_perf(code: str) -> list[Issue]:
    data = run_json_tool(
        [tool_bin("ruff"), "check", "--select", _RUFF_PERF_SELECT,
         "--output-format", "json", "--no-cache"],
        code,
    )
    if not data:
        return []
    issues = []
    for r in data:
        code_id = r.get("code") or "RUFF"
        severity = Severity.HIGH if code_id.startswith("ASYNC") else Severity.LOW
        issues.append(Issue(
            agent="performance",
            severity=severity,
            category=code_id,
            description=(r.get("message") or "").strip(),
            line_number=r.get("location", {}).get("row"),
            suggestion=ruff_suggestion(r),
            tier="verified",
            source="ruff",
            rule_id=code_id,
        ))
    return issues


# ── Scalability lens (suggested tier — LLM, code-grounded only) ──────────────────

class LLMScalabilityIssue(BaseModel):
    category: str
    severity: str = Field(description="one of: critical, high, medium, low")
    description: str
    line_number: int | None = None
    suggestion: str
    evidence: str = Field(
        description="The EXACT line this refers to, copied verbatim. Required — if you "
                    "cannot quote a specific line, do not report the issue."
    )


class LLMScalabilityResponse(BaseModel):
    issues: list[LLMScalabilityIssue] = Field(default_factory=list)


def _run_scalability_lens(code: str, language: str = "python") -> list[Issue]:
    """
    LLM suggestions for scalability problems VISIBLE IN THE CODE only. It must cite a
    line, and it must NOT propose infrastructure/capacity changes (load balancers,
    vertical/horizontal scaling, broker choice) — those aren't grounded in the source.
    """
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"), temperature=0)
    structured = llm.with_structured_output(LLMScalabilityResponse)

    prompt = f"""You are a scalability reviewer. Analyze the {language} code ONLY for problems
VISIBLE IN THE CODE that will not scale, such as:
1. Heavy/synchronous work in a request handler that should be offloaded to a background task queue
2. Missing pagination / unbounded queries (e.g. SELECT * with no limit)
3. No caching on a hot, repeated read path
4. Unbounded in-memory accumulation of results

STRICT RULES:
- Do NOT suggest infrastructure or capacity changes (load balancers, vertical vs horizontal
  scaling, message-broker choice) — nothing in the source justifies those.
- Do NOT flag security, style, or documentation — only code-visible scalability.
- For EVERY issue you MUST quote the exact offending line verbatim in `evidence`.
- If you cannot point to a specific line, DO NOT report the issue.

CODE:
```{language}
{code}
```"""

    response = llm_invoke(structured, prompt)
    if response is None:
        return []                      # LLM unavailable → degrade gracefully

    issues = []
    for item in response.issues:
        if not (item.evidence and item.evidence.strip()):
            continue
        try:
            sev = Severity(item.severity.lower())
        except ValueError:
            sev = Severity.LOW
        issues.append(Issue(
            agent="performance",
            severity=sev,
            category=item.category,
            description=item.description,
            line_number=item.line_number,
            suggestion=item.suggestion,
            tier="suggested",
            source="llm",
            evidence=item.evidence,
        ))
    return drop_duplicate_suggestions(issues)


def run_performance_agent(state: ReviewState) -> dict:
    is_python = state.language == "python"

    ast_issues: list[Issue] = []
    ruff_issues: list[Issue] = []
    if is_python:                       # our AST checks and Ruff are Python-only
        try:
            tree = ast.parse(state.code)
        except SyntaxError as e:
            return {"performance_output": AgentOutput(
                agent_name="performance",
                summary=f"Could not parse code: {e}",
            )}

        visitor = PerformanceVisitor()
        visitor.visit(tree)
        ast_issues = visitor.issues
        ruff_issues = _run_ruff_perf(state.code)

    # Verified tier: AST + Ruff PERF/ASYNC, deduped so overlaps become corroboration.
    verified = dedupe(ast_issues + ruff_issues, _perf_canonical)

    # Suggested tier: the code-grounded scalability lens. Works on any language.
    llm_issues = _run_scalability_lens(state.code, state.language)

    all_issues = verified + llm_issues
    corroborated = sum(1 for i in verified if i.corroborated_by)
    summary = (
        f"Found {len(all_issues)} performance issue(s) "
        f"({len(verified)} verified [AST+Ruff], {len(llm_issues)} suggested [scalability], "
        f"{corroborated} corroborated)."
        if all_issues else "No performance issues detected."
    )

    return {"performance_output": AgentOutput(
        agent_name="performance",
        issues=all_issues,
        summary=summary,
    )}
