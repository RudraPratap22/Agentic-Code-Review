"""
Performance Agent — pure AST, no LLM.
Detects performance anti-patterns that are structurally identifiable:
- DB/network calls inside loops (N+1 pattern)
- Blocking calls inside async functions
- Inefficient list building with += inside loops
"""

import ast
from models.state import ReviewState, AgentOutput, Issue, Severity


# Functions that typically do I/O (DB queries, HTTP requests, file reads)
_IO_CALLS = {
    "execute", "fetchone", "fetchall", "fetchmany",   # DB cursors
    "query", "filter", "get", "all", "first",         # ORMs (SQLAlchemy, Django)
    "requests.get", "requests.post", "requests.put",  # HTTP
    "urlopen",                                          # urllib
    "read", "write", "readlines",                      # File I/O
}

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
        self._in_loop = False
        self._in_async = False

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
        old = self._in_loop
        self._in_loop = True
        self.generic_visit(node)
        self._in_loop = old

    visit_While = visit_For  # same logic for while loops

    def visit_AsyncFunctionDef(self, node):
        old = self._in_async
        self._in_async = True
        self.generic_visit(node)
        self._in_async = old

    # ── Check function calls ──────────────────────────────────────────

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if call_name:
            # N+1: I/O call inside a loop
            if self._in_loop and call_name in _IO_CALLS:
                self._add(
                    node, Severity.HIGH, "n-plus-one",
                    f"I/O call '{call_name}()' inside a loop — possible N+1 query pattern",
                    "Batch the query before the loop, e.g. fetch all records with one WHERE...IN query.",
                )

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
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr  # e.g. self.cursor.execute → "execute"
        return None


def run_performance_agent(state: ReviewState) -> dict:
    try:
        tree = ast.parse(state.code)
    except SyntaxError as e:
        return {"performance_output": AgentOutput(
            agent_name="performance",
            summary=f"Could not parse code: {e}",
        )}

    visitor = PerformanceVisitor()
    visitor.visit(tree)

    summary = (
        f"Found {len(visitor.issues)} performance issue(s)."
        if visitor.issues else "No performance issues detected."
    )

    return {"performance_output": AgentOutput(
        agent_name="performance",
        issues=visitor.issues,
        summary=summary,
    )}
