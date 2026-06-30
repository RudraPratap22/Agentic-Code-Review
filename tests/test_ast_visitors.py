"""Tests for the deterministic AST detectors (no LLM, no tools)."""

import ast
from agents.security_agent import SecurityVisitor
from agents.quality_agent import QualityVisitor
from agents.performance_agent import PerformanceVisitor


def _cats(visitor_cls, code):
    v = visitor_cls()
    v.visit(ast.parse(code))
    return [i.category for i in v.issues]


def test_security_flags_eval_secret_sql():
    code = 'API_KEY = "abc123"\nq = f"SELECT * FROM t WHERE id={x}"\neval("1")'
    cats = _cats(SecurityVisitor, code)
    assert "hardcoded-secret" in cats
    assert "sql-injection" in cats
    assert "arbitrary-code-execution" in cats


def test_quality_flags_too_many_args_and_missing_docstring():
    cats = _cats(QualityVisitor, "def f(a, b, c, d, e, g):\n    return a")
    assert "too-many-arguments" in cats
    assert "missing-docstring" in cats


def test_performance_flags_blocking_in_async():
    code = "import time\nasync def f():\n    time.sleep(1)"
    assert "blocking-in-async" in _cats(PerformanceVisitor, code)
