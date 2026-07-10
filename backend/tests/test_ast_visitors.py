"""Tests for the deterministic AST detectors (no LLM, no tools)."""

import ast
from agents.security_agent import SecurityVisitor
from agents.quality_agent import QualityVisitor
from agents.performance_agent import PerformanceVisitor


def _issues(visitor_cls, code):
    v = visitor_cls()
    v.visit(ast.parse(code))
    return v.issues


def _cats(visitor_cls, code):
    return [i.category for i in _issues(visitor_cls, code)]


def test_security_flags_eval_secret_sql():
    code = 'API_KEY = "abc123"\nq = f"SELECT * FROM t WHERE id={x}"\neval("1")'
    cats = _cats(SecurityVisitor, code)
    assert "hardcoded-secret" in cats
    assert "sql-injection" in cats
    assert "arbitrary-code-execution" in cats


def test_sql_injection_ignores_prose_with_sql_keywords():
    # An f-string that merely contains a SQL keyword in prose (like our LLM prompts) must
    # NOT be flagged — only real query structure with an interpolated value counts.
    prose = 'msg = f"Flag names WHERE a reader cannot tell intent in {scope}."'
    assert "sql-injection" not in _cats(SecurityVisitor, prose)
    real = 'q = f"DELETE FROM users WHERE id = {uid}"'
    assert "sql-injection" in _cats(SecurityVisitor, real)


def test_quality_flags_too_many_args_but_not_docstring():
    cats = _cats(QualityVisitor, "def f(a, b, c, d, e, g):\n    return a")
    assert "too-many-arguments" in cats
    assert "missing-docstring" not in cats     # docstrings now owned by the documentation agent


def test_performance_flags_blocking_in_async():
    code = "import time\nasync def f():\n    time.sleep(1)"
    assert "blocking-in-async" in _cats(PerformanceVisitor, code)


def test_python_prose_secret_constant_not_flagged():
    # `_SECRET_FIX = "Load secrets from ..."` is advice text, not a credential.
    prose = '_SECRET_FIX = "Load secrets from environment variables or a vault."'
    assert "hardcoded-secret" not in _cats(SecurityVisitor, prose)
    real = 'API_KEY = "sk-live-abc123"'
    assert "hardcoded-secret" in _cats(SecurityVisitor, real)


# ── n+1 detection must look at the full call path, not a bare method name ──

def test_dict_get_in_loop_is_not_an_io_call():
    # `resp.links.get("next", {}).get("url")` is a dict lookup, not a database query.
    code = 'while url:\n    url = resp.links.get("next", {}).get("url")'
    assert "n-plus-one" not in _cats(PerformanceVisitor, code)


def test_env_get_in_loop_is_not_an_io_call():
    code = "for k in keys:\n    v = os.environ.get(k)"
    assert "n-plus-one" not in _cats(PerformanceVisitor, code)


def test_http_in_while_loop_is_pagination_not_n_plus_one():
    # Each page's URL comes from the previous response, so it cannot be batched.
    code = "while url:\n    resp = requests.get(url)"
    assert "n-plus-one" not in _cats(PerformanceVisitor, code)


def test_http_in_for_loop_is_still_flagged():
    code = "for u in users:\n    requests.get(u.url)"
    issues = _issues(PerformanceVisitor, code)
    assert [i.category for i in issues] == ["n-plus-one"]
    assert issues[0].severity.value == "medium"     # HTTP N+1, not a DB query


def test_db_calls_in_loop_still_flagged_high():
    for code in ("for u in users:\n    cursor.execute(q)",
                 "for u in users:\n    self.cursor.execute(q)",
                 "for u in users:\n    Profile.objects.get(id=u.id)",
                 "for u in users:\n    session.query(P).first()"):
        issues = _issues(PerformanceVisitor, code)
        assert any(i.category == "n-plus-one" and i.severity.value == "high" for i in issues), code
