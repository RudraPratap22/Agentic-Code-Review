"""Tests for the deterministic Go/Java AST checks (tree-sitter, no LLM)."""

from agents.treesitter_ast import run_security_ast, run_quality_ast, run_doc_ast


def _scats(code, language):
    return [i.category for i in run_security_ast(code, language)]


def _qcats(code, language):
    return [i.category for i in run_quality_ast(code, language)]


# ── Go: security ──

def test_go_flags_exec_command():
    code = 'package main\nfunc r(c string) { exec.Command("sh", "-c", c) }'
    assert "command-injection" in _scats(code, "go")


def test_go_flags_hardcoded_secret_const_and_var():
    assert "hardcoded-secret" in _scats('package main\nconst APIKey = "sk-1"', "go")
    assert "hardcoded-secret" in _scats('package main\nvar dbPassword = "hunter2"', "go")


def test_go_secret_from_env_not_flagged():
    code = 'package main\nvar APIKey = os.Getenv("API_KEY")'
    assert "hardcoded-secret" not in _scats(code, "go")


def test_go_flags_sprintf_sql_injection():
    code = 'package main\nfunc q(id string) { fmt.Sprintf("SELECT * FROM users WHERE id = %s", id) }'
    assert "sql-injection" in _scats(code, "go")


def test_go_prose_sprintf_with_sql_keyword_not_flagged():
    # Same guard as Python/JS: a SQL keyword in prose is not an injection.
    code = 'package main\nfunc m(s string) { fmt.Sprintf("Flag names WHERE a reader cannot tell %s", s) }'
    assert "sql-injection" not in _scats(code, "go")


# ── Go: quality (params are grouped: `a, b int` is ONE decl with TWO names) ──

def test_go_counts_grouped_parameters():
    code = "package main\nfunc f(a, b int, c, d string, e, g bool) {}"   # 6 params
    assert "too-many-arguments" in _qcats(code, "go")


def test_go_five_parameters_allowed():
    code = "package main\nfunc f(a, b int, c, d string, e bool) {}"      # 5 params
    assert "too-many-arguments" not in _qcats(code, "go")


def test_go_flags_function_too_long():
    body = "\n".join(f"  x{i} := {i}" for i in range(60))
    assert "function-too-long" in _qcats(f"package main\nfunc big() {{\n{body}\n}}", "go")


# ── Java: security ──

def test_java_flags_runtime_exec():
    code = 'class S { void r(String c) throws Exception { Runtime.getRuntime().exec(c); } }'
    assert "command-injection" in _scats(code, "java")


def test_java_flags_hardcoded_secret():
    code = 'class S { private static final String API_KEY = "sk-1"; }'
    assert "hardcoded-secret" in _scats(code, "java")


def test_java_flags_sql_string_concatenation():
    code = 'class S { void q(String id) { String s = "SELECT * FROM users WHERE id = " + id; } }'
    assert "sql-injection" in _scats(code, "java")


def test_java_prose_concatenation_not_flagged():
    code = 'class S { void m(String s) { String x = "Flag names WHERE a reader cannot tell " + s; } }'
    assert "sql-injection" not in _scats(code, "java")


def test_java_nested_concat_reported_once():
    code = 'class S { void q(String a, String b) { String s = "SELECT * FROM t WHERE x = " + a + b; } }'
    sqls = [i for i in run_security_ast(code, "java") if i.category == "sql-injection"]
    assert len(sqls) == 1        # outermost concatenation only


# ── Java: quality ──

def test_java_flags_too_many_arguments():
    code = "class S { void m(int a, int b, int c, int d, int e, int f) {} }"
    assert "too-many-arguments" in _qcats(code, "java")


# ── Shared behaviour ──

def test_findings_are_verified_treesitter():
    issues = run_security_ast('package main\nconst APIKey = "sk-1"', "go")
    assert issues[0].tier == "verified" and issues[0].source == "tree-sitter"


def test_doc_ast_is_noop_for_go_and_java():
    # JSDoc has no Go/Java equivalent wired up yet — must not emit anything.
    assert run_doc_ast("package main\nfunc F() {}", "go") == []
    assert run_doc_ast("class S { public void m() {} }", "java") == []


def test_unsupported_language_returns_empty():
    assert run_security_ast("x = 1", "python") == []
    assert run_quality_ast("x = 1", "ruby") == []
