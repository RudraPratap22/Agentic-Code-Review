"""Tests for the deterministic JS/TS security AST visitor (tree-sitter, no LLM)."""

from agents.treesitter_js import run_js_security_ast


def _cats(code, language="javascript"):
    return [i.category for i in run_js_security_ast(code, language)]


def test_flags_eval():
    assert "arbitrary-code-execution" in _cats("eval(userInput);")


def test_flags_new_function():
    assert "arbitrary-code-execution" in _cats('const f = new Function("x", "return x");')


def test_flags_child_process_exec():
    code = 'const cp = require("child_process");\ncp.exec("ls " + input);'
    assert "command-injection" in _cats(code)


def test_flags_bare_exec_sync():
    assert "command-injection" in _cats('execSync(cmd);')


def test_regex_exec_is_not_command_injection():
    # `pattern.exec(str)` is RegExp.prototype.exec — flagging it would be a false positive.
    assert "command-injection" not in _cats('const m = pattern.exec(str);')


def test_flags_hardcoded_secret():
    assert "hardcoded-secret" in _cats('const API_KEY = "sk-live-123";')


def test_ignores_secret_from_env():
    # Not a string literal → not a hardcoded secret.
    assert "hardcoded-secret" not in _cats("const API_KEY = process.env.API_KEY;")


def test_flags_sql_injection_in_template_literal():
    code = "const q = `SELECT * FROM users WHERE id = ${userId}`;"
    assert "sql-injection" in _cats(code)


def test_prose_template_literal_with_sql_keyword_is_not_flagged():
    # Mirrors the Python fix: a SQL keyword in prose must NOT be a CRITICAL false positive.
    code = "const msg = `Flag names WHERE a reader cannot tell intent in ${scope}.`;"
    assert "sql-injection" not in _cats(code)


def test_typescript_is_parsed():
    code = 'const API_KEY: string = "sk-live-123";\neval(x);'
    cats = _cats(code, "typescript")
    assert "hardcoded-secret" in cats and "arbitrary-code-execution" in cats


def test_findings_are_verified_tier_from_treesitter():
    issues = run_js_security_ast("eval(x);", "javascript")
    assert issues[0].tier == "verified"
    assert issues[0].source == "tree-sitter"     # a source distinct from semgrep


def test_unsupported_language_returns_empty():
    assert run_js_security_ast("eval(x);", "python") == []


def test_unparseable_code_degrades_gracefully():
    assert isinstance(run_js_security_ast("<<<not js>>>", "javascript"), list)
