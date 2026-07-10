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


# ── Quality checks (function size / arity) ──

from agents.treesitter_js import run_js_quality_ast, run_js_doc_ast


def _qcats(code, language="javascript"):
    return [i.category for i in run_js_quality_ast(code, language)]


def test_flags_too_many_arguments():
    assert "too-many-arguments" in _qcats("function f(a,b,c,d,e,g) { return a; }")


def test_allows_five_arguments():
    assert "too-many-arguments" not in _qcats("function f(a,b,c,d,e) { return a; }")


def test_flags_function_too_long():
    body = "\n".join(f"  const x{i} = {i};" for i in range(60))
    assert "function-too-long" in _qcats(f"function big() {{\n{body}\n}}")


def test_quality_findings_are_verified_quality_agent():
    issues = run_js_quality_ast("function f(a,b,c,d,e,g) {}", "javascript")
    assert issues[0].agent == "quality" and issues[0].tier == "verified"


# ── Documentation: JSDoc on the public API only ──

def _dnames(code, language="javascript"):
    return [i.description for i in run_js_doc_ast(code, language)]


def test_flags_exported_function_without_jsdoc():
    assert any("greet" in d for d in _dnames("export function greet(n) { return n; }"))


def test_documented_export_is_not_flagged():
    code = "/** Greets. */\nexport function greet(n) { return n; }"
    assert _dnames(code) == []


def test_internal_helper_is_not_flagged():
    # Not exported → internal → no JSDoc required (this is the noise guard).
    assert _dnames("function helper(n) { return n; }") == []


def test_commonjs_export_is_flagged():
    code = "function run(x) { return x; }\nmodule.exports = { run };"
    assert any("run" in d for d in _dnames(code))


def test_arrow_function_callback_is_not_flagged():
    code = "export const items = [1,2].map((x) => x * 2);"
    assert _dnames(code) == []


def test_constructor_is_not_flagged():
    code = "export class Svc {\n  constructor(a) { this.a = a; }\n}"
    assert not any("constructor" in d for d in _dnames(code))


def test_doc_findings_are_documentation_agent():
    issues = run_js_doc_ast("export function greet(n) {}", "javascript")
    assert issues[0].agent == "documentation" and issues[0].tier == "verified"
    assert issues[0].category == "missing-function-docstring"


def test_nested_long_functions_reported_once():
    # A long outer function whose nested callback inherits its length must yield ONE finding,
    # not one per nesting level (JS nests arrow callbacks everywhere).
    body = "\n".join(f"    const x{i} = {i};" for i in range(60))
    code = f"export const outer = (req) => {{\n  return new Promise((resolve) => {{\n{body}\n  }});\n}};"
    longs = [i for i in run_js_quality_ast(code, "javascript") if i.category == "function-too-long"]
    assert len(longs) == 1                       # only the outermost function is reported


def test_arrow_function_name_resolved_from_binding():
    body = "\n".join(f"  const x{i} = {i};" for i in range(60))
    code = f"export const uploadFileService = (req) => {{\n{body}\n}};"
    longs = [i for i in run_js_quality_ast(code, "javascript") if i.category == "function-too-long"]
    assert "uploadFileService" in longs[0].description   # not '<anonymous>'
