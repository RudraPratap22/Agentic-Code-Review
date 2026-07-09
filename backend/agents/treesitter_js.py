"""Deterministic security AST checks for JavaScript/TypeScript, via tree-sitter.

This is the JS/TS counterpart of SecurityVisitor in security_agent.py: hand-written rules
walking a real parse tree. It matters because it is an INDEPENDENT deterministic source
from Semgrep — a different parser and our own rules — so when the two agree on a line the
finding is marked *corroborated*. That restores for JS the two-source confidence Python
already gets from (custom AST + Bandit + Semgrep), and keeps the LLM out of the critical
path for non-Python code.

Findings use the SAME canonical categories as the Python visitor (arbitrary-code-execution,
command-injection, hardcoded-secret, sql-injection) so security_agent's dedupe groups them
with Semgrep's equivalents.

No LLM. If tree-sitter is unavailable we return [] and the review still runs.
"""

from models.state import Issue, Severity
from agents.security_patterns import SECRET_NAME_RE, SQL_INJECTION_RE

SUPPORTED_LANGUAGES = {"javascript", "typescript"}

# Calls that execute arbitrary code.
_EVAL_IDENTIFIERS = {"eval"}

# child_process helpers. The *Sync / *File variants are unambiguous. Bare `exec`/`spawn` on
# an object are only treated as command execution when the object looks like child_process —
# otherwise `regex.exec(str)` would be a false positive.
_CMD_IDENTIFIERS = {"exec", "execSync", "execFile", "execFileSync", "spawnSync"}
_CMD_PROPERTIES = {"execSync", "execFile", "execFileSync", "spawnSync"}
_CMD_AMBIGUOUS_PROPERTIES = {"exec", "spawn"}
_CHILD_PROCESS_OBJECTS = {"cp", "child_process", "childProcess", "childprocess", "proc"}

_CMD_FIX = "Use execFile/spawn with an argument array; never interpolate user input into a shell string."


def _text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "ignore")


def _line(node) -> int:
    return node.start_point[0] + 1


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _issue(category: str, severity: Severity, description: str, line: int, suggestion: str) -> Issue:
    return Issue(
        agent="security", severity=severity, category=category, description=description,
        line_number=line, suggestion=suggestion, tier="verified", source="tree-sitter",
    )


def _template_literal_text(src: bytes, node) -> str:
    """Rebuild a template literal with `{}` wherever a ${...} substitution appears.

    Mirrors the Python f-string handling: we compare STRUCTURE, so a template literal that
    merely contains a SQL keyword in prose (e.g. "...names WHERE a reader...") won't match.
    """
    parts = []
    for child in node.children:
        parts.append("{}" if child.type == "template_substitution" else _text(src, child))
    return "".join(parts)


def _check_call(src: bytes, node) -> Issue | None:
    fn = node.child_by_field_name("function")
    if fn is None:
        return None

    if fn.type == "identifier":
        name = _text(src, fn)
        if name in _EVAL_IDENTIFIERS:
            return _issue("arbitrary-code-execution", Severity.CRITICAL,
                          "eval() executes arbitrary code", _line(node),
                          "Avoid eval(); parse the input or use a safe lookup table instead.")
        if name in _CMD_IDENTIFIERS:
            return _issue("command-injection", Severity.HIGH,
                          f"Dangerous call detected: {name}()", _line(node), _CMD_FIX)

    elif fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        obj = fn.child_by_field_name("object")
        if prop is None:
            return None
        prop_name = _text(src, prop)
        obj_name = _text(src, obj) if obj is not None else ""
        unambiguous = prop_name in _CMD_PROPERTIES
        child_proc = prop_name in _CMD_AMBIGUOUS_PROPERTIES and obj_name in _CHILD_PROCESS_OBJECTS
        if unambiguous or child_proc:
            return _issue("command-injection", Severity.HIGH,
                          f"Dangerous call detected: {obj_name}.{prop_name}()", _line(node), _CMD_FIX)
    return None


def run_js_security_ast(code: str, language: str) -> list[Issue]:
    """Return deterministic security findings for a JS/TS source string."""
    if language not in SUPPORTED_LANGUAGES:
        return []
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser(language)
        src = code.encode("utf-8")
        root = parser.parse(src).root_node
    except Exception:
        return []                       # parser missing or unparseable → degrade, never crash

    issues: list[Issue] = []
    for node in _walk(root):
        if node.type == "call_expression":
            found = _check_call(src, node)
            if found:
                issues.append(found)

        elif node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            if ctor is not None and _text(src, ctor) == "Function":
                issues.append(_issue(
                    "arbitrary-code-execution", Severity.CRITICAL,
                    "new Function() compiles and executes arbitrary code", _line(node),
                    "Avoid new Function(); use a safe alternative."))

        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name_node is not None and value is not None and value.type == "string":
                var_name = _text(src, name_node)
                if SECRET_NAME_RE.search(var_name):
                    issues.append(_issue(
                        "hardcoded-secret", Severity.CRITICAL,
                        f"Hardcoded secret found in variable '{var_name}'", _line(node),
                        "Load secrets from environment variables (process.env) or a vault."))

        elif node.type == "template_string":
            if SQL_INJECTION_RE.search(_template_literal_text(src, node)):
                issues.append(_issue(
                    "sql-injection", Severity.CRITICAL,
                    "SQL query built with a template literal — user input can inject arbitrary SQL",
                    _line(node),
                    "Use parameterized queries: db.query('SELECT * FROM t WHERE id = ?', [id])"))
    return issues
