"""Deterministic AST checks for JavaScript/TypeScript, via tree-sitter.

These are the JS/TS counterparts of the Python visitors in security_agent.py,
quality_agent.py and documentation_agent.py: hand-written rules walking a real parse tree.

  run_js_security_ast — eval / new Function / child_process / hardcoded secrets /
                        template-literal SQL injection
  run_js_quality_ast  — function-too-long, too-many-arguments
  run_js_doc_ast      — missing JSDoc on the PUBLIC API (exports only)

The security checks matter most: tree-sitter is an INDEPENDENT deterministic source from
Semgrep — a different parser and our own rules — so when the two agree on a line the finding
is marked *corroborated*. That restores for JS the two-source confidence Python already gets
from (custom AST + Bandit + Semgrep), and keeps the LLM out of the critical path.

Findings reuse the SAME canonical categories as the Python visitors, so dedupe groups them
with Semgrep's equivalents and the shared test-file noise suppression applies unchanged.

No LLM. If tree-sitter is unavailable we return [] and the review still runs.
"""

from models.state import Issue, Severity
from agents.security_patterns import SECRET_NAME_RE, SQL_INJECTION_RE
from agents.thresholds import MAX_FUNCTION_LINES, MAX_FUNCTION_ARGS

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


def _issue(category: str, severity: Severity, description: str, line: int, suggestion: str,
           agent: str = "security") -> Issue:
    return Issue(
        agent=agent, severity=severity, category=category, description=description,
        line_number=line, suggestion=suggestion, tier="verified", source="tree-sitter",
    )


def _parse(code: str, language: str):
    """Return (src_bytes, root_node), or None if the parser is unavailable/unusable."""
    if language not in SUPPORTED_LANGUAGES:
        return None
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser(language)
        src = code.encode("utf-8")
        return src, parser.parse(src).root_node
    except Exception:
        return None                     # parser missing or unparseable → degrade, never crash


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
    parsed = _parse(code, language)
    if parsed is None:
        return []
    src, root = parsed

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


# ── Quality + documentation checks (the JS/TS counterparts of QualityVisitor/DocVisitor) ──

# Nodes that represent a callable, for the objective size/arity metrics.
_FUNCTION_NODES = {"function_declaration", "generator_function_declaration",
                   "function_expression", "arrow_function", "method_definition"}

# JSDoc is only required on the public API. Arrow functions (callbacks, React inline
# handlers) and constructors are excluded — flagging them buries a repo in LOW noise.
_DOCUMENTABLE_NODES = {"function_declaration", "generator_function_declaration",
                       "method_definition"}


def _param_count(node) -> int:
    """Number of declared parameters, ignoring punctuation tokens."""
    params = node.child_by_field_name("parameters")
    if params is not None:
        return len(params.named_children)
    single = node.child_by_field_name("parameter")   # arrow shorthand: `x => ...`
    return 1 if single is not None else 0


def _func_name(src: bytes, node) -> str:
    """Best-effort function name.

    Arrow functions and function expressions have no `name` field, so fall back to the
    binding they're assigned to — `const uploadFileService = (req) => {...}` should be
    reported as 'uploadFileService', not '<anonymous>'.
    """
    name = node.child_by_field_name("name")
    if name is not None:
        return _text(src, name)

    parent = node.parent
    if parent is not None:
        if parent.type == "variable_declarator":            # const f = () => {}
            bound = parent.child_by_field_name("name")
        elif parent.type == "pair":                          # { f: () => {} }
            bound = parent.child_by_field_name("key")
        elif parent.type == "assignment_expression":         # obj.f = () => {}
            bound = parent.child_by_field_name("left")
        else:
            bound = None
        if bound is not None:
            return _text(src, bound)
    return "<anonymous>"


def _collect_exported_names(src: bytes, root) -> set[str]:
    """Names exported CommonJS-style: `module.exports = {a, b}`, `exports.c = c`."""
    names: set[str] = set()
    for node in _walk(root):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "member_expression":
            continue
        obj, prop = left.child_by_field_name("object"), left.child_by_field_name("property")
        if obj is None or prop is None:
            continue
        obj_txt, prop_txt = _text(src, obj), _text(src, prop)
        if obj_txt == "exports":
            names.add(prop_txt)                       # exports.foo = ...
        elif obj_txt == "module" and prop_txt == "exports" and right is not None:
            if right.type == "identifier":
                names.add(_text(src, right))          # module.exports = foo
            elif right.type == "object":
                for child in right.named_children:    # module.exports = { foo, bar: baz }
                    if child.type == "shorthand_property_identifier":
                        names.add(_text(src, child))
                    elif child.type == "pair":
                        value = child.child_by_field_name("value")
                        if value is not None and value.type == "identifier":
                            names.add(_text(src, value))
    return names


def _is_exported(src: bytes, node, exported_names: set[str]) -> bool:
    """True for ESM `export function f()` or a name listed in CommonJS module.exports."""
    if node.parent is not None and node.parent.type == "export_statement":
        return True
    if _func_name(src, node) in exported_names:
        return True
    if node.type == "method_definition":              # a method is public if its class is
        cls = node.parent
        while cls is not None and "class" not in cls.type:
            cls = cls.parent
        if cls is not None:
            if cls.parent is not None and cls.parent.type == "export_statement":
                return True
            cls_name = cls.child_by_field_name("name")
            if cls_name is not None and _text(src, cls_name) in exported_names:
                return True
    return False


def _has_jsdoc(src: bytes, node) -> bool:
    """True if a `/** ... */` comment immediately precedes the function (or its export)."""
    target = node
    if target.parent is not None and target.parent.type == "export_statement":
        target = target.parent            # the doc comment sits above `export ...`
    prev = target.prev_sibling
    while prev is not None and prev.type == "comment":
        if _text(src, prev).lstrip().startswith("/**"):
            return True
        prev = prev.prev_sibling
    return False


def _is_nested_inside(node, candidates: set) -> bool:
    """True if any enclosing function is itself in `candidates`."""
    parent = node.parent
    while parent is not None:
        if parent.id in candidates:
            return True
        parent = parent.parent
    return False


def run_js_quality_ast(code: str, language: str) -> list[Issue]:
    """Deterministic size/arity quality findings for JS/TS (mirrors QualityVisitor)."""
    parsed = _parse(code, language)
    if parsed is None:
        return []
    src, root = parsed

    functions = [n for n in _walk(root) if n.type in _FUNCTION_NODES]

    # A long function nests callbacks (Promise executors, arrow handlers) that inherit its
    # length, so a single 115-line function would otherwise be reported three times. Report
    # only the OUTERMOST over-limit function — that's the one a human would flag.
    over_limit = {n.id for n in functions
                  if n.end_point[0] - n.start_point[0] > MAX_FUNCTION_LINES}

    issues: list[Issue] = []
    for node in functions:
        name = _func_name(src, node)
        line = _line(node)

        length = node.end_point[0] - node.start_point[0]
        if node.id in over_limit and not _is_nested_inside(node, over_limit):
            issues.append(_issue(
                "function-too-long", Severity.MEDIUM,
                f"Function '{name}' is {length} lines (limit: {MAX_FUNCTION_LINES})",
                line, "Break this into smaller, focused functions.", agent="quality"))

        arg_count = _param_count(node)
        if arg_count > MAX_FUNCTION_ARGS:
            issues.append(_issue(
                "too-many-arguments", Severity.MEDIUM,
                f"Function '{name}' has {arg_count} arguments (limit: {MAX_FUNCTION_ARGS})",
                line, "Group related arguments into an options object.", agent="quality"))
    return issues


def run_js_doc_ast(code: str, language: str) -> list[Issue]:
    """Missing JSDoc on the public API only (mirrors DocVisitor, scoped to exports)."""
    parsed = _parse(code, language)
    if parsed is None:
        return []
    src, root = parsed
    exported_names = _collect_exported_names(src, root)

    issues: list[Issue] = []
    for node in _walk(root):
        if node.type not in _DOCUMENTABLE_NODES:
            continue
        name = _func_name(src, node)
        if name == "constructor":                     # constructors rarely warrant JSDoc
            continue
        if not _is_exported(src, node, exported_names):
            continue                                  # internal helper → not public API
        if _has_jsdoc(src, node):
            continue
        issues.append(_issue(
            "missing-function-docstring", Severity.LOW,
            f"Exported function '{name}' has no JSDoc comment", _line(node),
            "Add a /** ... */ JSDoc block describing what it does, its params and return.",
            agent="documentation"))
    return issues
