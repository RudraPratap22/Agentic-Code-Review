"""Deterministic AST checks for non-Python languages, via tree-sitter.

These are the counterparts of the Python visitors in security_agent.py, quality_agent.py
and documentation_agent.py: hand-written rules walking a real parse tree.

  run_security_ast — per-language: eval / command execution / hardcoded secrets /
                     SQL built by interpolation
  run_quality_ast  — language-agnostic: function-too-long, too-many-arguments
  run_doc_ast      — missing doc comment on the PUBLIC API (JS/TS only for now)

Why this matters: tree-sitter is an INDEPENDENT deterministic source from Semgrep — a
different parser and our own rules — so when the two agree on a line the finding is marked
*corroborated*. Every supported language therefore has at least two deterministic sources,
exactly like Python (custom AST + Bandit + Semgrep), keeping the LLM out of the verified tier.

Findings reuse the SAME canonical categories as the Python visitors, so dedupe groups them
with Semgrep's equivalents and the shared test-file noise suppression applies unchanged.

Adding a language means adding one LangSpec entry — the quality checks come for free.

No LLM. If tree-sitter is unavailable we return [] and the review still runs.
"""

import re
from dataclasses import dataclass, field
from typing import Callable

from models.state import Issue, Severity
from agents.security_patterns import SECRET_NAME_RE, SQL_INJECTION_RE
from agents.thresholds import MAX_FUNCTION_LINES, MAX_FUNCTION_ARGS


# ── Generic tree helpers ──────────────────────────────────────────────────────

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
    if language not in LANG_SPEC:
        return None
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser(language)
        src = code.encode("utf-8")
        return src, parser.parse(src).root_node
    except Exception:
        return None                     # parser missing or unparseable → degrade, never crash


_CMD_FIX = "Never interpolate user input into a shell command; pass arguments as a list/array."
_SECRET_FIX = "Load secrets from environment variables or a vault, never a source literal."
_SQL_FIX = "Use parameterized queries / prepared statements instead of string interpolation."

# SQL_INJECTION_RE requires real query STRUCTURE with a `{}` placeholder, so a SQL keyword
# appearing in prose never matches. Each language only has to build that template.
_GO_FORMAT_VERB = re.compile(r"%[+\-# 0]*\d*(?:\.\d+)?[a-zA-Z]")


def _is_sql_injection(template: str) -> bool:
    return bool(SQL_INJECTION_RE.search(template))


# ══════════════════════════════════════════════════════════════════════════════
# JavaScript / TypeScript
# ══════════════════════════════════════════════════════════════════════════════

_JS_EVAL_IDENTIFIERS = {"eval"}
# child_process helpers. The *Sync / *File variants are unambiguous. Bare `exec`/`spawn` on
# an object are only command execution when the object looks like child_process — otherwise
# `regex.exec(str)` would be a false positive.
_JS_CMD_IDENTIFIERS = {"exec", "execSync", "execFile", "execFileSync", "spawnSync"}
_JS_CMD_PROPERTIES = {"execSync", "execFile", "execFileSync", "spawnSync"}
_JS_CMD_AMBIGUOUS = {"exec", "spawn"}
_JS_CHILD_PROCESS_OBJECTS = {"cp", "child_process", "childProcess", "childprocess", "proc"}


def _js_template_literal(src: bytes, node) -> str:
    """Rebuild a template literal with `{}` wherever a ${...} substitution appears."""
    return "".join("{}" if c.type == "template_substitution" else _text(src, c)
                   for c in node.children)


def _js_check_call(src: bytes, node) -> Issue | None:
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "identifier":
        name = _text(src, fn)
        if name in _JS_EVAL_IDENTIFIERS:
            return _issue("arbitrary-code-execution", Severity.CRITICAL,
                          "eval() executes arbitrary code", _line(node),
                          "Avoid eval(); parse the input or use a safe lookup table instead.")
        if name in _JS_CMD_IDENTIFIERS:
            return _issue("command-injection", Severity.HIGH,
                          f"Dangerous call detected: {name}()", _line(node), _CMD_FIX)
    elif fn.type == "member_expression":
        prop, obj = fn.child_by_field_name("property"), fn.child_by_field_name("object")
        if prop is None:
            return None
        prop_name = _text(src, prop)
        obj_name = _text(src, obj) if obj is not None else ""
        if prop_name in _JS_CMD_PROPERTIES or (
                prop_name in _JS_CMD_AMBIGUOUS and obj_name in _JS_CHILD_PROCESS_OBJECTS):
            return _issue("command-injection", Severity.HIGH,
                          f"Dangerous call detected: {obj_name}.{prop_name}()", _line(node), _CMD_FIX)
    return None


def _security_javascript(src: bytes, root) -> list[Issue]:
    issues: list[Issue] = []
    for node in _walk(root):
        if node.type == "call_expression":
            found = _js_check_call(src, node)
            if found:
                issues.append(found)

        elif node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            if ctor is not None and _text(src, ctor) == "Function":
                issues.append(_issue("arbitrary-code-execution", Severity.CRITICAL,
                                     "new Function() compiles and executes arbitrary code",
                                     _line(node), "Avoid new Function(); use a safe alternative."))

        elif node.type == "variable_declarator":
            name_node, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if name_node is not None and value is not None and value.type == "string":
                var_name = _text(src, name_node)
                if SECRET_NAME_RE.search(var_name):
                    issues.append(_issue("hardcoded-secret", Severity.CRITICAL,
                                         f"Hardcoded secret found in variable '{var_name}'",
                                         _line(node), _SECRET_FIX))

        elif node.type == "template_string":
            if _is_sql_injection(_js_template_literal(src, node)):
                issues.append(_issue("sql-injection", Severity.CRITICAL,
                                     "SQL query built with a template literal — user input can "
                                     "inject arbitrary SQL", _line(node), _SQL_FIX))
    return issues


def _count_params_js(src: bytes, node) -> int:
    params = node.child_by_field_name("parameters")
    if params is not None:
        return len(params.named_children)
    return 1 if node.child_by_field_name("parameter") is not None else 0   # `x => ...`


# ══════════════════════════════════════════════════════════════════════════════
# Go
# ══════════════════════════════════════════════════════════════════════════════

_GO_EXEC_FIELDS = {"Command", "CommandContext"}
_GO_STRING_LITERALS = {"interpreted_string_literal", "raw_string_literal"}


def _go_value_is_string_literal(node) -> bool:
    """Go wraps a spec's value in an `expression_list`, so look one level in.

    `const K = "lit"` → literal (flag it); `var K = os.Getenv("K")` → a call, not a literal.
    """
    value = node.child_by_field_name("value")
    if value is None:
        return False
    if value.type in _GO_STRING_LITERALS:
        return True
    if value.type == "expression_list":
        return any(c.type in _GO_STRING_LITERALS for c in value.named_children)
    return False


def _go_sprintf_template(src: bytes, node) -> str | None:
    """For fmt.Sprintf("SELECT ... %s", x), return the format string with verbs → `{}`."""
    args = node.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return None
    first = args.named_children[0]
    if first.type not in _GO_STRING_LITERALS:
        return None
    return _GO_FORMAT_VERB.sub("{}", _text(src, first))


def _security_go(src: bytes, root) -> list[Issue]:
    issues: list[Issue] = []
    for node in _walk(root):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "selector_expression":
                continue
            pkg, fld = fn.child_by_field_name("operand"), fn.child_by_field_name("field")
            if pkg is None or fld is None:
                continue
            pkg_name, fld_name = _text(src, pkg), _text(src, fld)

            if pkg_name == "exec" and fld_name in _GO_EXEC_FIELDS:
                issues.append(_issue("command-injection", Severity.HIGH,
                                     f"Dangerous call detected: exec.{fld_name}()",
                                     _line(node), _CMD_FIX))
            elif pkg_name == "fmt" and fld_name == "Sprintf":
                template = _go_sprintf_template(src, node)
                if template and _is_sql_injection(template):
                    issues.append(_issue("sql-injection", Severity.CRITICAL,
                                         "SQL query built with fmt.Sprintf — user input can "
                                         "inject arbitrary SQL", _line(node), _SQL_FIX))

        elif node.type in ("const_spec", "var_spec"):
            name_node = node.child_by_field_name("name")
            if name_node is None or not SECRET_NAME_RE.search(_text(src, name_node)):
                continue
            if _go_value_is_string_literal(node):
                issues.append(_issue("hardcoded-secret", Severity.CRITICAL,
                                     f"Hardcoded secret found in '{_text(src, name_node)}'",
                                     _line(node), _SECRET_FIX))
    return issues


def _count_params_go(src: bytes, node) -> int:
    """Go groups params: `func f(a, b int)` is ONE parameter_declaration with TWO names."""
    params = node.child_by_field_name("parameters")
    if params is None:
        return 0
    total = 0
    for decl in params.named_children:
        names = [c for c in decl.named_children if c.type == "identifier"]
        total += len(names) or 1        # unnamed params (`func(int)`) still count as one
    return total


# ══════════════════════════════════════════════════════════════════════════════
# Java
# ══════════════════════════════════════════════════════════════════════════════

def _op(src: bytes, node) -> str:
    operator = node.child_by_field_name("operator")
    return _text(src, operator) if operator is not None else ""


def _java_concat_template(src: bytes, node) -> str:
    """Flatten a `+` string concatenation into a template: literals kept, values → `{}`."""
    parts: list[str] = []

    def visit(n) -> None:
        if n.type == "binary_expression" and _op(src, n) == "+":
            for side in (n.child_by_field_name("left"), n.child_by_field_name("right")):
                if side is not None:
                    visit(side)
        elif n.type == "string_literal":
            parts.append(_text(src, n).strip('"'))
        else:
            parts.append("{}")

    visit(node)
    return "".join(parts)


def _security_java(src: bytes, root) -> list[Issue]:
    issues: list[Issue] = []
    for node in _walk(root):
        if node.type == "method_invocation":
            name, obj = node.child_by_field_name("name"), node.child_by_field_name("object")
            if (name is not None and _text(src, name) == "exec"
                    and obj is not None and "Runtime" in _text(src, obj)):
                issues.append(_issue("command-injection", Severity.HIGH,
                                     "Dangerous call detected: Runtime.exec()",
                                     _line(node), _CMD_FIX))

        elif node.type == "variable_declarator":
            name_node, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if name_node is not None and value is not None and value.type == "string_literal":
                var_name = _text(src, name_node)
                if SECRET_NAME_RE.search(var_name):
                    issues.append(_issue("hardcoded-secret", Severity.CRITICAL,
                                         f"Hardcoded secret found in variable '{var_name}'",
                                         _line(node), _SECRET_FIX))

        elif node.type == "binary_expression" and _op(src, node) == "+":
            # Only the OUTERMOST concatenation — `"a" + b + c` nests and would report twice.
            parent = node.parent
            if parent is not None and parent.type == "binary_expression" and _op(src, parent) == "+":
                continue
            if _is_sql_injection(_java_concat_template(src, node)):
                issues.append(_issue("sql-injection", Severity.CRITICAL,
                                     "SQL query built by string concatenation — user input can "
                                     "inject arbitrary SQL", _line(node), _SQL_FIX))
    return issues


def _count_params_java(src: bytes, node) -> int:
    params = node.child_by_field_name("parameters")
    return len(params.named_children) if params is not None else 0


# ══════════════════════════════════════════════════════════════════════════════
# Language registry — adding a language means adding one entry here.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class LangSpec:
    functions: frozenset            # node types that represent a callable
    count_params: Callable          # (src, node) -> int
    security: Callable              # (src, root) -> list[Issue]
    doc_nodes: frozenset = field(default_factory=frozenset)   # nodes needing a doc comment


_JS_FUNCTIONS = frozenset({"function_declaration", "generator_function_declaration",
                           "function_expression", "arrow_function", "method_definition"})
# Doc comments are required on the public API only. Arrow functions (callbacks, React inline
# handlers) and constructors are excluded — flagging them buries a repo in LOW noise.
_JS_DOC_NODES = frozenset({"function_declaration", "generator_function_declaration",
                           "method_definition"})

_JS_SPEC = LangSpec(functions=_JS_FUNCTIONS, count_params=_count_params_js,
                    security=_security_javascript, doc_nodes=_JS_DOC_NODES)

LANG_SPEC: dict[str, LangSpec] = {
    "javascript": _JS_SPEC,
    "typescript": _JS_SPEC,
    "go": LangSpec(
        functions=frozenset({"function_declaration", "method_declaration", "func_literal"}),
        count_params=_count_params_go, security=_security_go),
    "java": LangSpec(
        functions=frozenset({"method_declaration", "constructor_declaration", "lambda_expression"}),
        count_params=_count_params_java, security=_security_java),
}

SUPPORTED_LANGUAGES = frozenset(LANG_SPEC)
DOC_LANGUAGES = frozenset(lang for lang, spec in LANG_SPEC.items() if spec.doc_nodes)


# ══════════════════════════════════════════════════════════════════════════════
# Public entry points
# ══════════════════════════════════════════════════════════════════════════════

def run_security_ast(code: str, language: str) -> list[Issue]:
    """Deterministic security findings for a non-Python source string."""
    parsed = _parse(code, language)
    if parsed is None:
        return []
    src, root = parsed
    return LANG_SPEC[language].security(src, root)


def _func_name(src: bytes, node) -> str:
    """Best-effort function name.

    Arrow functions / lambdas have no `name` field, so fall back to the binding they're
    assigned to — `const uploadFileService = (req) => {...}` is reported as
    'uploadFileService', not '<anonymous>'.
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


def _is_nested_inside(node, candidates: set) -> bool:
    """True if any enclosing function is itself in `candidates`."""
    parent = node.parent
    while parent is not None:
        if parent.id in candidates:
            return True
        parent = parent.parent
    return False


def run_quality_ast(code: str, language: str) -> list[Issue]:
    """Size/arity quality findings — the same limits Python uses, on any grammar."""
    parsed = _parse(code, language)
    if parsed is None:
        return []
    src, root = parsed
    spec = LANG_SPEC[language]

    functions = [n for n in _walk(root) if n.type in spec.functions]

    # A long function nests callbacks (Promise executors, lambdas) that inherit its length,
    # so a single 115-line function would otherwise be reported several times. Report only
    # the OUTERMOST over-limit function — the one a human would flag.
    over_limit = {n.id for n in functions
                  if n.end_point[0] - n.start_point[0] > MAX_FUNCTION_LINES}

    issues: list[Issue] = []
    for node in functions:
        name, line = _func_name(src, node), _line(node)

        length = node.end_point[0] - node.start_point[0]
        if node.id in over_limit and not _is_nested_inside(node, over_limit):
            issues.append(_issue("function-too-long", Severity.MEDIUM,
                                 f"Function '{name}' is {length} lines (limit: {MAX_FUNCTION_LINES})",
                                 line, "Break this into smaller, focused functions.", agent="quality"))

        arg_count = spec.count_params(src, node)
        if arg_count > MAX_FUNCTION_ARGS:
            issues.append(_issue("too-many-arguments", Severity.MEDIUM,
                                 f"Function '{name}' has {arg_count} arguments "
                                 f"(limit: {MAX_FUNCTION_ARGS})",
                                 line, "Group related arguments into an options object.",
                                 agent="quality"))
    return issues


# ── Documentation (JS/TS only for now) ────────────────────────────────────────

def _collect_exported_names(src: bytes, root) -> set[str]:
    """Names exported CommonJS-style: `module.exports = {a, b}`, `exports.c = c`."""
    names: set[str] = set()
    for node in _walk(root):
        if node.type != "assignment_expression":
            continue
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
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


def run_doc_ast(code: str, language: str) -> list[Issue]:
    """Missing JSDoc on the public API only (scoped to exports to avoid noise)."""
    if language not in DOC_LANGUAGES:
        return []
    parsed = _parse(code, language)
    if parsed is None:
        return []
    src, root = parsed
    spec = LANG_SPEC[language]
    exported_names = _collect_exported_names(src, root)

    issues: list[Issue] = []
    for node in _walk(root):
        if node.type not in spec.doc_nodes:
            continue
        name = _func_name(src, node)
        if name == "constructor":                     # constructors rarely warrant JSDoc
            continue
        if not _is_exported(src, node, exported_names):
            continue                                  # internal helper → not public API
        if _has_jsdoc(src, node):
            continue
        issues.append(_issue("missing-function-docstring", Severity.LOW,
                             f"Exported function '{name}' has no JSDoc comment", _line(node),
                             "Add a /** ... */ JSDoc block describing what it does, its "
                             "params and return.", agent="documentation"))
    return issues
