"""
Security Agent — deterministic ("Verified" tier) security detection. No LLM here.

Two independent deterministic sources run side by side:
  1. Our own AST walk (hand-written rules) — see SecurityVisitor below.
  2. Bandit — the industry-standard Python security scanner (run as a subprocess).

Neither can hallucinate. Where they agree, confidence is very high (corroboration);
where they differ, each catches issues the other misses. Both are tagged
tier="verified".
"""

import ast
import re
import sys
import json
import shutil
import tempfile
import subprocess
import os
from models.state import ReviewState, AgentOutput, Issue, Severity


# Patterns that almost certainly indicate a hardcoded secret
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|secret|password|token|auth|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)

# Function calls that are inherently dangerous
_DANGEROUS_CALLS = {
    "eval": ("arbitrary-code-execution", Severity.CRITICAL,
             "eval() executes arbitrary code. Pass a safe literal instead or redesign."),
    "exec": ("arbitrary-code-execution", Severity.CRITICAL,
             "exec() executes arbitrary code. Avoid entirely."),
    "compile": ("arbitrary-code-execution", Severity.HIGH,
                "compile() can be used to execute dynamic code. Audit this usage."),
    "pickle.loads": ("unsafe-deserialization", Severity.CRITICAL,
                     "pickle.loads() executes arbitrary code on untrusted input. Use json instead."),
    "marshal.loads": ("unsafe-deserialization", Severity.HIGH,
                      "marshal.loads() is unsafe with untrusted data."),
    "subprocess.call": ("command-injection", Severity.HIGH,
                        "Use subprocess.run() with a list arg and shell=False."),
    "os.system": ("command-injection", Severity.HIGH,
                  "os.system() is vulnerable to shell injection. Use subprocess instead."),
}


class SecurityVisitor(ast.NodeVisitor):
    """
    Walks the AST tree and collects security issues.
    Each visit_* method is called automatically by ast.NodeVisitor
    when it encounters that node type.
    """

    def __init__(self):
        self.issues: list[Issue] = []

    def _add(self, node: ast.AST, severity: Severity, category: str,
             description: str, suggestion: str):
        self.issues.append(Issue(
            agent="security",
            severity=severity,
            category=category,
            description=description,
            line_number=getattr(node, "lineno", None),
            suggestion=suggestion,
        ))

    def visit_Assign(self, node: ast.Assign):
        """Check assignments like: API_KEY = 'abc123'"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                if _SECRET_PATTERNS.search(target.id):
                    # Only flag if the value is a string literal, not a variable
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self._add(
                            node,
                            Severity.CRITICAL,
                            "hardcoded-secret",
                            f"Hardcoded secret found in variable '{target.id}'",
                            "Load secrets from environment variables using os.getenv() or a vault.",
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check dangerous function calls like eval(), exec(), pickle.loads()"""
        call_name = self._get_call_name(node)
        if call_name and call_name in _DANGEROUS_CALLS:
            category, severity, suggestion = _DANGEROUS_CALLS[call_name]
            self._add(
                node, severity, category,
                f"Dangerous call detected: {call_name}()",
                suggestion,
            )
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """
        Check for f-strings used in SQL-like contexts.
        JoinedStr is the AST node for f-strings.
        """
        # We reconstruct the f-string template to look for SQL keywords
        raw_parts = [
            p.value for p in node.values
            if isinstance(p, ast.Constant) and isinstance(p.value, str)
        ]
        combined = " ".join(raw_parts).upper()
        sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE")
        if any(kw in combined for kw in sql_keywords):
            self._add(
                node,
                Severity.CRITICAL,
                "sql-injection",
                "SQL query built with f-string — user input can inject arbitrary SQL",
                "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (id,))",
            )
        self.generic_visit(node)

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Extract function name from a Call node, e.g. 'eval' or 'pickle.loads'"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return None


# ── Bandit integration (second deterministic source) ─────────────────────────

# Bandit reports severity as HIGH/MEDIUM/LOW. We map to our Severity enum.
# We deliberately cap Bandit at HIGH (not CRITICAL): Bandit is conservative, and we
# let our own AST rules own the CRITICAL label for the few patterns we're sure about.
_BANDIT_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _run_bandit(code: str) -> list[Issue]:
    """
    Run Bandit on `code` and return its findings as Issue objects (tier='verified').

    How it works: Bandit scans files on disk, but our code is a string. So we write
    the string to a temporary .py file, run `python -m bandit -f json` on it as a
    subprocess, parse the JSON, and map each result into our Issue model.

    If Bandit is missing or anything goes wrong, we return [] — the agent's own AST
    checks still run. An optional tool must never crash the pipeline.
    """
    tmp_path = None
    try:
        # Write the code to a temp file Bandit can scan.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        # Run Bandit. -f json = machine-readable output, -q = quiet (no banner).
        # check=False because Bandit exits non-zero whenever it finds issues.
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", tmp_path],
            capture_output=True,
            text=True,
            check=False,
        )

        data = json.loads(proc.stdout)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        # Bandit not installed, or produced no/invalid JSON — degrade gracefully.
        return []
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    issues: list[Issue] = []
    for result in data.get("results", []):
        severity = _BANDIT_SEVERITY.get(result.get("issue_severity"), Severity.LOW)
        issues.append(Issue(
            agent="security",
            severity=severity,
            category=result.get("test_name", "bandit-finding"),
            description=result.get("issue_text", ""),
            line_number=result.get("line_number"),
            suggestion="Review this Bandit finding and apply the recommended secure pattern.",
            tier="verified",
            source="bandit",
            rule_id=result.get("test_id"),
        ))
    return issues


# ── Semgrep integration (third deterministic source) ─────────────────────────

# Semgrep severity is ERROR/WARNING/INFO. Like Bandit we cap below CRITICAL and let
# our own AST rules own the CRITICAL label.
_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _semgrep_bin() -> str:
    """Find the semgrep executable in this venv, falling back to PATH."""
    candidate = os.path.join(os.path.dirname(sys.executable), "semgrep")
    return candidate if os.path.exists(candidate) else (shutil.which("semgrep") or "semgrep")


def _run_semgrep(code: str) -> list[Issue]:
    """
    Run Semgrep (--config auto) on `code` and return findings as Issues (tier='verified').

    Same subprocess + tempfile pattern as Bandit. We use `p/default` (Semgrep's curated
    ruleset) with `--metrics off` — it gives the same coverage as `--config auto` but
    without telemetry (auto refuses to run with metrics off). Rules are fetched from
    Semgrep's registry (network on first run, then cached); if Semgrep is missing or
    offline we return [] and the other sources still run.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        proc = subprocess.run(
            [_semgrep_bin(), "--config", "p/default", "--json", "--quiet",
             "--metrics", "off", tmp_path],
            capture_output=True, text=True, check=False,
        )
        data = json.loads(proc.stdout)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return []
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    issues: list[Issue] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        severity = _SEMGREP_SEVERITY.get(extra.get("severity"), Severity.LOW)
        short_id = result.get("check_id", "semgrep-finding").split(".")[-1]
        issues.append(Issue(
            agent="security",
            severity=severity,
            category=short_id,
            description=(extra.get("message") or "").strip(),
            line_number=result.get("start", {}).get("line"),
            suggestion="Review this Semgrep finding and apply the recommended secure pattern.",
            tier="verified",
            source="semgrep",
            rule_id=short_id,
        ))
    return issues


# ── Deterministic dedupe + corroboration ─────────────────────────────────────

# Map Bandit rule IDs onto the SAME category names our AST visitor already uses,
# so the same underlying bug gets one shared "canonical key" regardless of which
# tool found it. Rules with no entry here are genuinely Bandit-unique findings.
_BANDIT_TO_CANONICAL = {
    "B301": "unsafe-deserialization",   # pickle.loads
    "B307": "arbitrary-code-execution", # eval
    "B102": "arbitrary-code-execution", # exec
    "B608": "sql-injection",            # string-built SQL
    "B602": "command-injection",        # subprocess w/ shell=True
    "B605": "command-injection",        # start process with a shell
    "B607": "command-injection",        # start process with partial path
    "B105": "hardcoded-secret",         # hardcoded password string
    "B106": "hardcoded-secret",         # hardcoded password func arg
}


def _semgrep_canonical(rule_id: str) -> str | None:
    """
    Map a Semgrep rule name onto our canonical category by keyword. Order matters:
    'sql' is checked before 'exec' so 'sqlalchemy-execute-raw-query' → sql-injection,
    not arbitrary-code-execution. Returns None for rules with no canonical equivalent.
    """
    cid = (rule_id or "").lower()
    if "sql" in cid:
        return "sql-injection"
    if "pickle" in cid:
        return "unsafe-deserialization"
    if "eval" in cid or "exec" in cid:
        return "arbitrary-code-execution"
    if any(k in cid for k in ("subprocess", "shell", "os-system", "command")):
        return "command-injection"
    if any(k in cid for k in ("secret", "password", "hardcoded", "token")):
        return "hardcoded-secret"
    return None


def _canonical_key(issue: Issue) -> tuple:
    """
    Build a key that is the SAME for the same underlying bug across tools.

    Bandit and Semgrep rule names are translated to the canonical category our AST
    visitor already uses; a finding with no mapping is tool-unique, so we key it by its
    rule_id (it never collides with an AST issue). AST issues already use canonical names.
    """
    if issue.source == "bandit":
        canonical = _BANDIT_TO_CANONICAL.get(issue.rule_id, f"bandit:{issue.rule_id}")
    elif issue.source == "semgrep":
        canonical = _semgrep_canonical(issue.rule_id) or f"semgrep:{issue.rule_id}"
    else:
        canonical = issue.category
    return (issue.line_number, canonical)


def _dedupe(issues: list[Issue]) -> list[Issue]:
    """
    Collapse findings that multiple deterministic tools reported for the same bug.

    For each group sharing a canonical key we keep ONE issue — the higher-severity
    one (never downgrade a risk by merging) — and record the other tools in
    `corroborated_by`, preserving their rule_ids as evidence. Fully deterministic.
    """
    groups: dict[tuple, list[Issue]] = {}
    order: list[tuple] = []
    for issue in issues:
        key = _canonical_key(issue)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(issue)

    merged: list[Issue] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Keep the highest-severity issue as the representative.
        primary = min(group, key=lambda i: _SEVERITY_RANK[i.severity])
        for other in group:
            if other is primary:
                continue
            # Record corroboration only from a DIFFERENT tool (not the primary's own source).
            if other.source != primary.source and other.source not in primary.corroborated_by:
                primary.corroborated_by.append(other.source)
            # Preserve the corroborating tool's rule_id as citable evidence.
            if other.rule_id and not primary.rule_id:
                primary.rule_id = other.rule_id
        merged.append(primary)
    return merged


# Lower number = more severe, used to pick the representative when merging.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def run_security_agent(state: ReviewState) -> dict:
    """
    LangGraph node function. Takes the full state, returns only the fields
    it updates — LangGraph merges this dict back into the state.

    Runs THREE deterministic sources (our AST visitor + Bandit + Semgrep), then
    deterministically dedupes them: duplicates collapse into one issue marked as
    corroborated by the other tools.
    """
    try:
        tree = ast.parse(state.code)
    except SyntaxError as e:
        output = AgentOutput(
            agent_name="security",
            issues=[],
            summary=f"Could not parse code: {e}",
        )
        return {"security_output": output}

    visitor = SecurityVisitor()
    visitor.visit(tree)
    ast_issues = visitor.issues  # already tagged source='custom-ast' (model default)

    bandit_issues = _run_bandit(state.code)
    semgrep_issues = _run_semgrep(state.code)

    raw_count = len(ast_issues) + len(bandit_issues) + len(semgrep_issues)
    all_issues = _dedupe(ast_issues + bandit_issues + semgrep_issues)
    corroborated = sum(1 for i in all_issues if i.corroborated_by)

    summary = (
        f"Found {len(all_issues)} security issue(s) "
        f"({raw_count} raw from AST + Bandit + Semgrep, {corroborated} corroborated across tools)."
        if all_issues
        else "No security issues detected."
    )

    return {
        "security_output": AgentOutput(
            agent_name="security",
            issues=all_issues,
            summary=summary,
        )
    }
