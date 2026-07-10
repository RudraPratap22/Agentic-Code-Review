"""
Shared helpers for agents that shell out to external CLI tools (Bandit, Semgrep,
Ruff, ...) and for deterministic dedupe/corroboration across tools.

Keeping this in one place means every agent runs tools and merges findings the same
way — the tool itself practices the DRY principle it reviews for.
"""

import os
import re
import sys
import json
import time
import shutil
import tempfile
import subprocess
from typing import Callable, Hashable
from models.state import Issue, Severity


# ── Test-file noise suppression ───────────────────────────────────────────────
# Test files legitimately use asserts, skip docstrings, and hardcode expected values —
# so production rules generate pure noise on them. We drop a small, explicit set of
# low-value rules WHEN (and only when) the finding is on a test file. Production code is
# never affected; genuine issues on tests (e.g. a real security bug) still surface.

_TEST_FILE_RE = re.compile(
    r"(^|/)tests?/|(^|/)__tests__/|"          # test/ tests/ __tests__/ directories
    r"(^|/)test_[^/]*\.py$|_test\.py$|"        # python: test_x.py / x_test.py
    r"\.(test|spec)\.[jt]sx?$"                 # js/ts: x.test.jsx / x.spec.ts
)

# Rules/categories that are noise on test files (matched against rule_id OR category):
_TEST_NOISE = {
    "B101",                                                  # Bandit: assert_used
    "PLR2004", "ARG001", "ARG002", "ARG005",                 # Ruff: magic value / unused arg
    "missing-docstring", "missing-function-docstring",       # our AST docstring checks
    "missing-module-docstring",
}


def is_test_file(filename: str | None) -> bool:
    """True if `filename` looks like a test file (tests/ dir or test_*.py / *_test.py)."""
    return bool(filename and _TEST_FILE_RE.search(filename))


def drop_test_noise(issues: list[Issue]) -> list[Issue]:
    """Remove low-value production-rule findings that landed on test files."""
    return [
        i for i in issues
        if not (is_test_file(i.filename)
                and (i.rule_id in _TEST_NOISE or i.category in _TEST_NOISE))
    ]


def clean_findings(issues: list[Issue]) -> list[Issue]:
    """Post-process a collected finding list: suppress noise and calibrate the LLM tier.

    - Drop the verified-rule noise on test files (drop_test_noise).
    - Drop ALL suggested (LLM) findings on test files — nobody wants naming/perf/doc
      opinions on test code ("offload your test poll loop to Celery").
    - Cap the suggested tier at MEDIUM: a 'lower-confidence' hint being HIGH/CRITICAL is a
      contradiction, and the LLM tends to inflate. (Verified findings keep their severity.)
    """
    out: list[Issue] = []
    for i in drop_test_noise(issues):
        if i.tier == "suggested":
            if is_test_file(i.filename):
                continue
            if i.severity in (Severity.CRITICAL, Severity.HIGH):
                i.severity = Severity.MEDIUM
        out.append(i)
    return out


def llm_invoke(structured_llm, prompt, retries: int = 3, base_delay: float = 2.0):
    """Invoke an LLM with retry + exponential backoff on transient errors.

    Returns the response, or None if all attempts fail — so callers can degrade
    gracefully (drop the suggested tier for this file) instead of crashing the review.
    """
    for attempt in range(retries):
        try:
            return structured_llm.invoke(prompt)
        except Exception:
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))   # wait 2s, then 4s, then give up
    return None


def drop_duplicate_suggestions(issues: list[Issue]) -> list[Issue]:
    """Remove exact-duplicate LLM findings (same line, category, description)."""
    seen, out = set(), []
    for i in issues:
        key = (i.line_number, i.category, i.description)
        if key not in seen:
            seen.add(key)
            out.append(i)
    return out


def ruff_suggestion(result: dict) -> str:
    """Actionable fix text from a Ruff result: the autofix message, else the rule-doc link."""
    fix = result.get("fix")
    if fix and fix.get("message"):
        return fix["message"]                 # e.g. "Remove unused import: os"
    url = result.get("url")
    return f"See the rule: {url}" if url else "Review this Ruff finding."


def tool_bin(name: str) -> str:
    """Locate a CLI tool inside this venv, falling back to PATH."""
    candidate = os.path.join(os.path.dirname(sys.executable), name)
    return candidate if os.path.exists(candidate) else (shutil.which(name) or name)


def run_json_tool(argv: list[str], code: str, suffix: str = ".py"):
    """
    Write `code` to a temp file, run `argv + [tmpfile]`, and return the parsed JSON
    from stdout. Returns None if the tool is missing or emits no/invalid JSON.

    This is the one place the tempfile + subprocess + json pattern lives — Bandit,
    Semgrep, and Ruff runners all build their argv and call this.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        proc = subprocess.run(argv + [tmp_path], capture_output=True, text=True, check=False)
        return json.loads(proc.stdout)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ── Batched, repo-level tool runners ──────────────────────────────────────────
# Run a tool ONCE over the whole repo instead of once per file. Each tool boots and
# loads its ruleset a single time (Semgrep's startup is seconds), so a 50-file repo
# goes from ~150 subprocess boots (3 tools × 50 files) down to 3. The findings are
# identical — we just group them by file so each file can grab its own slice.


def _run_tool_over_dir(argv: list[str], repo_path: str):
    """Run `argv + [repo_path]` and return the parsed JSON, or None on failure.

    Same graceful-degradation contract as run_json_tool: a missing tool or invalid
    JSON returns None, and the caller falls back to per-file spawning.
    """
    try:
        proc = subprocess.run(argv + [repo_path], capture_output=True, text=True, check=False)
        return json.loads(proc.stdout)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return None


def _group_by_file(results, repo_path: str, path_key: str) -> dict:
    """Bucket a flat list of tool results into {rel_path: [result, ...]}.

    Each tool tags a result with the file it came from under a different key
    (Bandit/Ruff: 'filename', Semgrep: 'path') and reports an absolute path; we
    convert it to a repo-relative path so it matches the keys used in the pipeline.
    """
    out: dict[str, list] = {}
    for r in results or []:
        raw = r.get(path_key)
        if not raw:
            continue
        rel = os.path.relpath(raw, repo_path)
        out.setdefault(rel, []).append(r)
    return out


def run_bandit_repo(repo_path: str) -> dict:
    """Batched Bandit over the whole repo → {rel_path: [raw result dicts]}."""
    data = _run_tool_over_dir(
        [sys.executable, "-m", "bandit", "-r", "-f", "json", "-q"], repo_path)
    return _group_by_file((data or {}).get("results", []), repo_path, "filename")


def run_semgrep_repo(repo_path: str) -> dict:
    """Batched Semgrep (p/default) over the whole repo → {rel_path: [raw result dicts]}."""
    data = _run_tool_over_dir(
        [tool_bin("semgrep"), "--config", "p/default", "--json", "--quiet",
         "--metrics", "off"], repo_path)
    return _group_by_file((data or {}).get("results", []), repo_path, "path")


def run_ruff_repo(repo_path: str, select: str, config: str | None = None) -> dict:
    """Batched Ruff over the whole repo → {rel_path: [raw result dicts]}.

    Ruff emits a top-level JSON list (not wrapped in a key). `select` (and optional
    `config`) are passed in so this stays identical to the per-file quality-agent
    invocation.
    """
    argv = [tool_bin("ruff"), "check", "--select", select]
    if config:
        argv += ["--config", config]
    argv += ["--output-format", "json", "--no-cache"]
    data = _run_tool_over_dir(argv, repo_path)
    return _group_by_file(data or [], repo_path, "filename")


# Directories we never walk into when reviewing a repo.
SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", "node_modules", "build",
             "dist", ".ruff_cache", ".semgrep_cache", ".mypy_cache", ".pytest_cache"}


# ── Language detection ────────────────────────────────────────────────────────
# Which languages we review. Python gets the full stack (our AST visitors + Bandit +
# Ruff + Semgrep); the others currently get Semgrep (deterministic) + the LLM tier.

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
}

# The extension to use when we must write a snippet to a temp file for a tool.
_PRIMARY_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts",
                "go": ".go", "java": ".java", "ruby": ".rb", "php": ".php"}


def detect_language(filename: str) -> str | None:
    """Map a filename to a supported language, or None if we don't review it."""
    return LANG_BY_EXT.get(os.path.splitext(filename)[1].lower())


def ext_for_language(language: str) -> str:
    """Temp-file extension for a language, so tools parse the snippet correctly."""
    return _PRIMARY_EXT.get(language, ".txt")


def walk_source_files(repo_path: str) -> list[tuple[str, str, str]]:
    """Return [(relative_path, source_code, language)] for every supported source file.

    Junk dirs (venv, .git, node_modules, caches, ...) are pruned in place so os.walk never
    descends into them. Minified bundles and unreadable files are skipped rather than
    crashing the review.
    """
    files: list[tuple[str, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for f in filenames:
            language = detect_language(f)
            if not language or f.endswith((".min.js", ".bundle.js")):
                continue                                  # unsupported or generated
            full = os.path.join(dirpath, f)
            try:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    code = fh.read()
            except OSError:
                continue
            files.append((os.path.relpath(full, repo_path), code, language))
    return files


def walk_python_files(repo_path: str) -> list[tuple[str, str]]:
    """Python-only view of walk_source_files, as [(relative_path, source_code)].

    Kept for the architecture agent, whose import-graph analysis is Python-specific.
    """
    return [(p, code) for p, code, lang in walk_source_files(repo_path) if lang == "python"]


# Lower number = more severe; used to pick the representative when merging duplicates.
SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def dedupe(issues: list[Issue], canonical_of: Callable[[Issue], Hashable]) -> list[Issue]:
    """
    Collapse findings that multiple deterministic tools reported for the same bug.

    `canonical_of(issue)` returns a key that is identical for the same underlying bug
    across tools (e.g. AST 'too-many-arguments' and Ruff 'PLR0913' → the same key).
    For each group we keep the highest-severity issue (never downgrade a risk) and
    record the OTHER tools in `corroborated_by`, preserving a rule_id as evidence.
    Fully deterministic — no LLM involved.
    """
    groups: dict[Hashable, list[Issue]] = {}
    order: list[Hashable] = []
    for issue in issues:
        key = canonical_of(issue)
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

        primary = min(group, key=lambda i: SEVERITY_RANK[i.severity])
        for other in group:
            if other is primary:
                continue
            # Corroboration only counts from a DIFFERENT tool, not the primary's own source.
            if other.source != primary.source and other.source not in primary.corroborated_by:
                primary.corroborated_by.append(other.source)
            if other.rule_id and not primary.rule_id:
                primary.rule_id = other.rule_id
        merged.append(primary)
    return merged
