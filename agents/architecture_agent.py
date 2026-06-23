"""
Architecture & Structure Agent — whole-repo, deterministic ("verified" tier).

Unlike the other agents (which review one file's `code`), this one reviews the repo
at `state.repo_path`. Two deterministic halves, neither of which can hallucinate:

1. Structure checks — file/layout facts: is there a tests/ dir, a README, CI config,
   a .gitignore, a dependency manifest, any committed secrets?
2. Dependency-graph metrics — parse every module's imports, build an internal import
   graph, and measure: circular dependencies, fan-in/fan-out, god-modules.

(Day 5 will add a "suggested" LLM tier that *interprets* these measured metrics — and
must cite the number it reacts to.)
"""

import os
import ast
from models.state import ReviewState, AgentOutput, Issue, Severity

# Directories we never walk into.
_SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", "node_modules", "build",
              "dist", ".ruff_cache", ".semgrep_cache", ".mypy_cache", ".pytest_cache"}

# Coupling thresholds — a module that is BOTH widely depended on AND depends on many
# things is a "god module" coupling hotspot. (High fan-in alone is fine: that's a
# normal shared leaf module like models/state.py.)
_FANIN_THRESHOLD = 4
_FANOUT_THRESHOLD = 4


def _arch_issue(severity, category, description, suggestion, line=None):
    return Issue(
        agent="architecture", severity=severity, category=category,
        description=description, suggestion=suggestion, line_number=line,
        tier="verified", source="architecture",
    )


# ── Half 1: structure checks ────────────────────────────────────────────────────

def _exists_any(repo, names):
    return any(os.path.exists(os.path.join(repo, n)) for n in names)


def _has_tests(repo):
    if os.path.isdir(os.path.join(repo, "tests")):
        return True
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for f in filenames:
            if f.startswith("test_") and f.endswith(".py") or f.endswith("_test.py"):
                return True
    return False


def _gitignore_covers_env(repo):
    """True if .env is safely ignored (or no .env exists at all)."""
    if not os.path.exists(os.path.join(repo, ".env")):
        return True  # nothing to leak
    gi = os.path.join(repo, ".gitignore")
    if not os.path.exists(gi):
        return False
    with open(gi, encoding="utf-8", errors="ignore") as fh:
        return any(line.strip().rstrip("/") == ".env" for line in fh)


def _structure_checks(repo) -> list[Issue]:
    issues = []
    if not _has_tests(repo):
        issues.append(_arch_issue(
            Severity.HIGH, "missing-tests",
            "No tests/ directory or test_*.py files found",
            "Add a tests/ suite — untested code is a major production-readiness gap.",
        ))
    if not _exists_any(repo, ["README.md", "README.rst", "README", "README.txt"]):
        issues.append(_arch_issue(
            Severity.LOW, "missing-readme",
            "No README found",
            "Add a README describing what the project does and how to run it.",
        ))
    if not (os.path.isdir(os.path.join(repo, ".github", "workflows"))
            or _exists_any(repo, [".gitlab-ci.yml", ".circleci", "azure-pipelines.yml"])):
        issues.append(_arch_issue(
            Severity.MEDIUM, "missing-ci",
            "No CI configuration found (e.g. .github/workflows)",
            "Add CI to run tests/linters automatically on every push.",
        ))
    if not _exists_any(repo, [".gitignore"]):
        issues.append(_arch_issue(
            Severity.LOW, "missing-gitignore",
            "No .gitignore found",
            "Add a .gitignore so build artifacts and secrets aren't committed.",
        ))
    if not _exists_any(repo, ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]):
        issues.append(_arch_issue(
            Severity.MEDIUM, "missing-dependency-manifest",
            "No dependency manifest (requirements.txt / pyproject.toml) found",
            "Pin dependencies so the environment is reproducible.",
        ))
    if not _gitignore_covers_env(repo):
        issues.append(_arch_issue(
            Severity.CRITICAL, "committed-secret-risk",
            "A .env file exists but is not listed in .gitignore — secrets may be committed",
            "Add `.env` to .gitignore and rotate any exposed secrets immediately.",
        ))
    return issues


# ── Half 2: dependency-graph metrics ────────────────────────────────────────────

def _module_name(path, root):
    rel = os.path.relpath(path, root)
    parts = (rel[:-3] if rel.endswith(".py") else rel).split(os.sep)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _collect_modules(repo):
    """Map every internal module name → its file path."""
    modules = {}
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for f in filenames:
            if f.endswith(".py"):
                full = os.path.join(dirpath, f)
                modules[_module_name(full, repo)] = full
    return modules


def _resolve_relative(current, level, module):
    """Resolve a relative import (level>0) to an absolute dotted module name."""
    pkg = current.split(".")[:-1]                 # current module's package
    if level > 1:
        pkg = pkg[:-(level - 1)] if (level - 1) <= len(pkg) else []
    base = ".".join(pkg)
    if module:
        return f"{base}.{module}" if base else module
    return base


def _internal_targets(tree, current, internal):
    """Return the set of internal modules `current` imports."""
    targets = set()

    def longest_internal(name):
        # 'a.b.c' may be module a.b with attribute c; match the longest internal prefix.
        parts = name.split(".")
        for i in range(len(parts), 0, -1):
            cand = ".".join(parts[:i])
            if cand in internal:
                return cand
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                hit = longest_internal(alias.name)
                if hit and hit != current:
                    targets.add(hit)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(current, node.level, node.module or "")
            for cand in [base] + [f"{base}.{a.name}" for a in node.names]:
                hit = longest_internal(cand)
                if hit and hit != current:
                    targets.add(hit)
    return targets


def _build_graph(repo):
    """Return {module: set(internal modules it imports)}."""
    modules = _collect_modules(repo)
    internal = set(modules)
    graph = {}
    for mod, path in modules.items():
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                tree = ast.parse(fh.read())
        except (SyntaxError, OSError):
            graph[mod] = set()
            continue
        graph[mod] = _internal_targets(tree, mod, internal)
    return graph


def _find_cycles(graph):
    """Tarjan's SCC — any component with >1 node (or a self-loop) is a circular dep."""
    index = {}
    low = {}
    stack = []
    on_stack = set()
    counter = [0]
    sccs = []

    def strongconnect(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph.get(v, ()):
            if w not in index:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for v in graph:
        if v not in index:
            strongconnect(v)

    cycles = [c for c in sccs if len(c) > 1]
    cycles += [[v] for v in graph if v in graph.get(v, ())]  # self-imports
    return cycles


def _dependency_checks(repo):
    graph = _build_graph(repo)
    issues = []

    # Circular dependencies.
    for cycle in _find_cycles(graph):
        issues.append(_arch_issue(
            Severity.HIGH, "circular-dependency",
            f"Circular import dependency among: {' → '.join(sorted(cycle))}",
            "Break the cycle by extracting shared code into a lower-level module.",
        ))

    # Fan-in / fan-out → god-module detection.
    fan_in = {m: 0 for m in graph}
    for src, targets in graph.items():
        for t in targets:
            if t in fan_in:
                fan_in[t] += 1
    for mod in graph:
        fo = len(graph[mod])
        fi = fan_in.get(mod, 0)
        if fi >= _FANIN_THRESHOLD and fo >= _FANOUT_THRESHOLD:
            issues.append(_arch_issue(
                Severity.MEDIUM, "god-module",
                f"Module '{mod}' is highly coupled (fan-in={fi}, fan-out={fo})",
                "Split responsibilities — it is both widely depended on and depends on many modules.",
            ))

    metrics = {
        "modules": len(graph),
        "edges": sum(len(t) for t in graph.values()),
        "max_fan_in": max(fan_in.values()) if fan_in else 0,
        "cycles": len(_find_cycles(graph)),
    }
    return issues, metrics


# ── LangGraph node ──────────────────────────────────────────────────────────────

def run_architecture_agent(state: ReviewState) -> dict:
    repo = state.repo_path
    if not repo or not os.path.isdir(repo):
        return {"architecture_output": AgentOutput(
            agent_name="architecture",
            summary="No repo path provided; architecture review skipped.",
        )}

    structure = _structure_checks(repo)
    deps, metrics = _dependency_checks(repo)
    all_issues = structure + deps

    summary = (
        f"Reviewed repo structure + {metrics['modules']} modules "
        f"({metrics['edges']} internal imports, {metrics['cycles']} cycle(s), "
        f"max fan-in {metrics['max_fan_in']}). Found {len(all_issues)} architecture issue(s)."
    )
    return {"architecture_output": AgentOutput(
        agent_name="architecture", issues=all_issues, summary=summary,
    )}
