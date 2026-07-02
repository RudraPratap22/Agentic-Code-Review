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
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field
from models.state import ReviewState, AgentOutput, Issue, Severity
from agents.external_tools import llm_invoke, drop_duplicate_suggestions

load_dotenv()

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


def _graph_metrics(graph):
    """Per-module fan-in/fan-out, computed once and reused by both tiers."""
    fan_in = {m: 0 for m in graph}
    for _src, targets in graph.items():
        for t in targets:
            if t in fan_in:
                fan_in[t] += 1
    modules_metrics = [
        {"module": m, "fan_in": fan_in[m], "fan_out": len(graph[m])}
        for m in sorted(graph)
    ]
    return modules_metrics, fan_in


def _deterministic_dep_issues(modules_metrics, cycles):
    """The VERIFIED dependency findings: circular imports and god-modules."""
    issues = []
    for cycle in cycles:
        issues.append(_arch_issue(
            Severity.HIGH, "circular-dependency",
            f"Circular import dependency among: {' → '.join(sorted(cycle))}",
            "Break the cycle by extracting shared code into a lower-level module.",
        ))
    for m in modules_metrics:
        if m["fan_in"] >= _FANIN_THRESHOLD and m["fan_out"] >= _FANOUT_THRESHOLD:
            issues.append(_arch_issue(
                Severity.MEDIUM, "god-module",
                f"Module '{m['module']}' is highly coupled "
                f"(fan-in={m['fan_in']}, fan-out={m['fan_out']})",
                "Split responsibilities — it is both widely depended on and depends on many modules.",
            ))
    return issues


# ── Suggested tier: LLM interprets the MEASURED metrics (never the source) ───────

class LLMArchIssue(BaseModel):
    category: str
    severity: str = Field(description="one of: critical, high, medium, low")
    description: str
    suggestion: str
    evidence: str = Field(
        description="The EXACT measured metric you are reacting to, e.g. "
                    "'fan_in=7 on models.state'. Required — no metric, no finding."
    )


class LLMArchResponse(BaseModel):
    issues: list[LLMArchIssue] = Field(default_factory=list)


def _metrics_digest(modules_metrics, cycles):
    """Render the measured metrics as plain text — the ONLY thing the LLM sees."""
    lines = ["MODULE COUPLING METRICS (module: fan_in, fan_out):"]
    for m in modules_metrics:
        lines.append(f"  {m['module']}: fan_in={m['fan_in']}, fan_out={m['fan_out']}")
    cyc = [" → ".join(sorted(c)) for c in cycles] or ["none"]
    lines.append("CIRCULAR DEPENDENCIES: " + "; ".join(cyc))
    return "\n".join(lines)


def _run_design_interpretation(modules_metrics, cycles):
    """LLM design observations grounded ONLY in the measured metrics, each citing one."""
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"))
    structured = llm.with_structured_output(LLMArchResponse)

    prompt = f"""You are a software architecture reviewer. You are given ONLY measured
dependency metrics for a codebase — you do NOT see the source code. Interpret them for
DESIGN problems (poor separation of concerns, unstable/high coupling, layering smells).

IMPORTANT NUANCE:
- High fan_in with LOW fan_out is a NORMAL shared leaf module (e.g. a types/models file) —
  do NOT flag it.
- Circular dependencies and god-modules are already reported separately; add subtler
  observations, or confirm one with extra insight only if clearly warranted.

STRICT RULES:
- Reason ONLY from the metrics below. Never invent a module or a number not listed.
- Do NOT suggest infrastructure/scaling — this is about code structure only.
- For EVERY issue, cite the exact metric in `evidence` (e.g. 'fan_in=7 on models.state').
- If the metrics look healthy, return an empty list.

METRICS:
{_metrics_digest(modules_metrics, cycles)}
"""
    response = llm_invoke(structured, prompt)
    if response is None:
        return []                      # LLM unavailable → degrade gracefully

    issues = []
    for item in response.issues:
        if not (item.evidence and item.evidence.strip()):
            continue
        try:
            sev = Severity(item.severity.lower())
        except ValueError:
            sev = Severity.LOW
        issues.append(Issue(
            agent="architecture", severity=sev, category=item.category,
            description=item.description, suggestion=item.suggestion, line_number=None,
            tier="suggested", source="llm", evidence=item.evidence,
        ))
    return drop_duplicate_suggestions(issues)


# ── LangGraph node ──────────────────────────────────────────────────────────────

def run_architecture_agent(state: ReviewState) -> dict:
    repo = state.repo_path
    if not repo or not os.path.isdir(repo):
        return {"architecture_output": AgentOutput(
            agent_name="architecture",
            summary="No repo path provided; architecture review skipped.",
        )}

    # ── Verified tier (deterministic) ──
    structure = _structure_checks(repo)
    graph = _build_graph(repo)
    modules_metrics, _fan_in = _graph_metrics(graph)
    cycles = _find_cycles(graph)
    verified = structure + _deterministic_dep_issues(modules_metrics, cycles)

    # ── Suggested tier (LLM interprets the measured metrics) ──
    suggested = _run_design_interpretation(modules_metrics, cycles)

    all_issues = verified + suggested
    summary = (
        f"Reviewed structure + {len(modules_metrics)} modules ({len(cycles)} cycle(s)). "
        f"{len(verified)} verified, {len(suggested)} suggested architecture issue(s)."
    )
    return {"architecture_output": AgentOutput(
        agent_name="architecture", issues=all_issues, summary=summary,
    )}
