"""
Repo-level orchestration: review every file in a folder and produce one report.

This is the application-level MAP-REDUCE that wraps the per-file LangGraph graph:
  MAP    — run the per-file graph on each .py file
  (once) — run the architecture agent on the whole repo
  REDUCE — render one combined report over all findings
"""

import os
import shutil
import tempfile
import subprocess
from models.state import ReviewState, Issue
from agents.external_tools import (walk_python_files, run_bandit_repo,
                                   run_semgrep_repo, run_ruff_repo)
from agents.quality_agent import _RUFF_QUALITY_SELECT, _RUFF_CONFIG
from agents.architecture_agent import run_architecture_agent
from agents.supervisor_agent import render_report
from graph.review_graph import file_review_graph

# The per-file agents write to these state slots (the architecture slot is repo-level).
_FILE_KEYS = ["security_output", "quality_output", "performance_output", "documentation_output"]


def collect_repo_findings(repo_path: str, repo_name: str | None = None):
    """Producer: review a folder and return (title, list[Issue]) — the raw findings.

    The map-reduce lives here; consumers (render_report / the API / posting) build on
    top of the same collection so there's one source of truth for the findings.
    """
    repo_path = os.path.abspath(repo_path)
    all_issues: list[Issue] = []

    # ── MAP: review each file with the per-file graph (4 agents in parallel) ──
    files = walk_python_files(repo_path)

    # Run each deterministic tool ONCE over the whole repo, grouped by file, instead of
    # spawning it per file inside every agent (3 boots total vs ~3×N). Each file is then
    # handed only its own slice via ReviewState.tool_findings.
    bandit_by_file = run_bandit_repo(repo_path)
    semgrep_by_file = run_semgrep_repo(repo_path)
    ruff_by_file = run_ruff_repo(repo_path, _RUFF_QUALITY_SELECT, _RUFF_CONFIG)

    for rel_path, code in files:
        result = file_review_graph.invoke(ReviewState(
            code=code,
            filename=rel_path,
            tool_findings={
                # [] (not None) when a file has no findings: the batch DID run, so the
                # agent must not re-spawn the tool. None would trigger the fallback.
                "bandit": bandit_by_file.get(rel_path, []),
                "semgrep": semgrep_by_file.get(rel_path, []),
                "ruff": ruff_by_file.get(rel_path, []),
            },
        ))
        for key in _FILE_KEYS:
            output = result[key]
            if output:
                for issue in output.issues:
                    issue.filename = rel_path     # stamp which file this came from
                    all_issues.append(issue)

    # ── Repo-level: architecture once over the whole directory ──
    arch = run_architecture_agent(ReviewState(code="", repo_path=repo_path))["architecture_output"]
    if arch:
        all_issues.extend(arch.issues)

    name = repo_name or os.path.basename(repo_path)
    return f"{name} ({len(files)} files)", all_issues


def review_repo(repo_path: str, repo_name: str | None = None) -> str:
    """Consumer: render the findings as one markdown report (CLI path)."""
    title, issues = collect_repo_findings(repo_path, repo_name)
    return render_report(issues, title)


def collect_github_findings(url: str):
    """Producer for a repo URL: clone → collect → (title, list[Issue]); always cleans up."""
    tmpdir = tempfile.mkdtemp(prefix="acr_clone_")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", url, tmpdir],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr.strip()}")

        repo_name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        return collect_repo_findings(tmpdir, repo_name=repo_name)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def review_github(url: str) -> str:
    """Consumer: clone + render the findings as markdown (CLI path)."""
    title, issues = collect_github_findings(url)
    return render_report(issues, title)
