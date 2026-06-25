"""
Repo-level orchestration: review every file in a folder and produce one report.

This is the application-level MAP-REDUCE that wraps the per-file LangGraph graph:
  MAP    — run the per-file graph on each .py file
  (once) — run the architecture agent on the whole repo
  REDUCE — render one combined report over all findings
"""

import os
from models.state import ReviewState, Issue
from agents.external_tools import walk_python_files
from agents.architecture_agent import run_architecture_agent
from agents.supervisor_agent import render_report
from graph.review_graph import file_review_graph

# The per-file agents write to these state slots (the architecture slot is repo-level).
_FILE_KEYS = ["security_output", "quality_output", "performance_output", "documentation_output"]


def review_repo(repo_path: str) -> str:
    repo_path = os.path.abspath(repo_path)
    all_issues: list[Issue] = []

    # ── MAP: review each file with the per-file graph (4 agents in parallel) ──
    files = walk_python_files(repo_path)
    for rel_path, code in files:
        result = file_review_graph.invoke(ReviewState(code=code, filename=rel_path))
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

    # ── REDUCE: one report over everything ──
    title = f"{os.path.basename(repo_path)} ({len(files)} files)"
    return render_report(all_issues, title)
