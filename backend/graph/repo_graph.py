"""Outer repo-level graph: fan out over files with Send (map), collect, then architecture.

The per-file graph (review_graph.py) reviews ONE file with 4 agents in parallel. This
graph wraps it for the WHOLE repo:

  prep            — walk files + run the batched Bandit/Semgrep/Ruff scans once
  fan_out (Send)  — dispatch one concurrent branch per file (map)
  review_one_file — run the per-file graph on one file; its issues are ADDED to the shared
                    list by a reducer (so concurrent branches don't clobber each other)
  architecture    — run once over the whole repo, riding the same reducer (fan-in)

This replaces the old serial `for` loop in pipeline.py: files now run up to
`max_concurrency` at a time, overlapping their LLM waits instead of stacking them.
"""

import operator
from typing import Annotated, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from models.state import ReviewState, Issue
from agents.external_tools import (walk_python_files, run_bandit_repo,
                                    run_semgrep_repo, run_ruff_repo)
from agents.quality_agent import _RUFF_QUALITY_SELECT, _RUFF_CONFIG
from agents.architecture_agent import run_architecture_agent
from graph.review_graph import file_review_graph

# The per-file agents write to these state slots (architecture is repo-level, handled below).
_FILE_KEYS = ["security_output", "quality_output", "performance_output", "documentation_output"]


class RepoState(TypedDict):
    repo_path: str
    files: list                         # [(rel_path, code), ...]
    tool_findings_by_file: dict          # {rel_path: {"bandit": [...], "semgrep": [...], "ruff": [...]}}
    # Reducer: when concurrent file branches (and architecture) return issues, ADD them
    # into one shared list instead of overwriting each other.
    all_issues: Annotated[list, operator.add]


def prep(state: RepoState) -> dict:
    """Walk the repo and run the three batched tool scans once, grouped by file."""
    repo_path = state["repo_path"]
    files = walk_python_files(repo_path)
    bandit = run_bandit_repo(repo_path)
    semgrep = run_semgrep_repo(repo_path)
    ruff = run_ruff_repo(repo_path, _RUFF_QUALITY_SELECT, _RUFF_CONFIG)
    tf = {
        rel: {"bandit": bandit.get(rel, []),
              "semgrep": semgrep.get(rel, []),
              "ruff": ruff.get(rel, [])}
        for rel, _code in files
    }
    return {"files": files, "tool_findings_by_file": tf}


def fan_out(state: RepoState):
    """Dynamic map step: emit one concurrent Send per file into review_one_file."""
    return [
        Send("review_one_file", {
            "rel_path": rel,
            "code": code,
            "tool_findings": state["tool_findings_by_file"][rel],
        })
        for rel, code in state["files"]
    ]


def review_one_file(payload: dict) -> dict:
    """Run the existing per-file graph on ONE file; return its issues for the reducer."""
    result = file_review_graph.invoke(ReviewState(
        code=payload["code"],
        filename=payload["rel_path"],
        tool_findings=payload["tool_findings"],
    ))
    issues: list[Issue] = []
    for key in _FILE_KEYS:
        output = result[key]
        if output:
            for issue in output.issues:
                issue.filename = payload["rel_path"]   # stamp which file this came from
                issues.append(issue)
    return {"all_issues": issues}                      # reducer ADDs this into the shared list


def architecture(state: RepoState) -> dict:
    """Repo-level architecture agent, once over the whole directory (fan-in step)."""
    arch = run_architecture_agent(
        ReviewState(code="", repo_path=state["repo_path"])
    )["architecture_output"]
    return {"all_issues": arch.issues if arch else []}


def build_repo_graph():
    g = StateGraph(RepoState)
    g.add_node("prep", prep)
    g.add_node("review_one_file", review_one_file)
    g.add_node("architecture", architecture)
    g.add_edge(START, "prep")
    g.add_conditional_edges("prep", fan_out, ["review_one_file"])   # map: one Send per file
    g.add_edge("review_one_file", "architecture")   # fan-in: architecture waits for all files
    g.add_edge("architecture", END)
    return g.compile()


repo_review_graph = build_repo_graph()
