"""
Repo-level orchestration: review every file in a folder and produce one report.

The MAP-REDUCE over files lives in the outer LangGraph graph (graph/repo_graph.py):
  prep   — walk files + run the batched tool scans once
  MAP    — fan out one concurrent branch per file (Send), reduced into one issue list
  (once) — run the architecture agent on the whole repo
This module is the thin producer/consumer layer on top of it (clone, render, PR paths).
"""

import os
import shutil
import tempfile
import subprocess
from graph.repo_graph import repo_review_graph
from agents.supervisor_agent import render_report

# Cap on files reviewed concurrently. Each file makes ~3 LLM calls, so this bounds
# in-flight requests to keep us under the Groq free-tier rate limit.
_MAX_CONCURRENCY = 4


def collect_repo_findings(repo_path: str, repo_name: str | None = None):
    """Producer: review a folder and return (title, list[Issue]) — the raw findings.

    Delegates the map-reduce to the outer graph: prep (walk + batch tools) → fan out one
    concurrent branch per file (≤ _MAX_CONCURRENCY at once) → architecture once. Consumers
    (render_report / the API / posting) build on this one collection.
    """
    repo_path = os.path.abspath(repo_path)
    result = repo_review_graph.invoke(
        {"repo_path": repo_path, "all_issues": []},
        config={"max_concurrency": _MAX_CONCURRENCY},
    )
    all_issues = result["all_issues"]
    files = result["files"]
    name = repo_name or os.path.basename(repo_path)
    return f"{name} ({len(files)} files)", all_issues


def review_repo(repo_path: str, repo_name: str | None = None) -> str:
    """Consumer: render the findings as one markdown report (CLI path)."""
    title, issues = collect_repo_findings(repo_path, repo_name)
    return render_report(issues, title)


def _clone_url(url: str) -> str:
    """Inject GITHUB_TOKEN so private GitHub repos can be cloned.

    Public repos and non-GitHub / non-https URLs are returned unchanged, so the public
    path behaves exactly as before.
    """
    token = os.getenv("GITHUB_TOKEN")
    if token and url.startswith("https://github.com/"):
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


def _redact(text: str) -> str:
    """Scrub the token from any text shown to the user.

    A tokenized clone URL appears in git's stderr on failure — without this it would leak
    the token into the job's error message and back to the client.
    """
    token = os.getenv("GITHUB_TOKEN")
    return text.replace(token, "***") if token else text


def collect_github_findings(url: str):
    """Producer for a repo URL: clone → collect → (title, list[Issue]); always cleans up.

    Uses GITHUB_TOKEN (when set) to clone private repos; the token is redacted from any
    error surfaced to the caller.
    """
    tmpdir = tempfile.mkdtemp(prefix="acr_clone_")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", _clone_url(url), tmpdir],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {_redact(proc.stderr.strip())}")

        repo_name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        return collect_repo_findings(tmpdir, repo_name=repo_name)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def review_github(url: str) -> str:
    """Consumer: clone + render the findings as markdown (CLI path)."""
    title, issues = collect_github_findings(url)
    return render_report(issues, title)
