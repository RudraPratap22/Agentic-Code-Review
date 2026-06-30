"""
Pull-request review: fetch a GitHub PR's changed files via the API, review each
changed .py file, and keep only the findings on lines the PR actually added/changed.

No clone — we fetch only what changed. The architecture agent is skipped (it needs the
whole repo, which a PR diff doesn't provide).
"""

import os
import re
import requests
from dotenv import load_dotenv
from models.state import ReviewState
from agents.supervisor_agent import render_report
from graph.review_graph import file_review_graph

load_dotenv()

_API = "https://api.github.com"
_FILE_KEYS = ["security_output", "quality_output", "performance_output", "documentation_output"]
_PR_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _parse_pr_url(url: str):
    """'.../OWNER/REPO/pull/N' → (owner, repo, number)."""
    m = _PR_RE.search(url)
    if not m:
        raise ValueError(f"Not a GitHub PR URL: {url}")
    return m.group(1), m.group(2), int(m.group(3))


def _headers() -> dict:
    """GitHub API headers; add a bearer token if GITHUB_TOKEN is set (optional)."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _added_lines(patch: str) -> set[int]:
    """Unified-diff patch → set of NEW-file line numbers that were added/changed."""
    added: set[int] = set()
    new_line = 0
    for line in patch.splitlines():
        m = _HUNK_RE.match(line)
        if m:
            new_line = int(m.group(1))            # new file resumes at this line
        elif line.startswith("+") and not line.startswith("+++"):
            added.add(new_line)                   # an ADDED line in the new file
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass                                  # removed line — not in the new file
        elif line.startswith("\\"):
            pass                                  # "\ No newline at end of file"
        else:
            new_line += 1                         # context line — advance
    return added


def _collect_pr_findings(pr_url: str):
    """Fetch the PR, review changed files, scope findings to changed lines.
    Returns (owner, repo, number, list[Issue]) — the shared producer."""
    owner, repo, number = _parse_pr_url(pr_url)
    resp = requests.get(
        f"{_API}/repos/{owner}/{repo}/pulls/{number}/files?per_page=100",
        headers=_headers(), timeout=30,
    )
    resp.raise_for_status()

    all_issues = []
    for f in resp.json():
        name = f["filename"]
        patch = f.get("patch")
        if f["status"] == "removed" or not name.endswith(".py") or not patch:
            continue                              # skip deletions / non-python / binary
        added = _added_lines(patch)
        if not added:
            continue

        code = requests.get(f["raw_url"], headers=_headers(), timeout=30).text  # full new file
        result = file_review_graph.invoke(ReviewState(code=code, filename=name))
        for key in _FILE_KEYS:
            output = result[key]
            if output:
                for issue in output.issues:
                    if issue.line_number in added:    # keep only findings on changed lines
                        issue.filename = name
                        all_issues.append(issue)

    return owner, repo, number, all_issues


def review_pr(pr_url: str) -> str:
    """Consumer 1: render the scoped findings as a markdown report (read-only)."""
    owner, repo, number, issues = _collect_pr_findings(pr_url)
    return render_report(issues, f"PR #{number} — {owner}/{repo}")


def _issue_to_comment(issue) -> dict:
    """One Issue → a GitHub inline review-comment payload (path + line + side + body)."""
    tier = "✅ Verified" if issue.tier == "verified" else "🤖 Suggested (lower confidence)"
    rule = f" `{issue.rule_id}`" if issue.rule_id else ""
    body = (f"**[{issue.severity.value.upper()}] {issue.category}**{rule} — {tier}\n\n"
            f"{issue.description}\n\n**Suggested fix:** {issue.suggestion}")
    return {"path": issue.filename, "line": issue.line_number, "side": "RIGHT", "body": body}


def post_pr_review(pr_url: str) -> str:
    """Consumer 2: post the scoped findings as ONE batched inline review on the PR."""
    if not os.getenv("GITHUB_TOKEN"):
        raise RuntimeError("Posting requires GITHUB_TOKEN (pull-request write scope) in .env")

    owner, repo, number, issues = _collect_pr_findings(pr_url)
    if not issues:
        return f"No issues on changed lines for PR #{number} — nothing to post."

    comments = [_issue_to_comment(i) for i in issues]
    verified = sum(1 for i in issues if i.tier == "verified")
    body = (f"🤖 Automated review — {len(issues)} finding(s) on changed lines "
            f"({verified} verified, {len(issues) - verified} suggested). "
            f"Verified = deterministic tools; suggested = LLM hints.")

    resp = requests.post(
        f"{_API}/repos/{owner}/{repo}/pulls/{number}/reviews",
        headers=_headers(), timeout=30,
        json={"event": "COMMENT", "body": body, "comments": comments},
    )
    resp.raise_for_status()
    return f"Posted a review with {len(comments)} inline comment(s) to PR #{number}."
