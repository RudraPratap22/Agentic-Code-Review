"""FastAPI backend: an HTTP wrapper around the review engine.

Run with:
    uvicorn api:app --reload --port 8000
Interactive docs at http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models.state import Issue
from agents.supervisor_agent import render_report
from pipeline import collect_github_findings
from github_pr import _collect_pr_findings, _post_findings
import jobs

app = FastAPI(title="Agentic Code Review API")

# Let a browser frontend (a different origin) call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # demo: allow all; tighten to the real frontend origin in prod
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewRequest(BaseModel):
    target: str                     # a GitHub repo URL or PR URL
    post_comments: bool = False     # for PRs: also post inline comments


class Summary(BaseModel):
    total: int
    verified: int
    suggested: int
    by_severity: dict[str, int]


class ReviewResult(BaseModel):
    title: str
    summary: Summary
    findings: list[Issue]           # FastAPI serializes each Issue (a Pydantic model) to JSON
    report_markdown: str


def _summarize(issues) -> Summary:
    by_sev: dict[str, int] = {}
    for i in issues:
        by_sev[i.severity.value] = by_sev.get(i.severity.value, 0) + 1
    return Summary(
        total=len(issues),
        verified=sum(1 for i in issues if i.tier == "verified"),
        suggested=sum(1 for i in issues if i.tier == "suggested"),
        by_severity=by_sev,
    )


@app.get("/health")
def health():
    return {"status": "ok"}


def _do_review(target: str, post_comments: bool) -> dict:
    """The actual review — runs on a background worker thread, not the request thread.

    Returns a plain JSON-serializable dict (not the ReviewResult object) so the job store
    can persist it to disk.
    """
    if "/pull/" in target:                         # a pull request
        owner, repo, number, issues = _collect_pr_findings(target)
        title = f"PR #{number} — {owner}/{repo}"
        if post_comments and issues:
            _post_findings(owner, repo, number, issues)
    else:                                          # a repo URL
        title, issues = collect_github_findings(target)
    return ReviewResult(
        title=title,
        summary=_summarize(issues),
        findings=issues,
        report_markdown=render_report(issues, title),
    ).model_dump(mode="json")


@app.post("/review")
def review(req: ReviewRequest):
    """Kick off a review in the background and return a job_id immediately (no blocking)."""
    job_id = jobs.submit(_do_review, req.target, req.post_comments)
    return {"job_id": job_id, "status": "queued"}


@app.get("/jobs/{job_id}")
def job_status(job_id: str):
    """Poll a job: {status, result, error}. result is a ReviewResult once status is 'done'."""
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job id")
    return job
