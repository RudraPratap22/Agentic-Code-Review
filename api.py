"""FastAPI backend: an HTTP wrapper around the review engine.

Run with:
    uvicorn api:app --reload --port 8000
Interactive docs at http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline import review_github
from github_pr import review_pr, post_pr_review

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


class ReviewResponse(BaseModel):
    report: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/review", response_model=ReviewResponse)
def review(req: ReviewRequest):
    try:
        if "/pull/" in req.target:                     # a pull request
            report = post_pr_review(req.target) if req.post_comments else review_pr(req.target)
        else:                                          # a repo URL
            report = review_github(req.target)
        return ReviewResponse(report=report)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
