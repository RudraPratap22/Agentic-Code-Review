# 🔍 Agentic Code Review

A team of agents (built with **LangGraph**) reviews a codebase — a local folder, a GitHub
repo, or a pull request — and flags bugs, security holes, and violations of production
best practices. For each issue it explains **what's wrong, why it matters, and how to fix it**.

## The problem it solves

Most code today is increasingly AI-generated. AI writes fast but makes mistakes and often
ignores production discipline (error handling, security, testing, observability). This
system catches that — and answers the obvious objection head-on:

> **"Isn't using AI to review AI-written code circular?"**

It avoids that trap with a **two-tier trust model**:

- **✅ Verified tier** — findings from *deterministic* sources that **cannot hallucinate**:
  hand-written AST checks + industry tools (**Bandit**, **Semgrep**, **Ruff**) + measured
  metrics (dependency graph, complexity). These are facts.
- **🤖 Suggested tier** — the **LLM**, used only for judgment tools can't make (misleading
  names, comments that lie, design smells). It is clearly labelled lower-trust and **must
  cite the exact line/metric as evidence** — which mechanically stops hallucinations.

Deterministic dedupe surfaces **cross-tool corroboration** (a bug flagged by both Bandit
*and* Semgrep) as a confidence signal — never via the LLM. In short: **deterministic tools
detect; the LLM only explains, always grounded in something verifiable.**

## Features

- **5 specialised agents** — security, code quality, performance, documentation, and a
  whole-repo **architecture** agent (structure checks + import-graph metrics: circular
  dependencies via Tarjan's SCC, fan-in/fan-out, god-modules).
- **Three input modes** — a local folder, a GitHub **repo URL** (shallow clone), or a
  GitHub **pull request** (reviews *only the changed lines* via the diff).
- **Posts inline PR comments** back to GitHub (`--post`), tier-labelled.
- **Corroboration + evidence** — every finding is attributable (rule id, source, cited line).
- **REST API** (FastAPI) returning structured findings as JSON, and a **React** frontend.
- **Tested + hardened** — deterministic pytest suite + mocked-LLM/tool tests; LLM calls
  retry with backoff and degrade gracefully under rate limits.

## Architecture

```
frontend/  — React (Vite) UI  ──HTTP + JSON──►  backend/  — FastAPI + LangGraph engine
                                                  ├─ per-file graph: security · quality ·
                                                  │  performance · documentation (parallel)
                                                  ├─ architecture agent (whole repo)
                                                  └─ supervisor: render Verified vs Suggested
```

- **Per-file review** is a LangGraph graph (4 agents in parallel); `pipeline.py` **maps** it
  over every file and **reduces** the results (application-level map-reduce).
- Each finding is an `Issue` (the universal data shape); the API serialises it to JSON.

## Tech stack

LangGraph · FastAPI · Pydantic · React (Vite) · Bandit · Semgrep · Ruff · Groq (Llama 3.3) · pytest

## Getting started

### 1. Backend
```bash
python -m venv venv && source venv/bin/activate
pip install -r backend/requirements.txt

# add your key(s) to a .env file in the project root:
#   GROQ_API_KEY=...            (required)
#   GITHUB_TOKEN=...            (optional: higher API limits; required to POST PR comments)

cd backend
uvicorn api:app --reload --port 8000     # API + interactive docs at /docs
pytest -q                                # run the test suite
```

CLI (from `backend/`):
```bash
python main.py .                                           # review a local folder
python main.py https://github.com/OWNER/REPO               # review a repo
python main.py https://github.com/OWNER/REPO/pull/1        # review a PR (changed lines)
python main.py https://github.com/OWNER/REPO/pull/1 --post # ...and post inline comments
```

### 2. Frontend
```bash
cd frontend
npm install
npm run dev        # http://localhost:5173  (calls the backend at :8000)
```
Paste a GitHub repo or PR URL and hit **Review** — findings render with severity/tier
filters and corroboration badges.

## How the review works (the flow)

`target → collect findings → Issue objects → split by tier → render`

1. **Detect (deterministic):** AST visitors + Bandit/Semgrep/Ruff produce verified findings;
   duplicates across tools collapse into one, recording who corroborated it.
2. **Interpret (LLM, fenced):** the LLM adds *suggested* findings, each forced to cite a
   line/metric; ungrounded ones are dropped in code.
3. **Report:** the supervisor renders the findings deterministically into **Verified** and
   **Suggested** sections; the LLM writes only the summary + top fixes.

## Roadmap (post-MVP)

Auto-review every PR via a **GitHub Action**; async job queue + object storage for scale;
auto-fix for deterministic findings; multi-language support.
