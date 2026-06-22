# Agentic Code Review — Project Plan & Schedule

> A team of LangGraph agents reviews a codebase for bugs, security issues, and
> violations of production best practices. Each finding explains what's wrong, why it
> matters, and how to fix it.

## The thesis (and the answer to "isn't AI reviewing AI circular?")

Most code today is AI-generated, and AI skips production discipline (error handling,
security, tests, observability). This system catches that. It avoids the circularity
trap with a **two-tier trust model**:

- **Verified tier** — deterministic sources that *cannot hallucinate*: hand-written
  AST checks + industry tools (Bandit, Semgrep, Ruff) + measured metrics (dependency
  graph, complexity). These are facts.
- **Suggested tier** — the LLM, used only for subjective judgment tools can't make
  (misleading names, lying comments, design smells). Clearly labelled lower-trust and
  **required to cite the exact line or measured metric as evidence**, which
  mechanically kills hallucinations.

Deterministic dedupe in code surfaces **cross-tool corroboration** (e.g. a bug flagged
by both Bandit and Semgrep) as a confidence signal — never via the LLM.

## Per-agent coverage

| Agent | Verified tier (deterministic) | Suggested tier (LLM) |
|---|---|---|
| **Security** | custom AST + Bandit + Semgrep | — (security findings must be facts) |
| **Quality** | custom AST + Ruff | naming / SRP, with evidence |
| **Performance** | custom AST + Ruff `PERF` rules | **scalability lens** — queue-offload, pagination, caching, N+1 depth, blocking-async; each **cites the code**. Explicitly excludes infra/capacity advice (load balancers, scaling strategy) |
| **Documentation** | custom AST coverage (+ optional `pydocstyle`) | misleading comments, with evidence |
| **Architecture & Structure** | file/layout checks (tests/, README, CI, .gitignore, secrets, packaging) **+ dependency-graph metrics** (circular deps, fan-in/out, complexity via `radon`, layering via `import-linter`) | design interpretation that **cites the measured metric** (e.g. "fan-in 14 → likely god-module") |

Pattern: every agent = *(hand-written AST / measured facts)* + *(industry tool)* in the
Verified tier, plus a *fenced, evidence-citing LLM* in the Suggested tier where judgment
helps. Even architecture *opinions* are anchored to a deterministic measurement.

## Scope (locked)

Backend + **all agents tiered** + **whole-repo structure review** + **grounded
architecture/system-design review** + **code-grounded scalability lens** + **GitHub PR
review** + full testing + frontend UI. PR-review depth (post inline comments vs
display-only) decided when we build it.

**Explicit non-goal:** no infrastructure/capacity recommendations (load balancers,
vertical-vs-horizontal scaling, message-broker choice). The source code does not contain
the runtime/traffic/deployment context those require, so suggesting them would be
ungrounded — the exact circularity trap this project avoids. We flag only scalability
problems visible *in the code*, each citing the line.

## Development workflow (we dogfood our own advice)

A code-review tool that preaches best practices must follow them. So from Day 3 on:

- **No direct commits to `main`.** `main` is protected (PR required).
- **One feature branch per logical change** (usually one Day), named with conventional
  prefixes: `feat/`, `test/`, `docs/`, `chore/`. e.g. `feat/day3-ruff`.
- **Every change goes through a pull request** — branch → push → PR → review → merge.
- **Bonus / dogfooding:** once the PR-review feature (Days 8–9) works, the tool reviews
  its own pull requests.

(Days 1–2 landed directly on `main` as the project foundation; the workflow starts here.)

## Deadlines

- Start: **Jun 20, 2026**
- **Target completion: Jul 3, 2026** (Day 14)
- **Hard deadline (with buffer): Jul 6, 2026**
- Assumes ~2–3 focused hrs/day of *understanding/review* — the bottleneck is learning,
  not coding (the assistant writes the code).

## Day-by-day schedule

| Day | Date | Focus | Agents / area |
|---|---|---|---|
| 1 | Jun 20 | Supervisor: report split into Verified vs Suggested; LLM may not invent issues | All |
| 2 | Jun 21 | Semgrep → 2nd verified security tool + corroboration | Security |
| 3 | Jun 22 | Ruff → verified tier for Quality **and** Performance (`PERF` rules); add code-grounded **scalability lens** (suggested, cites code; no infra advice) | Quality + Performance |
| 4 | Jun 23 | **Architecture & Structure pt1** — file/layout checks + dependency-graph metrics (circular deps, fan-in/out, `radon`, `import-linter`) | Architecture |
| 5 | Jun 24 | **Architecture & Structure pt2** — LLM design interpretation citing the measured metrics (suggested tier) | Architecture |
| 6 | Jun 25 | Real input: walk local folders, multi-file review (LangGraph state design) | Pipeline-wide |
| 7 | Jun 26 | Real input: GitHub URL → clone → review | Pipeline-wide |
| 8 | Jun 27 | **PR review pt1**: fetch PR diff via GitHub API, scope review to changed lines | New feature |
| 9 | Jun 28 | **PR review pt2**: map findings to diff hunks; post-vs-display decided here | New feature |
| 10 | Jun 29 | Tests pt1: `pytest` for all deterministic checks (AST, tool mappings, dedupe, structure, metrics, diff-scoping) | All |
| 11 | Jun 30 | Tests pt2: mocked-LLM integration test; hardening, logging, config | All |
| 12 | Jul 1 | FastAPI backend wraps the graph (repo + PR endpoints, streaming progress) | Backend |
| 13 | Jul 2 | Frontend UI — stack (React vs Streamlit) decided this day; repo/PR input + tiered results | Frontend |
| 14 | Jul 3 | Polish + anti-circularity README + screenshots | Docs |
| Buffer | Jul 4–6 | Slippage, polish, optional deploy (clickable link for recruiters) | — |

## Risk flags (where buffer gets used)

1. **Multi-file state design (Day 6)** — the one genuinely tricky LangGraph decision:
   run the graph per-file vs redesign state for a whole repo. Discuss alternatives first.
2. **Dependency-graph build (Days 4–5)** — resolving imports to modules across a real
   repo is fiddly; metrics must stay deterministic and correct.
3. **PR diff-to-line mapping (Days 8–9)** — mapping findings onto diff hunks + GitHub
   API auth is the most error-prone new work.
4. **Mocking the LLM (Day 11)** — new testing concept (fake the LLM so tests are fast/free).
5. **Frontend stack (Day 13)** — React (impressive, ~1 day more) vs Streamlit (fast).

## Optional stretch (only if buffer allows)

- `pydocstyle` as a 2nd verified tool for Documentation.
- A suggested-tier LLM for Performance design smells.
- Live deployment.

## Status (as of Jun 20, 2026)

Done (pre-Day-1 pilot):
- `Issue` model extended: `tier`, `source`, `rule_id`, `evidence`, `corroborated_by`.
- Security agent: custom AST + Bandit, deterministic dedupe + corroboration, evidence in output.
- Quality + Documentation: LLM moved to `suggested` tier (`source="llm"`), required to cite evidence.
- Repo initialised and pushed to GitHub (personal account, SSH alias `github-personal`).

Teaching note: each step is tagged by skill — **LangGraph** vs **Python** vs **Pydantic**
vs **backend/frontend** — so the three learning tracks stay clear.
