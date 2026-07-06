"""In-memory async job store: run slow work off the request thread and poll for it.

A review can take minutes on a big repo — far longer than a browser (or proxy) will
hold an HTTP connection open. So instead of blocking the request, the API `submit`s the
review here, gets a `job_id` back instantly, and the browser polls `get(job_id)` until
the job is done.

Deliberately simple: a plain dict + a small thread pool, no external infra. The store is
in-memory, so jobs are lost on restart and don't span multiple server instances — fine
for a single-instance demo. Persistence comes in the object-storage upgrade; a heavier
Redis/Celery queue is a later option if we ever need cross-process durability.
"""

from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

# job_id -> {"status": queued|running|done|error, "result": <any>|None, "error": str|None}
JOBS: dict[str, dict] = {}

# At most 2 reviews run at once. Each review already fans out to ~4 files internally
# (Send parallelism), so this bounds total in-flight LLM work and stays under the Groq
# free-tier rate limit. Extra submissions queue here automatically until a worker frees up.
_pool = ThreadPoolExecutor(max_workers=2)


def submit(fn, *args) -> str:
    """Schedule fn(*args) to run in the background; return a job_id immediately.

    Generic on purpose — it runs any callable, not just reviews — so the store has no
    knowledge of the review pipeline.
    """
    job_id = uuid4().hex
    JOBS[job_id] = {"status": "queued", "result": None, "error": None}
    _pool.submit(_run, job_id, fn, *args)
    return job_id


def _run(job_id: str, fn, *args) -> None:
    """Run one job on a worker thread, recording its outcome on the shared store."""
    JOBS[job_id]["status"] = "running"
    try:
        JOBS[job_id]["result"] = fn(*args)   # set result BEFORE flipping to done, so a
        JOBS[job_id]["status"] = "done"      # poller never sees done without a result
    except Exception as e:                   # a background exception would otherwise vanish
        JOBS[job_id]["error"] = str(e)
        JOBS[job_id]["status"] = "error"


def get(job_id: str) -> dict | None:
    """Return a job's current state, or None if the id is unknown."""
    return JOBS.get(job_id)
