"""Async job store: run slow work off the request thread and poll for it.

A review can take minutes on a big repo — far longer than a browser (or proxy) will
hold an HTTP connection open. So instead of blocking the request, the API `submit`s the
review here, gets a `job_id` back instantly, and the browser polls `get(job_id)` until
the job is done.

Split by durability: the small STATUS lives in an in-memory dict (fine to lose on
restart); the heavy RESULT is persisted to the Store (survives restart, doesn't pile up
in RAM). `get` falls back to the Store when memory has forgotten a job — that's what
makes a finished result outlive a restart. A cross-process Redis/Celery queue is a later
option if we ever need multi-instance durability.
"""

from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

from storage import LocalStore

# Where finished results are persisted (tests swap this for a temp dir via conftest.py).
_store = LocalStore()

# job_id -> {"status": queued|running|done|error, "error": str|None}. The RESULT is NOT
# kept here — it goes to _store — so memory holds only tiny status notes.
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
    JOBS[job_id] = {"status": "queued", "error": None}
    _pool.submit(_run, job_id, fn, *args)
    return job_id


def _run(job_id: str, fn, *args) -> None:
    """Run one job on a worker thread: persist the result, record status in memory."""
    JOBS[job_id]["status"] = "running"
    try:
        _store.save(job_id, fn(*args))       # heavy result → disk (persist BEFORE 'done',
        JOBS[job_id]["status"] = "done"       # so a poller never sees done without a result)
    except Exception as e:                   # a background exception would otherwise vanish
        JOBS[job_id]["error"] = str(e)
        JOBS[job_id]["status"] = "error"


def get(job_id: str) -> dict | None:
    """Return {status, result, error}, or None if the id is unknown.

    result is loaded from the Store only once the job is done. If memory has forgotten the
    job (e.g. after a restart) we still check the Store — a persisted result means it
    finished earlier, so it survives the restart.
    """
    job = JOBS.get(job_id)
    if job is not None:
        result = _store.load(job_id) if job["status"] == "done" else None
        return {"status": job["status"], "result": result, "error": job["error"]}

    result = _store.load(job_id)             # not in memory — maybe persisted pre-restart
    if result is not None:
        return {"status": "done", "result": result, "error": None}
    return None
