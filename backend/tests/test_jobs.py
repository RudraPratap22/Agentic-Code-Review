"""Tests for the in-memory async job store."""

import time
import jobs


def _wait_for(job_id, status, timeout=2.0):
    """Poll the store until the job reaches `status` (or time out)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = jobs.get(job_id)
        if job and job["status"] == status:
            return job
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {status}: {jobs.get(job_id)}")


def test_submit_runs_fn_and_reaches_done():
    job_id = jobs.submit(lambda a, b: a + b, 2, 3)
    assert isinstance(job_id, str) and job_id
    job = _wait_for(job_id, "done")
    assert job["result"] == 5
    assert job["error"] is None


def test_failure_is_captured_as_error():
    def boom():
        raise ValueError("kaboom")
    job_id = jobs.submit(boom)
    job = _wait_for(job_id, "error")
    assert "kaboom" in job["error"]
    assert job["result"] is None


def test_get_unknown_id_returns_none():
    assert jobs.get("does-not-exist") is None
