"""Tests for durable result storage (LocalStore) and the job-store restart fallback."""

import jobs
from storage import LocalStore


def test_local_store_round_trip(tmp_path):
    store = LocalStore(str(tmp_path))
    store.save("abc123", {"title": "hi", "n": 1})
    assert store.load("abc123") == {"title": "hi", "n": 1}


def test_local_store_unknown_id_returns_none(tmp_path):
    assert LocalStore(str(tmp_path)).load("never-saved") is None


def test_local_store_rejects_path_traversal(tmp_path):
    store = LocalStore(str(tmp_path))
    store.save("../escape", {"x": 1})            # unsafe id → refused, nothing written
    assert store.load("../escape") is None
    assert not (tmp_path.parent / "escape.json").exists()


def test_result_survives_restart(tmp_path, monkeypatch):
    # A finished job's result must be retrievable even after in-memory state is wiped.
    store = LocalStore(str(tmp_path / "store"))
    monkeypatch.setattr(jobs, "_store", store)

    import time
    job_id = jobs.submit(lambda: {"title": "done-report"})
    deadline = time.time() + 2.0
    while time.time() < deadline and jobs.get(job_id)["status"] != "done":
        time.sleep(0.01)
    assert jobs.get(job_id)["result"] == {"title": "done-report"}

    jobs.JOBS.clear()                            # simulate a server restart (memory wiped)
    recovered = jobs.get(job_id)                 # ...but the Store still has it
    assert recovered["status"] == "done"
    assert recovered["result"] == {"title": "done-report"}
