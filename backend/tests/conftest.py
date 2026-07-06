"""Shared test fixtures."""

import pytest
import jobs
from storage import LocalStore


@pytest.fixture(autouse=True)
def _isolate_store(tmp_path, monkeypatch):
    """Point the job store at a throwaway dir so tests never touch the real storage/."""
    monkeypatch.setattr(jobs, "_store", LocalStore(str(tmp_path / "store")))
