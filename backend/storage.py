"""Durable storage for finished review results, behind a swappable interface.

The job store (jobs.py) keeps only tiny status notes in memory; the heavy review result
is persisted here so it survives a server restart and doesn't pile up in RAM.

LocalStore writes one JSON file per job under storage/. Swapping to S3/Redis/SQLite later
is just a new Store subclass — callers never change.
"""

import re
import json
from pathlib import Path

# A job_id arrives from the URL (GET /jobs/{id}), so validate it before touching the
# filesystem — this refuses path-traversal ids like "../../etc/passwd".
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]+$")


class Store:
    """Interface: any result store must be able to save and load by job_id."""

    def save(self, job_id: str, result) -> None:
        raise NotImplementedError

    def load(self, job_id: str):
        raise NotImplementedError


class LocalStore(Store):
    """Persist each result as storage/<job_id>.json on the local disk."""

    def __init__(self, root: str = "storage"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, job_id: str) -> Path | None:
        """Map a job_id to its file path, or None if the id is unsafe."""
        if not _SAFE_ID.match(job_id):
            return None
        return self.root / f"{job_id}.json"

    def save(self, job_id: str, result) -> None:
        p = self._path(job_id)
        if p:
            p.write_text(json.dumps(result))

    def load(self, job_id: str):
        """Return the stored result, or None if the id is unsafe / unknown."""
        p = self._path(job_id)
        return json.loads(p.read_text()) if (p and p.exists()) else None
