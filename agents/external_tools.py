"""
Shared helpers for agents that shell out to external CLI tools (Bandit, Semgrep,
Ruff, ...) and for deterministic dedupe/corroboration across tools.

Keeping this in one place means every agent runs tools and merges findings the same
way — the tool itself practices the DRY principle it reviews for.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
from typing import Callable, Hashable
from models.state import Issue, Severity


def tool_bin(name: str) -> str:
    """Locate a CLI tool inside this venv, falling back to PATH."""
    candidate = os.path.join(os.path.dirname(sys.executable), name)
    return candidate if os.path.exists(candidate) else (shutil.which(name) or name)


def run_json_tool(argv: list[str], code: str, suffix: str = ".py"):
    """
    Write `code` to a temp file, run `argv + [tmpfile]`, and return the parsed JSON
    from stdout. Returns None if the tool is missing or emits no/invalid JSON.

    This is the one place the tempfile + subprocess + json pattern lives — Bandit,
    Semgrep, and Ruff runners all build their argv and call this.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        proc = subprocess.run(argv + [tmp_path], capture_output=True, text=True, check=False)
        return json.loads(proc.stdout)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# Lower number = more severe; used to pick the representative when merging duplicates.
SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def dedupe(issues: list[Issue], canonical_of: Callable[[Issue], Hashable]) -> list[Issue]:
    """
    Collapse findings that multiple deterministic tools reported for the same bug.

    `canonical_of(issue)` returns a key that is identical for the same underlying bug
    across tools (e.g. AST 'too-many-arguments' and Ruff 'PLR0913' → the same key).
    For each group we keep the highest-severity issue (never downgrade a risk) and
    record the OTHER tools in `corroborated_by`, preserving a rule_id as evidence.
    Fully deterministic — no LLM involved.
    """
    groups: dict[Hashable, list[Issue]] = {}
    order: list[Hashable] = []
    for issue in issues:
        key = canonical_of(issue)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(issue)

    merged: list[Issue] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])
            continue

        primary = min(group, key=lambda i: SEVERITY_RANK[i.severity])
        for other in group:
            if other is primary:
                continue
            # Corroboration only counts from a DIFFERENT tool, not the primary's own source.
            if other.source != primary.source and other.source not in primary.corroborated_by:
                primary.corroborated_by.append(other.source)
            if other.rule_id and not primary.rule_id:
                primary.rule_id = other.rule_id
        merged.append(primary)
    return merged
