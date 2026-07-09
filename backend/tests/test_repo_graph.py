"""Tests for the outer repo graph's map-reduce wiring (fan-out + reducer)."""

import graph.repo_graph as rg
from models.state import AgentOutput, Issue, Severity


def test_fan_out_emits_one_send_per_file():
    state = {
        "files": [("a.py", "x=1", "python"), ("b.js", "y=2", "javascript"),
                  ("c.py", "z=3", "python")],
        "tool_findings_by_file": {"a.py": {}, "b.js": {}, "c.py": {}},
    }
    sends = rg.fan_out(state)
    assert len(sends) == 3                                  # one Send per file
    assert {s.node for s in sends} == {"review_one_file"}   # all into the per-file node
    # each Send carries that file's payload, including its language
    assert {s.arg["rel_path"] for s in sends} == {"a.py", "b.js", "c.py"}
    assert {s.arg["language"] for s in sends} == {"python", "javascript"}


def test_reducer_collects_issues_across_files(monkeypatch):
    # Stub the per-file graph so each file returns exactly one issue in its security slot.
    def _one_issue(rel):
        return Issue(agent="security", severity=Severity.LOW, category="c",
                     description="d", suggestion="s")

    class FakeGraph:
        def invoke(self, state):
            slots = {k: None for k in rg._FILE_KEYS}
            slots["security_output"] = AgentOutput(
                agent_name="security", issues=[_one_issue(state.filename)])
            return slots

    monkeypatch.setattr(rg, "file_review_graph", FakeGraph())
    monkeypatch.setattr(rg, "prep", lambda s: {
        "files": [("a.py", "", "python"), ("b.py", "", "python")],
        "tool_findings_by_file": {"a.py": {}, "b.py": {}},
    })
    monkeypatch.setattr(rg, "architecture", lambda s: {"all_issues": []})

    graph = rg.build_repo_graph()
    result = graph.invoke({"repo_path": "/x", "all_issues": []},
                          config={"max_concurrency": 4})
    # reducer ADDED both files' issues into one list, each stamped with its filename
    assert len(result["all_issues"]) == 2
    assert {i.filename for i in result["all_issues"]} == {"a.py", "b.py"}
