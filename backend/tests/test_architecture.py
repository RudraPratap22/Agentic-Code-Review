"""Tests for the architecture agent's deterministic pieces (cycles, metrics, structure)."""

from agents.architecture_agent import (_find_cycles, _graph_metrics,
                                        _has_tests, _gitignore_covers_env)


def test_find_cycles_detects_a_cycle():
    cycles = _find_cycles({"a": {"b"}, "b": {"a"}, "c": set()})
    assert any(set(c) == {"a", "b"} for c in cycles)


def test_find_cycles_none_when_acyclic():
    assert _find_cycles({"a": {"b"}, "b": set()}) == []


def test_find_cycles_self_loop():
    assert _find_cycles({"a": {"a"}}) == [["a"]]


def test_graph_metrics_fan_in_out():
    metrics, _fan_in = _graph_metrics({"A": {"B", "C"}, "B": {"C"}, "C": set()})
    by_mod = {m["module"]: m for m in metrics}
    assert by_mod["C"]["fan_in"] == 2 and by_mod["C"]["fan_out"] == 0   # shared leaf
    assert by_mod["A"]["fan_out"] == 2 and by_mod["A"]["fan_in"] == 0   # entry point


def test_has_tests(tmp_path):
    assert _has_tests(str(tmp_path)) is False
    (tmp_path / "tests").mkdir()
    assert _has_tests(str(tmp_path)) is True


def test_gitignore_covers_env(tmp_path):
    (tmp_path / ".env").write_text("SECRET=1")
    assert _gitignore_covers_env(str(tmp_path)) is False   # .env present but not ignored
    (tmp_path / ".gitignore").write_text(".env\n")
    assert _gitignore_covers_env(str(tmp_path)) is True
