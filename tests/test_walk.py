"""Tests for the repo file walker (skips junk dirs, finds .py)."""

from agents.external_tools import walk_python_files


def test_walk_finds_py_and_skips_junk(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("y = 2")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "c.py").write_text("z = 3")
    (tmp_path / "notes.txt").write_text("hi")

    found = {rel for rel, _code in walk_python_files(str(tmp_path))}
    assert found == {"a.py", "sub/b.py"}    # venv pruned, .txt ignored
