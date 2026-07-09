"""Tests for language detection and multi-language file discovery."""

from agents.external_tools import (detect_language, ext_for_language,
                                    walk_source_files, walk_python_files)


def test_detect_language():
    assert detect_language("a.py") == "python"
    assert detect_language("src/app.jsx") == "javascript"
    assert detect_language("src/App.TSX") == "typescript"     # case-insensitive
    assert detect_language("main.go") == "go"
    assert detect_language("README.md") is None               # unsupported → skipped
    assert detect_language("noext") is None


def test_ext_for_language():
    assert ext_for_language("javascript") == ".js"
    assert ext_for_language("python") == ".py"
    assert ext_for_language("cobol") == ".txt"                # unknown → harmless default


def test_walk_source_files_finds_multiple_languages(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.js").write_text("const y = 2")
    (tmp_path / "c.ts").write_text("let z: number = 3")
    (tmp_path / "notes.md").write_text("# hi")               # unsupported
    (tmp_path / "vendor.min.js").write_text("!function(){}") # minified → skipped
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("junk")  # pruned dir

    found = {(rel, lang) for rel, _code, lang in walk_source_files(str(tmp_path))}
    assert found == {("a.py", "python"), ("b.js", "javascript"), ("c.ts", "typescript")}


def test_walk_python_files_still_python_only(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.js").write_text("const y = 2")
    assert {rel for rel, _code in walk_python_files(str(tmp_path))} == {"a.py"}
