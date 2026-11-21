"""Tests for run_pack_tests.py's choice of tool test files."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_pack_tests  # noqa: E402


def names(paths):
    return {p.name for p in paths}


def test_tool_tests_are_the_test_star_files_in_tools(tmp_path, monkeypatch):
    for name in ("test_one.py", "test_two.py", "run_tests.py", "check_test_data.py", "helper.py"):
        (tmp_path / name).write_text("")
    monkeypatch.setattr(run_pack_tests, "TOOLS", tmp_path)
    assert names(run_pack_tests.tool_test_files()) == {"test_one.py", "test_two.py"}


def test_tool_tests_are_sorted(tmp_path, monkeypatch):
    for name in ("test_b.py", "test_a.py"):
        (tmp_path / name).write_text("")
    monkeypatch.setattr(run_pack_tests, "TOOLS", tmp_path)
    assert [p.name for p in run_pack_tests.tool_test_files()] == ["test_a.py", "test_b.py"]


def test_repo_tool_tests_include_this_file():
    assert "test_run_pack_tests.py" in names(run_pack_tests.tool_test_files())
