"""check_fix_test_fails_on_main: a fix carries a test that fails on main."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_fix_test_fails_on_main import is_fix, split_changes, verdict  # noqa: E402


def test_a_fix_is_named_by_its_title():
    assert is_fix("fix(tools): a look-alike is not reserved")
    assert is_fix("Fix: wrapper skips a vendor")
    assert not is_fix("fixtures: add a Proofpoint click")
    assert not is_fix("feat(gate): scan test data")
    assert not is_fix("docs: fix a typo")


def test_changes_split_into_code_and_tests():
    code, tests = split_changes([
        "Packs/p/Scripts/S/S.py",
        "Packs/p/Scripts/S/S_test.py",
        "Packs/p/Scripts/S/S_test_extra.py",
        "tools/check_x.py",
        "tools/test_check_x.py",
        "docs/page.md",
        "scenarios/a.yml",
    ])
    assert code == ["Packs/p/Scripts/S/S.py", "tools/check_x.py"]
    assert tests == ["Packs/p/Scripts/S/S_test.py", "Packs/p/Scripts/S/S_test_extra.py", "tools/test_check_x.py"]


def test_a_test_failing_on_main_passes_the_check():
    ok, _ = verdict(code=["tools/check_x.py"], passed_on_main={"tools/test_check_x.py": False})
    assert ok


def test_tests_that_all_pass_on_main_fail_the_check():
    ok, why = verdict(code=["tools/check_x.py"], passed_on_main={"tools/test_check_x.py": True})
    assert not ok and "pass on main" in why


def test_a_code_fix_with_no_test_fails_the_check():
    ok, why = verdict(code=["tools/check_x.py"], passed_on_main={})
    assert not ok and "no test" in why


def test_a_fix_with_no_code_change_is_not_checked():
    ok, why = verdict(code=[], passed_on_main={})
    assert ok and "no code" in why


def test_a_tool_with_test_in_its_name_is_code():
    code, tests = split_changes(["tools/check_test_data.py", "tools/test_check_test_data.py"])
    assert code == ["tools/check_test_data.py"]
    assert tests == ["tools/test_check_test_data.py"]
