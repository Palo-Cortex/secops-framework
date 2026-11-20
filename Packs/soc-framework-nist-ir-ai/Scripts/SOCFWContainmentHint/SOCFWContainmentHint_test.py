"""
SOCFWContainmentHint_test.py

Characterization tests: the dynamic section under the containment buttons is
one fixed HTML note that points the analyst to the War Room, and it does
nothing on import.

Run: pytest Scripts/SOCFWContainmentHint/SOCFWContainmentHint_test.py -v
"""
import os
import runpy
import sys
import types

HERE = os.path.dirname(__file__)
PATH = os.path.join(HERE, "SOCFWContainmentHint.py")

results = []
demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.formats = {"html": "html", "markdown": "markdown"}
csp.entryTypes = {"note": 1, "error": 4}
csp.return_results = results.append
csp.__all__ = ["formats", "entryTypes", "return_results"]
sys.modules["CommonServerPython"] = csp


def test_importing_it_renders_nothing():
    results.clear()
    runpy.run_path(PATH, run_name="SOCFWContainmentHint")
    assert results == []


def test_it_renders_one_html_note_pointing_to_the_war_room():
    results.clear()
    ns = runpy.run_path(PATH, run_name="__main__")
    assert results == [{"ContentsFormat": "html", "Type": 1, "Contents": ns["HINT"]}]
    assert "<b>War Room</b>" in ns["HINT"]
    assert "listed there with the reason" in ns["HINT"]


def test_the_hint_is_fixed_text():
    ns = runpy.run_path(PATH, run_name="SOCFWContainmentHint")
    assert "{" not in ns["HINT"] and "%s" not in ns["HINT"]
    assert ns["HINT"].startswith("<div") and ns["HINT"].endswith("</div>")
