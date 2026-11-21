"""check_ruff_no_new: a changed file may not end up with more ruff findings than on main."""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_ruff_no_new import (  # noqa: E402
    added_findings,
    changed_lines,
    function_spans,
    high_risk,
    undocumented_touched,
)


def test_the_same_findings_pass():
    assert added_findings(Counter({"C901": 2, "E501": 1}), Counter({"C901": 2, "E501": 1})) == {}


def test_fewer_findings_pass():
    assert added_findings(Counter({"C901": 2, "E501": 3}), Counter({"C901": 1})) == {}


def test_a_new_finding_fails_and_names_its_rule():
    assert added_findings(Counter({"C901": 1}), Counter({"C901": 1, "B904": 2})) == {"B904": 2}


def test_one_rule_up_fails_even_when_another_goes_down():
    assert added_findings(Counter({"E501": 5, "C901": 1}), Counter({"E501": 1, "C901": 2})) == {"C901": 1}


def test_a_new_file_must_be_clean():
    assert added_findings(Counter(), Counter({"F401": 1})) == {"F401": 1}


def test_high_risk_paths_are_recognised():
    assert high_risk("Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/SOCCommandWrapper.py")
    assert high_risk("Packs/soc-framework-nist-ir-ai/Scripts/SOCFWCloseDecision/SOCFWCloseDecision.py")
    assert high_risk("tools/check_contribution.py")
    assert not high_risk("tools/prep_docs.py")
    assert not high_risk("Packs/soc-optimization-unified/Scripts/SOCFWHealthCheck/SOCFWHealthCheck.py")


DIFF = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -3,0 +4,2 @@ def a():
+    one = 1
+    two = 2
@@ -10 +12 @@ def b():
-    old
+    new
@@ -20,3 +21,0 @@ def c():
-    gone
"""

SOURCE = """\
import os


@decorated
def outer(x):
    def inner(y):
        return y
    return inner(x)


def other(z):
    return z
"""


def test_changed_lines_are_the_added_lines_on_the_branch():
    assert changed_lines(DIFF) == {4, 5, 12}


def test_function_spans_start_at_the_decorator_and_include_nested_functions():
    assert function_spans(SOURCE) == [(4, 8), (6, 7), (11, 12)]


def test_a_touched_function_must_be_documented_and_typed():
    findings = [("D103", 5), ("ANN001", 5), ("ANN201", 5)]
    assert undocumented_touched(findings, function_spans(SOURCE), {8}) == findings


def test_an_untouched_function_keeps_its_old_findings():
    assert undocumented_touched([("D103", 11), ("ANN001", 11)], function_spans(SOURCE), {8}) == []


def test_only_the_innermost_function_counts():
    # Editing outer's own line must not make the untouched inner function fail.
    assert undocumented_touched([("ANN001", 6)], function_spans(SOURCE), {8}) == []
    assert undocumented_touched([("ANN001", 6)], function_spans(SOURCE), {7}) == [("ANN001", 6)]


def test_other_rules_are_left_to_the_count_check():
    assert undocumented_touched([("C901", 5), ("E501", 5)], function_spans(SOURCE), {5}) == []
