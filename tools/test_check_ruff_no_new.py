"""check_ruff_no_new: a changed file may not end up with more ruff findings than on main."""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_ruff_no_new import added_findings, high_risk  # noqa: E402


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
