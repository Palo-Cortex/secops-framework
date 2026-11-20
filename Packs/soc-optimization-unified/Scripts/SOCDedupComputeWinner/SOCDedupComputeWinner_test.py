"""
SOCDedupComputeWinner_test.py

Characterization tests: the dedup winner is the numeric minimum of the similar
alert ids and the current one, written as a string to
SOCFramework.Dedup.WinnerID. Ids arrive as lists, comma-separated text or a
scalar; blanks are dropped; a lexicographic minimum is used only when no id is
numeric.

Run: pytest Scripts/SOCDedupComputeWinner/SOCDedupComputeWinner_test.py -v
"""
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)

demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCDedupComputeWinner as dw  # noqa: E402


@pytest.mark.parametrize("value,expected", [
    (None, []),
    ("", []),
    ([" 12 ", None, "", 7], ["12", "7"]),
    ("12, 7,,  9 ", ["12", "7", "9"]),
    (42, ["42"]),
])
def test_ids_arrive_in_any_shape_and_blanks_are_dropped(value, expected):
    assert dw._to_list(value) == expected


@pytest.mark.parametrize("similar,current,expected", [
    (["10000", "9999"], "10500", "9999"),          # numeric, not "10000" < "9999"
    ("200,30", "1000", "30"),
    ([], "55", "55"),
    (None, None, ""),
    (["abc", "abd"], "abe", "abc"),                # nothing numeric: lexicographic
    (["abc", "5"], "zz", "5"),                     # any numeric id wins over text
    (["007", "8"], None, "7"),                     # leading zeros read as numbers
])
def test_the_winner_is_the_numeric_minimum(similar, current, expected):
    assert dw.compute_winner(similar, current) == expected


def test_main_writes_the_winner_and_shows_the_candidates(monkeypatch):
    ctx, results = {}, []
    monkeypatch.setattr(demisto, "args", lambda: {"similar_ids": ["10000", "9999"], "current_id": "10500"},
                        raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: ctx.__setitem__(k, v), raising=False)
    monkeypatch.setattr(dw, "return_results", results.append, raising=False)
    dw.main()
    assert ctx == {"SOCFramework.Dedup.WinnerID": "9999"}
    out = results[0]["readable_output"]
    assert "**Dedup winner:** `9999`" in out and "['10000', '9999', '10500']" in out


def test_no_ids_writes_an_empty_winner(monkeypatch):
    ctx = {}
    monkeypatch.setattr(demisto, "args", lambda: {}, raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: ctx.__setitem__(k, v), raising=False)
    monkeypatch.setattr(dw, "return_results", lambda r: None, raising=False)
    dw.main()
    assert ctx == {"SOCFramework.Dedup.WinnerID": ""}
