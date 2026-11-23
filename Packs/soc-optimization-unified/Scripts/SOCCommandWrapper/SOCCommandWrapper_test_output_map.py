"""
SOCCommandWrapper_test_output_map.py

Characterisation tests for apply_output_map: which UC.* keys it writes, with
what value, from which context, and what it logs, in order, compared with a
golden file captured from the code before it was restructured. The lookup in
the command's own EntryContext (_resolve_from_entry_context) runs for real.

A source path with a filter (Vendor.Report[type=x].count) is read from its
first segment only. No shipped action uses one; the golden file pins that
as it is.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCCommandWrapper_test_output_map.py
"""

import json
import os
from pathlib import Path

import pytest

from SOCCommandWrapper_test import load_script

GOLDEN = Path(__file__).parent / "test_data" / "output_map_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"

FORENSICS = {"UC.Email.Forensics.behavior": "Proofpoint.Report.Behavior",
             "UC.Email.Forensics.dns": "Proofpoint.Report.DNS"}
REPORT = {"Behavior": [{"rule": "r1"}], "DNS": ["a.example"]}

SCENARIOS = {
    "no_map": dict(output_map=None),
    "map_not_a_dict": dict(output_map=["UC.X", "Vendor.Y"]),
    "empty_map": dict(output_map={}),
    "blank_keys_skipped": dict(output_map={"": "Vendor.Y", "UC.X": "", "UC.Z": None}),
    "shadow_writes_sentinel": dict(output_map=FORENSICS, shadow_mode=True,
                                   entry_context={"Proofpoint.Report": REPORT}),
    "shadow_skips_blank_keys": dict(output_map={"UC.X": "", "UC.Y": "Vendor.Y"}, shadow_mode=True),
    "entry_context_exact_key": dict(output_map={"UC.Hunt": "MsGraph.Hunt"},
                                    entry_context={"MsGraph.Hunt": [{"id": "1"}]}),
    "entry_context_sub_path": dict(output_map=FORENSICS, entry_context={"Proofpoint.Report": REPORT}),
    "entry_context_longest_prefix": dict(output_map={"UC.V": "A.B.C.value"},
                                         entry_context={"A": {"B": {"C": {"value": "short"}}},
                                                        "A.B": {"C": {"value": "middle"}},
                                                        "A.B.C": {"value": "long"}}),
    "entry_context_list_walks_first_item": dict(output_map={"UC.V": "Vendor.Items.name"},
                                                entry_context={"Vendor.Items": [{"name": "first"},
                                                                                {"name": "second"}]}),
    "entry_context_list_of_text": dict(output_map={"UC.V": "Vendor.Items.name"},
                                       entry_context={"Vendor.Items": ["text"]}, ctx={"Vendor": {
                                           "Items": {"name": "from context"}}}),
    "entry_context_walk_hits_text": dict(output_map={"UC.V": "Vendor.Report.verdict.code"},
                                         entry_context={"Vendor.Report": {"verdict": "bad"}}),
    "entry_context_wins_over_context": dict(output_map={"UC.V": "Vendor.Report.verdict"},
                                            entry_context={"Vendor.Report": {"verdict": "fresh"}},
                                            ctx={"Vendor": {"Report": {"verdict": "stale"}}}),
    "falls_back_to_context": dict(output_map={"UC.V": "Vendor.Report.verdict"},
                                  entry_context={"Other.Key": {"verdict": "x"}},
                                  ctx={"Vendor": {"Report": {"verdict": "from context"}}}),
    "entry_context_empty_value_falls_back": dict(output_map={"UC.V": "Vendor.Report.verdict"},
                                                 entry_context={"Vendor.Report": {"verdict": []}},
                                                 ctx={"Vendor": {"Report": {"verdict": "from context"}}}),
    "no_entry_context_reads_context": dict(output_map={"UC.V": "Vendor.Report.verdict"},
                                           ctx={"Vendor": {"Report": {"verdict": 0}}}),
    "empty_everywhere_skipped": dict(output_map={"UC.A": "V.a", "UC.B": "V.b", "UC.C": "V.c", "UC.D": "V.d"},
                                     entry_context={"V": {"a": None, "b": ""}},
                                     ctx={"V": {"c": [], "d": {}}}),
    "entry_context_not_a_dict": dict(output_map={"UC.V": "Vendor.Report.verdict"},
                                     entry_context=["Vendor.Report"],
                                     ctx={"Vendor": {"Report": {"verdict": "from context"}}}),
    "filtered_source_reads_first_segment": dict(output_map={"UC.V": "Vendor.Report[type=x].count"},
                                                entry_context={"Vendor": {"Report": [{"type": "x", "count": 2}]}}),
    "filtered_source_falls_back_to_context": dict(output_map={"UC.V": "Vendor.Report[type=x].count"},
                                                  ctx={"Vendor": {"Report": [{"count": 3}]}}),
    "mixed_map_in_order": dict(output_map={"UC.One": "Vendor.Report.verdict", "UC.Two": "Missing.Path",
                                           "UC.Three": "MsGraph.Hunt"},
                               entry_context={"MsGraph.Hunt": {"rows": 1}},
                               ctx={"Vendor": {"Report": {"verdict": "ok"}}}),
}


def _run(name):
    spec = SCENARIOS[name]
    script, demisto = load_script()
    events = []
    demisto.setContext = lambda key, value: events.append(["setContext", key, value])
    demisto.debug = lambda message: events.append(["debug", message])
    script.apply_output_map(spec["output_map"], spec.get("ctx", {}), spec.get("shadow_mode", False),
                            entry_context=spec.get("entry_context"))
    return json.loads(json.dumps(events, default=repr))


def _golden():
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_output_map_matches_golden(name):
    """
    Given an action's output map, the command's EntryContext and the investigation context
    When apply_output_map runs, simulated or live
    Then every UC.* key written, its value, and every log line match the golden file, in order
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False) == json.dumps(_golden()[name], ensure_ascii=False)


def test_golden_has_no_stale_scenarios():
    """
    Given the golden file
    When its scenario names are compared with this file's
    Then each golden entry still has a scenario that produces it
    """
    assert set(_golden()) <= set(SCENARIOS)
