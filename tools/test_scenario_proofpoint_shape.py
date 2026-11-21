"""Proofpoint TAP events in scenarios/ have the shape the vendor sends.

In each threatsInfoMap entry, `threat` holds the malicious URL and `threatUrl`
is the link to the threat in the Proofpoint console. Content that reads one in
place of the other works on a fixture with them swapped and fails in production.
"""
import glob
import os

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONSOLE = "https://threatinsight.proofpoint.com/"


def _threat_entries():
    for path in sorted(glob.glob(os.path.join(ROOT, "scenarios", "*.yml"))):
        with open(path) as f:
            doc = yaml.safe_load(f)
        for event in (doc or {}).get("events") or []:
            payload = event.get("data") or {}
            for entry in payload.get("threatsInfoMap") or []:
                yield os.path.basename(path), event.get("label", ""), entry


ENTRIES = list(_threat_entries())


def test_scenarios_carry_proofpoint_threat_entries():
    assert ENTRIES, "no threatsInfoMap entries found: the scenario layout changed"


@pytest.mark.parametrize("name,label,entry", ENTRIES, ids=[f"{n}:{lb}" for n, lb, _ in ENTRIES])
def test_threat_holds_the_url_and_threaturl_the_console_link(name, label, entry):
    assert entry.get("threat"), "threat is missing; it holds the malicious URL"
    assert str(entry.get("threatUrl", "")).startswith(CONSOLE), (
        "threatUrl must be the Proofpoint console link, got %r" % entry.get("threatUrl"))
    assert entry["threatID"] in entry["threatUrl"], "the console link names the entry's threatID"
