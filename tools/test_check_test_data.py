"""check_test_data: test data may only use values that can never belong to anyone."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_test_data import _tracked_files, findings, replay_data  # noqa: E402

NO_EXEMPTIONS: dict[str, str] = {}


def values(text, allowed=NO_EXEMPTIONS):
    return [v for _, v, _ in findings(text, allowed)]


def test_reserved_names_and_addresses_pass():
    text = (
        'user = "analyst@example.com"; host = "host-01.example"; c2 = "evil.test"\n'
        'ips = ["192.0.2.10", "198.51.100.7", "203.0.113.9", "10.1.2.3", "172.16.0.5", "192.168.1.1"]\n'
        'dc = "dc01.corp.local"; bad = "x.invalid"; v6 = "2001:db8::1"\n'
    )
    assert values(text) == []


def test_a_public_ip_is_flagged():
    assert values('src = "8.8.4.4"') == ["8.8.4.4"]


def test_a_real_looking_domain_is_flagged():
    assert values('url = "https://login.acme-corp.com/x"') == ["login.acme-corp.com"]


def test_an_email_outside_the_reserved_domains_is_flagged():
    assert values('to = "jane.doe@acme-corp.com"') == ["acme-corp.com"]


def test_an_exempted_value_passes():
    assert values('url = "https://attack.mitre.org/techniques/T1566/"', {"attack.mitre.org": "MITRE ATT&CK link"}) == []


def test_an_exempted_domain_covers_its_subdomains_but_not_lookalikes():
    allowed = {"proofpoint.com": "vendor console host"}
    assert values('u = "https://threatinsight.proofpoint.com/a"', allowed) == []
    assert values('u = "https://proofpoint.com.attacker.net/a"', allowed) == ["proofpoint.com.attacker.net"]


def test_each_finding_names_its_line():
    assert [line for line, _, _ in findings('a = 1\nb = "8.8.4.4"\n', NO_EXEMPTIONS)] == [2]


def test_multicast_and_shared_address_space_pass():
    assert values('ips = ["224.0.0.1", "100.64.0.1"]') == []


def test_a_lookalike_of_a_reserved_domain_is_flagged():
    assert values('to = "dc@notexample.com"; u = "https://notexample.org/x"') == ["notexample.com", "notexample.org"]


def test_replay_captures_are_refused_wherever_they_sit():
    paths = [
        "data/CrowdStrike-MITRE-Turla-Carbon-in-XSIAM.tsv",
        "Packs/x/Lists/SOCFWPoVData_Foo_V1/SOCFWPoVData_Foo_V1_data.json",
        "Packs/x/Scripts/S/test_data/input.TSV",
    ]
    assert replay_data(paths) == paths


def test_ordinary_lists_and_test_data_are_not_replay_data():
    paths = [
        "Packs/x/Lists/SOCActionTimeMap_V3/SOCActionTimeMap_V3_data.json",
        "Packs/x/Scripts/S/test_data/golden.json",
        "tools/replay_scenario.py",
    ]
    assert replay_data(paths) == []


def test_the_repo_holds_no_replay_data():
    assert replay_data(_tracked_files()) == []
