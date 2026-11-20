"""
SOCFWCaseLedgerWrite_test.py

Characterization tests: what the case ledger row holds today. Case analysis reads
these rows to group a case's issues by host, hash and technique, so a change to
a column name or to how the case id is stored breaks the analysis without any
error on the issue.

Run: pytest Scripts/SOCFWCaseLedgerWrite/SOCFWCaseLedgerWrite_test.py -v
"""
import json
import os
import sys
import types

HERE = os.path.dirname(__file__)

demisto = types.ModuleType("demistomock")
demisto.debug = lambda *a, **k: None
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.return_results = lambda *a, **k: None
csp.is_error = lambda entry: isinstance(entry, dict) and entry.get("Type") == 4
csp.get_error = lambda res: str(res[0].get("Contents"))
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseLedgerWrite as led  # noqa: E402

CONTRACT = {
    "lifecycle": "NIST_IR",
    "lifecycle_version": "3",
    "Product": {"category": "endpoint", "key": "crowdstrike_falcon"},
    "Artifacts": {
        "Endpoint": {"Hostname": "bannik", "AgentID": "a1", "IPAddress": ["10.0.0.5"]},
        "Process": {"SHA256": "abc123", "Parent": {"SHA256": "stock-os"}},
        "Source": {"AlertDomain": "DOMAIN_SECURITY"},
    },
    "Intel": {"Hash": {"verdict": "malicious"}},
    "Enrichment": {"big": "blob"},
}
ISSUE = {"id": "1101", "parentXDRIncident": "INCIDENT-52098", "severity": 3,
         "name": "bannik | Credential Dumping | lsass access",
         "CustomFields": {"ruleid": "r-9", "alert_domain": "DOMAIN_OTHER"}}


def row(contract=CONTRACT, issue=ISSUE):
    return led.build_row(contract, issue, "foundation", "contract")


def test_the_case_id_is_stored_bare_so_it_joins_on_case_ids():
    assert row()["case_id"] == "52098"


def test_the_shape_key_drops_the_host_segment():
    assert row()["shape_key"] == "Credential Dumping | lsass access"
    assert led.shape_key_from_name("one | two") == "one | two"
    assert led.shape_key_from_name("") is None


def test_entity_columns_come_from_the_normalized_contract():
    r = row()
    assert (r["host_name"], r["endpoint_id"], r["file_sha256"], r["local_ip"]) == \
        ("bannik", "a1", "abc123", "10.0.0.5")


def test_a_parent_process_hash_is_never_used_as_the_file_hash():
    contract = json.loads(json.dumps(CONTRACT))
    del contract["Artifacts"]["Process"]["SHA256"]
    assert "file_sha256" not in row(contract)


def test_the_case_domain_comes_from_the_contract_before_the_issue_field():
    assert row()["domain"] == "DOMAIN_SECURITY"
    contract = json.loads(json.dumps(CONTRACT))
    del contract["Artifacts"]["Source"]
    assert row(contract)["domain"] == "DOMAIN_OTHER"


def test_evidence_and_the_rest_of_the_contract_are_kept_apart():
    r = row()
    assert set(json.loads(r["contract_evidence"])) == {"Artifacts", "Product", "Intel", "lifecycle"}
    assert set(json.loads(r["contract_full"])) == {"lifecycle_version", "Enrichment"}


def test_empty_values_are_left_out_of_the_row():
    r = led.build_row({}, {"id": "7"}, "foundation", "empty")
    assert r["alert_id"] == "7" and r["contract_source"] == "empty"
    assert "case_id" not in r and "host_name" not in r and "contract_evidence" not in r


def _main(context, post_result, args=None):
    sent, results = [], []
    demisto.args = lambda: dict(args or {})
    demisto.context = lambda: context
    demisto.incident = lambda: ISSUE
    demisto.executeCommand = lambda cmd, a: sent.append((cmd, a)) or post_result
    led.return_results = results.append
    led.main()
    return sent, results


def test_main_posts_one_row_through_the_ledger_writer():
    sent, results = _main({"SOCFramework": CONTRACT}, [{"Type": 1, "Contents": "ok"}])
    (cmd, args), = sent
    assert cmd == "socfw-post-to-dataset" and args["using"] == "socfw_case_ledger_writer"
    posted, = json.loads(args["JSON"])
    assert posted["case_id"] == "52098" and posted["contract_source"] == "contract"
    assert results[0]["outputs"] == {"written": True, "phase": "foundation", "case_id": "52098"}


def test_an_issue_with_no_contract_still_gets_a_row_marked_empty():
    sent, _ = _main({}, [{"Type": 1, "Contents": "ok"}])
    posted, = json.loads(sent[0][1]["JSON"])
    assert posted["contract_source"] == "empty" and posted["alert_id"] == "1101"


def test_a_failed_write_is_silent_on_the_issue():
    _, results = _main({"SOCFramework": CONTRACT}, [{"Type": 4, "Contents": "no instance"}])
    assert results == [{"readable_output": ""}]
