"""sanitize_tsv --fix: tenant identity is always replaced; host identifiers only when asked; no two values collide."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanitize_tsv  # noqa: E402

CID = "9a3c51e07b2d4f6e8c1a0b2d3e4f5a6b"
AID = "4e7d2c9b1a0f48e3b6c5d4e3f2a1b0c9"
OTHER_CID = "7f1e2d3c4b5a69788796a5b4c3d2e1f0"
ROW = (
    "cid\tagent_id\tcomposite_id\trawJSON\n"
    f'{CID}\t{AID}\t{CID}:ind:{AID}:1\t'
    f'"{{""device"": {{""cid"": ""{CID}"", ""device_id"": ""{AID}"", '
    '""mac_address"": ""3c-5a-b4-19-7e-02"", ""external_ip"": ""203.0.114.7""}, '
    '""sid"": ""S-1-5-21-1234567890-987654321-1122334455-1107"", '
    '""other_sid"": ""S-1-5-21-1234567890-987654321-1122334455-1112"", '
    '""remote_address"": ""224.0.0.251"", ""path"": ""Edge Shopping\\\\2.1.88.0""}"\n'
)
# The cid column, the composite id and rawJSON.
PLACES_THE_CID_APPEARS = 3

# Values here look real on purpose: a scrubber's test has to show it replaces
# real-shaped values. They are invented, and this file is exempt from the
# test-data scan for that reason (policies/test_data_allowed.json).
ALLOW = {"ips": ["2.1.88.0", "176.59.15.33"], "domains": [], "values": [], "columns": []}


def _fix(tmp_path, text, name="a.tsv", **options):
    src = tmp_path / name
    src.write_text(text)
    out = tmp_path / "out" / name
    sanitize_tsv.apply_fixes(str(src), str(out), ALLOW, **options)
    return out.read_text()


def _new_run():
    """Start a fresh run, as a separate invocation of the tool would."""
    sanitize_tsv._replacement_cache.clear()
    for key in sanitize_tsv._replacement_counters:
        sanitize_tsv._replacement_counters[key] = 1


def _categories(path, **options):
    return {f.category for f in sanitize_tsv.scan_tsv(str(path), ALLOW, **options)}


def test_the_tenant_id_is_replaced_everywhere_it_appears(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert CID not in fixed
    first_cid = fixed.splitlines()[1].split("\t")[0]
    assert fixed.count(first_cid) == PLACES_THE_CID_APPEARS


def test_host_identifiers_stay_unless_asked(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert AID in fixed
    assert "3c-5a-b4-19-7e-02" in fixed
    assert "S-1-5-21-1234567890-987654321-1122334455-1107" in fixed


def test_host_identifiers_are_replaced_when_asked(tmp_path):
    fixed = _fix(tmp_path, ROW, host_identifiers=True)
    assert AID not in fixed and "3c-5a-b4-19-7e-02" not in fixed and "1234567890" not in fixed
    assert "00-00-5e-00-53-" in fixed
    domains = {s.rsplit("-", 1)[0] for s in fixed.split('""') if s.startswith("S-1-5-21-")}
    assert len(domains) == 1  # both accounts stay in one domain


def test_tenant_only_leaves_addresses_and_hosts_as_recorded(tmp_path):
    fixed = _fix(tmp_path, ROW, tenant_only=True)
    assert CID not in fixed
    assert "203.0.114.7" in fixed and AID in fixed


def test_by_default_a_public_ip_is_replaced_and_allowlisted_and_reserved_ones_stay(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert "203.0.114.7" not in fixed
    assert "2.1.88.0" in fixed
    assert "224.0.0.251" in fixed


def test_two_files_scrubbed_in_separate_runs_never_share_a_fabricated_value(tmp_path):
    first = _fix(tmp_path, ROW, "a.tsv", host_identifiers=True)
    _new_run()
    second = _fix(tmp_path, ROW.replace(CID, OTHER_CID), "b.tsv", host_identifiers=True)
    assert first.splitlines()[1].split("\t")[0] != second.splitlines()[1].split("\t")[0]


def test_the_same_value_gets_the_same_replacement_in_every_run(tmp_path):
    first = _fix(tmp_path, ROW, "a.tsv")
    _new_run()
    second = _fix(tmp_path, ROW, "b.tsv")
    assert first == second


def test_multicast_is_safe():
    assert sanitize_tsv.is_safe_ip("224.0.0.251")


def test_report_flags_the_tenant_id_and_host_identifiers_only_when_asked(tmp_path):
    src = tmp_path / "a.tsv"
    src.write_text(ROW)
    assert "TENANT_ID" in _categories(src)
    assert not {"VENDOR_ID", "MAC_ADDRESS", "DOMAIN_SID"} & _categories(src)
    assert {"VENDOR_ID", "MAC_ADDRESS", "DOMAIN_SID"} <= _categories(src, host_identifiers=True)


def test_tenant_only_report_ignores_addresses(tmp_path):
    src = tmp_path / "a.tsv"
    src.write_text(ROW)
    assert "TENANT_ID" in _categories(src, tenant_only=True)
    assert "PUBLIC_IP" not in _categories(src, tenant_only=True)


def test_report_is_clean_after_fixing(tmp_path):
    _fix(tmp_path, ROW, tenant_only=True)
    assert not {"TENANT_ID", "PUBLIC_IP"} & _categories(tmp_path / "out" / "a.tsv", tenant_only=True)
