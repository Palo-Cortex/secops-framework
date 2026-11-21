"""sanitize_tsv --fix: real identifiers are replaced the same way everywhere, published values stay."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanitize_tsv  # noqa: E402

CID = "9a3c51e07b2d4f6e8c1a0b2d3e4f5a6b"
AID = "4e7d2c9b1a0f48e3b6c5d4e3f2a1b0c9"
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


def _fix(tmp_path, text, name="a.tsv"):
    src = tmp_path / name
    src.write_text(text)
    out = tmp_path / "out" / name
    sanitize_tsv.apply_fixes(str(src), str(out), ALLOW)
    return out.read_text()


def test_vendor_ids_are_replaced_everywhere_they_appear(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert CID not in fixed and AID not in fixed
    first_cid = fixed.splitlines()[1].split("\t")[0]
    assert fixed.count(first_cid) == PLACES_THE_CID_APPEARS


def test_a_mac_address_becomes_a_documentation_mac(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert "3c-5a-b4-19-7e-02" not in fixed
    assert "00-00-5e-00-53-" in fixed


def test_a_domain_sid_is_replaced_and_keeps_its_relative_id(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert "1234567890" not in fixed
    assert fixed.count("-1107") == 1 and fixed.count("-1112") == 1
    # Both accounts are still in one domain after the change.
    domains = {s.rsplit("-", 1)[0] for s in fixed.split('""') if s.startswith("S-1-5-21-")}
    assert len(domains) == 1


def test_a_public_ip_is_replaced_and_allowlisted_and_reserved_ones_stay(tmp_path):
    fixed = _fix(tmp_path, ROW)
    assert "203.0.114.7" not in fixed
    assert "2.1.88.0" in fixed       # allowlisted: a version folder, not an address
    assert "224.0.0.251" in fixed    # multicast is reserved, never a real host


def test_the_same_value_gets_the_same_replacement_in_every_file_of_a_run(tmp_path):
    first = _fix(tmp_path, ROW, "a.tsv")
    second = _fix(tmp_path, ROW, "b.tsv")
    assert first == second


def test_multicast_is_safe():
    assert sanitize_tsv.is_safe_ip("224.0.0.251")


def _categories(path):
    return {f.category for f in sanitize_tsv.scan_tsv(str(path), ALLOW)}


def test_report_flags_vendor_ids_macs_and_domain_sids(tmp_path):
    src = tmp_path / "a.tsv"
    src.write_text(ROW)
    assert {"VENDOR_ID", "MAC_ADDRESS", "DOMAIN_SID"} <= _categories(src)


def test_report_is_clean_for_identifiers_after_fixing(tmp_path):
    _fix(tmp_path, ROW)
    assert not {"VENDOR_ID", "MAC_ADDRESS", "DOMAIN_SID", "PUBLIC_IP"} & _categories(tmp_path / "out" / "a.tsv")
