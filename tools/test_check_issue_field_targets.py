"""Tests for check_issue_field_targets: blocked fields fail, warn fields warn, the rest pass."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_issue_field_targets as c  # noqa: E402


def _pack(tmp_path, name, alert_fields):
    rules = tmp_path / "Packs" / name / "CorrelationRules"
    rules.mkdir(parents=True)
    body = "alert_fields:\n" + "".join(f"  {k}: {v}\n" for k, v in alert_fields.items())
    (rules / "Rule.yml").write_text(body)
    return str(tmp_path / "Packs" / name)


def _policy(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"blocked": {"hostos": "fixed values"}, "warn": {"tags": "review"}}))
    return str(p)


def test_blocked_field_in_rule_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "REPO", str(tmp_path))
    pack = _pack(tmp_path, "p1", {"hostos": "device_platform_name", "hostfqdn": "device_fqdn"})
    errors, warnings = c.check([pack], _policy(tmp_path))
    assert [e[1] for e in errors] == ["hostos"]
    assert warnings == []


def test_warn_field_only_warns(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "REPO", str(tmp_path))
    pack = _pack(tmp_path, "p1", {"tags": "alert_tags"})
    errors, warnings = c.check([pack], _policy(tmp_path))
    assert errors == []
    assert [w[1] for w in warnings] == ["tags"]


def test_blocked_field_in_contract_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "REPO", str(tmp_path))
    pack = _pack(tmp_path, "p1", {"hostfqdn": "device_fqdn"})
    vendor = tmp_path / "schemas" / "vendors" / "v"
    vendor.mkdir(parents=True)
    (vendor / "c.yaml").write_text(
        "pack: p1\ncorrelation_rules:\n- alert_fields:\n  - issue_field: hostos\n    source: device_platform_name\n")
    errors, _ = c.check([pack], _policy(tmp_path))
    assert [(os.path.basename(e[0]), e[1]) for e in errors] == [("c.yaml", "hostos")]


def test_contract_for_another_pack_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "REPO", str(tmp_path))
    pack = _pack(tmp_path, "p1", {"hostfqdn": "device_fqdn"})
    vendor = tmp_path / "schemas" / "vendors" / "v"
    vendor.mkdir(parents=True)
    (vendor / "c.yaml").write_text(
        "pack: p2\ncorrelation_rules:\n- alert_fields:\n  - issue_field: hostos\n    source: x\n")
    errors, _ = c.check([pack], _policy(tmp_path))
    assert errors == []


def test_field_names_match_case_insensitively(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "REPO", str(tmp_path))
    pack = _pack(tmp_path, "p1", {"HostOS": "device_platform_name"})
    errors, _ = c.check([pack], _policy(tmp_path))
    assert [e[1] for e in errors] == ["hostos"]
