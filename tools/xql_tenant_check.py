"""Validate correlation rule XQL against a live tenant's dataset schema.

Why this exists
---------------
Every static check in ``correlation_rule_preflight`` passed on
``soc-crowdstrike-saas`` while the rule was unusable: it referenced seven
columns that only exist once a tenant has ingested ``product="saas-security"``.
Referencing an absent column fails XQL validation at install, which the pack
bundle installer reports as a bare ``101704`` with no field name. The defect was
invisible until a pack install failed, and then gave nothing to act on.

Parsing field references out of XQL locally is a trap — multi-assign ``alter``
blocks, string literals and function arguments all look like field references to
a regex, and an earlier attempt at exactly that over-reported badly. So this
does not parse XQL. It hands the query to the platform, which already has a
parser and the dataset schema, and reads back the field it rejects:

    XQL query is invalid: unknown field user_names.

Mechanics worth knowing (all learned the hard way)
--------------------------------------------------
* ``request_data`` must be a LIST of rule JSONs. A bare object returns
  "The request should contain only a list of JSONs".
* ``insert`` has a strict allowed-field list and rejects extras by name —
  ``fromversion``, ``global_rule_id`` and ``system`` are pack/content fields and
  must be stripped.
* It reports only the FIRST offending field, so finding all of them needs a
  loop that neutralises each one and re-submits.
* It refuses ``REAL_TIME`` on datasets that are not real-time-eligible, which is
  stricter than the live engine. Probes are therefore always submitted as
  ``SCHEDULED`` regardless of what the rule ships — we are validating field
  references, not scheduling.
* A probe that validates is really created, so it must be deleted. Delete takes
  the ``filters`` form; ``{"correlation_ids": [...]}`` returns "Required param
  is missing".
"""

from __future__ import annotations

import json
import os
import re
import urllib3
import requests
import yaml
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_TIMEOUT = 60
MAX_FIELD_PROBES = 25  # a rule with more unknown fields than this is a rewrite

# Mirrors the platform's allowed-field list. Anything outside it is rejected by
# name, so the payload is built as an intersection rather than a blocklist —
# a blocklist silently breaks when the platform adds a field.
INSERT_ALLOWED = {
    "suppression_enabled", "mapping_strategy", "drilldown_query_timeframe",
    "user_defined_severity", "name", "alert_domain", "user_defined_category",
    "execution_mode", "dataset", "investigation_query_link", "action",
    "alert_description", "search_window", "alert_category", "alert_fields",
    "lookup_mapping", "is_enabled", "simple_schedule", "description",
    "mitre_defs", "timezone", "severity", "suppression_fields", "alert_name",
    "crontab", "alert_type", "xql_query", "suppression_duration",
}


class TenantConfig:
    """Credentials from the environment. Absent creds are not a failure."""

    def __init__(self) -> None:
        self.base_url = (os.environ.get("DEMISTO_BASE_URL") or "").rstrip("/")
        self.api_key = os.environ.get("DEMISTO_API_KEY") or ""
        self.auth_id = os.environ.get("XSIAM_AUTH_ID") or ""

    @property
    def available(self) -> bool:
        return bool(self.base_url and self.api_key and self.auth_id)

    @property
    def headers(self) -> dict:
        return {
            "Authorization": self.api_key,
            "x-xdr-auth-id": self.auth_id,
            "Content-Type": "application/json",
        }


def _post(cfg: TenantConfig, path: str, body: dict) -> dict:
    resp = requests.post(
        f"{cfg.base_url}{path}",
        headers=cfg.headers,
        json=body,
        timeout=HTTP_TIMEOUT,
        verify=False,
    )
    try:
        return resp.json()
    except ValueError:
        return {"_raw": resp.text, "_status": resp.status_code}


def build_probe(rule: dict, suffix: str) -> dict:
    """A probe rule the insert endpoint will accept structurally.

    Only the XQL matters. Everything else is shaped to get past validation so
    that the one error we DO get back is about field references.
    """
    probe = {k: v for k, v in rule.items() if k in INSERT_ALLOWED}
    probe["name"] = f"_xqlcheck_delete_me_{suffix}"
    probe["is_enabled"] = False

    # SCHEDULED unconditionally: insert refuses REAL_TIME on datasets that are
    # not real-time-eligible, which would mask the field errors we came for.
    probe["execution_mode"] = "SCHEDULED"
    probe["crontab"] = probe.get("crontab") or "*/10 * * * *"
    probe["search_window"] = probe.get("search_window") or "25 hours"
    probe["simple_schedule"] = probe.get("simple_schedule") or "10 minutes"
    probe["timezone"] = probe.get("timezone") or "UTC"

    # user_defined_category is mandatory when alert_category is User Defined,
    # and returns a 400 that has nothing to do with the XQL.
    if probe.get("alert_category") == "User Defined" and not probe.get("user_defined_category"):
        probe["user_defined_category"] = "Preflight"
    return probe


def delete_probe(cfg: TenantConfig, rule_id) -> None:
    """Best-effort cleanup. A probe that validated was really created."""
    try:
        _post(cfg, "/public_api/v1/correlations/delete",
              {"request_data": {"filters": [
                  {"field": "rule_id", "operator": "eq", "value": rule_id}]}})
    except Exception:
        pass


def _unknown_field(status: str) -> str | None:
    marker = "unknown field "
    if "XQL query is invalid" not in status or marker not in status:
        return None
    return status.split(marker, 1)[1].strip().rstrip(".").strip()


def check_rule_xql(cfg: TenantConfig, rule_path: Path) -> tuple[list[str], list[str]]:
    """Return (errors, notes) for one rule file.

    Iterates: submit, read the rejected field, neutralise it, resubmit — because
    the platform names only the first offender.
    """
    errors: list[str] = []
    notes: list[str] = []

    rule = yaml.safe_load(rule_path.read_text())
    xql = rule.get("xql_query")
    if not xql:
        return errors, notes

    # alert_fields maps columns straight off the alert the query emits, and the
    # insert endpoint validates xql_query ONLY -- so a mapping onto a column the
    # tenant does not have passes this check while the rule editor marks it
    # "field is invalid" and the pack install fails 101704. Sixteen such
    # mappings shipped in SocFrameworkProofPointTap.
    #
    # Appending the mapped sources as a trailing stage puts them inside the
    # query, so the platform validates them too and names any it cannot
    # resolve. This is the only reliable oracle: whether a bare column is
    # legitimate depends on the tenant's live dataset schema, which no static
    # check can know -- a repo-wide scan flags 114 such mappings, most of them
    # in packs that install perfectly well.
    fields_map = rule.get("alert_fields") or {}
    sources = sorted({
        v for v in fields_map.values()
        if isinstance(v, str) and v and re.fullmatch(r"\w+", v)
    }) if isinstance(fields_map, dict) else []

    base_xql = xql
    if sources:
        base_xql = f"{xql}\n| fields {', '.join(sources)}"

    unknown: list[str] = []
    probe_xql = base_xql

    for i in range(MAX_FIELD_PROBES):
        probe = build_probe(rule, f"{abs(hash(rule_path.name)) % 100000}_{i}")
        probe["xql_query"] = probe_xql
        reply = _post(cfg, "/public_api/v1/correlations/insert",
                      {"request_data": [probe]})

        inner = reply.get("reply", reply)
        added = inner.get("added_objects") or []
        if added:
            # Validated. It was really created, so remove it.
            for obj in added:
                if obj.get("id") is not None:
                    delete_probe(cfg, obj["id"])
            break

        errs = inner.get("errors") or []
        if not errs:
            notes.append(f"inconclusive tenant response: {json.dumps(reply)[:200]}")
            break

        status = str(errs[0].get("status", ""))
        field = _unknown_field(status)
        if not field:
            # A real validation error that is not a field reference — surface it
            # verbatim rather than guessing at it.
            errors.append(f"{rule_path.name}: {status}")
            break

        unknown.append(field)
        # Neutralise this field so the next submit reveals the following one.
        # Defining it up front is enough; we are enumerating, not executing.
        lines = base_xql.splitlines()
        probe_xql = (
            lines[0] + "\n| alter " + " = null, ".join(unknown) + " = null\n"
            + "\n".join(lines[1:])
        )

    if unknown:
        errors.append(
            f"{rule_path.name}: {len(unknown)} field(s) not in the tenant dataset "
            f"schema — the pack install will fail with 101704: {', '.join(unknown)}"
        )
        notes.append(
            "If the tenant has simply never ingested this product, read these "
            "from rawJSON and alias back to the canonical names (see the "
            "compatibility shim in soc-crowdstrike-idp / soc-crowdstrike-saas)."
        )
    return errors, notes
