import json
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

# The consumer reads only these. Everything else in the contract goes to
# contract_full, which nothing on the analysis path scans.
EVIDENCE_KEYS = ("Artifacts", "Product", "Intel", "lifecycle")

DEFAULT_INSTANCE = "socfw_case_ledger_writer"

# Category-agnostic entity columns, resolved from the structured contract so the
# values are normalized rather than vendor-spelled. First non-empty path wins.
ENTITY_PATHS = {
    "host_name": ("Artifacts.Endpoint.Hostname", "Artifacts.Endpoint.FQDN"),
    "endpoint_id": ("Artifacts.Endpoint.AgentID", "Artifacts.EndPointID"),
    # No parent-process fallback: a parent hash is usually a stock OS binary and
    # would surface across unrelated issues as a shared indicator.
    "file_sha256": ("Artifacts.Process.SHA256",),
    "local_ip": ("Artifacts.Endpoint.IPAddress", "Artifacts.Network.IP"),
}


def dig(obj, path):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def first_value(obj, paths):
    for path in paths:
        val = dig(obj, path)
        if isinstance(val, list):
            val = val[0] if val else None
        if val not in (None, "", []):
            return str(val)
    return None


def shape_key_from_name(name):
    """Collapse key for grouping like issues.

    Issue names are pipe-delimited and the technique lives in segments 1 and 2.
    Segment 0 carries the hostname, which would multiply every technique by the
    number of hosts. Computed at write time so the collapse does not depend on a
    string split re-run on every JOB pass.
    """
    if not name:
        return None
    parts = [p.strip() for p in str(name).split("|")]
    if len(parts) >= 3:
        return "{} | {}".format(parts[1], parts[2])
    return str(name).strip()


def build_row(contract, issue, phase, contract_source):
    evidence = {k: v for k, v in contract.items() if k in EVIDENCE_KEYS}
    full = {k: v for k, v in contract.items() if k not in EVIDENCE_KEYS}

    # The issue object carries the case as "INCIDENT-<n>"; the ledger stores the
    # bare id so it joins against xdm.issue.case_ids without rewriting.
    parent = str(issue.get("parentXDRIncident") or "")
    case_id = parent.rsplit("-", 1)[-1] if parent else None

    fields = issue.get("CustomFields") or {}

    row = {
        "event_type": "case_ledger",
        "phase": phase,
        "contract_source": contract_source,
        "case_id": case_id,
        "alert_id": issue.get("id"),
        # Case domain, not the host's AD domain. CustomFields carries both under
        # confusingly similar names; alert_domain is the one that scopes a case.
        "domain": dig(contract, "Artifacts.Source.AlertDomain") or fields.get("alert_domain"),
        "lifecycle": contract.get("lifecycle"),
        "lifecycle_version": contract.get("lifecycle_version"),
        "product_category": dig(contract, "Product.category"),
        "shape_key": shape_key_from_name(issue.get("name")),
        "source_tag": dig(contract, "Product.key"),
        "severity": issue.get("severity"),
        "rule_id": fields.get("ruleid"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contract_evidence": json.dumps(evidence) if evidence else None,
        "contract_full": json.dumps(full) if full else None,
    }

    for column, paths in ENTITY_PATHS.items():
        row[column] = first_value(contract, paths)

    return {k: v for k, v in row.items() if v not in (None, "", [])}


def post_row(row, instance):
    result = demisto.executeCommand(
        "socfw-post-to-dataset",
        {"using": instance, "JSON": json.dumps([row])},
    )
    if isinstance(result, list) and result and is_error(result[0]):
        return get_error(result)
    return None


def main():
    args = demisto.args()
    phase = args.get("phase") or "foundation"
    contract_path = args.get("contract_path") or "SOCFramework"
    instance = args.get("instance") or DEFAULT_INSTANCE

    contract = dig(demisto.context() or {}, contract_path) or {}
    if not isinstance(contract, dict):
        contract = {}

    # A row is written even when the contract is empty. Row absence is what tells
    # the consumer Upon Trigger never ran; an empty contract that did run is a
    # different fact and has to stay distinguishable from it.
    contract_source = args.get("contract_source") or ("contract" if contract else "empty")

    row = build_row(contract, demisto.incident() or {}, phase, contract_source)

    error = post_row(row, instance)
    if error:
        # Stay quiet rather than put a failure entry on every issue. This script
        # ships in soc-optimization-unified, which installs everywhere, while the
        # ledger needs a collector and writer instance the tenant creates by hand.
        # On a tenant that has neither, a visible error reads to an analyst like a
        # broken pipeline. Suppressing output only on a path that already failed
        # cannot stop a working write.
        demisto.debug("SOCFWCaseLedgerWrite: {}".format(error))
        return_results(CommandResults(readable_output=""))
        return

    return_results(CommandResults(
        readable_output="Case ledger row written for issue {} (phase {}).".format(
            row.get("alert_id"), phase),
        outputs_prefix="SOCFramework.CaseLedger",
        outputs={"written": True, "phase": phase, "case_id": row.get("case_id")},
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
