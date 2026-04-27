"""
SOCActionFingerprintCheck

Action-level idempotency for the SOC Framework. Call as the FIRST task in
a SOC Action playbook (e.g. SOC_Action_Isolate_Endpoint_V3), BEFORE the
approval task. Computes a fingerprint of (action, entity), checks the
parent case's SOCFramework.ActionFingerprints namespace, and writes a
'pending_approval' record if absent.

Returns is_duplicate so the playbook can route around the approval +
wrapper flow when an earlier sibling on the same case is already handling
this action+entity.

Shares the parentIncidentContext.SOCFramework.ActionFingerprints.fp_<short>
namespace with SOCCommandWrapper. The two layers use different fingerprint
inputs (playbook: action+entity; wrapper: action+vendor+command+args), so
their hashes differ and their leaf keys do not collide. Both reading the
same namespace makes the case's action audit trail single-source.

In playground/debug there is no parent case — the check returns
IsDuplicate=false and the write no-ops. Correct: dedup doesn't apply
outside a case.
"""

import json
import hashlib
import uuid
from datetime import datetime


def utc_now():
    return datetime.utcnow().isoformat() + "Z"


def compute_fingerprint(action, entity):
    if not action or not entity:
        return None
    payload = f"{action}:{entity}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def fp_key_path(fp):
    """
    Match the namespace used by SOCCommandWrapper. First 16 hex chars of
    sha1 is collision-safe at case scope. 'fp_' prefix keeps the leading
    character a letter so demisto.get's dotted-path traversal is unambiguous.
    """
    return f"SOCFramework.ActionFingerprints.fp_{fp[:16]}"


def parse_existing(existing):
    """
    setParentIncidentContext stores complex values as JSON strings, and
    accumulates rather than overwrites under repeated writes to an
    array-shaped key. Handle scalar string, list of strings, and dict
    shapes — all are valid evidence of a prior write.
    """
    if isinstance(existing, str):
        try:
            return json.loads(existing)
        except Exception:
            return {"run_id": "unknown"}
    if isinstance(existing, list) and existing:
        first = existing[0]
        if isinstance(first, str):
            try:
                return json.loads(first)
            except Exception:
                return {"run_id": "unknown"}
        if isinstance(first, dict):
            return first
    if isinstance(existing, dict):
        return existing
    return {"run_id": "unknown"}


def main():
    args = demisto.args()
    action = args.get("action")
    entity = args.get("entity")
    phase = args.get("phase", "")
    lifecycle = args.get("lifecycle", "")

    if not action:
        return_error("SOCActionFingerprintCheck: missing required argument 'action'")
    if not entity:
        return_error("SOCActionFingerprintCheck: missing required argument 'entity'")

    fp = compute_fingerprint(action, entity)
    fp_short = fp[:16]
    key_path = fp_key_path(fp)

    ctx = demisto.context()
    existing = demisto.get(ctx, f"parentIncidentContext.{key_path}")

    if existing:
        prior = parse_existing(existing)
        demisto.setContext("SOCFramework.Dedup.IsDuplicate", "true")
        demisto.setContext("SOCFramework.Dedup.Fingerprint", fp_short)
        demisto.setContext("SOCFramework.Dedup.PriorRunId", prior.get("run_id", ""))
        demisto.setContext("SOCFramework.Dedup.PriorTs", prior.get("ts", ""))

        return_results({
            "Type": EntryType.NOTE,
            "ContentsFormat": "json",
            "Contents": {
                "is_duplicate": True,
                "fingerprint": fp_short,
                "prior_run_id": prior.get("run_id", ""),
                "prior_ts": prior.get("ts", ""),
                "prior_status": prior.get("status", "")
            },
            "HumanReadable": (
                f"### Action Skipped (Duplicate)\n"
                f"- Action: `{action}`\n"
                f"- Entity: `{entity}`\n"
                f"- Original run: `{prior.get('run_id', '')}`\n"
                f"- Original ts: `{prior.get('ts', '')}`\n"
                f"- Status: `{prior.get('status', '')}`"
            )
        })
        return

    # Not a duplicate. Record the fingerprint UPFRONT so concurrent siblings
    # see it before they spawn their own approval tasks. Status is
    # 'pending_approval' — when SOCCommandWrapper eventually runs, it writes
    # its own (different-hash) fingerprint at the wrapper layer; this
    # playbook-layer record stays as the audit trail of the approval gate.
    run_id = str(uuid.uuid4())
    ts = utc_now()
    record = {
        "fp": fp,
        "action": action,
        "entity": entity,
        "phase": phase,
        "lifecycle": lifecycle,
        "run_id": run_id,
        "ts": ts,
        "status": "pending_approval",
        "source": "playbook_check"
    }

    try:
        demisto.executeCommand("setParentIncidentContext", {
            "key": key_path,
            "value": json.dumps(record)
        })
    except Exception as e:
        demisto.debug(
            f"SOCActionFingerprintCheck: setParentIncidentContext failed "
            f"(ok in playground/debug): {e}"
        )

    demisto.setContext("SOCFramework.Dedup.IsDuplicate", "false")
    demisto.setContext("SOCFramework.Dedup.Fingerprint", fp_short)
    demisto.setContext("SOCFramework.Dedup.PriorRunId", "")
    demisto.setContext("SOCFramework.Dedup.PriorTs", "")

    return_results({
        "Type": EntryType.NOTE,
        "ContentsFormat": "json",
        "Contents": {
            "is_duplicate": False,
            "fingerprint": fp_short,
            "run_id": run_id,
            "ts": ts
        },
        "HumanReadable": (
            f"### Action Proceeding (First Attempt)\n"
            f"- Action: `{action}`\n"
            f"- Entity: `{entity}`\n"
            f"- Run: `{run_id}`\n"
            f"- Status: `pending_approval`"
        )
    })


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
