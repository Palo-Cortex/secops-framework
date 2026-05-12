"""
SOCDedupComputeWinner
Foundation utility for Foundation - Dedup_V3.

Given similar alert IDs (from DBotFindSimilarIncidents.similarIncident.id)
plus the current alert ID, returns the numeric minimum as a string and
writes SOCFramework.Dedup.WinnerID. Deterministic, race-free, no
coordination required.

Replaces the broken `min` transformer on SetAndHandleEmpty.
Cortex transformers do not include `min`/`max`, and the alternative
(`sort` + accessor `[0]`) is lexicographic — which orders alert IDs
incorrectly across order-of-magnitude ranges
(e.g. "10000" < "9999" string-wise).
"""
import demistomock as demisto
from CommonServerPython import *


def _to_list(val):
    """Normalize an XSIAM context value into a flat list of trimmed strings."""
    if val is None or val == "":
        return []
    if isinstance(val, list):
        out = []
        for item in val:
            if item is None or item == "":
                continue
            out.append(str(item).strip())
        return out
    if isinstance(val, str):
        # CSV from list / transformer surfaces
        return [x.strip() for x in val.split(",") if x.strip()]
    return [str(val).strip()]


def compute_winner(similar_ids, current_id):
    """Return the numeric minimum of (similar_ids + current_id) as a string.

    Falls back to lexicographic min only if NO candidate is numeric
    (defensive — XSIAM alert IDs are always numeric in practice).
    """
    candidates = _to_list(similar_ids) + _to_list(current_id)
    if not candidates:
        return ""

    numeric = [int(c) for c in candidates if c.isdigit()]
    if numeric:
        return str(min(numeric))

    return min(candidates)


def main():
    args = demisto.args()
    similar_ids = args.get("similar_ids")
    current_id = args.get("current_id")

    candidates = _to_list(similar_ids) + _to_list(current_id)
    winner = compute_winner(similar_ids, current_id)

    demisto.setContext("SOCFramework.Dedup.WinnerID", winner)
    return_results(CommandResults(
        readable_output=(
            f"**Dedup winner:** `{winner}`  \n"
            f"**Candidates:** `{candidates}`"
        ),
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
