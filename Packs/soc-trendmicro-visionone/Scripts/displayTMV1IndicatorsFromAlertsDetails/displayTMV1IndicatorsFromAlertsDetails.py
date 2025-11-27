import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Script name: displayTMV1Indicators_FromAlertDetails
# Purpose: Read indicators from VisionOne Alert Details already in *any* context path and render them nicely.

import json
from collections import defaultdict

# -------------------- tiny helpers --------------------
def md_out(text):
    demisto.results({"Type": 1, "ContentsFormat": "markdown", "Contents": text})

def esc(s):
    if s is None:
        return ""
    if not isinstance(s, str):
        try:
            s = json.dumps(s, ensure_ascii=False)
        except Exception:
            s = str(s)
    return s.replace("`", "\\`")

def flat_join(seq, sep=", "):
    if not seq:
        return ""
    return sep.join(str(x) for x in seq if x not in (None, ""))

def looks_like_alert_obj(obj: dict) -> bool:
    """Heuristics to identify a Vision One alert object."""
    if not isinstance(obj, dict):
        return False
    if not obj.get("id"):
        return False
    # Must have either indicators or an impact_scope with entities
    if obj.get("indicators"):
        return True
    iscope = obj.get("impact_scope") or {}
    if isinstance(iscope, dict) and isinstance(iscope.get("entities"), list):
        return True
    return False

def find_alert_in_context(ctx):
    """
    Recursively walk the entire context dict/list to find the first Vision One alert object.
    Handles keys like 'VisionOne.Alert_Details(val.etag && val.etag == obj.etag)' and more.
    """
    seen = set()
    def _walk(node):
        nid = id(node)
        if nid in seen:
            return None
        seen.add(nid)

        if isinstance(node, dict):
            # Fast path: direct subkey 'alert'
            if "alert" in node and looks_like_alert_obj(node["alert"]):
                return node["alert"]
            if looks_like_alert_obj(node):
                return node
            for v in node.values():
                found = _walk(v)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for it in node:
                found = _walk(it)
                if found is not None:
                    return found
        return None

    return _walk(ctx)

def normalize_indicator(ind):
    """
    Return a flat dict for table rendering.
    Expected fields:
      id, type, value, related_entities, provenance, field, filter_ids
    """
    row = {
        "ID": ind.get("id"),
        "Type": ind.get("type"),
        "Field": ind.get("field") or "",
        "Value": "",
        "Related Entities": "",
        "Provenance": "",
        "Filter IDs": "",
    }

    # value can be scalar or object (e.g., host {name, ips, guid})
    val = ind.get("value")
    if isinstance(val, dict):
        name = val.get("name")
        ips = flat_join(val.get("ips"))
        guid = val.get("guid")
        parts = []
        if name: parts.append(f"name={name}")
        if ips: parts.append(f"ips=[{ips}]")
        if guid: parts.append(f"guid={guid}")
        row["Value"] = ", ".join(parts) if parts else esc(val)
    else:
        row["Value"] = esc(val)

    # lists
    row["Related Entities"] = flat_join(ind.get("related_entities"))
    row["Provenance"] = flat_join(ind.get("provenance"))
    row["Filter IDs"] = flat_join(ind.get("filter_ids"))

    # stringify everything for markdown
    for k in list(row.keys()):
        row[k] = esc(row[k])
    return row

def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(str(r.get(h, "")) for h in headers) + "|\n"
    return md

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}

    alert = find_alert_in_context(ctx)
    if not isinstance(alert, dict):
        md_out("### Trend Micro Vision One — Indicators\n❌ Couldn’t locate a Vision One alert object anywhere in context.")
        return

    wb_id = alert.get("id") or "—"
    indicators = alert.get("indicators") or []
    if not isinstance(indicators, list) or not indicators:
        md_out(
            "### Trend Micro Vision One — Indicators\n"
            f"**Workbench ID:** `{wb_id}`  \n"
            "_No indicators were returned on this alert._"
        )
        return

    # Bucket by indicator type for cleaner sections
    buckets = defaultdict(list)
    for ind in indicators:
        row = normalize_indicator(ind)
        buckets[(row.get("Type") or "").lower()].append(row)

    # Summary
    total = len(indicators)
    types_summary = ", ".join(f"{t or 'unknown'}: {len(rows)}" for t, rows in buckets.items())

    md = []
    md.append("### Trend Micro Vision One — Indicators")
    md.append(f"**Workbench ID:** `{wb_id}`  ")
    md.append(f"**Total Indicators:** {total}  ")
    md.append(f"**By Type:** {esc(types_summary)}\n")

    # Render sections in a sensible order
    headers = ["ID", "Type", "Field", "Value", "Related Entities", "Provenance", "Filter IDs"]
    preferred = ["command_line", "file_sha256", "fullpath", "host"]
    emitted = set()

    for t in preferred:
        rows = buckets.get(t, [])
        if rows:
            md.append(f"#### {t.replace('_',' ').title()}")
            md.append(make_table(headers, rows))
            emitted.add(t)

    # Any remaining types
    for t, rows in buckets.items():
        if t in emitted:
            continue
        title = (t or "unknown").replace("_", " ").title()
        md.append(f"#### {title}")
        md.append(make_table(headers, rows))

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
