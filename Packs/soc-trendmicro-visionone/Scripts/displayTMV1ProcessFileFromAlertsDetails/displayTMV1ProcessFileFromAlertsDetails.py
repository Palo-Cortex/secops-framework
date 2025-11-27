import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Script name: displayTMV1ProcessFile_FromAlertDetails
# Purpose: Render a Process & File view using VisionOne Alert Details already in context.
# Notes:
#  - No external calls; reads what's already in the alert object.
#  - Finds the alert anywhere in context (dynamic keys supported).
#  - Sections:
#      Process: Command Lines + Matched Process Events
#      File: File Paths + File Hashes

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

def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(str(r.get(h, "")) for h in headers) + "|\n"
    return md

# -------------------- normalization --------------------
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
        # Render compactly for file/host objects if they appear
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

    # stringify for markdown
    for k in list(row.keys()):
        row[k] = esc(row[k])
    return row

def extract_matched_process_events(alert):
    """
    Flatten matched_rules -> matched_filters -> matched_events (process-centric).
    Returns rows with: Time, Type, UUID, Filter Name, Rule Name
    """
    rows = []
    rules = alert.get("matched_rules") or []
    if not isinstance(rules, list):
        return rows
    for r in rules:
        rule_name = r.get("name") or r.get("id") or ""
        mfs = r.get("matched_filters") or []
        for f in mfs:
            filter_name = f.get("name") or f.get("id") or ""
            events = f.get("matched_events") or []
            for ev in events:
                ev_type = ev.get("type") or ""
                # keep it if it looks like a process event (very light heuristic)
                if "PROCESS" in ev_type.upper():
                    rows.append({
                        "Time": esc(ev.get("matched_date_time") or ""),
                        "Type": esc(ev_type),
                        "UUID": esc(ev.get("uuid") or ""),
                        "Filter": esc(filter_name),
                        "Rule": esc(rule_name),
                    })
    return rows

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}
    alert = find_alert_in_context(ctx)
    if not isinstance(alert, dict):
        md_out("### Trend Micro Vision One — Process & File\n❌ Couldn’t locate a Vision One alert object anywhere in context.")
        return

    wb_id = alert.get("id") or "—"
    indicators = alert.get("indicators") or []
    if not isinstance(indicators, list):
        indicators = []

    # Bucket indicators for process/file
    buckets = defaultdict(list)
    for ind in indicators:
        row = normalize_indicator(ind)
        t = (row.get("Type") or "").lower()
        buckets[t].append(row)

    # Compose markdown
    md = []
    md.append("### Trend Micro Vision One — Process & File")
    md.append(f"**Workbench ID:** `{wb_id}`  \n")

    # ---- Process section ----
    md.append("#### Process")
    # Command lines (from indicators)
    cmd_headers = ["ID", "Field", "Value", "Related Entities", "Provenance", "Filter IDs"]
    cmd_rows = [
        {k: r.get(k, "") for k in cmd_headers}
        for r in buckets.get("command_line", [])
    ]
    md.append("**Command Lines**")
    md.append(make_table(cmd_headers, cmd_rows))

    # Matched process events (from matched_rules.*)
    proc_evt_headers = ["Time", "Type", "UUID", "Filter", "Rule"]
    proc_evt_rows = extract_matched_process_events(alert)
    md.append("**Matched Process Events**")
    md.append(make_table(proc_evt_headers, proc_evt_rows))

    # ---- File section ----
    md.append("#### File")
    # File paths (from indicators: fullpath)
    path_headers = ["ID", "Field", "Value", "Related Entities", "Provenance", "Filter IDs"]
    path_rows = [
        {k: r.get(k, "") for k in path_headers}
        for r in buckets.get("fullpath", [])
    ]
    md.append("**File Paths**")
    md.append(make_table(path_headers, path_rows))

    # File hashes (from indicators: file_sha256, file_md5, file_sha1 if present)
    hash_headers = ["ID", "Type", "Value", "Related Entities", "Provenance", "Filter IDs"]
    hash_rows = []
    for t in ("file_sha256", "file_sha1", "file_md5"):
        for r in buckets.get(t, []):
            hash_rows.append({
                "ID": r.get("ID", ""),
                "Type": r.get("Type", ""),
                "Value": r.get("Value", ""),
                "Related Entities": r.get("Related Entities", ""),
                "Provenance": r.get("Provenance", ""),
                "Filter IDs": r.get("Filter IDs", ""),
            })
    md.append("**File Hashes**")
    md.append(make_table(hash_headers, hash_rows))

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
