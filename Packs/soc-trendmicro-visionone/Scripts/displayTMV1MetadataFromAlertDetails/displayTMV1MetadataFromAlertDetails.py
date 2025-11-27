import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Script name: displayTMV1Metadata_FromAlertDetails
# Purpose: Render Vision One "Metadata" from Alert Details already in context (no external calls).
# Sections:
#   - Core
#   - Status
#   - Timestamps
#   - Impact Scope (counts)
#   - Matched Rules (summary)
#
# Safe on any python3 image (no CommonServerPython import).

import json

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
    if obj.get("impact_scope") or obj.get("indicators"):
        return True
    return False

def find_alert_and_meta_in_context(ctx):
    """
    Recursively walk the entire context to locate the Vision One alert object.
    Return (alert_obj, meta_dict) where meta_dict may include 'etag' if available
    (e.g., on the wrapper object "VisionOne.Alert_Details(...)" that contains both
    'alert' and 'etag').
    """
    seen = set()

    def _walk(node, parent=None):
        nid = id(node)
        if nid in seen:
            return (None, None)
        seen.add(nid)

        if isinstance(node, dict):
            # If node has 'alert', prefer that
            if "alert" in node and looks_like_alert_obj(node["alert"]):
                meta = {}
                # Common wrapper includes 'etag'
                if "etag" in node and isinstance(node["etag"], (str, int)):
                    meta["etag"] = node["etag"]
                return (node["alert"], meta)
            # If node itself looks like the alert
            if looks_like_alert_obj(node):
                return (node, {})
            # Recurse into children
            for v in node.values():
                a, m = _walk(v, node)
                if a is not None:
                    # If wrapper info (etag) is on current node and not in child, add it
                    if not m and isinstance(node, dict) and "etag" in node:
                        m = {"etag": node.get("etag")}
                    return (a, m)
        elif isinstance(node, list):
            for it in node:
                a, m = _walk(it, parent)
                if a is not None:
                    return (a, m)
        return (None, None)

    return _walk(ctx, None)

def make_kv_table(pairs):
    """
    Render a simple two-column markdown table from (key, value) tuples.
    Filters out empty values.
    """
    rows = [(k, v) for (k, v) in pairs if v not in (None, "", [], {})]
    if not rows:
        return "_none_\n"
    md = "|Key|Value|\n|---|---|\n"
    for k, v in rows:
        md += f"|{esc(k)}|{esc(v)}|\n"
    return md

def summarize_impact_scope(iscope):
    if not isinstance(iscope, dict):
        return None, None
    counts = []
    for key in ("desktop_count", "server_count", "account_count", "email_address_count",
                "container_count", "cloud_identity_count"):
        if key in iscope:
            counts.append((key.replace("_", " ").title(), iscope.get(key)))
    entities = iscope.get("entities") or []
    return counts, entities

def summarize_matched_rules(alert):
    """
    Flatten matched_rules -> matched_filters, capture key info.
    Returns a list of dict rows.
    """
    out = []
    rules = alert.get("matched_rules") or []
    if not isinstance(rules, list):
        return out
    for r in rules:
        rule_name = r.get("name") or r.get("id") or ""
        mfs = r.get("matched_filters") or []
        if not isinstance(mfs, list):
            continue
        for f in mfs:
            filt_name = f.get("name") or f.get("id") or ""
            when = ""
            # pick first matched event time if available
            evs = f.get("matched_events") or []
            if isinstance(evs, list) and evs:
                when = evs[0].get("matched_date_time") or ""
            techniques = flat_join(f.get("mitre_technique_ids"))
            out.append({
                "Rule": rule_name,
                "Filter": filt_name,
                "When": when,
                "MITRE": techniques,
            })
    return out

def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(esc(str(r.get(h, ""))) for h in headers) + "|\n"
    return md

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}

    alert, meta = find_alert_and_meta_in_context(ctx)
    if not isinstance(alert, dict):
        md_out("### Trend Micro Vision One — Metadata\n❌ Couldn’t locate a Vision One alert object anywhere in context.")
        return

    # Core fields
    wb_id = alert.get("id") or "—"
    workbench_link = alert.get("workbench_link") or ""
    provider = alert.get("alert_provider") or alert.get("provider") or ""
    model = alert.get("model") or ""
    model_type = alert.get("model_type") or ""
    model_id = alert.get("model_id") or ""
    severity = alert.get("severity") or ""
    score = alert.get("score")
    schema_version = alert.get("schema_version") or ""
    incident_id = alert.get("incident_id") or ""
    case_id = alert.get("case_id") or ""
    owner_ids = alert.get("owner_ids")
    owner_txt = flat_join(owner_ids) if isinstance(owner_ids, list) else (owner_ids or "")

    # Status fields
    status = alert.get("status") or ""
    inv_status = alert.get("investigation_status") or ""
    inv_result = alert.get("investigation_result") or ""

    # Timestamps
    t_created = alert.get("created_date_time") or ""
    t_updated = alert.get("updated_date_time") or ""
    t_first_investigated = alert.get("first_investigated_date_time") or ""

    # Impact scope
    counts, entities = summarize_impact_scope(alert.get("impact_scope") or {})

    # Matched rules summary
    mr_rows = summarize_matched_rules(alert)

    # Indicators count (quick hint)
    indicators = alert.get("indicators") or []
    ind_count = len(indicators) if isinstance(indicators, list) else 0

    # ETag (from wrapper meta if we saw one)
    etag = meta.get("etag") if isinstance(meta, dict) else None

    # ----- Compose Markdown -----
    md = []
    md.append("### Trend Micro Vision One — Metadata")
    md.append(f"**Workbench ID:** `{wb_id}`  ")
    if workbench_link:
        md.append(f"**Workbench Link:** {esc(workbench_link)}  ")
    md.append("")

    # Core
    core_pairs = [
        ("Provider", provider),
        ("Model", model),
        ("Model Type", model_type),
        ("Model ID", model_id),
        ("Severity", severity),
        ("Score", score),
        ("Schema Version", schema_version),
        ("Incident ID", incident_id),
        ("Case ID", case_id),
        ("Owner IDs", owner_txt),
        ("Indicators (count)", ind_count),
        ("ETag", etag),
    ]
    md.append("#### Core")
    md.append(make_kv_table(core_pairs))

    # Status
    status_pairs = [
        ("Status", status),
        ("Investigation Status", inv_status),
        ("Investigation Result", inv_result),
    ]
    md.append("#### Status")
    md.append(make_kv_table(status_pairs))

    # Timestamps
    time_pairs = [
        ("Created", t_created),
        ("Updated", t_updated),
        ("First Investigated", t_first_investigated),
    ]
    md.append("#### Timestamps")
    md.append(make_kv_table(time_pairs))

    # Impact scope counts
    md.append("#### Impact Scope")
    if counts:
        md.append(make_kv_table(counts))
    else:
        md.append("_none_\n")

    # Matched Rules summary
    md.append("#### Matched Rules")
    mr_headers = ["Rule", "Filter", "When", "MITRE"]
    md.append(make_table(mr_headers, mr_rows))

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
