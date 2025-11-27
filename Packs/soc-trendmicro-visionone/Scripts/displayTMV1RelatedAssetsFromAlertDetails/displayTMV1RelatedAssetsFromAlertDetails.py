import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Script name: displayTMV1RelatedAssets_FromAlertDetails
# Purpose: Render "Related Assets" from VisionOne Alert Details in context (no external calls).
# Sections:
#   - Summary (counts by type)
#   - Hosts (GUID, Name, IPs, Provenance, Related Entities)
#   - Accounts (Name, Provenance, Related Entities)
#   - Other entity types (Email, Container, Cloud Identity, etc., if present)
#   - Simple relationship map (who references whom)
#
# Safe on any python3 image (no CommonServerPython import).

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
    iscope = obj.get("impact_scope") or {}
    if isinstance(iscope, dict) and isinstance(iscope.get("entities"), list):
        return True
    if obj.get("indicators"):
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
def norm_host_entity(e):
    """
    Host entity_value is a dict: { name, ips[], guid }
    Return flat row for table rendering.
    """
    ev = e.get("entity_value") or {}
    name = ev.get("name") or ""
    ips = flat_join(ev.get("ips"))
    guid = ev.get("guid") or ""
    prov = flat_join(e.get("provenance"))
    rel = flat_join(e.get("related_entities"))
    return {
        "GUID": esc(guid),
        "Name": esc(name),
        "IPs": esc(ips),
        "Provenance": esc(prov),
        "Related Entities": esc(rel),
    }

def norm_account_entity(e):
    """
    Account entity_value in your sample is a string (e.g., 'NDMHNB93\\adminelet').
    """
    val = e.get("entity_value")
    prov = flat_join(e.get("provenance"))
    rel = flat_join(e.get("related_entities"))
    return {
        "Account": esc(val),
        "Provenance": esc(prov),
        "Related Entities": esc(rel),
    }

def norm_generic_entity(e):
    """
    For other entity types (email, container, cloud identity, etc.).
    Tries to render value compactly.
    """
    ev = e.get("entity_value")
    if isinstance(ev, dict):
        # Try common keys
        pretty = []
        for k in ("name", "address", "id", "guid", "resource", "namespace"):
            if ev.get(k):
                v = ev.get(k)
                if isinstance(v, list):
                    v = "[" + flat_join(v) + "]"
                pretty.append(f"{k}={v}")
        val_str = ", ".join(pretty) if pretty else esc(ev)
    else:
        val_str = esc(ev)
    prov = flat_join(e.get("provenance"))
    rel = flat_join(e.get("related_entities"))
    return {
        "Entity ID": esc(e.get("entity_id") or ""),
        "Value": val_str,
        "Provenance": esc(prov),
        "Related Entities": esc(rel),
    }

def build_relationship_map(entities):
    """
    Produce simple lines showing relations such as:
      account NDMHNB93\adminelet → host 207923EB-... (NDMHNB93)
    Uses 'related_entities' (often host GUIDs) where available.
    """
    # Index hosts by entity_id and GUID to resolve names in edges
    host_index = {}
    for e in entities:
        if e.get("entity_type") == "host":
            ev = e.get("entity_value") or {}
            disp = ev.get("name") or ev.get("guid") or e.get("entity_id") or "host"
            host_index[e.get("entity_id")] = disp
            if ev.get("guid"):
                host_index[ev.get("guid")] = disp

    lines = []
    for e in entities:
        etype = e.get("entity_type")
        if not e.get("related_entities"):
            continue
        src_label = ""
        if etype == "account":
            src_label = f"account {e.get('entity_value')}"
        elif etype == "host":
            ev = e.get("entity_value") or {}
            src_label = f"host {ev.get('name') or ev.get('guid') or e.get('entity_id')}"
        else:
            src_label = f"{etype} {e.get('entity_id') or ''}".strip()

        for target in e.get("related_entities") or []:
            tgt = host_index.get(target, target)
            if tgt:
                lines.append(f"- {esc(src_label)} → **{esc(str(tgt))}**")
    return lines

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}
    alert = find_alert_in_context(ctx)
    if not isinstance(alert, dict):
        md_out("### Trend Micro Vision One — Related Assets\n❌ Couldn’t locate a Vision One alert object anywhere in context.")
        return

    wb_id = alert.get("id") or "—"
    entities = (alert.get("impact_scope", {}) or {}).get("entities", []) or []

    if not entities:
        md_out(
            "### Trend Micro Vision One — Related Assets\n"
            f"**Workbench ID:** `{wb_id}`  \n"
            "_No related assets present in impact scope._"
        )
        return

    # Bucketize by type
    by_type = defaultdict(list)
    for e in entities:
        et = (e.get("entity_type") or "").lower()
        by_type[et].append(e)

    # Summary
    counts = ", ".join(f"{t}: {len(v)}" for t, v in by_type.items())
    md = []
    md.append("### Trend Micro Vision One — Related Assets")
    md.append(f"**Workbench ID:** `{wb_id}`  ")
    md.append(f"**By Type:** {esc(counts)}\n")

    # Hosts
    host_rows = [norm_host_entity(e) for e in by_type.get("host", [])]
    host_headers = ["GUID", "Name", "IPs", "Provenance", "Related Entities"]
    md.append("#### Hosts")
    md.append(make_table(host_headers, host_rows))

    # Accounts
    acct_rows = [norm_account_entity(e) for e in by_type.get("account", [])]
    acct_headers = ["Account", "Provenance", "Related Entities"]
    md.append("#### Accounts")
    md.append(make_table(acct_headers, acct_rows))

    # Other types (email, container, cloud_identity, etc.)
    for t, items in sorted(by_type.items()):
        if t in ("host", "account"):
            continue
        rows = [norm_generic_entity(e) for e in items]
        headers = ["Entity ID", "Value", "Provenance", "Related Entities"]
        md.append(f"#### {t.replace('_',' ').title()}")
        md.append(make_table(headers, rows))

    # Relationship map
    rel_lines = build_relationship_map(entities)
    if rel_lines:
        md.append("#### Relationships")
        md.extend(rel_lines)

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
