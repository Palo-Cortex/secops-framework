#!/usr/bin/env python3
"""Regression test: does the NEW category map resolve the same way as the
SHIPPED one for every source a tenant actually emits?

Replicates what Foundation - Product Classification does at runtime:
  DS: tag -> ds_* key -> map lookup -> _base_cat
  product_map[_product] overrides category when present
  responses[resolved category] selects the responder

Compares HEAD vs working tree. Any difference for an existing source is a
behaviour change; only NEW sources should differ (from absent to present).
"""
import json, os, re, subprocess, sys, glob
from collections import Counter

REPO = "/home/scott/secops-framework"
LIST = ("Packs/soc-optimization-unified/Lists/SOCProductCategoryMap_V3/"
        "SOCProductCategoryMap_V3_data.json")
os.chdir(REPO)

old = json.loads(subprocess.run(["git", "show", f"HEAD:{LIST}"],
                                capture_output=True, text=True).stdout)
new = json.load(open(LIST))


def ds_key(tag):
    raw = tag[3:] if tag.startswith("DS:") else tag
    ch = list(raw)
    for i, c in enumerate(ch):
        if not c.isalnum() and 0 < i < len(ch) - 1:
            ch[i] = "_"
    return "ds_" + "".join(ch).lower()


def resolve(mapping, tag, product):
    """Foundation's resolution, condensed."""
    entry = mapping.get(ds_key(tag))
    if not isinstance(entry, dict):
        return {"category": None, "response": None, "responder": None,
                "routed": False}
    base = entry.get("category")
    cat = (entry.get("product_map") or {}).get(product, base)
    responses = entry.get("responses") or {}
    responder = responses.get(str(cat or "").lower()) or entry.get("response")
    return {"category": cat, "response": entry.get("response"),
            "responder": responder, "routed": True}


# every (DS: tag, product) pair observed across the captures
pairs = {}
for path in sorted(glob.glob("/home/scott/captures/*.json")):
    doc = json.load(open(path))
    for src in doc.get("sources", []):
        pairs[(src["ds_tag"], src["product"])] = (
            pairs.get((src["ds_tag"], src["product"]), 0) + src.get("issues", 0))

EMAIL = ("proofpoint", "abnormal", "email", "tap")
ENDPOINT = ("crowdstrike", "defender", "graph_security", "sentinel", "trend", "xdr")


def stream(tag):
    low = tag.lower()
    if any(t in low for t in EMAIL):
        return "EMAIL"
    if any(t in low for t in ENDPOINT):
        return "ENDPOINT"
    return "other"


print(f"{'stream':<9} {'DS: tag / product':<58} {'before':<26} {'after':<26} verdict")
print("-" * 132)
regressions, changes, unchanged = [], [], 0
for (tag, product), n in sorted(pairs.items(), key=lambda x: -x[1]):
    s = stream(tag)
    o, w = resolve(old, tag, product), resolve(new, tag, product)
    before = f"{o['category']}/{o['responder']}" if o["routed"] else "UNROUTED"
    after = f"{w['category']}/{w['responder']}" if w["routed"] else "UNROUTED"
    if o == w:
        unchanged += 1
        verdict = "same"
    elif not o["routed"] and w["routed"]:
        verdict = "NEWLY ROUTED"
        changes.append((s, tag, product, before, after))
    else:
        verdict = "** CHANGED **"
        regressions.append((s, tag, product, before, after))
    if s != "other" or verdict != "same":
        print(f"{s:<9} {(tag + ' / ' + product)[:57]:<58} "
              f"{before[:25]:<26} {after[:25]:<26} {verdict}")

print(f"\nunchanged: {unchanged}   newly routed: {len(changes)}   "
      f"changed behaviour: {len(regressions)}")
if regressions:
    print("\n** BEHAVIOUR CHANGED FOR EXISTING SOURCES **")
    for s, tag, product, before, after in regressions:
        print(f"   [{s}] {tag} / {product}: {before} -> {after}")
    sys.exit(1)
print("\nNo existing source changed behaviour.")
