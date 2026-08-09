#!/usr/bin/env python3
"""How many of a tenant's live DS: tags have NO exact match in the shipped
SOCProductCategoryMap? Those are silently unrouted at runtime -- Foundation -
Product Classification does the same exact-key lookup this checks."""
import json, os, sys, argparse, urllib.request, difflib
from collections import Counter

ap = argparse.ArgumentParser()
ap.add_argument("--env", required=True)
ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ap.add_argument("--pages", type=int, default=20)
ap.add_argument("--query", default=None)
a = ap.parse_args()

env = {}
for line in open(a.env, encoding="utf-8"):
    line = line.strip()
    if "=" in line and not line.startswith("#"):
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
base = env["DEMISTO_BASE_URL"].rstrip("/")
h = {"Authorization": env["DEMISTO_API_KEY"],
     "x-xdr-auth-id": str(env["XSIAM_AUTH_ID"]), "Content-Type": "application/json"}

shipped = json.load(open(os.path.join(
    a.repo, "Packs/soc-optimization-unified/Lists/SOCProductCategoryMap_V3/"
    "SOCProductCategoryMap_V3_data.json"), encoding="utf-8"))


def ds_key(tag):
    raw = tag[3:] if tag.startswith("DS:") else tag
    ch = list(raw)
    for i, c in enumerate(ch):
        if not c.isalnum() and 0 < i < len(ch) - 1:
            ch[i] = "_"
    return "ds_" + "".join(ch).lower()


seen = Counter()
prods = {}
for page in range(a.pages):
    flt = {"page": page, "size": 100, "sort": [{"field": "created", "asc": False}]}
    if a.query:
        flt["query"] = a.query
    r = urllib.request.Request(base + "/xsoar/public/v1/incidents/search",
                               data=json.dumps({"filter": flt}).encode(),
                               headers=h, method="POST")
    rows = json.loads(urllib.request.urlopen(r, timeout=180).read().decode()).get("data") or []
    if not rows:
        break
    for inc in rows:
        cf = inc.get("CustomFields") or {}
        tags = []
        for k in ("tags", "family_tags"):
            v = cf.get(k)
            tags += [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])
        ds = next((t for t in tags if t.startswith("DS:")), None)
        if not ds:
            continue
        seen[ds] += 1
        p = cf.get("_product") or cf.get("product")
        if isinstance(p, list):
            p = p[0] if p else None
        prods.setdefault(ds, Counter())[str(p)] += 1

print(f"tenant: {base}")
print(f"distinct DS: tags observed: {len(seen)}   (shipped map has {len(shipped)} keys)\n")

matched, missing = [], []
for tag, n in seen.most_common():
    key = ds_key(tag)
    if key in shipped:
        matched.append((tag, key, n, shipped[key].get("category")))
    else:
        close = difflib.get_close_matches(key, list(shipped), n=1, cutoff=0.5)
        missing.append((tag, key, n, close[0] if close else None))

print(f"=== ROUTED ({len(matched)}) — exact key match ===")
for tag, key, n, cat in matched:
    print(f"  {n:>6}  {key:<44} {cat}")

print(f"\n=== UNROUTED ({len(missing)}) — no key in shipped map ===")
print("  These fall through Product Classification at runtime.")
tot = 0
for tag, key, n, close in missing:
    tot += n
    hint = ""
    if close:
        hint = f"   ~ shipped has '{close}' ({shipped[close].get('category')})"
    print(f"  {n:>6}  {key:<44}{hint}")
    pl = prods.get(tag, {})
    if len(pl) > 1:
        print(f"          products: {dict(pl)}")
print(f"\n  {tot} issues on unrouted sources "
      f"({tot / max(sum(seen.values()), 1) * 100:.0f}% of sampled)")
