#!/usr/bin/env python3
"""
normalize_regression.py -- prove a NormalizeMap change did not break anything.

Same idea as socfw-mapper/regression_check.py for the category map: replicate
what the runtime would resolve, before and after, and diff.

For every target in a category, work out WHICH issue.* field would populate it
for each source, given a sanitised capture. Then compare HEAD against the
working tree.

  target resolved before, not after   -> REGRESSION
  target resolves from a different field -> BEHAVIOUR CHANGE (flagged, not failed;
                                            fallback order legitimately changes)
  target newly resolves               -> improvement

Exits non-zero on regression.

Usage:
  python3 tools/socfw-mapper/normalize_regression.py --captures '~/captures/*.json'
  python3 tools/socfw-mapper/normalize_regression.py --category email \\
      --captures '~/captures/*.json'
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NM_REL = ("Packs/soc-framework-nist-ir/Lists/SOCFrameworkNormalizeMap_NIST_IR/"
          "SOCFrameworkNormalizeMap_NIST_IR_data.json")
CM_REL = ("Packs/soc-optimization-unified/Lists/SOCProductCategoryMap_V3/"
          "SOCProductCategoryMap_V3_data.json")

# Populated on every issue with one constant value. Counting these as coverage
# would hide a regression: a target could "resolve" purely from a constant.
CONSTANTS = {
    "xdmsourcelocationcountry", "xdmsourcehostosfamily",
    "xdmsourceprocessexecutablesignaturestatus",
    "xdmtargetprocessexecutablesignaturestatus",
}


def base_field(value):
    return re.sub(r"\.?\[\d+\]$", "", str(value)).strip()


def ds_key(tag):
    raw = tag[3:] if tag.startswith("DS:") else tag
    chars = list(raw)
    for i, ch in enumerate(chars):
        if not ch.isalnum() and 0 < i < len(chars) - 1:
            chars[i] = "_"
    return "ds_" + "".join(chars).lower()


def git_show(rev, rel):
    out = subprocess.run(["git", "show", f"{rev}:{rel}"],
                         capture_output=True, text=True, cwd=REPO)
    if out.returncode != 0:
        sys.exit(f"cannot read {rel} at {rev}: {out.stderr.strip()[:160]}")
    return json.loads(out.stdout)


def load_local(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return json.load(fh)


def fallbacks(nm, category):
    """target -> [issue_field, ...] in declared order (the fallback chain)."""
    out = defaultdict(list)
    blk = (nm.get("categories") or {}).get(category) or {}
    for row in (blk.get("mappings") or []):
        if row.get("target") and row.get("issue_field"):
            out[row["target"]].append(base_field(row["issue_field"]))
    return out


def populated_by_source(category, cm, capture_glob, present_pct=50.0):
    """ds_key -> set(issue.* fields populated), for sources in this category."""
    keys = {k for k, v in cm.items()
            if isinstance(v, dict)
            and str(v.get("category", "")).lower() == category.lower()}
    out = {}
    for path in sorted(glob.glob(os.path.expanduser(capture_glob))):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for src in doc.get("sources", []):
            key = ds_key(src["ds_tag"])
            if key not in keys:
                continue
            n = src.get("issues", 0)
            if not n:
                continue
            fields = {f for f, c in (src.get("fields") or {}).items()
                      if c / n * 100 >= present_pct and f not in CONSTANTS}
            out.setdefault(key, set()).update(fields)
    return out


def resolve(chain, available):
    """First field in the fallback chain the source actually populates."""
    for field in chain:
        if field in available:
            return field
    return None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures", required=True)
    ap.add_argument("--category", help="one category; default every category")
    ap.add_argument("--rev", default="HEAD", help="baseline revision")
    ap.add_argument("--present-pct", type=float, default=50.0)
    args = ap.parse_args()

    old_nm = git_show(args.rev, NM_REL)
    new_nm = load_local(NM_REL)
    cm = load_local(CM_REL)

    categories = ([args.category] if args.category
                  else sorted(set(old_nm.get("categories", {}))
                              | set(new_nm.get("categories", {}))))

    regressions, changes, gains = [], [], []
    checked = 0
    skipped = []

    for category in categories:
        sources = populated_by_source(category, cm, args.captures, args.present_pct)
        if not sources:
            skipped.append(category)
            continue
        old_fb = fallbacks(old_nm, category)
        new_fb = fallbacks(new_nm, category)

        for target in sorted(set(old_fb) | set(new_fb)):
            for key, available in sorted(sources.items()):
                before = resolve(old_fb.get(target, []), available)
                after = resolve(new_fb.get(target, []), available)
                checked += 1
                if before and not after:
                    regressions.append((category, key, target, before))
                elif before and after and before != after:
                    changes.append((category, key, target, before, after))
                elif after and not before:
                    gains.append((category, key, target, after))

    print(f"baseline           : {args.rev}")
    print(f"categories checked : {len(categories) - len(skipped)}"
          f"{'  (skipped, no sources in captures: ' + ', '.join(skipped) + ')' if skipped else ''}")
    print(f"target/source pairs: {checked}\n")

    if gains:
        print(f"=== NEWLY RESOLVES ({len(gains)}) — improvement ===")
        for cat, key, target, field in gains[:20]:
            print(f"   [{cat}] {key:<38} {target:<40} <- {field}")
        if len(gains) > 20:
            print(f"   ... and {len(gains) - 20} more")
        print()

    if changes:
        print(f"=== RESOLVES FROM A DIFFERENT FIELD ({len(changes)}) — review ===")
        print("   Not a failure: fallback order legitimately changes. But the")
        print("   normalized VALUE may differ, so confirm the fields are equivalent.")
        for cat, key, target, before, after in changes:
            print(f"   [{cat}] {key:<38} {target:<40} {before} -> {after}")
        print()

    if regressions:
        print(f"=== REGRESSION ({len(regressions)}) — resolved before, empty now ===")
        for cat, key, target, before in regressions:
            print(f"   [{cat}] {key:<38} {target:<40} was <- {before}")
        print(f"\nFAIL: {len(regressions)} target/source pair(s) stopped resolving.")
        return 1

    print("PASS: no target stopped resolving for any source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
