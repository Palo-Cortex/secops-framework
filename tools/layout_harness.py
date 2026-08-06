#!/usr/bin/env python3
"""
Local layout harness — runs the REAL normalize engine and the REAL panel script
offline against a mocked incident context. No tenant, no replay.

Pipeline:  raw alert CustomFields  ->  normalize (SOCFramework.Artifacts.*)
           ->  mirror (Entity Enrichment norm tasks -> Analysis.Identity.User.*)
           ->  panel (SOCFramework_displayEntityContext -> layout markdown)

Usage:
  python3 tools/layout_harness.py --category email
  python3 tools/layout_harness.py --category endpoint --enrich
  python3 tools/layout_harness.py --category identity --cie
"""
import sys, os, re, json, types, argparse, importlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NORM = os.path.join(REPO, "Packs/soc-optimization-unified/Scripts/SOCNormalizeFromList")
PANEL = os.path.join(REPO, "Packs/soc-framework-nist-ir/Scripts/SOCFramework_displayEntityContext")
NORMDATA = os.path.join(REPO, "Packs/soc-framework-nist-ir/Lists/SOCFrameworkNormalizeMap_NIST_IR/SOCFrameworkNormalizeMap_NIST_IR_data.json")
ENTITY = os.path.join(REPO, "Packs/soc-framework-nist-ir/Playbooks/SOC_Entity_Enrichment_V3.yml")


# ---------- tiny dt / context helpers ----------
def dt(obj, path):
    cur = obj
    for part in re.split(r"\.", path):
        part = part.replace("[", "").replace("]", "")
        if part == "":
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except Exception:
                return None
        else:
            return None
    return cur


def is_empty(v):
    return v in (None, "", [], {}, "null")


def set_path(obj, path, val):
    parts = path.split(".")
    cur = obj
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = val


def eval_coalesce(expr, ctx):
    """Evaluate a playbook value like ${A||B||C} against ctx (first non-empty)."""
    m = re.match(r"^\$\{(.+)\}$", expr.strip())
    if not m:
        return expr
    for path in m.group(1).split("||"):
        v = dt(ctx, path.strip())
        if not is_empty(v):
            return v
    return None


# ---------- stage 1: normalize (real engine) ----------
def run_normalize(custom_fields, category):
    import builtins
    builtins.demisto = types.SimpleNamespace(
        debug=lambda *a, **k: None, error=lambda *a, **k: None,
        info=lambda *a, **k: None, results=lambda *a, **k: None)
    if NORM not in sys.path:
        sys.path.insert(0, NORM)
    import SOCNormalizeFromList as eng
    importlib.reload(eng)
    band = json.load(open(NORMDATA))["categories"][category]
    writes, skipped = {}, {"empty": [], "filtered": []}
    eng.apply_mappings(band, custom_fields, writes, skipped)
    eng.apply_stamps(band, None, writes, skipped)
    eng.apply_mirrors(band, writes, skipped)
    ctx = {}
    for t, v in writes.items():          # engine prepends "SOCFramework."
        set_path(ctx, "SOCFramework." + t, v)
    return ctx


# ---------- stage 2: mirror (real Entity Enrichment norm tasks) ----------
def apply_mirror(ctx):
    import yaml
    d = yaml.safe_load(open(ENTITY))
    applied = {}
    for t in d["tasks"].values():
        sa = t.get("scriptarguments") or {}
        key = ((sa.get("key") or {}).get("simple") or "")
        if key.startswith("Analysis.Identity.User.") or key.startswith("Analysis.Endpoint."):
            expr = ((sa.get("value") or {}).get("simple") or "")
            v = eval_coalesce(expr, ctx)
            if not is_empty(v):
                set_path(ctx, key, v)
                applied[key] = v
    return applied


# ---------- stage 3: panel (real script) ----------
def render_panel(ctx):
    dm = types.ModuleType("demistomock")
    dm.context = lambda: ctx
    dm.dt = lambda obj, path: dt(obj, path)
    dm.debug = dm.error = dm.info = lambda *a, **k: None
    dm.results = lambda *a, **k: None
    sys.modules["demistomock"] = dm
    cap = {}
    csp = types.ModuleType("CommonServerPython")

    class CommandResults:
        def __init__(self, readable_output=None, **k):
            self.readable_output = readable_output

    def return_results(r):
        cap["md"] = getattr(r, "readable_output", r)
    csp.CommandResults = CommandResults
    csp.return_results = return_results
    csp.demisto = dm
    sys.modules["CommonServerPython"] = csp
    if PANEL not in sys.path:
        sys.path.insert(0, PANEL)
    import SOCFramework_displayEntityContext as panel
    importlib.reload(panel)
    panel.main()
    return cap.get("md", "")


# ---------- scenarios ----------
def scenario(category, enrich, cie):
    # raw alert fields the correlation rule would carry
    cf = {
        "email": {"emailrecipient": "Gunter@SKT.LOCAL", "username": "Gunter@SKT.LOCAL"},
        "endpoint": {"userid": "Gunter@SKT.LOCAL", "username": "Gunter@SKT.LOCAL"},
        "identity": {"email": "Gunter@SKT.LOCAL", "username": "Gunter@SKT.LOCAL", "userid": "Gunter@SKT.LOCAL"},
    }[category]
    if cie:  # CIE overlay populates these on the alert
        cf["usersid"] = "S-1-5-21-1111-2222-3333-1104"
        cf["socfwidentityuserdisplayname"] = "Gunter Schmidt"
    return cf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", choices=["email", "endpoint", "identity"], default="email")
    ap.add_argument("--enrich", action="store_true", help="simulate live directory enrichment (MSGraphUser)")
    ap.add_argument("--cie", action="store_true", help="simulate CIE overlay on the alert (usersid, display name)")
    a = ap.parse_args()

    cf = scenario(a.category, a.enrich, a.cie)
    print("=== 1. raw alert CustomFields ===")
    print("   ", cf)

    root = run_normalize(cf, a.category)
    print("\n=== 2. normalize (ROOT) -> SOCFramework.Artifacts.Identity.User ===")
    print("   ", dt(root, "SOCFramework.Artifacts.Identity.User"))

    # Simulate live enrichment landing in MSGraphUser (what soc-enrich-user writes).
    if a.enrich:
        set_path(root, "MSGraphUser.DisplayName", "Gunter Schmidt (Directory)")
        set_path(root, "MSGraphUser.Mail", "gunter@skt.local")
        set_path(root, "MSGraphUser.Department", "Finance")

    # Simulate the actual ordered SetAndHandleEmpty tasks: write-if-non-empty, last wins.
    import yaml as _yaml
    d = _yaml.safe_load(open(ENTITY))
    log = []
    for k in sorted((kk for kk in d["tasks"] if kk.isdigit() and int(kk) >= 5), key=int):
        sa = d["tasks"][k].get("scriptarguments") or {}
        key = ((sa.get("key") or {}).get("simple") or "")
        expr = ((sa.get("value") or {}).get("simple") or "")
        if not key.startswith("Analysis."):
            continue
        m = re.match(r"^\$\{(.+)\}$", expr.strip())
        if not m:
            continue
        v = dt(root, m.group(1).strip())
        if not is_empty(v):
            set_path(root, key, v)
            log.append("  %-38s <= %s = %s" % (key, m.group(1).strip(), v))
    print("\n=== 3. SetAndHandleEmpty coalesce (flow order, last wins) ===")
    for line in log:
        print(line)
    if not log:
        print("   (nothing)")

    md = render_panel(root)
    print("\n=== 4. LAYOUT (panel on ROOT context) ===")
    print(md)


if __name__ == "__main__":
    main()
