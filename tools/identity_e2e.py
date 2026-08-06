"""E2E: rule issue.* -> SOCFramework.* -> Entity Enrichment tasks -> layout. Playbook tasks only."""
import sys, re, yaml
sys.path.insert(0, 'tools')
import layout_harness as h

ENTITY = "Packs/soc-framework-nist-ir/Playbooks/SOC_Entity_Enrichment_V3.yml"


def run(label, cf, category, enrich=False):
    print("=" * 74)
    print(label)
    print("=" * 74)
    root = h.run_normalize(cf, category)
    print("1. issue.*:", cf)
    print("2. SOCFramework.Artifacts.Identity.User:", h.dt(root, 'SOCFramework.Artifacts.Identity.User'))

    if enrich:
        h.set_path(root, "MSGraphUser.JobTitle", "Financial Analyst")
        h.set_path(root, "MSGraphUser.Department", "Finance")
        h.set_path(root, "MSGraphUser.City", "Memphis")
        h.set_path(root, "MSGraphUserManager.DisplayName", "Dana Reed")

    d = yaml.safe_load(open(ENTITY))
    fired = []
    for k in sorted((x for x in d["tasks"] if x.isdigit()), key=int):
        t = d["tasks"][k]
        sa = t.get("scriptarguments") or {}
        key = ((sa.get("key") or {}).get("simple") or "")
        expr = ((sa.get("value") or {}).get("simple") or "")
        if not key.startswith("Analysis."):
            continue
        m = re.match(r"^\$\{(.+)\}$", expr.strip())
        if not m:
            continue
        v = h.dt(root, m.group(1).strip())
        if not h.is_empty(v):
            h.set_path(root, key, v)
            fired.append("%s <- %s" % (key.rsplit('.', 1)[-1], m.group(1).split('.')[0]))
    print("3. tasks that wrote:", ", ".join(fired) or "none")
    print("4. Analysis.Identity.User:", h.dt(root, 'Analysis.Identity.User'))
    print()
    print(h.render_panel(root))
    print()


run("A. ENDPOINT, no CIE, no directory integration (brumxdr today)",
    {'userid': 'Gunter@SKT.LOCAL', 'username': 'Gunter@SKT.LOCAL'}, 'endpoint')

run("B. EMAIL + CIE uncommented in the rule",
    {'emailrecipient': 'Gunter@SKT.LOCAL', 'username': 'Gunter@SKT.LOCAL',
     'user_principal': 'Gunter@SKT.LOCAL', 'socfwidentityuserdisplayname': 'Gunter Schmidt'}, 'email')

run("C. ENDPOINT + CIE + live directory enrichment (customer tenant)",
    {'userid': 'Gunter@SKT.LOCAL', 'username': 'Gunter@SKT.LOCAL',
     'usersid': 'S-1-5-21-1111-2222-3333-1104', 'user_principal': 'Gunter@SKT.LOCAL',
     'socfwidentityuserdisplayname': 'Gunter Schmidt'}, 'endpoint', enrich=True)
