#!/usr/bin/env python3
"""Confirm every script and list in the repo's SOCFW packs is present on the tenant.

`upload_package.sh` passes `--override-existing`, which is what makes a pack's
changes actually land — a plain upload is additive and silently skips content
that already exists. On this tenant it has a side effect: uploading one pack can
remove content belonging to another. That has happened repeatedly and is silent,
so a later run fails somewhere unrelated with a missing script or an unparseable
list, hours after the upload that caused it.

Run after an upload. Reports what is missing and exits non-zero so the gate
catches it rather than the next person to trip over it.

Pass the packs to check. The gate passes the ones it just uploaded; with no
arguments it checks every SOCFW pack, which will report content from packs that
were never installed on the tenant.

  python3 tools/verify_tenant_content.py Packs/soc-framework-nist-ir-ai
  python3 tools/verify_tenant_content.py            # all SOCFW packs
"""
import glob
import json
import os
import sys
import yaml
import urllib.request

PACK_GLOB = "Packs/soc*"


def creds():
    env = {}
    if os.path.exists(".env"):
        for line in open(".env"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k] = v.strip().strip('"').strip("'")
    for k in ("DEMISTO_BASE_URL", "DEMISTO_API_KEY", "XSIAM_AUTH_ID"):
        env.setdefault(k, os.environ.get(k, ""))
    missing = [k for k in ("DEMISTO_BASE_URL", "DEMISTO_API_KEY", "XSIAM_AUTH_ID") if not env.get(k)]
    if missing:
        sys.exit(f"ERROR: missing credentials: {', '.join(missing)}")
    return env


def api(env, path, payload=None, method="POST"):
    base = env["DEMISTO_BASE_URL"].rstrip("/")
    hdr = {"Authorization": env["DEMISTO_API_KEY"],
           "x-xdr-auth-id": str(env["XSIAM_AUTH_ID"]),
           "Content-Type": "application/json", "Accept": "application/json"}
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{base}/xsoar{path}", data=data, headers=hdr, method=method)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read() or b"{}")


def main():
    env = creds()
    packs = sys.argv[1:] or sorted(glob.glob(PACK_GLOB))
    packs = [p for p in packs if os.path.isdir(p)]

    on_tenant_lists = {L.get("name") for L in api(env, "/lists", method="GET")}

    # Playbooks, correlation rules and modeling rules were never checked here.
    # That blind spot is why a pack could report its catalog version with none
    # of its content installed and this tool still printed a tick: it only
    # looked at Scripts/ and Lists/, so a rules-only or playbook-only pack was
    # "Checked: 0 item(s)" and passed having verified nothing.
    #
    # Observed 19 Sep 2026: soc-optimization-unified reported 3.20.3 on the
    # tenant with all 24 scripts and lists missing, and 19 packs were reported
    # as installed on version numbers alone.
    on_tenant_playbooks = {
        pb.get("name")
        for pb in api(env, "/playbook/search", {"page": 0, "size": 5000}).get("playbooks", [])
    }
    on_tenant_fields = {
        f.get("cliName") for f in api(env, "/incidentfields", method="GET") or []
    }

    missing = []
    unverifiable = []
    checked = 0

    for pack in packs:
        for d in sorted(glob.glob(f"{pack}/Scripts/*/")):
            name = os.path.basename(d.rstrip("/"))
            checked += 1
            found = api(env, "/automation/search", {"query": f"name:{name}", "size": 5})
            if not any(s.get("name") == name for s in found.get("scripts", [])):
                missing.append((pack, "script", name))

        for f in sorted(glob.glob(f"{pack}/Lists/*/*_data.json")):
            name = os.path.basename(f).replace("_data.json", "")
            checked += 1
            if name not in on_tenant_lists:
                missing.append((pack, "list", name))

        # Playbooks are matched on the internal name, not the filename: the
        # two legitimately differ (underscores vs spaces) and the tenant only
        # knows the name.
        for f in sorted(glob.glob(f"{pack}/Playbooks/*.yml")):
            try:
                name = (yaml.safe_load(open(f)) or {}).get("name")
            except Exception:
                name = None
            if not name:
                continue
            checked += 1
            if name not in on_tenant_playbooks:
                missing.append((pack, "playbook", name))

        for f in sorted(glob.glob(f"{pack}/IncidentFields/*.json")):
            try:
                cli = (json.load(open(f)) or {}).get("cliName")
            except Exception:
                cli = None
            if not cli:
                continue
            checked += 1
            if cli not in on_tenant_fields:
                missing.append((pack, "field", cli))

        # Correlation and modeling rules are counted but NOT verified: the
        # correlations API returns custom (API/UI-created) rules only and
        # cannot see pack-installed ones, so there is no endpoint to check
        # them against. Saying so is better than a silent gap.
        rules = glob.glob(f"{pack}/CorrelationRules/*.yml")
        models = glob.glob(f"{pack}/ModelingRules/*/*.yml")
        if rules or models:
            unverifiable.append((pack, len(rules), len(models)))

    print(f"\n  Tenant : {env['DEMISTO_BASE_URL']}")
    print(f"  Checked: {checked} item(s) across {len(packs)} pack(s)\n")
    if unverifiable:
        print("  ! Not verifiable via API (correlations/get sees custom rules only) —")
        print("    confirm these in the tenant UI:")
        for pack, nr, nm in unverifiable:
            bits = []
            if nr:
                bits.append(f"{nr} correlation rule(s)")
            if nm:
                bits.append(f"{nm} modeling rule(s)")
            print(f"      {os.path.basename(pack):38} {', '.join(bits)}")
        print()

    if not missing:
        print("  ✓ Every script, list, playbook and incident field in these packs")
        print("    is present on the tenant\n")
        return 0

    print(f"  ✗ {len(missing)} item(s) missing from the tenant:\n")
    for pack, kind, name in missing:
        print(f"      {kind:7} {name:38} ({os.path.basename(pack)})")
    print("\n  An --override-existing upload of one pack can remove another pack's")
    print("  content on this tenant. Re-upload the affected pack, or for lists,")
    print("  POST the *_data.json contents to /xsoar/lists/save.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
