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
    missing = []
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

    print(f"\n  Tenant : {env['DEMISTO_BASE_URL']}")
    print(f"  Checked: {checked} item(s) across {len(packs)} pack(s)\n")
    if not missing:
        print("  ✓ Every script and list in these packs is present on the tenant\n")
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
