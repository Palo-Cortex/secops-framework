import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# name: SOC_Normalize_VisionOne
# type: python
# dockerimage: demisto/python3:3.11.10.123456
# description: Normalize Vision One Alert_Details.alert → Normalized[] (list) for layouts/playbooks

import re
from typing import Any, Dict, List, Optional

# ---------- helpers ----------
def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, (tuple, set)):
        return list(x)
    return [x]

def first_nonempty(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str):
            s = v.strip()
            if s:
                return s
        elif isinstance(v, (int, float, bool)):
            return v
        elif isinstance(v, list):
            if v:
                return v
        elif isinstance(v, dict):
            if v:
                return v
    return None

def prune_empty(d):
    if not isinstance(d, dict):
        return d
    return {k: v for k, v in d.items() if v not in (None, "", [], {}, ())}

_URL_RE = re.compile(r'(?i)\b(?:https?://|ftp://|www\.)[^\s<>"\'\]\)]+')
_WIN_PATH_RE = re.compile(r'^(?:[A-Za-z]:\\|\\\\)[^\s]+')
_LIKELY_SDB_RE = re.compile(r'^\{[0-9a-fA-F-]{36}\}\.sdb$')

def extract_urls(*vals):
    out, seen = [], set()
    for v in vals:
        for s in ensure_list(v):
            if not isinstance(s, str):
                continue
            txt = s.strip().strip('<>').strip('\'"')
            candidates = []
            if txt.lower().startswith(('http://', 'https://', 'ftp://', 'www.')):
                candidates = [txt]
            else:
                candidates = _URL_RE.findall(txt)

            for u in candidates:
                u = u.strip()
                if not u:
                    continue
                if u.lower().startswith('www.'):
                    u = 'http://' + u
                # skip windows paths/sdbs
                if _WIN_PATH_RE.match(u) or _LIKELY_SDB_RE.match(u):
                    continue
                # skip Trend Workbench deep links
                if 'xdr.trendmicro.com' in u.lower() and 'workbench' in u.lower():
                    continue
                if u not in seen:
                    seen.add(u); out.append(u)
    return out

def join_unique(items, sep=', '):
    out, seen = [], set()
    for x in items or []:
        if not x:
            continue
        s = str(x).strip()
        if not s:
            continue
        if s not in seen:
            seen.add(s); out.append(s)
    return sep.join(out) if out else None

def basename(p):
    if not p:
        return None
    return str(p).replace('\\', '/').rstrip('/').split('/')[-1]

def canon_proc_id(hashes, path, filename):
    h256 = (hashes or {}).get('sha256')
    h1   = (hashes or {}).get('sha1')
    hmd5 = (hashes or {}).get('md5')
    if h256: return 'sha256:' + h256.lower()
    if h1:   return 'sha1:' + h1.lower()
    if hmd5: return 'md5:' + hmd5.lower()
    if path: return 'path:' + str(path).lower()
    if filename: return 'file:' + str(filename).lower()
    return 'unknown:process'

# ---------- core ----------
def main():
    ctx = demisto.context() or {}
    v = (ctx.get('VisionOne') or {})
    ad = (v.get('Alert_Details') or {})
    alert = (ad.get('alert') or {})

    if not alert:
        return_results('No VisionOne.Alert_Details.alert in context — nothing to normalize.')
        return

    # ---- pull impact scope entities ----
    hosts: List[Dict[str, Any]] = []
    users: List[str] = []
    ips: List[str] = []

    impact = alert.get('impact_scope') or {}
    for e in ensure_list(impact.get('entities')):
        if not isinstance(e, dict):
            continue
        et = e.get('entity_type')
        ev = e.get('entity_value')
        if et == 'host':
            if isinstance(ev, dict):
                name = first_nonempty(ev.get('name'))
                host_ips = [str(ip).strip() for ip in ensure_list(ev.get('ips')) if str(ip).strip()]
                host = prune_empty({"name": name, "ips": host_ips or None})
                if host and host not in hosts:
                    hosts.append(host)
                for ip in host_ips:
                    if ip not in ips:
                        ips.append(ip)
            elif isinstance(ev, str) and ev.strip():
                host = {"name": ev.strip()}
                if host not in hosts:
                    hosts.append(host)
        elif et == 'account':
            if isinstance(ev, str) and ev.strip() and ev.strip() not in users:
                users.append(ev.strip())

    # ---- indicators pass ----
    # We collect: file hashes, process image/command_line, additional host/IPs
    hashes: Dict[str, str] = {}
    proc_image_path = None
    proc_cmdline = None
    proc_filename = None

    for ind in ensure_list(alert.get('indicators')):
        if not isinstance(ind, dict):
            continue
        t = (ind.get('type') or '').lower()
        val = ind.get('value')

        if t in ('file_sha256', 'sha256'):
            s = str(val).strip()
            if s:
                hashes['sha256'] = s
        elif t in ('sha1', 'file_sha1'):
            s = str(val).strip()
            if s:
                hashes['sha1'] = s
        elif t in ('md5', 'file_md5'):
            s = str(val).strip()
            if s:
                hashes['md5'] = s
        elif t in ('fullpath', 'path'):
            proc_image_path = first_nonempty(proc_image_path, val)
            proc_filename = first_nonempty(proc_filename, basename(val))
        elif t in ('command_line', 'commandline'):
            proc_cmdline = first_nonempty(proc_cmdline, val)
        elif t == 'host' and isinstance(val, dict):
            nm = val.get('name')
            if nm:
                host = {"name": nm}
                if host not in hosts:
                    hosts.append(host)
            for ip in ensure_list(val.get('ips')):
                s = str(ip).strip()
                if s and s not in ips:
                    ips.append(s)
        elif t in ('ip', 'remote_ip', 'dest_ip', 'src_ip'):
            s = str(val).strip()
            if s and s not in ips:
                ips.append(s)

    # ---- urls (exclude workbench) ----
    urls = extract_urls(alert.get('description'), alert.get('workbench_link'))

    # ---- user/email/id if present in alert model ----
    user_name = first_nonempty(alert.get('user_name'), alert.get('account'), alert.get('actor'))
    user_id   = first_nonempty(alert.get('user_id'), alert.get('account_id'))
    user_mail = first_nonempty(alert.get('user_email'), alert.get('email'))

    if user_name and user_name not in users:
        users.append(user_name)

    # ---- process object (if any) ----
    proc_hashes = prune_empty(hashes) or None
    process = None
    if proc_hashes or proc_image_path or proc_cmdline:
        process = prune_empty({
            "canonical_id": canon_proc_id(proc_hashes, proc_image_path, proc_filename),
            "hashes": proc_hashes,
            "image": prune_empty({
                "path": proc_image_path,
                "filename": proc_filename or basename(proc_image_path),
                "command_line": proc_cmdline
            })
        })

    # ---- choose primary entity ----
    primary_ip = ips[0] if ips else None
    primary_host_name = hosts[0].get('name') if hosts else None

    if process:
        primary = {"type": "process"}
        for k in ("canonical_id", "hashes", "image"):
            if process.get(k) is not None:
                primary[k] = process.get(k)
    elif primary_host_name or primary_ip:
        primary = {"type": ("host" if primary_host_name else "ip")}
        if primary_host_name:
            primary["name"] = primary_host_name
        if primary_ip:
            primary["ip"] = primary_ip
    else:
        primary = {"type": "unknown"}

    # ---- MITRE (if present) ----
    # Vision One may expose mapped tactics/techniques differently; try common shapes
    mitre_techniques = []
    for t in ensure_list(alert.get('mitre_techniques')):  # ['T1059', ...] or [{'id':'T1059'}]
        if isinstance(t, dict):
            tid = first_nonempty(t.get('id'), t.get('technique'), t.get('name'))
            if tid:
                mitre_techniques.append(str(tid))
        else:
            s = str(t).strip()
            if s:
                mitre_techniques.append(s)

    # ---- build Normalized[0] ----
    norm0 = prune_empty({
        "primary": primary,
        "user": prune_empty({
            "name": user_name,
            "id": user_id,
            "email": user_mail,
            "all_usernames": users or None
        }),
        "users": users or None,
        "host": (hosts or None),            # list[ {name, ips[]} ]
        "ips": (ips or None),               # list[str]
        "ip": prune_empty({"ip": primary_ip}) if primary_ip else None,
        "urls": (urls or None),
        "process": process,
        "hashes": (list({h for h in [hashes.get('sha256'), hashes.get('sha1'), hashes.get('md5')] if h}) or None),
        "mitre": prune_empty({
            "techniques": mitre_techniques or None
        }),
        # convenient flat copies for your existing fields
        "actor": prune_empty({
            "username": user_name
        })
    })

    Normalized = [norm0]  # IMPORTANT: list form for Normalized[0].host[0].name compatibility

    # ---- set context ----
    demisto.executeCommand('Set', {'key': 'Normalized', 'value': Normalized, 'append': 'false'})
    demisto.executeCommand('Set', {'key': 'NormalizedEntity', 'value': primary, 'append': 'false'})

    # quick preview
    demisto.results({
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": {
            "Normalized.preview": norm0
        },
        "HumanReadable": "SOC_Normalize_VisionOne completed — Normalized[] set.",
        "EntryContext": {
            "Normalized": Normalized,
            "NormalizedEntity": primary
        }
    })

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
