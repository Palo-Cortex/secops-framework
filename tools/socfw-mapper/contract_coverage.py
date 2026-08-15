#!/usr/bin/env python3
"""
contract_coverage.py -- does every source satisfy the contract?

The SOC Framework contract exists so downstream can RELY on a field being
there. So the question is not "what do sources emit, let us map it" -- it is
"for every field the contract promises, can each source fill it, and if not
what would."

For each target in a category, per source:
    SATISFIED   which issue.* field in the fallback chain the source populates
    CANDIDATE   the chain is empty for this source, but the source populates a
                field of the same concept -> add it as a fallback alias
    ABSENT      the source carries nothing of that concept -> a real gap; the
                vendor pack must emit it, or the contract must not promise it

The CANDIDATE column is the automatable part: it turns a source-specific gap
into a one-line alias without inventing a target.
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NM = os.path.join(REPO, "Packs/soc-framework-nist-ir/Lists/"
                        "SOCFrameworkNormalizeMap_NIST_IR/"
                        "SOCFrameworkNormalizeMap_NIST_IR_data.json")
CM = os.path.join(REPO, "Packs/soc-optimization-unified/Lists/"
                        "SOCProductCategoryMap_V3/SOCProductCategoryMap_V3_data.json")

CONSTANTS = {"xdmsourcelocationcountry", "xdmsourcehostosfamily",
             "xdmsourceprocessexecutablesignaturestatus",
             "xdmtargetprocessexecutablesignaturestatus"}

# Concept vocabulary. A candidate is only offered when the source field and the
# contract's existing field reduce to the SAME concept -- never on similarity.
# Concept vocabulary. A candidate is only offered when the source field and the
# contract's existing field reduce to the SAME concept -- never on similarity.
#
# ORDER MATTERS: first match wins. The specific patterns must precede the
# general ones, otherwise `alert_domain` (a security-domain CLASSIFICATION,
# Security/IT) matches the network-`domain` pattern and gets proposed as
# Artifacts.Endpoint.Domain, which is wrong.
#
# Three distinct concepts that are easy to collapse and must not be:
#   fqdn        host.corp.example.com   -- fully qualified, resolvable
#   domain      CORP                    -- NetBIOS / AD short domain
#   dnsdomain   corp.example.com        -- DNS suffix only
CONCEPT_PATTERNS = [
    # -- specific first, so they win over the general patterns below
    ("alertdomain", r"alert_?domain"),
    ("alertname",  r"alert_?name|^name$|original_?alert_?name"),
    ("alertsource", r"alert_?source|source_?brand|original_?alert_?source"),

    ("fqdn",       r"fqdn|dns_?name|host_?dns"),
    ("dnsdomain",  r"dns_?domain|device_?dns_?domain"),
    ("domain",     r"^domain$|nt_?domain|netbios|ad_?domain|device_?domain|"
                   r"agent_?device_?domain|host_?domain"),

    ("hostname",   r"(^|_)host_?name$|hosthostname|agent_?hostname|^hostname$"),
    ("hostip",     r"host_?ip|hostipv4|sourceipv4|^localip$|local_ip"),
    ("remoteip",   r"remote_?ip|targetipv4|destination_?ip"),
    ("macaddress", r"mac_?address"),
    ("agentid",    r"agent_?id$|agentidentifier|endpoint_?id"),
    ("os",         r"host_?os$|os_?type$|osname|os_?family"),
    ("osversion",  r"os_?sub_?type|os_?version|osbuild"),

    ("usersid",    r"user_?sid|usersid"),
    ("samaccount", r"sam_?account"),
    ("upn",        r"upn|user_?principal|principal_?name"),
    ("useremail",  r"^email$|user_?email|employee_?email|contact_?email|mail_?address"),
    ("displayname", r"display_?name"),
    ("department", r"department"),
    ("manager",    r"manager"),
    ("username",   r"user_?name$|userusername|effective_?user|^user$|^username$"),

    # PARENT is a different entity from the initiating process. Collapsing them
    # writes the initiator's command line into parent_process_cmd, which is
    # silently wrong and unrecoverable downstream. Parent patterns come first.
    ("parentname", r"parent_?process_?name|os_?parent_?name|parentprocessname"),
    ("parentpath", r"parent_?process_?path|parentprocesspath"),
    ("parentcmd",  r"parent_?process_?cmd|parent_?command|parentprocesscmd"),
    ("parentpid",  r"parent_?process_?id|os_?parent_?id|parentprocessid"),
    ("parentsha256", r"parent_?process_?sha256|parentprocesssha256"),
    ("parentsigner", r"parent_?signer|os_?parent_?signature"),

    ("processname", r"process_?name|initiatedby|initiator_?name"),
    ("processpath", r"process_?(executable_?)?path|initiator_?path"),
    ("processcmd", r"command_?line|initiator_?cmd|process_?cmd"),
    ("processpid", r"(^|_)pid$|process_?id$|initiator_?pid"),
    ("processsha256", r"process_?(executable_?)?sha256|initiator_?sha256|cgosha256"),
    ("processmd5", r"process_?md5|initiator_?md5"),
    ("signer",     r"signer"),

    ("filename",   r"file_?(file)?name|^filename$"),
    ("filepath",   r"file_?path"),
    ("filesha256", r"file_?sha256|^filesha256$"),
    ("filemd5",    r"file_?md5|^filemd5$"),

    ("emailfrom",  r"email_?sender|smtp_?sender|headers_?from|^sender$"),
    ("emailto",    r"email_?recipient|^recipient"),
    ("emailsubject", r"subject"),
    ("emailmsgid", r"message_?id|messageid"),

    ("url",        r"^url$|threat_?url|suspicious_?url|target_?url|clicked_?urls"),
    # An ID is not a name. mitreattcktactic carries "Defense Evasion";
    # MITRE.TacticID expects "TA0005". Matching one to the other puts a label
    # where an identifier is expected.
    ("tacticid",   r"tactic_?id"),
    ("techniqueid", r"technique_?id"),
    ("subtechniqueid", r"sub_?technique_?id"),
    ("tactic",     r"tactic"),
    ("technique",  r"technique"),
    ("port",       r"port"),
    ("country",    r"country"),
    ("useragent",  r"user_?agent"),
    ("eventtype",  r"event_?type|operation_?name"),
]
COMPILED = [(name, re.compile(pat)) for name, pat in CONCEPT_PATTERNS]


def concept_of(field):
    low = str(field).lower()
    for name, pat in COMPILED:
        if pat.search(low):
            return name
    return None


def base_field(v):
    return re.sub(r"\.?\[\d+\]$", "", str(v)).strip()


def ds_key(tag):
    raw = tag[3:] if tag.startswith("DS:") else tag
    ch = list(raw)
    for i, c in enumerate(ch):
        if not c.isalnum() and 0 < i < len(ch) - 1:
            ch[i] = "_"
    return "ds_" + "".join(ch).lower()


def load_sources(category, capture_glob, min_issues, present_pct):
    """ds_key -> set(issue.* fields it populates)"""
    with open(CM, encoding="utf-8") as fh:
        cm = json.load(fh)
    keys = {k for k, v in cm.items() if isinstance(v, dict)
            and str(v.get("category", "")).lower() == category.lower()}
    fields, issues = defaultdict(set), defaultdict(int)
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
            issues[key] += n
            fields[key] |= {f for f, c in (src.get("fields") or {}).items()
                            if c / n * 100 >= present_pct and f not in CONSTANTS}
    return ({k: v for k, v in fields.items() if issues[k] >= min_issues},
            dict(issues), keys)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--category", required=True)
    ap.add_argument("--captures", default="/home/scott/captures/*.json")
    ap.add_argument("--min-issues", type=int, default=10)
    ap.add_argument("--present-pct", type=float, default=50.0)
    ap.add_argument("--only-gaps", action="store_true",
                    help="hide targets every source already satisfies")
    ap.add_argument("--emit-aliases", action="store_true",
                    help="print the alias rows that would close CANDIDATE gaps")
    args = ap.parse_args()

    with open(NM, encoding="utf-8") as fh:
        nm = json.load(fh)
    blk = (nm.get("categories") or {}).get(args.category) or {}
    chains = defaultdict(list)
    for row in (blk.get("mappings") or []):
        if row.get("target") and row.get("issue_field"):
            chains[row["target"]].append(base_field(row["issue_field"]))

    sources, issue_counts, mapped = load_sources(
        args.category, args.captures, args.min_issues, args.present_pct)
    if not sources:
        sys.exit(f"no {args.category} source has >= {args.min_issues} issues "
                 f"in {args.captures}")

    order = sorted(sources, key=lambda k: -issue_counts[k])
    print(f"category : {args.category}   status={blk.get('status')}   "
          f"targets={len(chains)}")
    print(f"sources  : {len(order)} with >= {args.min_issues} issues "
          f"({len(mapped)} mapped to this category)\n")
    for key in order:
        print(f"   {key:<44} {issue_counts[key]:>6} issues, "
              f"{len(sources[key])} fields")
    print()

    # per source: what each source populates, by concept
    by_concept = {k: defaultdict(list) for k in order}
    for key in order:
        for field in sources[key]:
            c = concept_of(field)
            if c:
                by_concept[key][c].append(field)

    header = f"{'contract target':<40}" + "".join(f"{k.replace('ds_','')[:13]:<15}" for k in order)
    print(header)
    print("-" * len(header))

    stats = {"satisfied": 0, "candidate": 0, "absent": 0}
    alias_rows = []
    for target in sorted(chains):
        chain = chains[target]
        chain_concepts = {concept_of(f) for f in chain} - {None}
        cells, any_gap = [], False
        for key in order:
            hit = next((f for f in chain if f in sources[key]), None)
            if hit:
                cells.append("ok")
                stats["satisfied"] += 1
                continue
            any_gap = True
            cand = None
            for c in chain_concepts:
                if by_concept[key].get(c):
                    cand = sorted(by_concept[key][c])[0]
                    break
            if cand:
                cells.append(f"+{cand[:12]}")
                stats["candidate"] += 1
                alias_rows.append((target, cand, key))
            else:
                cells.append("--")
                stats["absent"] += 1
        if args.only_gaps and not any_gap:
            continue
        print(f"{target:<40}" + "".join(f"{c:<15}" for c in cells))

    total = sum(stats.values()) or 1
    print(f"\n  satisfied {stats['satisfied']:>4} ({stats['satisfied']/total:.0%})   "
          f"candidate {stats['candidate']:>4} ({stats['candidate']/total:.0%})   "
          f"absent {stats['absent']:>4} ({stats['absent']/total:.0%})")
    print("\n  ok         chain already resolves for that source")
    print("  +field     source carries the same concept under another name ->")
    print("             add as a fallback alias, no new target")
    print("  --         source carries nothing of that concept -> real gap:")
    print("             the vendor pack must emit it, or the contract should")
    print("             not promise it for this category")

    if args.emit_aliases and alias_rows:
        seen = set()
        print(f"\n=== ALIAS ROWS TO ADD ({len(set((t, f) for t, f, _ in alias_rows))}) ===")
        for target, field, key in alias_rows:
            if (target, field) in seen:
                continue
            seen.add((target, field))
            print(f"      - target: {target}")
            print(f"        issue_field: {field}")
            print(f"        role: fallback        # for {key}")


if __name__ == "__main__":
    main()
