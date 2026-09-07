"""
SOCFWContractCoverage
=====================
Answers, on a tenant, the question the contract exists to answer: for every
field the contract promises, can each source fill it?

This is the runtime twin of tools/socfw-mapper/contract_coverage.py. It samples
issues through demisto.incident()'s surface — CustomFields — which is the same
surface SOCNormalizeFromList reads. The issues dataset carries XDM columns
instead, so an XQL query cannot answer this: xdm.email.message_id and
emailmessageid are two different views and only the latter reaches the contract.

VERDICTS
  satisfied   a field in the target's fallback chain is populated by the source
  candidate   the chain is empty for this source, but the source populates a
              field of the same concept -> add it as a fallback alias
  absent      the source carries nothing of that concept -> a real gap. Either
              the source must emit it, or the category should not promise it.

Concept matching is an exact match on an ordered vocabulary, never string
similarity. Similarity was tried during the category work and is unsafe:
ds_armis_security_activities matched ds_azure_activity.
"""

CONSTANT_PACK_VERSION = '3.15.1'
demisto.debug(f'pack id = soc-optimization-unified, pack version = {CONSTANT_PACK_VERSION}')

import json
import re
from collections import defaultdict

# Populated on 100% of issues on every source with a single value, so counting
# them as coverage makes the contract look more complete than it is.
CONSTANTS = {"xdmsourcelocationcountry", "xdmsourcehostosfamily",
             "xdmsourceprocessexecutablesignaturestatus",
             "xdmtargetprocessexecutablesignaturestatus"}

# ORDER MATTERS: first match wins, so specific patterns precede general ones.
# alert_domain is a security-domain classification (Security/IT), not a network
# domain; without the ordering it is proposed as Artifacts.Endpoint.Domain.
# fqdn / domain / dnsdomain are three distinct concepts and must not collapse.
# parent process is a different entity from the initiating process — collapsing
# them writes the initiator's command line into a parent field, silently wrong.
CONCEPT_PATTERNS = [
    ("alertdomain", r"alert_?domain"),
    ("alertname", r"alert_?name|^name$|original_?alert_?name"),
    ("alertsource", r"alert_?source|source_?brand|original_?alert_?source"),

    ("fqdn", r"fqdn|dns_?name|host_?dns"),
    ("dnsdomain", r"dns_?domain|device_?dns_?domain"),
    ("domain", r"^domain$|nt_?domain|netbios|ad_?domain|device_?domain|"
               r"agent_?device_?domain|host_?domain"),

    ("hostname", r"(^|_)host_?name$|hosthostname|agent_?hostname|^hostname$"),
    ("hostip", r"host_?ip|hostipv4|sourceipv4|^localip$|local_ip"),
    ("remoteip", r"remote_?ip|targetipv4|destination_?ip"),
    ("macaddress", r"mac_?address"),
    ("agentid", r"agent_?id$|agentidentifier|endpoint_?id"),
    ("os", r"host_?os$|os_?type$|osname|os_?family"),
    ("osversion", r"os_?sub_?type|os_?version|osbuild"),

    ("usersid", r"user_?sid|usersid"),
    ("samaccount", r"sam_?account"),
    ("upn", r"upn|user_?principal|principal_?name"),
    ("useremail", r"^email$|user_?email|employee_?email|contact_?email|mail_?address"),
    ("displayname", r"display_?name"),
    ("department", r"department"),
    ("manager", r"manager"),
    ("username", r"user_?name$|userusername|effective_?user|^user$|^username$"),

    ("parentname", r"parent_?process_?name|os_?parent_?name|parentprocessname"),
    ("parentpath", r"parent_?process_?path|parentprocesspath"),
    ("parentcmd", r"parent_?process_?cmd|parent_?command|parentprocesscmd"),
    ("parentpid", r"parent_?process_?id|os_?parent_?id|parentprocessid"),
    ("parentsha256", r"parent_?process_?sha256|parentprocesssha256"),
    ("parentsigner", r"parent_?signer|os_?parent_?signature"),

    ("processname", r"process_?name|initiatedby|initiator_?name"),
    ("processpath", r"process_?(executable_?)?path|initiator_?path"),
    ("processcmd", r"command_?line|initiator_?cmd|process_?cmd"),
    ("processpid", r"(^|_)pid$|process_?id$|initiator_?pid"),
    ("processsha256", r"process_?(executable_?)?sha256|initiator_?sha256|cgosha256"),
    ("processmd5", r"process_?md5|initiator_?md5"),
    ("signer", r"signer"),

    ("filename", r"file_?(file)?name|^filename$"),
    ("filepath", r"file_?path"),
    ("filesha256", r"file_?sha256|^filesha256$"),
    ("filemd5", r"file_?md5|^filemd5$"),

    ("emailfrom", r"email_?sender|smtp_?sender|headers_?from|^sender$"),
    ("emailto", r"email_?recipient|^recipient"),
    ("emailsubject", r"subject"),
    ("emailmsgid", r"message_?id|messageid"),

    ("url", r"^url$|threat_?url|suspicious_?url|target_?url|clicked_?urls"),
    # An ID is not a name. mitreattcktactic carries "Defense Evasion";
    # MITRE.TacticID expects "TA0005".
    ("tacticid", r"tactic_?id"),
    ("techniqueid", r"technique_?id"),
    ("subtechniqueid", r"sub_?technique_?id"),
    ("tactic", r"tactic"),
    ("technique", r"technique"),
    ("port", r"port"),
    ("country", r"country"),
    ("useragent", r"user_?agent"),
    ("eventtype", r"event_?type|operation_?name"),
]
COMPILED = [(name, re.compile(pat)) for name, pat in CONCEPT_PATTERNS]

EMPTY = (None, "", [], {}, "null")


def concept_of(field):
    low = str(field).lower()
    for name, pat in COMPILED:
        if pat.search(low):
            return name
    return None


def base_field(value):
    return re.sub(r"\.?\[\d+\]$", "", str(value)).strip()


def ds_key(tag):
    raw = tag[3:] if tag.startswith("DS:") else tag
    chars = list(raw)
    for i, char in enumerate(chars):
        if not char.isalnum() and 0 < i < len(chars) - 1:
            chars[i] = "_"
    return "ds_" + "".join(chars).lower()


def load_list(name):
    res = demisto.executeCommand("getList", {"listName": name})
    if not res:
        raise ValueError(f"getList returned no result for {name}")
    contents = res[0].get("Contents")
    if not contents:
        raise ValueError(f"List {name} has no contents")
    if isinstance(contents, str):
        if "not found" in contents.lower():
            raise ValueError(f"List {name} not found on tenant")
        return json.loads(contents)
    return contents


def sample_issues(query, limit, page_size):
    """Populated CustomFields names per DS key. Values are read for emptiness only."""
    fields, counts = defaultdict(lambda: defaultdict(int)), defaultdict(int)
    page, seen = 0, 0
    while seen < limit:
        size = min(page_size, limit - seen)
        args = {"size": size, "page": page}
        if query:
            args["query"] = query
        res = demisto.executeCommand("getIncidents", args)
        if not res or is_error(res[0]):
            break
        data = ((res[0].get("Contents") or {}).get("data")) or []
        if not data:
            break
        for inc in data:
            custom = inc.get("CustomFields") or {}
            tags = custom.get("tags") or []
            if not isinstance(tags, list):
                tags = [tags]
            tag = next((str(t) for t in tags if str(t).startswith("DS:")), None)
            if not tag:
                continue
            key = ds_key(tag)
            counts[key] += 1
            for name, val in custom.items():
                if val not in EMPTY and name not in CONSTANTS:
                    fields[key][name] += 1
        seen += len(data)
        page += 1
    return fields, counts


def main():
    args = demisto.args()
    category = (args.get("category") or "").lower()
    lifecycle = args.get("lifecycle") or "nist_ir"
    query = args.get("query") or ""
    limit = int(args.get("limit") or 500)
    page_size = int(args.get("page_size") or 100)
    min_issues = int(args.get("min_issues") or 10)
    present_pct = float(args.get("present_pct") or 50)
    emit_aliases = str(args.get("emit_aliases") or "false").lower() == "true"

    try:
        nm = load_list(args.get("list_name") or
                       f"SOCFrameworkNormalizeMap_{lifecycle.upper()}")
        block = (nm.get("categories") or {}).get(category) or {}
        chains = defaultdict(list)
        for row in (block.get("mappings") or []):
            if row.get("target") and row.get("issue_field"):
                chains[row["target"]].append(base_field(row["issue_field"]))
        if not chains:
            raise ValueError(f"category {category!r} declares no mappings in the contract")

        # Which sources belong to this category. An explicit list wins so an
        # unmapped source can be measured before it is added to the map.
        explicit = [s.strip() for s in str(args.get("sources") or "").split(",") if s.strip()]
        if explicit:
            wanted = {ds_key(s) for s in explicit}
        else:
            cm = load_list("SOCProductCategoryMap_V3")
            wanted = {k for k, v in cm.items() if isinstance(v, dict)
                      and str(v.get("category", "")).lower() == category}

        raw_fields, counts = sample_issues(query, limit, page_size)
        sources = {}
        for key, hist in raw_fields.items():
            if key not in wanted or counts[key] < min_issues:
                continue
            sources[key] = {f for f, c in hist.items()
                            if c / counts[key] * 100 >= present_pct}
        if not sources:
            return_results(CommandResults(readable_output=(
                f"### SOC Framework — contract coverage\n"
                f"No **{category}** source reached {min_issues} issues in a sample of "
                f"{sum(counts.values())}. Narrow with `query`, or raise `limit`.\n\n"
                f"_Sampling is newest-first, so a high-volume source crowds the rest out._"
            )))
            return

        order = sorted(sources, key=lambda k: -counts[k])
        by_concept = {k: defaultdict(list) for k in order}
        for key in order:
            for field in sources[key]:
                concept = concept_of(field)
                if concept:
                    by_concept[key][concept].append(field)

        per_source, alias_rows = {}, []
        for key in order:
            tally = {"satisfied": 0, "candidate": 0, "absent": 0}
            for target, chain in chains.items():
                if next((f for f in chain if f in sources[key]), None):
                    tally["satisfied"] += 1
                    continue
                cand = None
                for concept in {concept_of(f) for f in chain} - {None}:
                    if by_concept[key].get(concept):
                        cand = sorted(by_concept[key][concept])[0]
                        break
                if cand:
                    tally["candidate"] += 1
                    alias_rows.append((target, cand, key))
                else:
                    tally["absent"] += 1
            per_source[key] = tally

        width = max(len(k.replace("ds_", "")) for k in order)
        lines = [
            f"### SOC Framework — contract coverage",
            f"**{category}** · contract status `{block.get('status')}` · "
            f"{len(chains)} targets · {sum(counts.values())} issues sampled",
            "",
            "SOURCES",
        ]
        for key in order:
            tally = per_source[key]
            total = sum(tally.values()) or 1
            pct = tally["satisfied"] * 100 // total
            marker = "🟢" if pct >= 70 else ("🔵" if pct >= 40 else "🟠")
            name = key.replace("ds_", "")
            pad = " " * (width - len(name))
            lines.append(
                f"{marker} **{name}**{pad}  {counts[key]:>5} issues   "
                f"satisfied {tally['satisfied']:>3}  "
                f"candidate {tally['candidate']:>3}  "
                f"absent {tally['absent']:>3}   ({pct}%)")
        lines += [
            "",
            "🟢 70%+ satisfied · 🔵 40-69% · 🟠 under 40%",
            "candidate = source has the concept under another name, add a fallback alias",
            "absent = source carries nothing of that concept; a real gap",
        ]

        if emit_aliases and alias_rows:
            seen, rows = set(), []
            for target, field, key in alias_rows:
                if (target, field) in seen:
                    continue
                seen.add((target, field))
                rows.append(f"      - target: {target}\n"
                            f"        issue_field: {field}\n"
                            f"        role: fallback        # for {key}")
            lines += ["", f"ALIAS ROWS ({len(rows)})", "```yaml"] + rows + ["```"]

        return_results(CommandResults(
            readable_output="\n".join(lines),
            outputs_prefix="SOCFramework.ContractCoverage",
            outputs={"category": category, "lifecycle": lifecycle,
                     "issues_sampled": sum(counts.values()),
                     "targets": len(chains),
                     "sources": [{"source": k, "issues": counts[k], **per_source[k]}
                                 for k in order]},
        ))

    except Exception as e:  # noqa: BLE001 — a read-only report must not raise on a tenant
        demisto.error(f"SOCFWContractCoverage: {type(e).__name__}: {e}")
        return_results(CommandResults(readable_output=(
            f"### ⚠️ SOC Framework — contract coverage failed\n"
            f"`{type(e).__name__}: {e}`")))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
