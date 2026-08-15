#!/usr/bin/env python3
"""
socfw_contract.py -- audit and extend the SOC Framework normalization contract.

Two jobs, deliberately separate:

  audit    True up what exists. Finds contract defects by deterministic
           comparison of the NormalizeMap against the field registry, live
           tenant population, and downstream playbook consumption.

  extend   Propose new mapping rows for a category from fields its sources
           actually populate, using precedent from the complete blocks.

No LLM. Every finding is a set operation over artefacts already in the repo or
in a sanitised capture, so every result is reproducible and reviewable.

Usage:
  python3 tools/socfw-mapper/socfw_contract.py audit
  python3 tools/socfw-mapper/socfw_contract.py audit --category network
  python3 tools/socfw-mapper/socfw_contract.py extend --category network \\
      --captures '~/captures/*.json'
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

try:
    import yaml
except ImportError:  # enum-agreement check degrades to a skip without PyYAML
    yaml = None

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NORMALIZE_MAP = os.path.join(
    REPO, "Packs/soc-framework-nist-ir/Lists/SOCFrameworkNormalizeMap_NIST_IR/"
          "SOCFrameworkNormalizeMap_NIST_IR_data.json")
CATEGORY_MAP = os.path.join(
    REPO, "Packs/soc-optimization-unified/Lists/SOCProductCategoryMap_V3/"
          "SOCProductCategoryMap_V3_data.json")

PLAYBOOK_GLOBS = [
    "Packs/soc-framework-nist-ir/Playbooks/*.yml",
    "Packs/soc-common-playbooks-unified/Playbooks/*.yml",
    "Packs/soc-optimization-unified/Playbooks/*.yml",
]

# XSOAR platform fields. Present on issues, never security artefacts. Left out
# of gap analysis so the remainder is small enough to reason about.
PLATFORM_NOISE = {
    "starred", "followup", "excluded", "local_insert_ts", "last_update_timestamp",
    "external_id", "family_tags", "tags", "status.progress", "timestamp",
    "resolution_status_modified_ts", "is_rule_triggering", "cicdkeepplaceholdersinfiles",
    "salesforceescalated", "emailsentsuccessfully", "passwordresetsuccessfully",
    "asmdevcheck", "xdmresolutiontimer", "runwithinsecure", "dbotprediction",
    "dbotpredictionprobability", "dbotclosed", "dbotcurrentdirtyfields",
    "dbotdirtyfields", "dbotmirrordirection", "dbotmirrorid", "dbotmirrorinstance",
    "dbotmirrorlastsync", "dbotmirrortags", "_vendor", "_product", "vendor",
    "product", "sourcebrand", "sourceinstance", "containsfeaturedhost",
    "containsfeaturedipaddress", "containsfeatureduser", "timcampaignthreatdetected",
}

# Fields observed to carry a single constant value on every issue of every
# source. Populated, but information-free -- must not be treated as coverage.
# Verified on brumxdr: 800/800 issues, one distinct value each.
KNOWN_CONSTANTS = {
    "xdmsourcelocationcountry": "UNKNOWN",
    "xdmsourcehostosfamily": "NO_HOST",
    "xdmsourceprocessexecutablesignaturestatus": "SIGNATURE_UNAVAILABLE",
    "xdmtargetprocessexecutablesignaturestatus": "SIGNATURE_UNAVAILABLE",
}


def base_field(value):
    """issue_field as written in the map -> bare cliName."""
    return re.sub(r"\.?\[\d+\]$", "", str(value)).strip()


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ─────────────────────────────────────────────────────────────── model loading

class Contract:
    """The NormalizeMap, indexed for comparison."""

    def __init__(self, path=NORMALIZE_MAP):
        self.doc = load(path)
        self.categories = self.doc.get("categories") or {}

    def block(self, category):
        return self.categories.get(category) or {}

    def status(self, category):
        return self.block(category).get("status")

    def mappings(self, category):
        """[(issue_field, target, row)] for one category."""
        out = []
        for row in (self.block(category).get("mappings") or []):
            if row.get("issue_field") and row.get("target"):
                out.append((base_field(row["issue_field"]), row["target"], row))
        return out

    def targets(self, category):
        """target -> [issue_field, ...] (several = fallback aliases)."""
        out = defaultdict(list)
        for field, target, _ in self.mappings(category):
            out[target].append(field)
        for section in ("stamps", "mirrors"):
            for row in (self.block(category).get(section) or []):
                if row.get("target"):
                    out[row["target"]].append(f"<{section[:-1]}>")
        return dict(out)

    def reads(self, category):
        """Every issue.* field this category reads."""
        return {f for f, _, _ in self.mappings(category)}

    def dedup_keys(self, category):
        return [t for _, t, row in self.mappings(category) if row.get("dedup_key")]

    def complete_categories(self):
        return [c for c in self.categories if self.status(c) == "complete"]

    def precedent(self, exclude=None):
        """issue_field -> [(category, target)] from COMPLETE blocks only.

        A field already mapped in a finished block has a settled target name,
        so proposing it elsewhere is a lookup rather than a judgement call.
        """
        out = defaultdict(list)
        for category in self.complete_categories():
            if category == exclude:
                continue
            for field, target, _ in self.mappings(category):
                out[field].append((category, target))
        return dict(out)


def ds_key(tag):
    """Replicate Foundation - Product Classification key derivation."""
    raw = tag[3:] if tag.startswith("DS:") else tag
    chars = list(raw)
    for i, ch in enumerate(chars):
        if not ch.isalnum() and 0 < i < len(chars) - 1:
            chars[i] = "_"
    return "ds_" + "".join(chars).lower()


def sources_for(category, category_map):
    """ds_keys the product map assigns to this category."""
    return {k for k, v in category_map.items()
            if isinstance(v, dict)
            and str(v.get("category", "")).lower() == category.lower()}


MIN_ISSUES_TO_JUDGE = 20      # below this a signature is noise, not evidence


def observed_fields(category, category_map, capture_glob, present_pct=50.0):
    """issue.* fields the category's sources actually populate.

    Constants are excluded: a field carrying one value on every issue is
    populated but information-free, and counting it as coverage inflates the
    contract's apparent completeness.
    """
    keys = sources_for(category, category_map)
    seen = Counter()
    sources = set()
    issues = {}
    for path in sorted(glob.glob(os.path.expanduser(capture_glob))):
        doc = load(path)
        for src in doc.get("sources", []):
            if ds_key(src["ds_tag"]) not in keys:
                continue
            n = src.get("issues", 0)
            if not n:
                continue
            sources.add(ds_key(src["ds_tag"]))
            issues[ds_key(src["ds_tag"])] = issues.get(ds_key(src["ds_tag"]), 0) + n
            for field, count in (src.get("fields") or {}).items():
                if count / n * 100 >= present_pct:
                    seen[field] += 1
    for field in KNOWN_CONSTANTS:
        seen.pop(field, None)
    return seen, sources, keys, sum(issues.values())


# ──────────────────────────────────────────────────────────────── audit checks
#
# Each check corresponds to a defect class observed in the field, not a
# hypothetical. The comment on each says what it caught.

def check_dead_reads(contract, category, category_map, capture_glob):
    """Reads that no source populates.

    Caught `Endpoint.os <- ostype`: dead on BOTH the native XDR agent and
    Defender, so the flat OS field was never populated for anyone. Distinct
    from a fallback alias, where a sibling row does populate the target.
    """
    seen, sources, _, n_issues = observed_fields(category, category_map, capture_glob)
    if not sources:
        return [], "no sources for this category appear in the captures"
    if n_issues < MIN_ISSUES_TO_JUDGE:
        return [], (f"only {n_issues} issue(s) sampled across {len(sources)} source(s) "
                    f"-- too little evidence to call a target dead")
    targets = contract.targets(category)
    findings = []
    for target, fields in sorted(targets.items()):
        real = [f for f in fields if not f.startswith("<")]
        if not real:
            continue
        live = [f for f in real if f in seen]
        if not live:
            findings.append((target, real))
    return findings, None


def check_constants(contract, category):
    """Rows reading a field known to carry a single constant value.

    Verified on 800 brumxdr issues: xdmsourcelocationcountry is 'UNKNOWN' on
    every one, the two signature-status fields are 'SIGNATURE_UNAVAILABLE'.
    Mapping these produces a populated-looking artefact with no information.
    """
    out = []
    for field, target, _ in contract.mappings(category):
        if field in KNOWN_CONSTANTS:
            out.append((target, field, KNOWN_CONSTANTS[field]))
    return out


def check_unregistered(contract, category, registered):
    """Reads of a cliName that is not a registered incident field.

    A correlation rule can map to an unregistered LHS and XSIAM drops it
    silently -- 25 such names in the Defender rule. On the read side the
    equivalent defect is a mapping row pointing at a field that can never
    exist on an issue.
    """
    if not registered:
        return []
    return sorted({f for f in contract.reads(category) if f not in registered})


def check_ambiguity(contract, category):
    """One target written from fields that are NOT the same concept.

    Fallback aliases are intentional and common (agentid/agent_id,
    hostip/localip). Genuine ambiguity is a target fed by different concepts,
    which makes the normalized value non-deterministic. Concept tokens
    separate the two.
    """
    CONCEPTS = [
        ("md5", ["md5"]), ("sha256", ["sha256"]), ("sha1", ["sha1"]),
        ("mac", ["mac"]), ("ip", ["ip", "ipv4", "ipv6"]),
        ("port", ["port"]), ("fqdn", ["fqdn", "dns"]), ("pid", ["pid"]),
        ("user", ["user", "account", "upn", "sam"]),
        ("host", ["host", "agent", "device"]),
        ("signer", ["signer"]), ("signature", ["signature"]),
        ("cmd", ["cmd", "commandline"]), ("path", ["path"]),
        ("name", ["name"]), ("country", ["country"]), ("zone", ["zone"]),
    ]

    def concepts(value):
        low = re.sub(r"[^a-z0-9]", "", value.lower())
        return {c for c, toks in CONCEPTS if any(t in low for t in toks)}

    out = []
    for target, fields in contract.targets(category).items():
        real = [f for f in fields if not f.startswith("<")]
        if len(set(real)) < 2:
            continue
        sets = [concepts(f) for f in real]
        # A field with no recognised concept token cannot be judged -- absence
        # of evidence is not ambiguity. agent_device_domain vs domain is a
        # fallback alias, not a conflict.
        if not all(sets):
            continue
        if not set.intersection(*sets):
            out.append((target, sorted(set(real))))
    return out


def check_downstream(contract, category, playbook_globs):
    """Targets nothing reads, and reads nothing produces.

    The second is a live break. The first is not automatically a defect --
    it can mean the consumer has not been built yet, which is the state of
    SOC_Network_Analysis_V3 (an empty stub) -- so it is reported separately
    rather than as an error.
    """
    ref = re.compile(r"SOCFramework\.((?:Artifacts\.)?[A-Za-z0-9_.]+)")
    consumed = Counter()
    for pattern in playbook_globs:
        for path in glob.glob(os.path.join(REPO, pattern)):
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for match in ref.findall(text):
                consumed[match.rstrip(".")] += 1

    produced = {t.replace("SOCFramework.", "") for t in contract.targets(category)}
    prefix = category.capitalize()
    mine = {r for r in consumed
            if r.startswith(f"Artifacts.{prefix}.") or r.startswith(f"{prefix}.")}
    broken = sorted(mine - produced)
    unread = sorted(p for p in produced
                    if (p.startswith(f"Artifacts.{prefix}.") or p.startswith(f"{prefix}."))
                    and p not in consumed)
    return broken, unread


def check_dedup(contract, category, category_map, capture_glob):
    """Do the category's dedup keys actually populate?

    Dedup keys are the grouping contract. If a source does not fill them, its
    issues will not merge into a case and the failure is silent.
    """
    keys = contract.dedup_keys(category)
    seen, sources, _, n_issues = observed_fields(category, category_map, capture_glob)
    if not sources or n_issues < MIN_ISSUES_TO_JUDGE:
        return keys, [], (f"only {n_issues} issue(s) sampled -- insufficient evidence")
    targets = contract.targets(category)
    dead = []
    for key in keys:
        fields = [f for f in targets.get(key, []) if not f.startswith("<")]
        if not any(f in seen for f in fields):
            dead.append((key, fields))
    return keys, dead, None


# ────────────────────────────────────────────────── normalized name matching
#
# Exact-match precedent misses obvious equivalents: xdmsourceagentidentifier is
# the XDM twin of agentid, mitreattcktactic of mitretacticname. Both targets are
# already settled, so treating these as "needs judgement" wastes review effort.
#
# This is deliberately NOT fuzzy string similarity, which was tested during the
# category work and proved unsafe (ds_armis_security_activities matched
# ds_azure_activity). It strips known decorations, then requires the remaining
# token multiset to match exactly. No edit distance, no partial credit.

PREFIXES = ["xdm", "socfw", "evidence", "action_"]
SUFFIXES = ["identifier", "addresses", "address"]

# Concept keys. Both sides of a pair reduce to the same value, so an alias is
# recognised without any fuzzy matching.
SYNONYMS = {
    "sourceagent": "agent", "agentid": "agent", "agent": "agent",
    "sourceuserusername": "username", "username": "username", "user": "username",
    "sourcehosthostname": "hostname", "hostname": "hostname",
    "sourcehostipv4": "hostip", "sourceipv4": "hostip", "hostip": "hostip",
    "targetipv4": "remoteip", "remoteip": "remoteip",
    "sourcehostfqdn": "hostfqdn", "targethostfqdn": "hostfqdn", "hostfqdn": "hostfqdn",
    "targetfilesha256": "filesha256", "filesha256": "filesha256",
    "targetfilefilename": "filename", "filename": "filename",
    "attcktactic": "tactic", "mitreattcktactic": "tactic",
    "mitretacticname": "tactic", "tacticname": "tactic",
    "attcktechnique": "technique", "mitreattcktechnique": "technique",
    "mitretechniquename": "technique", "techniquename": "technique",
    "identitysamaccountname": "samaccountname", "samaccountname": "samaccountname",
    "sourceprocessname": "processname", "initiatedby": "processname",
    "eventtype": "eventtype", "sourcehostosfamily": "hostos", "hostos": "hostos",
}


def normalize_name(field):
    """Reduce a cliName to comparable tokens.

    Strips known PREFIXES in order, then a small suffix set. Substring
    replacement was tried first and corrupts: removing "name" from
    "xdmsourceuserusername" leaves nonsense.
    """
    low = re.sub(r"[^a-z0-9]", "", str(field).lower())
    for _ in range(4):
        for pre in PREFIXES:
            if low.startswith(pre) and len(low) > len(pre) + 2:
                low = low[len(pre):]
                break
        else:
            break
    for suf in SUFFIXES:
        if low.endswith(suf) and len(low) > len(suf) + 2:
            low = low[: -len(suf)]
            break
    return SYNONYMS.get(low, low)


def build_normalized_precedent(contract, exclude=None):
    """normalized-name -> [(category, target, original_field)]"""
    out = defaultdict(list)
    for category in contract.complete_categories():
        if category == exclude:
            continue
        for field, target, _ in contract.mappings(category):
            key = normalize_name(field)
            if key:
                out[key].append((category, target, field))
    return dict(out)



CATEGORY_PREFIXES = ("Endpoint.", "Email.", "Network.", "Identity.",
                     "Cloud.", "Generic.", "Workload.")


def rewrite_namespace(target, category):
    """Precedent carries the CONCEPT, not the namespace.

    A network row must not be proposed as `Cloud.action` just because the cloud
    block happens to be complete. Flat targets are category-scoped, so the
    prefix is rewritten to the requesting category. Artifacts.* targets are
    cross-category by design and are left alone.
    """
    for prefix in CATEGORY_PREFIXES:
        if target.startswith(prefix):
            return category.capitalize() + "." + target[len(prefix):]
    return target


def dead_target_aliases(contract, category, seen):
    """normalized-name -> (dead target, the field it currently reads)

    A dead read plus an unmapped field that means the same thing is not two
    problems -- it is one. Adding the field as a fallback alias repairs the
    target instead of creating a second row for the same concept. Identity
    reads `Artifacts.MITRE.Tactic <- mitretacticname`, which is dead, while
    Okta emits `mitreattcktactic`.
    """
    out = {}
    for target, fields in contract.targets(category).items():
        real = [f for f in fields if not f.startswith("<")]
        if not real or any(f in seen for f in real):
            continue                       # target already resolves
        for field in real:
            key = normalize_name(field)
            if key:
                out.setdefault(key, (target, field))
    return out


# ────────────────────────────────────────────────────────────── extend (job B)

def propose(contract, category, category_map, capture_glob, present_pct=50.0):
    """Propose mapping rows for fields the category's sources populate but the
    block does not read.

    Split three ways so the reviewable surface is as small as possible:
      precedent  a COMPLETE block already maps this field -> target is known
      noise      XSOAR platform field, not a security artefact
      judgement  everything left. This is the only set that needs a human,
                 and it is the set an LLM would have to earn its place on.
    """
    seen, sources, keys, n_issues = observed_fields(
        category, category_map, capture_glob, present_pct)
    already = contract.reads(category)
    prec = contract.precedent(exclude=category)
    norm_prec = build_normalized_precedent(contract, exclude=category)
    revive = dead_target_aliases(contract, category, seen)

    precedent_rows, noise, judgement, aliases = [], [], [], []
    for field, n_sources in sorted(seen.items(), key=lambda x: -x[1]):
        if field in already:
            continue
        key = normalize_name(field)
        if field in PLATFORM_NOISE:
            noise.append((field, n_sources))
        elif key in revive:
            target, current = revive[key]
            aliases.append((field, target, current, n_sources))
        elif field in prec:
            target = Counter(t for _, t in prec[field]).most_common(1)[0][0]
            froms = sorted({c for c, _ in prec[field]})
            precedent_rows.append((field, rewrite_namespace(target, category),
                                   froms, n_sources, "exact", ""))
        elif normalize_name(field) in norm_prec:
            hits = norm_prec[normalize_name(field)]
            target = Counter(t for _, t, _ in hits).most_common(1)[0][0]
            froms = sorted({c for c, _, _ in hits})
            via = sorted({f for _, _, f in hits})[0]
            precedent_rows.append((field, rewrite_namespace(target, category),
                                   froms, n_sources, "normalized", via))
        else:
            judgement.append((field, n_sources))
    return {"sources": sources, "mapped_sources": keys, "issues": n_issues,
            "precedent": precedent_rows, "noise": noise, "aliases": aliases,
            "judgement": judgement, "observed": len(seen)}


def yaml_rows(precedent_rows):
    """Emit proposals as schema rows, ready to paste after review."""
    lines = []
    for field, target, froms, _, how, via in sorted(precedent_rows, key=lambda x: x[1]):
        lines.append(f"      - target: {target}")
        lines.append(f"        issue_field: {field}")
        lines.append(f"        shape: {'structured' if target.startswith('Artifacts.') else 'flat'}")
        lines.append(f"        role: canonical")
        lines.append(f"        # precedent: {', '.join(froms)}"
                     + (f" via {via}" if how == "normalized" else ""))
    return lines


# ──────────────────────────────────────────────────────────────────── commands

# ───────────────────────────────────────────────── enum-domain agreement
#
# The value-level analogue of check_downstream. That check asks whether a *key*
# a playbook reads is ever produced; this asks the same of each *value* a
# playbook branches on. A branch on a value no task writes to that path is dead
# (Analysis.Endpoint.compromise_level == suspicious was one -- suspicious is
# only ever written to Analysis.Identity.compromise_level).
#
# It also grounds the AI-vs-deterministic reconciliation: pass an AI prompt's
# declared output enums with --prompt-enums and the same set comparison reports
# which consumer values the prompt cannot emit (a live break the moment the
# prompt becomes the producer) and which values it introduces with no
# deterministic precedent.
#
# Scope: the scoring enums written as SetAndHandleEmpty literals. verdict is
# excluded on purpose -- it is derived (DBot / analysis), never a literal write,
# so this extractor cannot see its producers.

ANALYSIS_ENUM_KEYS = ["compromise_decision", "compromise_level", "spread_level",
                      "signal_type", "persistence_type"]
_ENUM_LITERAL = re.compile(r"^[a-z][a-z0-9_]*$")
_ENUM_PATH = {k: re.compile(rf"^Analysis\.(?:[A-Za-z]+\.)?{k}$")
              for k in ANALYSIS_ENUM_KEYS}


def _simple(node):
    """The 'simple' scalar of a playbook value node, ${..} unwrapped; else None."""
    if isinstance(node, dict):
        if "value" in node:
            return _simple(node["value"])
        node = node.get("simple")
    if isinstance(node, str):
        s = node.strip()
        if s.startswith("${") and s.endswith("}"):
            s = s[2:-1].strip()
        return s
    return None


def _is_enum_literal(s):
    return isinstance(s, str) and bool(_ENUM_LITERAL.match(s.strip()))


def _enum_key(path):
    for key, rx in _ENUM_PATH.items():
        if path and rx.match(path):
            return key
    return None


def check_enum_agreement(playbook_globs, prompt_enums=None):
    """Producer/consumer value-domain agreement for Analysis.* scoring enums.

    Returns {key: {produced, consumed, dead[, breaks, drift]}}, or None if
    PyYAML is unavailable. produced/consumed are the union of values
    written/branched-on across every path for that key; dead is [(path, [vals])]
    for consumer values no producer writes to that path (nor the bare rollup,
    nor -- for a bare consumer -- any category path). breaks/drift appear only
    when prompt_enums is supplied.
    """
    if yaml is None:
        return None
    prod, cons = {}, {}   # full context path -> set(values)

    def add(store, path, val):
        store.setdefault(path, set()).add(val)

    def walk(node):
        if isinstance(node, dict):
            task = node.get("task") or {}
            script = task.get("scriptName") or task.get("script") or ""
            if str(script).endswith("SetAndHandleEmpty"):
                sa = node.get("scriptarguments") or {}
                p, v = _simple(sa.get("key")), _simple(sa.get("value"))
                if _enum_key(p) and _is_enum_literal(v):
                    add(prod, p, v)
            if isinstance(node.get("left"), dict) and "right" in node:
                if node["left"].get("iscontext"):
                    p, rv = _simple(node["left"]), _simple(node.get("right"))
                    if _enum_key(p) and _is_enum_literal(rv):
                        add(cons, p, rv)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    for pattern in playbook_globs:
        for path in glob.glob(os.path.join(REPO, pattern)):
            try:
                walk(yaml.safe_load(open(path, encoding="utf-8")))
            except Exception:
                continue

    def union(store, key):
        out = set()
        for path, vals in store.items():
            if _enum_key(path) == key:
                out |= vals
        return out

    findings = {}
    for key in ANALYSIS_ENUM_KEYS:
        bare = prod.get(f"Analysis.{key}", set())
        dead = []
        for path, cvals in cons.items():
            if _enum_key(path) != key:
                continue
            avail = prod.get(path, set()) | bare
            if path == f"Analysis.{key}":
                avail |= union(prod, key)
            missing = sorted(cvals - avail)
            if missing:
                dead.append((path, missing))
        entry = {"produced": union(prod, key), "consumed": union(cons, key),
                 "dead": dead}
        if prompt_enums and key in prompt_enums:
            declared = set(prompt_enums[key])
            entry["breaks"] = sorted(entry["consumed"] - declared)
            entry["drift"] = sorted(declared - entry["produced"])
        findings[key] = entry
    return findings


def audit_enums(playbook_globs, prompt_enums_path=None):
    """Print the enum-agreement section; return the defect count."""
    print(f"\n{'=' * 74}")
    print("  enum contract   (Analysis.* scoring-enum producer/consumer agreement)")
    print("=" * 74)
    findings = check_enum_agreement(
        playbook_globs, load(prompt_enums_path) if prompt_enums_path else None)
    if findings is None:
        print("\n  (enum check skipped: PyYAML not available)")
        return 0
    defects = 0
    for key in ANALYSIS_ENUM_KEYS:
        r = findings[key]
        if not r["produced"] and not r["consumed"] and "breaks" not in r:
            continue
        print(f"\n  {key}")
        print(f"    produced: {sorted(r['produced']) or '—'}")
        print(f"    consumed: {sorted(r['consumed']) or '—'}")
        for path, missing in r["dead"]:
            defects += len(missing)
            print(f"    DEFECT — dead branch: {path} reads {missing}, "
                  f"never produced on that path")
        if "breaks" in r:
            if r["breaks"]:
                defects += len(r["breaks"])
                print(f"    DEFECT — prompt cannot emit consumed value(s) "
                      f"(breaks when AI is producer): {r['breaks']}")
            if r["drift"]:
                print(f"    note — prompt emits value(s) with no deterministic "
                      f"precedent: {r['drift']}")
    return defects


def cmd_audit(args):
    contract = Contract()
    category_map = load(CATEGORY_MAP)
    registered = set()
    if args.registered:
        registered = set(load(args.registered))

    categories = [args.category] if args.category else sorted(contract.categories)
    total_defects = 0

    for category in categories:
        print(f"\n{'=' * 74}")
        print(f"  {category}   status={contract.status(category)}   "
              f"targets={len(contract.targets(category))}  "
              f"reads={len(contract.reads(category))}")
        print("=" * 74)

        constants = check_constants(contract, category)
        if constants:
            total_defects += len(constants)
            print(f"\n  DEFECT — reads a constant-valued field ({len(constants)})")
            print("    Populated on every issue with a single value. No information.")
            for target, field, value in constants:
                print(f"      {target:<44} <- {field}  (always {value!r})")

        unreg = check_unregistered(contract, category, registered)
        if unreg:
            total_defects += len(unreg)
            print(f"\n  DEFECT — reads an unregistered cliName ({len(unreg)})")
            print("    Cannot ever be populated on an issue.")
            for field in unreg:
                print(f"      {field}")

        ambiguous = check_ambiguity(contract, category)
        if ambiguous:
            total_defects += len(ambiguous)
            print(f"\n  DEFECT — one target, unrelated concepts ({len(ambiguous)})")
            print("    Normalized value is non-deterministic. Fallback aliases are")
            print("    excluded; these share no concept token.")
            for target, fields in ambiguous:
                print(f"      {target:<44} <- {', '.join(fields)}")

        broken, unread = check_downstream(contract, category, PLAYBOOK_GLOBS)
        if broken:
            total_defects += len(broken)
            print(f"\n  DEFECT — consumed downstream, never produced ({len(broken)})")
            for ref in broken:
                print(f"      {ref}")

        if args.captures:
            dead, note = check_dead_reads(contract, category, category_map, args.captures)
            if note:
                print(f"\n  (dead-read check skipped: {note})")
            elif dead:
                total_defects += len(dead)
                print(f"\n  DEFECT — target no source populates ({len(dead)})")
                for target, fields in dead:
                    print(f"      {target:<44} <- {', '.join(fields)}")

            keys, dead_keys, dnote = check_dedup(contract, category, category_map, args.captures)
            if dnote:
                print(f"\n  (dedup check skipped: {dnote})")
            if dead_keys:
                total_defects += len(dead_keys)
                print(f"\n  DEFECT — dedup key not populated ({len(dead_keys)})")
                print("    Grouping will silently fail for this category.")
                for key, fields in dead_keys:
                    print(f"      {key:<44} <- {', '.join(fields)}")

        if unread:
            print(f"\n  note — produced, not read downstream ({len(unread)})")
            print("    Not necessarily a defect: the consumer may not be built yet.")
            for ref in unread[:6]:
                print(f"      {ref}")
            if len(unread) > 6:
                print(f"      ... and {len(unread) - 6} more")

    # enum-domain agreement is cross-category (verdict/compromise/... are one
    # contract), so it runs once over all playbooks rather than per category.
    total_defects += audit_enums(PLAYBOOK_GLOBS,
                                 getattr(args, "prompt_enums", None))

    print(f"\n{'=' * 74}")
    print(f"  {total_defects} defect(s) across {len(categories)} categor(ies)")
    print("=" * 74)
    return 1 if total_defects else 0


def cmd_extend(args):
    contract = Contract()
    category_map = load(CATEGORY_MAP)
    result = propose(contract, args.category, category_map,
                     args.captures, args.present_pct)

    print(f"category            : {args.category}  "
          f"(status={contract.status(args.category)})")
    print(f"already reads       : {len(contract.reads(args.category))} fields")
    print(f"sources             : {len(result['mapped_sources'])} mapped, "
          f"{len(result['sources'])} seen in captures")
    print(f"fields observed     : {result['observed']} "
          f"(constants excluded)\n")

    print(f"=== REPAIRS A DEAD READ ({len(result['aliases'])}) "
          f"— add as a fallback alias, do not create a new target ===")
    for field, target, current, n in result["aliases"]:
        print(f"   {target:<42} += {field:<34} (currently dead: <- {current})")

    print(f"\n=== PROPOSED FROM PRECEDENT ({len(result['precedent'])}) "
          f"— target name already settled ===")
    for field, target, froms, n, how, via in result["precedent"]:
        note = f"via {via}" if how == "normalized" else "exact"
        print(f"   {field:<42} -> {target:<40} [{note}]")

    print(f"\n=== PLATFORM NOISE ({len(result['noise'])}) — not security artefacts ===")
    print("   " + ", ".join(f for f, _ in result["noise"][:14]))

    print(f"\n=== NEEDS JUDGEMENT ({len(result['judgement'])}) "
          f"— no precedent anywhere ===")
    for field, n in result["judgement"]:
        print(f"   {field:<42} on {n} source(s)")

    if result["precedent"] and args.emit:
        print(f"\n=== SCHEMA ROWS (review before pasting) ===")
        for line in yaml_rows(result["precedent"]):
            print(line)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="find contract defects")
    a.add_argument("--category", help="one category; default all")
    a.add_argument("--captures", help="glob of sanitised captures; enables "
                                      "population-dependent checks")
    a.add_argument("--registered", help="JSON list of registered cliNames")
    a.add_argument("--prompt-enums",
                   help="JSON {key: [values]} of an AI prompt's declared output "
                        "enums; checks interchangeability with the deterministic "
                        "producers")
    a.set_defaults(func=cmd_audit)

    e = sub.add_parser("extend", help="propose new mapping rows")
    e.add_argument("--category", required=True)
    e.add_argument("--captures", required=True)
    e.add_argument("--present-pct", type=float, default=50.0)
    e.add_argument("--emit", action="store_true", help="print schema rows")
    e.set_defaults(func=cmd_extend)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
