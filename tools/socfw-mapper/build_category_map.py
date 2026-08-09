#!/usr/bin/env python3
"""
build_category_map.py -- Build a tenant-specific SOCProductCategoryMap from
live issue.* data.

Connects to an XSIAM tenant, enumerates every data source / product pair that
has produced issues, derives a field signature from the runtime issue.* context,
and classifies each into a SOC Framework product category.

Training corpus is the vendor packs' alert_fields in the local repo. The
canonical 'generic core' (fields every category shares) is suppressed, since it
carries no category signal and otherwise swamps the discriminative tail.

Deterministic. No LLM. Every proposal carries the evidence that produced it.

Usage:
  python3 build_category_map.py --env /path/to/tenant-a.env
  python3 build_category_map.py --env prod.env --out prod_categorymap.json
  python3 build_category_map.py --env dev.env --allowlist socfw_sources.txt

Exit codes: 0 ok, 1 config/connection error.
"""
import argparse
import glob
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip3 install pyyaml --break-system-packages")

# issue.* keys that are framework/plumbing rather than vendor evidence.
# These would otherwise look discriminative purely by accident of sampling.
ALWAYS_IGNORE = {
    "tags", "family_tags", "_vendor", "_product", "vendor", "product",
    "sourcebrand", "sourceinstance", "dbotpredictionprobability",
    "dbotclosed", "dbotcurrentdirtyfields", "dbotmirrordirection",
    "dbotmirrorid", "dbotmirrorinstance", "dbotmirrorlastsync",
    "dbotmirrortags", "dbotdirtyfields",
}

TAG_TO_CATEGORY = {
    "endpoint": "Endpoint",
    "email": "Email",
    "identity": "Identity",
    "network": "Network",
    "cloud": "Cloud",
    "workload": "Workload",
    "saas": "SaaS",
}

RESPONSE_PLACEHOLDER = "TODO-REVIEW"

# Production convention: `responses` always carries identity + indicator on top
# of the source's own category, because a case that starts as e.g. an email
# alert still needs to disable the account and enrich the indicator. These are
# the framework's standing capability set, not a property of the data source.
ALWAYS_RESPOND = ("identity", "indicator")

# House defaults, mined from the shipped SOCProductCategoryMap_V3 (majority
# responder per category) and cross-checked against SOCFrameworkActions_V3
# coverage. Applied only where the source is NOT itself that category's vendor:
# Proofpoint's own entry responds to email with Proofpoint TAP v2, CrowdStrike's
# responds to endpoint with CrowdStrike Falcon. Own category stays TODO.
DEFAULT_RESPONDERS = {
    "indicator": "Cortex Core - IR",            # 94% of shipped sources
    "identity": "Active Directory Query v2",    # 75%
    "email": "Proofpoint TAP v2",               # 71%
    "endpoint": "CrowdStrike Falcon",           # 67%
    # no `network` default: only one shipped source used one, which is not a
    # convention. Asserting it would contradict `response: TODO-REVIEW` on the
    # same entry when the vendor has no integration at all.
}

# Fields a human owns. On re-run these are preserved from any prior output
# unless they still hold the placeholder.
HUMAN_OWNED = ("type", "response", "responses")


# --------------------------------------------------------------- credentials
def load_env(path):
    """Minimal .env parser. Returns dict. Does not mutate os.environ."""
    if not os.path.isfile(path):
        sys.exit(f"env file not found: {path}")
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip().strip('"').strip("'")
            out[k.strip()] = v
    missing = [k for k in ("DEMISTO_BASE_URL", "DEMISTO_API_KEY", "XSIAM_AUTH_ID")
               if not out.get(k)]
    if missing:
        sys.exit(f"{path} missing required keys: {', '.join(missing)}")
    return out


class Tenant:
    def __init__(self, creds, timeout=180):
        self.base = creds["DEMISTO_BASE_URL"].rstrip("/")
        self.timeout = timeout
        self.hdrs = {
            "Authorization": creds["DEMISTO_API_KEY"],
            "x-xdr-auth-id": str(creds["XSIAM_AUTH_ID"]),
            "Content-Type": "application/json",
        }

    def call(self, path, body=None, attempts=3):
        data = json.dumps(body).encode() if body is not None else None
        last = None
        for attempt in range(attempts):
            req = urllib.request.Request(
                self.base + path, data=data, headers=self.hdrs,
                method="POST" if body is not None else "GET")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode()[:300]
                except Exception:
                    pass
                last = RuntimeError(f"HTTP {exc.code} on {path}: {detail}")
                # 5xx on a big tenant is usually the query being too expensive
                # server-side, not a client error. Back off and retry.
                if exc.code < 500:
                    raise last
            except Exception as exc:                    # timeouts, resets
                last = RuntimeError(f"{type(exc).__name__} on {path}: {exc}")
            if attempt < attempts - 1:
                time.sleep(2 ** attempt * 3)
        raise last

    def issues(self, pages, size, query=None):
        """Yield issue dicts, newest first.

        Deep paging is the usual failure mode on large tenants: /incidents/search
        re-sorts the whole result set for every page, so high page numbers get
        progressively more expensive and eventually 500. A failure part-way
        through is NOT fatal -- whatever was already retrieved is still a valid
        sample. A failure on page 0 IS fatal: there is no sample.
        """
        self.failed_page = None
        self.failure = None
        for page in range(pages):
            flt = {"page": page, "size": size,
                   "sort": [{"field": "created", "asc": False}]}
            if query:
                flt["query"] = query
            try:
                res = self.call("/xsoar/public/v1/incidents/search", {"filter": flt})
            except RuntimeError as exc:
                self.failed_page = page
                self.failure = str(exc)
                print(f"\n  !! page {page} failed: {exc}")
                if page == 0:
                    print("     No issues retrieved at all — this is not a paging\n"
                          "     depth problem. Check in this order:\n"
                          "       1. credentials / API key scope for this tenant\n"
                          "       2. the --query filter is valid there\n"
                          "          (try without --detections-only)\n"
                          "       3. --size 25, in case the page size is the issue")
                else:
                    print(f"     Keeping the {page * size} issues already retrieved.\n"
                          f"     Large tenants often 500 on deep paging. Narrow the\n"
                          f"     sample instead of going deeper:\n"
                          f"       --query 'name:<vendor>'   (one source at a time)\n"
                          f"       --size 50                 (smaller pages)\n"
                          f"       --pages {max(page, 1)}    (stop before the failure)")
                return
            rows = res.get("data") or []
            if not rows:
                return
            for row in rows:
                yield row


# ------------------------------------------------------------------ training
def fit(docs, generic_frac):
    """Build the scoring model from labelled documents [(signature, category)].

    The generic core is recomputed HERE, over whatever documents are in the
    corpus. This matters: bootstrap documents are runtime issue.* signatures
    (46-63 fields, including plumbing that repo alert_fields never carries),
    so a core computed from packs alone leaves those fields unsuppressed and
    they become spuriously "discriminative" for whichever category the
    bootstrap happened to add. Measured: bootstrapping two Check Point sources
    without recomputing turned every source on the tenant into Network,
    including Proofpoint TAP.
    """
    freq = Counter()
    for sig, _ in docs:
        for field in sig:
            freq[field] += 1
    generic = {f for f, c in freq.items() if c / len(docs) >= generic_frac}
    generic |= ALWAYS_IGNORE

    per_cat = defaultdict(Counter)
    docfreq = Counter()
    ncat = Counter()
    for sig, cat in docs:
        ncat[cat] += 1
        for field in sig - generic:
            per_cat[cat][field] += 1
            docfreq[field] += 1
    return {"per_cat": per_cat, "docfreq": docfreq, "ncat": ncat,
            "generic": generic, "packs": len(docs), "docs": docs}


def build_corpus(repo, generic_frac):
    """Learn category -> discriminative issue.* fields from vendor packs."""
    packs = {}
    pattern = os.path.join(repo, "Packs", "*", "CorrelationRules", "*.yml")
    for path in sorted(glob.glob(pattern)):
        try:
            doc = yaml.safe_load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        fields = doc.get("alert_fields") or {}
        if not isinstance(fields, dict) or len(fields) < 10:
            continue
        category = next((TAG_TO_CATEGORY[str(t).lower()]
                         for t in (doc.get("tags") or [])
                         if str(t).lower() in TAG_TO_CATEGORY), None)
        if not category:
            continue
        pack = os.path.relpath(path, repo).split(os.sep)[1]
        seen, _ = packs.get(pack, (set(), category))
        packs[pack] = (seen | set(fields.keys()), category)

    if not packs:
        sys.exit(f"no labeled correlation rules found under {repo}/Packs")

    return fit([(sig, cat) for sig, cat in packs.values()], generic_frac)


def classify(signature, model):
    """IDF-weighted score per category. Returns (best, scores, evidence)."""
    per_cat, docfreq = model["per_cat"], model["docfreq"]
    ncat, generic = model["ncat"], model["generic"]
    total = sum(ncat.values())
    usable = signature - generic
    scores, evidence = {}, {}
    for category, ctr in per_cat.items():
        score = 0.0
        hits = []
        for field in usable:
            if field not in ctr:
                continue
            idf = math.log((total + 1) / (docfreq[field] + 1)) + 1.0
            weight = (ctr[field] / ncat[category]) * idf
            score += weight
            hits.append((field, round(weight, 2)))
        scores[category] = round(score, 2)
        # Sort ties by field name, not by set-iteration order. Without the
        # secondary key the evidence list shuffles between runs (many fields
        # share an identical weight), which defeats the point of shipping the
        # evidence for audit.
        evidence[category] = sorted(hits, key=lambda x: (-x[1], x[0]))[:6]
    if not scores:
        return None, {}, []
    best = max(scores, key=scores.get)
    return best, scores, evidence[best]


def confidence_of(scores, best, floor):
    """high/medium/low/weak/none from absolute score and margin over runner-up.

    'none' is reserved for sources with NO category evidence at all -- health,
    audit, licensing, ingestion telemetry. Those aren't detections and never
    will be. 'weak' means real but insufficient evidence: possibly a category
    the corpus can't yet recognize, which is worth a human look.
    """
    if best is None or not scores:
        return "none"
    top = scores[best]
    if max(scores.values()) <= 0.0:
        return "none"          # structurally not an IR data source
    rest = sorted((v for k, v in scores.items() if k != best), reverse=True)
    runner = rest[0] if rest else 0.0
    if top < floor:
        return "weak"          # has signal, below threshold -- review
    margin = top / runner if runner > 0 else float("inf")
    if top >= floor * 2 and margin >= 3:
        return "high"
    if margin >= 1.5:
        return "medium"
    return "low"


# ------------------------------------------------------------------ sampling
def ds_key(ds_tag):
    """Replicate Foundation - Product Classification key derivation."""
    raw = ds_tag[3:] if ds_tag.startswith("DS:") else ds_tag
    chars = list(raw)
    for i, ch in enumerate(chars):
        if not ch.isalnum() and 0 < i < len(chars) - 1:
            chars[i] = "_"
    return "ds_" + "".join(chars).lower()


def scalar(value):
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def sanitize_issue(inc):
    """SANITISATION BOUNDARY. Raw issues never travel past this function.

    Takes one API issue object and returns only non-sensitive structure:
      (ds_tag, product, [field names that were populated])

    Everything else -- every field VALUE, the issue name, id, owner, timestamps,
    war room, labels -- is dropped here and never reaches analysis, memory, or
    disk. Field values are tested for emptiness and discarded in the same
    expression; they are never bound to a variable that outlives this call.

    Issue names are dropped deliberately: SOCFW alert names embed hostnames
    (`[Endpoint] <host> | Execution | T1053.005`).

    ds_tag and product are RETAINED -- they are the vendor/product identifiers
    the map is keyed on. On a customer tenant these can still carry in-house
    naming, so they are surfaced in the capture file for review before any
    promotion to shipped content.
    """
    cf = inc.get("CustomFields") or {}
    tags = []
    for key in ("tags", "family_tags"):
        val = cf.get(key)
        if isinstance(val, list):
            tags += [str(x) for x in val]
        elif val:
            tags.append(str(val))
    ds_tag = next((t for t in tags if t.startswith("DS:")), None)
    if not ds_tag:
        return None
    product = scalar(cf.get("_product") or cf.get("product")) or "-"
    fields = [f for f, v in cf.items() if v not in (None, "", [], {}, "null")]
    return ds_tag, product, fields


def capture(tenant, pages, size, query=None):
    """Pull from the tenant and sanitise at the boundary. Returns a plain,
    inspectable structure: no values, no free text."""
    populated = defaultdict(Counter)
    totals = Counter()
    scanned = 0
    for inc in tenant.issues(pages, size, query):
        scanned += 1
        clean = sanitize_issue(inc)
        del inc                       # drop the raw object immediately
        if not clean:
            continue
        ds_tag, product, fields = clean
        group = (ds_tag, product)
        totals[group] += 1
        for field in fields:
            populated[group][field] += 1
    return populated, totals, scanned


def capture_to_dict(populated, totals, scanned, tenant_url, query):
    """Serialisable form of a sanitised capture, for review before analysis."""
    return {
        "_schema": "socfw-mapper capture v1 — sanitised: field names and counts "
                   "only, no values",
        "tenant": tenant_url,
        "query": query,
        "issues_scanned": scanned,
        "sources": [
            {"ds_tag": ds_tag, "product": product, "issues": totals[(ds_tag, product)],
             "fields": {f: c for f, c in sorted(populated[(ds_tag, product)].items())}}
            for (ds_tag, product) in sorted(totals)
        ],
    }


def capture_from_dict(doc):
    populated, totals = defaultdict(Counter), Counter()
    for src in doc.get("sources", []):
        group = (src["ds_tag"], src["product"])
        totals[group] = src["issues"]
        populated[group] = Counter(src.get("fields") or {})
    return populated, totals, doc.get("issues_scanned", 0)


def collect(tenant, pages, size, query=None):
    """Deprecated alias retained for callers; use capture()."""
    return capture(tenant, pages, size, query)


def yaml_quote(val):
    """Quote a scalar for YAML output."""
    s = str(val)
    if s == "" or any(c in s for c in ':#{}[],&*?|<>=!%@`"\'\n') or s != s.strip():
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def write_schema_yaml(path, header, entries):
    """Emit the schema YAML by hand.

    yaml.dump is forbidden in this repo -- it reorders keys and breaks XSIAM
    -- so key order is controlled explicitly here. Everything outside the
    reserved header keys is the list payload, emitted verbatim by
    tools/generate_soc_framework_content.py.
    """
    lines = [
        "# " + "=" * 74,
        "# SOC Product Category Map",
        "# Maps a data source (the DS: tag on an issue) to its SOC Framework",
        "# product category, response engine, and per-category responders.",
        "# Generated by build_category_map.py from live tenant issue.* data.",
        "# Hand edits to type / response / responses are preserved on re-run.",
        "# " + "=" * 74,
    ]
    for key in ("lifecycle", "pack", "list_name", "description"):
        if header.get(key) is not None:
            lines.append(f"{key}: {yaml_quote(header[key])}")
    lines.append("")
    # `id` and `name` are list PAYLOAD, not header: every shipped List in the
    # repo carries them and the emitter does not regenerate them, so omitting
    # them would make this the only List without. They always equal list_name.
    list_name = header.get("list_name")
    if list_name:
        lines.append(f"id: {yaml_quote(list_name)}")
        lines.append(f"name: {yaml_quote(list_name)}")
        lines.append("")

    KNOWN = ("category", "type", "confidence", "response", "responses",
             "product_map", "_note")
    for ds_key in sorted(entries):
        entry = entries[ds_key]
        lines.append(f"{ds_key}:")
        for field in ("category", "type", "confidence", "response"):
            val = entry.get(field)
            # Placeholders are never written. Foundation feeds `response` to
            # SOCCommandWrapper, so "TODO-REVIEW" would be treated as an
            # integration name at runtime; an ABSENT key falls back safely.
            if val is None or val == RESPONSE_PLACEHOLDER:
                continue
            lines.append(f"  {field}: {yaml_quote(val)}")
        responses = {k: v for k, v in (entry.get("responses") or {}).items()
                     if v and v != RESPONSE_PLACEHOLDER}
        if responses:
            lines.append("  responses:")
            for cat in sorted(responses):
                lines.append(f"    {cat}: {yaml_quote(responses[cat])}")
        product_map = entry.get("product_map") or {}
        if product_map:
            lines.append("  product_map:")
            for prod in sorted(product_map):
                lines.append(f"    {yaml_quote(prod)}: {yaml_quote(product_map[prod])}")
        # Preserve anything this tool does not model (e.g. `Name` on
        # ds_fortinet_fortigate). Silently dropping fields from a shipped
        # artifact is not acceptable.
        for field in sorted(entry):
            if field in KNOWN or field.startswith("_conflicts"):
                continue
            if entry[field] is not None:
                lines.append(f"  {field}: {yaml_quote(entry[field])}")
        note = entry.get("_note")
        if note:
            lines.append(f"  _note: {yaml_quote(note)}")
        lines.append("")

    tmp = path + ".tmp"
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")
    os.replace(tmp, path)


RESERVED_HEADER = ("lifecycle", "pack", "list_name", "description",
                   "validation", "emit")

# `_product` values that are NOT vendor products. Fusion is Palo XSIAM's own
# analytics engine firing on top of a third-party or PANW source, so a
# Check Point issue can arrive as product "-" (the vendor's own detection) or
# "Fusion" (XSIAM analytics over Check Point data). Same source, same category,
# different detection engine.
#
# These must not become product_map entries -- that would split one source
# into two categories -- and must not drive differential scoring, since the
# Fusion signature is a superset of the vendor's (measured: Check Point Threat
# Emulation "-" has 46 fields, all 46 shared with its Fusion sibling, so
# subtracting the shared core left ZERO fields and the source scored 0.0).
#
# They ARE tracked and reported: where Fusion appears is where native analytics
# has coverage, which is useful in its own right.
ANALYTICS_ENGINES = {"fusion"}


def is_analytics_product(product):
    return str(product).strip().lower() in ANALYTICS_ENGINES


def read_schema_yaml(path):
    """Load an existing schema back. Returns (header, entries)."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    header = {k: doc[k] for k in RESERVED_HEADER if k in doc}
    entries = {k: v for k, v in doc.items()
               if k not in RESERVED_HEADER and k not in ("id", "name")
               and isinstance(v, dict)}
    return header, entries


def load_allowlist(path):
    if not path:
        return None
    if not os.path.isfile(path):
        sys.exit(f"allowlist not found: {path}")
    keys = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                keys.add(line)
    return keys


def load_shipped_map(repo, explicit=None):
    """The shipped SOCProductCategoryMap_V3. Used to seed `type`, `response`
    and the own-category responder for sources the framework already knows.

    This is authored content, not tenant state, so it is the right source of
    truth for the human-owned fields -- far better than leaving TODO on a
    source that has been mapped for months."""
    path = explicit or os.path.join(
        repo, "Packs", "soc-optimization-unified", "Lists",
        "SOCProductCategoryMap_V3", "SOCProductCategoryMap_V3_data.json")
    if not os.path.isfile(path):
        return {}, path
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), path
    except Exception:
        return {}, path


def seed_from_shipped(entry, shipped):
    """Fill human-owned fields from the shipped contract where they match."""
    filled = []
    for field in ("type", "response"):
        if entry.get(field) == RESPONSE_PLACEHOLDER and shipped.get(field):
            entry[field] = shipped[field]
            filled.append(field)
    ship_resp = shipped.get("responses") or {}
    for key, val in (entry.get("responses") or {}).items():
        if val == RESPONSE_PLACEHOLDER and ship_resp.get(key):
            entry["responses"][key] = ship_resp[key]
            filled.append(f"responses.{key}")
    # product_map is ADDITIVE ONLY. A derived value must never replace an
    # existing one: minority products score low (a vendor's identity alerts
    # still carry its endpoint fields), so the classifier reliably mislabels
    # them -- and product_map routes a product to its whole lifecycle. Getting
    # it wrong sends every alert for that product to the wrong playbooks.
    # Disagreements are REPORTED, never applied.
    ship_pm = shipped.get("product_map") or {}
    if ship_pm:
        gen_pm = entry.get("product_map") or {}
        conflicts = [f"{p}: derived={gen_pm[p]} shipped={ship_pm[p]}"
                     for p in gen_pm if p in ship_pm and gen_pm[p] != ship_pm[p]]
        merged = dict(gen_pm)          # keep products shipped doesn't know
        merged.update(ship_pm)         # shipped wins on every conflict
        entry["product_map"] = merged
        filled.append("product_map")
        if conflicts:
            entry.setdefault("_conflicts", []).extend(conflicts)
    return filled


def merge_entry(generated, existing, allow_category_change=False):
    """Reconcile a freshly generated entry with a prior/hand-edited one.

    Rules, in order of precedence:
      * Human edits win. Any HUMAN_OWNED field that a person has filled in
        (i.e. is not the placeholder) is preserved verbatim.
      * Derived fields refresh. category / confidence / _generated always take
        the new value, since they reflect current tenant evidence.
      * product_map MERGES rather than replaces. A single-product tenant must
        never narrow an entry authored from a multi-product one.
      * New response keys are added; existing values are never overwritten.
    """
    out = dict(existing)
    notes = []

    # `confidence` always refreshes -- it describes the current evidence.
    RANK = {"none": 0, "weak": 1, "low": 2, "medium": 3, "vendor-match": 4, "high": 5}
    gen_c = str(generated.get("confidence", "")).lower()
    cur_c = str(existing.get("confidence", "")).lower()
    # Never lower an existing confidence. A human wrote `high` because they
    # knew; the tool writes `medium` because it sampled 300 issues.
    if gen_c and RANK.get(gen_c, 0) >= RANK.get(cur_c, 0):
        out["confidence"] = generated["confidence"]

    # `category` does NOT silently refresh. The base category is taken from the
    # highest-volume product in the sample, and sampling is skewed: an 800-issue
    # capture showed CrowdStrike as 15 Falcon Identity Protection vs 2 Falcon,
    # which would flip the source from Endpoint to Identity. A tenant sample is
    # not authority to redefine a shipped source. Disagreements are REPORTED;
    # --allow-category-change applies them.
    gen_cat = generated.get("category")
    cur_cat = existing.get("category")
    TOOL_CONF = {"high", "medium", "low", "weak", "none", "vendor-match"}
    prior_was_generated = str(existing.get("confidence", "")).lower() in TOOL_CONF
    # A vendor-match is resolved FROM the shipped contract, not inferred from
    # fields, so it is better evidence than anything a previous run scored.
    # Without this an early bad run pins the category forever: ds_okta_sso was
    # written Network by an earlier run and then blocked the correct Identity.
    vendor_authoritative = (str(generated.get("confidence", "")).lower()
                            == "vendor-match" and prior_was_generated)
    if gen_cat and cur_cat and gen_cat != cur_cat:
        if vendor_authoritative:
            out["category"] = gen_cat
            notes.append(f"category {cur_cat} -> {gen_cat} (vendor-match "
                         f"overrides earlier generated value)")
        elif allow_category_change:
            out["category"] = gen_cat
            notes.append(f"category CHANGED {cur_cat} -> {gen_cat} "
                         f"(--allow-category-change)")
        else:
            notes.append(f"category derived={gen_cat} kept={cur_cat}")
    elif gen_cat and not cur_cat:
        out["category"] = gen_cat

    for field in ("type", "response"):
        cur = existing.get(field)
        if cur in (None, "", RESPONSE_PLACEHOLDER):
            val = generated.get(field)
            if val in (None, "", RESPONSE_PLACEHOLDER) and field == "type":
                out.pop("type", None)      # type is not generated; omit it
            else:
                out[field] = val if val else RESPONSE_PLACEHOLDER
        else:
            out[field] = cur

    merged_resp = dict(existing.get("responses") or {})
    for key, val in (generated.get("responses") or {}).items():
        cur = merged_resp.get(key)
        if cur in (None, "", RESPONSE_PLACEHOLDER):
            merged_resp[key] = val
        # else: keep the human value
    if merged_resp:
        out["responses"] = merged_resp

    # Additive only, same reasoning as seed_from_shipped: an existing
    # product->category assignment is never replaced by a derived one.
    old_pm = dict(existing.get("product_map") or {})
    new_pm = dict(generated.get("product_map") or {})
    for prod, cat in new_pm.items():
        if prod not in old_pm:
            old_pm[prod] = cat                      # genuinely new product
        elif old_pm[prod] != cat:
            notes.append(f"product '{prod}' derived={cat} kept={old_pm[prod]}")
    if old_pm:
        out["product_map"] = old_pm

    if notes:
        out["_note"] = "; ".join(notes)
    return out, notes


# ---------------------------------------------------------------------- main
def review_for_promotion(generated, shipped):
    """Flag anything that should not reach shipped content.

    The output is schema vocabulary only -- no field values are ever written.
    The residual risk is NAMING: a customer's in-house data source produces a
    ds_key derived from whatever they called it, and a custom product string
    can carry an internal system or business-unit name. Those are fine in a
    tenant-local map (customers need automation on their own detections) but
    must not be committed to the framework.

    This does not block; it surfaces. Use --allowlist to control promotion.
    """
    flags = []
    for key, entry in sorted(generated.items()):
        if key in shipped:
            continue                      # already framework-known
        reasons = []
        if entry.get("confidence") in ("low", "weak", "none"):
            reasons.append(f"confidence={entry.get('confidence')}")
        for prod in (entry.get("product_map") or {}):
            if prod not in {p for s in shipped.values()
                            for p in (s.get("product_map") or {})}:
                reasons.append(f"unrecognised product '{prod}'")
        reasons.append("not in shipped map — confirm this is a vendor source, "
                       "not a customer-specific one")
        flags.append((key, reasons))
    return flags


def bootstrap_from_captures(model, capture_paths, shipped, present_pct,
                            generic_frac, min_issues=10):
    """Expand the training corpus with REAL tenant signatures, labelled by the
    shipped contract.

    The repo corpus is 9 vendor packs with Identity/Network/Cloud at one each,
    so those categories have almost no discriminative vocabulary and every
    source in them scores 1-5 and falls to `weak`. But the shipped map already
    holds 36 hand-authored labels, and captures hold real field signatures for
    those same sources. Pairing them gives the thin categories a real corpus.

    EXACT ds_key matches only. Fuzzy matching was tested and is unsafe:
    ds_armis_security_activities fuzzy-matches ds_azure_activity (Workload) and
    ds_microsoft_windows matches ds_microsoft_defender_identity (Identity) --
    both wrong. A wrong label does not merely fail to classify, it corrupts the
    corpus for every future run.

    Sources below `min_issues` are skipped: a signature built from 1-2 issues
    is noise at any present_pct threshold.
    """
    added, skipped, unlabelled = [], [], []
    for path in capture_paths:
        if not os.path.isfile(path):
            sys.exit(f"--bootstrap capture not found: {path}")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        # Fold analytics rows (Fusion) into their vendor sibling, exactly as
        # classification does. Skipping them outright discards the label of any
        # source whose ONLY row is Fusion -- ds_msft_azure_ad is in the shipped
        # map as Identity and was being dropped for this reason.
        merged = {}
        for src in doc.get("sources", []):
            key = ds_key(src["ds_tag"])
            slot = merged.setdefault(key, {"issues": 0, "fields": Counter(),
                                           "vendor_rows": 0})
            slot["issues"] += src.get("issues", 0)
            for f, c in (src.get("fields") or {}).items():
                slot["fields"][f] += c
            if not is_analytics_product(src.get("product", "-")):
                slot["vendor_rows"] += 1

        for key, slot in merged.items():
            n = slot["issues"]
            label = (shipped.get(key) or {}).get("category")
            if not label:
                unlabelled.append((key, n))
                continue
            if n < min_issues:
                skipped.append((key, n, label))
                continue
            sig = {f for f, c in slot["fields"].items()
                   if n and c / n * 100 >= present_pct}
            if not sig:
                continue
            added.append((key, n, label, sig))

    if not added:
        return model, added, skipped, unlabelled

    # Refit over packs + bootstrap docs together, so the generic core is
    # recomputed across the whole corpus rather than inherited from the packs.
    docs = list(model["docs"]) + [(sig, label) for _, _, label, sig in added]
    return (fit(docs, generic_frac), added, skipped, unlabelled)


def apply_bootstrap(args, model):
    """Fold category definitions and labelled tenant signatures into the corpus."""
    if not args.no_normalize_map:
        nm_docs, nm_path = normalize_map_docs(args.repo, args.normalize_map)
        if nm_docs:
            model = fit(list(model["docs"]) + nm_docs, args.generic_frac)
            print(f"  +normalize map: {len(nm_docs)} category definitions "
                  f"({os.path.basename(nm_path)}) -> {dict(model['ncat'])}")
        else:
            print("  !! NormalizeMap not found — categories without vendor packs "
                  "cannot be classified")
    if args.no_bootstrap or not args.bootstrap:
        return model
    shipped, _ = load_shipped_map(args.repo, args.shipped_map)
    if not shipped:
        print("  !! --bootstrap: shipped map not found, skipping")
        return model
    before = dict(model["ncat"])
    model, added, skipped, unlabelled = bootstrap_from_captures(
        model, args.bootstrap, shipped, args.present_pct,
        args.generic_frac, args.bootstrap_min_issues)
    print(f"\n=== CORPUS BOOTSTRAP ===")
    print(f"  labelled from shipped map (exact ds_key match only): {len(added)}")
    for key, n, label, sig in sorted(added, key=lambda x: -x[1]):
        print(f"    +{label:<10} {key:<44} {n:>5} issues, {len(sig)} fields")
    if skipped:
        print(f"  skipped, under {args.bootstrap_min_issues} issues: "
              f"{', '.join(k for k, _, _ in skipped[:8])}")
    if unlabelled:
        uniq = sorted({k for k, _ in unlabelled})
        print(f"  no shipped label ({len(uniq)}): {', '.join(uniq[:8])}")
    after = dict(model["ncat"])
    delta = {c: f"{before.get(c,0)}->{after.get(c,0)}"
             for c in sorted(after) if before.get(c, 0) != after.get(c, 0)}
    print(f"  corpus now: {after}  ({len(model['generic'])} generic suppressed)")
    if delta:
        print(f"  changed   : {delta}")
    return model


# Vendor aliases, so msft/microsoft and paloaltonetworks/panw are not treated
# as different vendors when checking whether a vendor's category is ambiguous.
VENDOR_ALIASES = {
    "msft": "microsoft",
    "panw": "paloaltonetworks",
    "checkpoint": "check_point",
    "crowdstrike": "crowdstrike",
}


def vendor_of(key):
    """Leading vendor token of a ds_key. ds_okta_sso -> okta."""
    raw = key[3:] if key.startswith("ds_") else key
    parts = [p for p in raw.split("_") if p]
    if not parts:
        return ""
    # try progressively longer prefixes so multi-word vendors resolve
    for n in (2, 1):
        cand = "_".join(parts[:n])
        if cand in VENDOR_ALIASES:
            return VENDOR_ALIASES[cand]
        if cand in ("check_point",):
            return cand
    return VENDOR_ALIASES.get(parts[0], parts[0])


def vendor_categories(shipped):
    """vendor token -> set of categories it appears with in the shipped map."""
    out = defaultdict(set)
    for key, entry in shipped.items():
        if isinstance(entry, dict) and entry.get("category"):
            out[vendor_of(key)].add(entry["category"])
    return out


def seed_by_vendor(key, shipped, vend_cats):
    """Recover a category for a source whose ds_key is not in the shipped map.

    The shipped map is authored against whatever DS: values its author saw;
    a tenant may emit a different spelling for the same product (shipped
    ds_okta_systemlog vs tenant ds_okta_sso). Exact matching loses those.

    Matching on the VENDOR token recovers them, but ONLY where that vendor
    maps to exactly one category in the shipped map. Okta appears once, as
    Identity -- unambiguous. Microsoft appears as Endpoint, Identity AND Email,
    so a Microsoft source cannot be resolved this way and is left to the
    classifier.

    This is deliberately not fuzzy string matching, which was tested and is
    unsafe: ds_armis_security_activities fuzzy-matches ds_azure_activity.
    """
    vend = vendor_of(key)
    cats = vend_cats.get(vend) or set()
    if len(cats) == 1:
        return next(iter(cats)), vend
    return None, vend


def normalize_map_docs(repo, path=None):
    """Training documents from SOCFrameworkNormalizeMap_NIST_IR.

    This is the answer to bringing on a NEW category. The NormalizeMap already
    declares, per category, which issue.* fields that category consumes -- an
    authored, framework-owned definition of what the category looks like. So a
    new category becomes classifiable the moment its normalization contract
    exists, with no tenant data and no vendor packs required.

    Measured effect on brumxdr: Check Point (was Email), Zscaler (was Endpoint)
    and Wiz (was Email) all corrected to Network purely from these definitions.
    """
    candidates = [path] if path else [
        os.path.join(repo, "Packs", "soc-framework-nist-ir", "Lists",
                     "SOCFrameworkNormalizeMap_NIST_IR",
                     "SOCFrameworkNormalizeMap_NIST_IR_data.json"),
        os.path.join(repo, "schemas", "soc-framework", "soc-framework-nist-ir",
                     "SOCFrameworkNormalizeMap_NIST_IR.yaml"),
    ]
    doc = None
    used = None
    for cand in candidates:
        if cand and os.path.isfile(cand):
            try:
                with open(cand, encoding="utf-8") as fh:
                    doc = (json.load(fh) if cand.endswith(".json")
                           else yaml.safe_load(fh))
                used = cand
                break
            except Exception:
                continue
    if not doc:
        return [], None

    out = []
    for cat, blk in (doc.get("categories") or {}).items():
        label = TAG_TO_CATEGORY.get(str(cat).lower())
        if not label or not isinstance(blk, dict):
            continue
        fields = {base_issue_field(m.get("issue_field"))
                  for m in (blk.get("mappings") or [])
                  if isinstance(m, dict) and m.get("issue_field")}
        fields = {f for f in fields if f}
        if fields:
            out.append((fields, label))
    return out, used


def base_issue_field(value):
    return re.sub(r"\.?\[\d+\]$", "", str(value)).strip()


def load_actions(repo, path=None):
    """Integrations configured in SOCFrameworkActions_V3."""
    cand = path or os.path.join(
        repo, "Packs", "soc-optimization-unified", "Lists",
        "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")
    if not os.path.isfile(cand):
        return set(), None
    try:
        with open(cand, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception:
        return set(), None
    ints = set()
    for spec in doc.values():
        if isinstance(spec, dict) and isinstance(spec.get("responses"), dict):
            ints |= set(spec["responses"].keys())
    return ints, cand


def shipped_responders(shipped):
    """Integration usage in the shipped map, globally and per category.

    Per-category matters: Microsoft has five integrations in the actions list,
    and which one is right depends on what you need to DO. Defender ATP for an
    endpoint, Microsoft Graph User for an identity. Ranking globally picks the
    most common overall, which is wrong for the minority categories.
    """
    used = Counter()
    per_cat = defaultdict(Counter)
    for entry in shipped.values():
        if not isinstance(entry, dict):
            continue
        if entry.get("response"):
            used[entry["response"]] += 1
        for cat, val in (entry.get("responses") or {}).items():
            used[val] += 1
            per_cat[str(cat).lower()][val] += 1
    return used, per_cat


def responder_for_vendor(key, integrations, used, per_cat=None, category=None):
    """Pick the response integration for a source, from what SOCFW already has.

    Matches the ds_key's vendor token against integration names configured in
    SOCFrameworkActions_V3 -- i.e. only integrations the framework can actually
    drive. Where a vendor has several (Okta IAM / Okta v2), the one the shipped
    map already uses wins, so the tool converges on existing convention rather
    than inventing a second one.

    Returns (integration, note). A None integration means SOCFW has no
    responder for that vendor at all -- true today for Check Point and Zscaler
    -- which is a framework coverage gap, not something to guess at.
    """
    vend = re.sub(r"[^a-z0-9]", "", vendor_of(key))
    if not vend:
        return None, "no vendor token"
    matches = [i for i in integrations
               if vend in re.sub(r"[^a-z0-9]", "", i.lower())]
    if not matches:
        return None, f"no integration for vendor '{vendor_of(key)}' in SOCFrameworkActions"
    if len(matches) == 1:
        return matches[0], None
    cat_used = (per_cat or {}).get(str(category or "").lower(), Counter())
    ranked = sorted(matches,
                    key=lambda i: (-cat_used.get(i, 0), -used.get(i, 0), len(i)))
    top = ranked[0]
    if cat_used.get(top, 0) > 0:
        return top, None
    if used.get(top, 0) > 0:
        return top, f"ambiguous ({len(matches)}), no {category} precedent"
    return top, f"ambiguous ({len(matches)} integrations), unverified"


def safety_check(new_entries, shipped):
    """Classify the change against the shipped map BEFORE anything is written.

    This runs at generation time rather than after emit, because by the time a
    bad value reaches _data.json it is one `git add` from production. The map
    drives routing and response: Foundation feeds `response` to
    SOCCommandWrapper, so a wrong or invented value there is executed, and
    `category` decides which lifecycle an alert enters.

    Additive change is safe -- a new source, or a field an entry did not have.
    Anything that REMOVES or REPLACES what is shipped is not, and has to be
    asked for explicitly.
    """
    safe, destructive = [], []

    for key in sorted(set(shipped) - set(new_entries)):
        if isinstance(shipped[key], dict) and key.startswith("ds_"):
            destructive.append(f"REMOVED source {key}")

    for key in sorted(set(new_entries) - set(shipped)):
        safe.append(f"added source {key}")

    for key in sorted(set(new_entries) & set(shipped)):
        old, new = shipped[key], new_entries[key]
        if not isinstance(old, dict) or not isinstance(new, dict):
            continue
        for field in sorted(set(old) | set(new)):
            o, n = old.get(field), new.get(field)
            if o == n:
                continue
            if o is None:
                safe.append(f"{key}.{field} added")
            elif n is None:
                destructive.append(f"{key}.{field} REMOVED (was {o!r})")
            elif field == "confidence":
                safe.append(f"{key}.confidence {o!r} -> {n!r}")
            elif field == "product_map" and isinstance(o, dict) and isinstance(n, dict):
                lost = [p for p in o if p not in n or n[p] != o[p]]
                if lost:
                    destructive.append(f"{key}.product_map CHANGED for {lost}")
                else:
                    safe.append(f"{key}.product_map extended")
            elif field == "responses" and isinstance(o, dict) and isinstance(n, dict):
                lost = [c for c in o if c not in n or n[c] != o[c]]
                if lost:
                    destructive.append(f"{key}.responses CHANGED for {lost}")
                else:
                    safe.append(f"{key}.responses extended")
            else:
                destructive.append(f"{key}.{field} CHANGED {o!r} -> {n!r}")
    return safe, destructive


def main():
    ap = argparse.ArgumentParser(
        description="Build a tenant SOCProductCategoryMap from live issue.* data.")
    ap.add_argument("--env", default=".env",
                    help="path to the .env holding this tenant's credentials")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    help="secops-framework checkout, used as the training corpus")
    ap.add_argument("--out", default="SOCProductCategoryMap_V3.yaml",
                    help="schema YAML; feed to generate_soc_framework_content.py emit")
    ap.add_argument("--pages", type=int, default=8, help="pages of issues to sample")
    ap.add_argument("--size", type=int, default=100, help="issues per page (max 100)")
    ap.add_argument("--present-pct", type=float, default=50.0,
                    help="field counts toward the signature at >= this %% populated")
    ap.add_argument("--generic-frac", type=float, default=0.5,
                    help="suppress fields present in >= this fraction of packs")
    ap.add_argument("--floor", type=float, default=10.0,
                    help="minimum score to emit a category; below this = review")
    ap.add_argument("--allowlist", help="file of ds_* keys SOCFW engineers for")
    ap.add_argument("--query", default=None,
                    help="issue search filter, e.g. 'sourceBrand:CORRELATION'. "
                         "Use this on high-volume tenants where posture/vuln "
                         "alerts would otherwise crowd out detection sources.")
    ap.add_argument("--detections-only", action="store_true",
                    help="shorthand for --query sourceBrand:CORRELATION")
    ap.add_argument("--merge",
                    help="explicit file to merge into. Defaults to --out when "
                         "that file already exists, so hand edits are never "
                         "silently overwritten.")
    ap.add_argument("--allow-destructive", action="store_true",
                    help="permit writes that remove or replace values already in "
                         "the shipped map. Blocked by default.")
    ap.add_argument("--overwrite", action="store_true",
                    help="DESTRUCTIVE. Ignore any existing --out and rebuild "
                         "from scratch, discarding hand-edited fields.")
    ap.add_argument("--shipped-map",
                    help="path to SOCProductCategoryMap_V3_data.json; defaults "
                         "to the copy in --repo. Seeds type/response/own-category "
                         "responder for sources the framework already ships.")
    ap.add_argument("--no-seed", action="store_true",
                    help="do not seed from the shipped contract")
    ap.add_argument("--capture", metavar="PATH",
                    help="PHASE 1: connect, sanitise, write the capture to PATH "
                         "and STOP. Nothing is analysed. Inspect the file, then "
                         "run again with --from-capture.")
    ap.add_argument("--from-capture", nargs="+", metavar="PATH",
                    help="PHASE 2: analyse reviewed capture files offline. Does "
                         "not connect to any tenant. Pass SEVERAL captures to "
                         "build one consolidated map across production tenants: "
                         "signatures and issue counts for the same ds_key are "
                         "summed, so a source thinly sampled on one tenant is "
                         "still classified well if another saw it properly.")
    ap.add_argument("--actions-map", metavar="PATH",
                    help="explicit SOCFrameworkActions_V3_data.json path; used to "
                         "derive `response` from integrations SOCFW can actually drive")
    ap.add_argument("--no-normalize-map", action="store_true",
                    help="do not seed the corpus from the NormalizeMap category "
                         "definitions. On by default: it is how a category with "
                         "no vendor packs becomes classifiable at all.")
    ap.add_argument("--normalize-map", metavar="PATH",
                    help="explicit SOCFrameworkNormalizeMap path")
    ap.add_argument("--no-bootstrap", action="store_true",
                    help="do not learn from the captures being analysed. By "
                         "default every --from-capture file also trains the "
                         "corpus (labelled by the shipped map, exact ds_key "
                         "matches only). That is what lifts Network / Identity "
                         "/ Cloud out of `weak`.")
    ap.add_argument("--bootstrap-min-issues", type=int, default=10,
                    help="ignore bootstrap sources with fewer issues than this; "
                         "a signature from 1-2 issues is noise (default 10)")
    ap.add_argument("--allow-category-change", action="store_true",
                    help="apply a derived category that disagrees with the "
                         "shipped map or a prior file. Default is to REPORT the "
                         "disagreement and keep the existing value: base category "
                         "comes from the highest-volume product in the sample, and "
                         "sampling skew can flip a source (15 Falcon Identity vs "
                         "2 Falcon reads CrowdStrike as Identity).")
    ap.add_argument("--no-differential", action="store_true",
                    help="score multi-product sources on their absolute field "
                         "signature instead of subtracting the shared vendor "
                         "core. Absolute scoring mislabels minority products.")
    ap.add_argument("--include-unmapped", action="store_true",
                    help="emit below-floor sources too, marked for review")
    args = ap.parse_args()

    query = args.query
    if args.detections_only and not query:
        query = "sourceBrand:CORRELATION"
    # Training on the captures being analysed is the normal case, so it is the
    # default rather than a second flag repeating the same file list.
    args.bootstrap = [] if args.no_bootstrap else list(args.from_capture or [])

    # ---- PHASE 2: offline analysis of a reviewed capture. No tenant contact.
    if args.from_capture:
        populated, totals = defaultdict(Counter), Counter()
        scanned = 0
        origins = []
        for path in args.from_capture:
            if not os.path.isfile(path):
                sys.exit(f"capture not found: {path}")
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            p2, t2, s2 = capture_from_dict(doc)
            # Same ds_key/product across tenants is the same source: sum it.
            for group, cnt in t2.items():
                totals[group] += cnt
                populated[group].update(p2[group])
            scanned += s2
            origins.append((os.path.basename(path), doc.get("tenant"), s2,
                            len(doc.get("sources") or [])))
            if doc.get("_partial"):
                print(f"  !! {os.path.basename(path)} is a PARTIAL capture "
                      f"(paging failed at page {doc['_partial'].get('failed_at_page')})")
        print(f"captures : {len(origins)}  (offline — no tenant connection)")
        for name, tenant_url, n, nsrc in origins:
            print(f"   {name:<34} {n:>6} issues, {nsrc:>3} sources   {tenant_url}")
        model = build_corpus(args.repo, args.generic_frac)
        print(f"corpus   : {model['packs']} packs, {dict(model['ncat'])}, "
              f"{len(model['generic'])} generic fields suppressed")
        print(f"sampled  : {scanned} issues, {len(totals)} source/product pairs")
        model = apply_bootstrap(args, model)
        print()
        return run_analysis(args, model, populated, totals, query)

    creds = load_env(args.env)
    tenant = Tenant(creds)
    print(f"env      : {args.env}")
    print(f"tenant   : {tenant.base}")

    model = build_corpus(args.repo, args.generic_frac)
    print(f"corpus   : {model['packs']} packs, "
          f"{dict(model['ncat'])}, {len(model['generic'])} generic fields suppressed")

    query = args.query
    if args.detections_only and not query:
        query = "sourceBrand:CORRELATION"
    if query:
        print(f"filter   : {query}")

    try:
        populated, totals, scanned = capture(
            tenant, args.pages, args.size, query)
    except RuntimeError as exc:
        sys.exit(f"tenant error: {exc}")
    print(f"sampled  : {scanned} issues, {len(totals)} source/product pairs\n")

    # ---- PHASE 1 STOP: write the sanitised capture and analyse nothing.
    if args.capture:
        if scanned == 0:
            sys.exit(
                "\nNO ISSUES RETRIEVED — refusing to write an empty capture.\n"
                "  An empty file is worse than no file: it can be analysed to\n"
                "  nothing, or overwrite a good capture. Nothing was written.\n"
                f"  See the page 0 failure above for what to try next.")
        doc = capture_to_dict(populated, totals, scanned, tenant.base, query)
        if getattr(tenant, "failed_page", None):
            doc["_partial"] = {
                "failed_at_page": tenant.failed_page,
                "error": tenant.failure,
                "note": "Sample is truncated. Sources appearing only in later "
                        "pages are missing from this capture.",
            }
        parent = os.path.dirname(os.path.abspath(args.capture))
        os.makedirs(parent, exist_ok=True)
        tmp = args.capture + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        os.replace(tmp, args.capture)
        nfields = sum(len(s["fields"]) for s in doc["sources"])
        print(f"\n=== CAPTURE WRITTEN — nothing analysed ===")
        print(f"  {args.capture}")
        print(f"  {len(doc['sources'])} sources, {nfields} field names, "
              f"0 field values")
        if "_partial" in doc:
            print(f"  PARTIAL — paging stopped at page {tenant.failed_page}; "
                  f"later sources may be missing.")
        print(f"\n  Review the file, then analyse offline with:")
        print(f"    --from-capture {args.capture} --out <schema.yaml>")
        return

    model = apply_bootstrap(args, model)
    return run_analysis(args, model, populated, totals, query)


def run_analysis(args, model, populated, totals, query):
    """Classification and emit. Operates only on sanitised capture data --
    never touches a tenant."""

    allow = load_allowlist(args.allowlist)
    generated, review = {}, []
    by_ds = defaultdict(dict)

    # Pre-group by ds_key so multi-product sources can be scored differentially.
    # A vendor's minority products carry the parent's field vocabulary
    # (CrowdStrike identity alerts still ship agentid/initiatorpid), so the
    # ABSOLUTE signature ranks them by the parent's category. Subtracting the
    # per-source shared core leaves only what distinguishes the product --
    # measured on brumxdr, this flips Falcon Identity Protection from
    # Endpoint 5.64 / Identity 2.2 (wrong) to Identity 2.2 / Endpoint 1.6.
    groups_by_ds = defaultdict(list)
    for group in totals:
        groups_by_ds[ds_key(group[0])].append(group)

    signatures = {}
    for group in totals:
        n = totals[group]
        signatures[group] = {f for f, c in populated[group].items()
                             if c / n * 100 >= args.present_pct}

    # Fusion (XSIAM native analytics) is a detection engine, not a product.
    # Fold it into the source's vendor signature so it neither splits the
    # category nor drives differential scoring, but record where it appears.
    analytics = defaultdict(lambda: {"issues": 0, "products": set()})
    for key, groups in list(groups_by_ds.items()):
        engine = [g for g in groups if is_analytics_product(g[1])]
        vendor = [g for g in groups if not is_analytics_product(g[1])]
        for g in engine:
            analytics[key]["issues"] += totals[g]
            analytics[key]["products"].add(g[1])
        if engine and vendor:
            # merge the engine signature into every vendor row for this source
            extra = set().union(*(signatures[g] for g in engine))
            for g in vendor:
                signatures[g] = signatures[g] | extra
            groups_by_ds[key] = vendor
        elif engine and not vendor:
            # analytics-only source: keep it, it is the only evidence there is
            groups_by_ds[key] = engine

    scored_groups = {g for gs in groups_by_ds.values() for g in gs}

    # Domain generic core. The training corpus is repo alert_fields; the things
    # being classified are runtime issue.* signatures. Those are different
    # feature spaces -- tenant signatures carry ~40 runtime plumbing fields
    # (_device_id, alert_domain, hostip...) that no repo pack has, so they never
    # reach the corpus generic threshold. If bootstrap then adds tenant docs,
    # that plumbing concentrates in whichever category was bootstrapped and
    # every source on the tenant scores for it. Measured: bootstrapping two
    # Check Point sources made all 28 sources Network, Proofpoint included.
    #
    # So suppress fields common across the POPULATION being classified as well.
    # A field on most sources of a tenant cannot discriminate between them.
    if len(scored_groups) >= 4:
        freq = Counter()
        for g in scored_groups:
            for f in signatures[g]:
                freq[f] += 1
        domain_generic = {f for f, c in freq.items()
                          if c / len(scored_groups) >= args.generic_frac}
        new_generic = domain_generic - model["generic"]
        if new_generic:
            model = dict(model)
            model["generic"] = model["generic"] | domain_generic
            print(f"  domain core: {len(new_generic)} extra fields common across "
                  f"{len(scored_groups)} tenant sources suppressed\n")

    vendor_core = {}
    for key, groups in groups_by_ds.items():
        if len(groups) > 1 and not args.no_differential:
            core = set.intersection(*(signatures[g] for g in groups))
            vendor_core[key] = core

    for group in sorted(scored_groups, key=lambda g: -totals[g]):
        ds_tag, product = group
        n = totals[group]
        key = ds_key(ds_tag)
        signature = signatures[group]
        core = vendor_core.get(key)
        scoring_sig = signature
        used_diff = False
        if core:
            reduced = signature - core
            # Never let differential scoring erase a signature. If two
            # "products" share everything they are not really different
            # products, and the absolute signature is the honest input.
            if reduced:
                scoring_sig = reduced
                used_diff = True
        best, scores, evidence = classify(scoring_sig, model)
        conf = confidence_of(scores, best, args.floor)

        row = {"ds_key": key, "ds_tag": ds_tag, "product": product,
               "issues_sampled": n, "signature_size": len(signature),
               "differential": used_diff,
               "category": best, "confidence": conf,
               "scores": scores, "evidence": evidence}

        if allow is not None and key not in allow:
            row["skipped"] = "not in allowlist"
            review.append(row)
            continue
        if conf in ("none", "weak"):
            reason = ("no category evidence — not an IR data source"
                      if conf == "none"
                      else f"score {scores.get(best, 0)} below floor {args.floor}")
            row["skipped"] = reason
            row["verdict"] = conf
            review.append(row)
            if not args.include_unmapped:
                continue
        by_ds[key][product] = row

    # assemble map entries, adding product_map where a source spans categories
    for key, products in by_ds.items():
        cats = {r["category"] for r in products.values() if r["category"]}
        primary = Counter({p: r["issues_sampled"]
                           for p, r in products.items()}).most_common(1)[0][0]
        base_cat = products[primary]["category"]
        # responses = the categories this source can produce, plus the
        # framework's standing capabilities (identity + indicator).
        # Own category stays TODO (that's the ingesting vendor's integration);
        # every other category gets the mined house default.
        own = base_cat.lower() if base_cat else None
        resp_keys = sorted({c.lower() for c in cats} | set(ALWAYS_RESPOND))
        responses = {}
        for k in resp_keys:
            responses[k] = (RESPONSE_PLACEHOLDER if k == own
                            else DEFAULT_RESPONDERS.get(k, RESPONSE_PLACEHOLDER))
        entry = {
            "category": base_cat,
            "confidence": products[primary]["confidence"],
            "response": RESPONSE_PLACEHOLDER,
            "responses": responses,
        }
        if len(products) > 1 or len(cats) > 1:
            entry["product_map"] = {p: r["category"] for p, r in sorted(products.items())
                                    if r["category"]}
        generated[key] = entry

    # -------------------------------- seed human-owned fields from shipped map
    shipped, shipped_path = load_shipped_map(args.repo, args.shipped_map)
    if shipped and not args.no_seed:
        vend_cats = vendor_categories(shipped)
        print(f"\n=== SEEDED FROM SHIPPED CONTRACT ===")
        print(f"  {os.path.basename(shipped_path)} ({len(shipped)} known sources)")
        any_seed = False
        for key, entry in generated.items():
            if key not in shipped:
                # Not an exact key match. The shipped map may still know this
                # vendor under a different DS: spelling (ds_okta_systemlog vs
                # ds_okta_sso). Adopt it only where the vendor is unambiguous.
                vcat, vend = seed_by_vendor(key, shipped, vend_cats)
                if vcat and vcat != entry.get("category"):
                    print(f"  {key}: category {entry.get('category')} -> {vcat} "
                          f"(vendor '{vend}' is {vcat} in shipped map)")
                    entry["category"] = vcat
                    entry["confidence"] = "vendor-match"
                    any_seed = True
                elif vcat:
                    entry["confidence"] = "vendor-match"
                continue
            ship = shipped[key]
            if ship.get("category") and ship["category"] != entry.get("category"):
                if args.allow_category_change:
                    print(f"  !! {key}: CATEGORY CHANGED "
                          f"{ship['category']} -> {entry.get('category')} "
                          f"(--allow-category-change)")
                else:
                    print(f"  !! {key}: CATEGORY DISAGREES — shipped="
                          f"{ship['category']} derived={entry.get('category')} "
                          f"— keeping shipped")
                    entry["category"] = ship["category"]
                    entry.setdefault("_conflicts", []).append(
                        f"category: derived={entry.get('category')} "
                        f"shipped={ship['category']}")
            filled = seed_from_shipped(entry, ship)
            if filled:
                any_seed = True
                print(f"  {key}: filled {', '.join(filled)}")
            for conflict in entry.pop("_conflicts", []):
                print(f"  !! {key}: PRODUCT CONFLICT (shipped kept) — {conflict}")
        if not any_seed:
            print("  nothing seeded (no matching sources, or all fields already set)")

    integrations, actions_path = load_actions(args.repo, args.actions_map)
    used_resp, used_by_cat = shipped_responders(shipped or {})
    if integrations:
        print(f"\n=== RESPONDERS FROM SOCFrameworkActions_V3 ===")
        print(f"  {len(integrations)} integrations configured")
        gaps = []
        for key, entry in generated.items():
            integ, note = responder_for_vendor(
                key, integrations, used_resp, used_by_cat, entry.get('category'))
            own = (entry.get("category") or "").lower()

            # Rebuild the responses key set against the FINAL category. Category
            # can change after scoring (vendor-match, shipped-map seeding), which
            # would otherwise leave a stale key -- an Okta source classified
            # Network then corrected to Identity kept a `network:` responder.
            prev = entry.get("responses") or {}
            wanted = sorted({own} | set(ALWAYS_RESPOND)) if own else sorted(ALWAYS_RESPOND)
            resp = {}
            for cat in wanted:
                val = prev.get(cat)
                if val in (None, "", RESPONSE_PLACEHOLDER):
                    val = DEFAULT_RESPONDERS.get(cat, RESPONSE_PLACEHOLDER)
                resp[cat] = val
            # the vendor's own integration wins for its own category
            if integ and own:
                resp[own] = integ
            entry["responses"] = resp

            if integ:
                if entry.get("response") in (None, "", RESPONSE_PLACEHOLDER):
                    entry["response"] = integ
                print(f"  {key:<44} -> {integ}" + (f"   [{note}]" if note else ""))
            else:
                gaps.append((key, note))
        if gaps:
            print(f"\n  NO RESPONDER CONFIGURED ({len(gaps)}) — SOCFW cannot action these:")
            for key, note in gaps:
                print(f"    {key:<44} {note}")

    # ------------------------------------------------------------- reporting
    print(f"{'ds_key / product':<58} {'n':>5} {'category':<10} {'conf':<8} score")
    print("-" * 100)
    for key, products in sorted(by_ds.items()):
        for product, row in sorted(products.items()):
            # Report the FINAL entry, not the pre-seeding classifier output --
            # vendor-match seeding can correct the category after scoring.
            final = generated.get(key, {})
            cat = final.get("category", row["category"])
            conf = final.get("confidence", row["confidence"])
            top = row["scores"].get(row["category"], 0) if row["category"] else 0
            mark = " diff" if row.get("differential") else ""
            if cat != row["category"]:
                mark += f" (was {row['category']})"
            print(f"{(key + ' / ' + product)[:57]:<58} {row['issues_sampled']:>5} "
                  f"{str(cat):<10} {str(conf):<13} {top}{mark}")

    if analytics:
        print(f"\n=== XSIAM NATIVE ANALYTICS COVERAGE ({len(analytics)}) ===")
        print("  Fusion firing on top of these sources — folded into the vendor")
        print("  signature, not treated as a separate product or category.")
        for key in sorted(analytics, key=lambda k: -analytics[k]["issues"]):
            info = analytics[key]
            print(f"  {info['issues']:>6} issues  {key:<44} "
                  f"{', '.join(sorted(info['products']))}")

    if review:
        not_ir = [r for r in review if r.get("verdict") == "none"]
        weak = [r for r in review if r.get("verdict") == "weak"]
        blocked = [r for r in review if "verdict" not in r]
        if not_ir:
            print(f"\n=== NOT AN IR DATA SOURCE ({len(not_ir)}) — ignore ===")
            for row in not_ir:
                print(f"  {row['ds_key']:<44} no category evidence "
                      f"({row['issues_sampled']} issues)")
        if weak:
            print(f"\n=== WEAK EVIDENCE ({len(weak)}) — needs a human look ===")
            print("  Real signal below the floor. May be a category the corpus")
            print("  under-represents (Identity/Network/Cloud have 1 pack each).")
            for row in weak:
                top = sorted(row["scores"].items(), key=lambda x: -x[1])[:3]
                print(f"  {row['ds_key']:<44} {', '.join(f'{k}:{v}' for k, v in top)}")
        if blocked:
            print(f"\n=== FILTERED BY ALLOWLIST ({len(blocked)}) ===")
            for row in blocked:
                print(f"  {row['ds_key']}")

    # ------------------------------------------------- merge with prior/manual
    # Merge is the DEFAULT whenever the target already exists. Overwriting a
    # curated map is destructive and has to be asked for explicitly.
    prior_header = None
    merge_path = args.merge
    if not merge_path and not args.overwrite and os.path.isfile(args.out):
        merge_path = args.out
        print(f"\n(merging into existing {args.out}; "
              f"pass --overwrite to rebuild from scratch)")
    if args.overwrite and os.path.isfile(args.out):
        print(f"\n!! --overwrite: discarding hand-edited fields in {args.out}")

    if merge_path:
        if not os.path.isfile(merge_path):
            sys.exit(f"--merge file not found: {merge_path}")
        with open(merge_path, encoding="utf-8") as fh:
            prior_header, prior = read_schema_yaml(merge_path)
        kept, added, changed = 0, 0, []
        for key, entry in list(generated.items()):
            if key in prior:
                generated[key], notes = merge_entry(entry, prior[key],
                                                    args.allow_category_change)
                kept += 1
                if notes:
                    changed.append((key, notes))
            else:
                added += 1
        untouched = 0
        for key, entry in prior.items():
            if key not in generated:
                generated[key] = entry     # never drop a source we didn't observe
                untouched += 1
        print(f"\n=== MERGE with {merge_path} ===")
        print(f"  updated in place : {kept}")
        print(f"  newly discovered : {added}")
        print(f"  carried forward  : {untouched}  (not seen this run, preserved)")
        if changed:
            print("  CHANGES NEEDING REVIEW:")
            for key, notes in changed:
                for note in notes:
                    print(f"     {key}: {note}")

    # Header survives a merge so hand edits to the description aren't lost.
    # NOTE: `lifecycle` is deliberately omitted. The emitter treats it as list
    # payload (unlike pack/list_name/description, which it strips), so setting
    # it would leak a `lifecycle` key into the shipped _data.json that the
    # hand-maintained map does not have.
    header = {
        "pack": "soc-optimization-unified",
        "list_name": "SOCProductCategoryMap_V3",
        "description": ("Maps a data source (DS: tag) to its SOC Framework product "
                        "category, response engine, and per-category responders."),
    }
    header.update(prior_header or {})

    flags = review_for_promotion(generated, shipped or {})
    if flags:
        print(f"\n=== PROMOTION REVIEW ({len(flags)}) — check before committing ===")
        print("  Output holds no issue values, but source and product NAMES are")
        print("  tenant-derived. Confirm these are vendor sources, not customer ones.")
        for key, reasons in flags:
            print(f"  {key}")
            for reason in reasons:
                print(f"      - {reason}")

    # ---- SAFETY GATE: classify the change before writing anything.
    safe, destructive = safety_check(generated, shipped or {})
    print(f"\n=== SAFETY CHECK vs shipped map ===")
    print(f"  additive   : {len(safe)}")
    for line in safe[:12]:
        print(f"    + {line}")
    if len(safe) > 12:
        print(f"    ... and {len(safe) - 12} more")
    if destructive:
        print(f"  DESTRUCTIVE: {len(destructive)}")
        for line in destructive:
            print(f"    !! {line}")
        if not args.allow_destructive:
            sys.exit(
                f"\nREFUSING TO WRITE {args.out}\n"
                "  The changes above REMOVE or REPLACE shipped values. This map\n"
                "  drives routing and response -- Foundation feeds `response` to\n"
                "  SOCCommandWrapper, and `category` selects the lifecycle. A\n"
                "  tenant sample is not authority to overwrite shipped content.\n"
                "  Review each line, then re-run with --allow-destructive if\n"
                "  they are genuinely correct.")
        print("  --allow-destructive: applying anyway")
    else:
        print("  DESTRUCTIVE: none — change is purely additive")

    write_schema_yaml(args.out, header, generated)
    todos = sum(1 for e in generated.values()
                for v in [e.get("response"),
                          *(e.get("responses") or {}).values()]
                if v == RESPONSE_PLACEHOLDER)
    print(f"\nemitted {len(generated)} entries -> {args.out}")
    print(f"  next: generate_soc_framework_content.py emit --mapping {args.out} "
          f"--pack-root Packs/soc-optimization-unified")
    if todos:
        print(f"  {todos} field(s) still '{RESPONSE_PLACEHOLDER}' "
              f"— type, response, own-category responder.")
    else:
        print("  no fields need human input.")


if __name__ == "__main__":
    main()
