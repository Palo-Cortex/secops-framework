"""
SOCFWInferProductCategory
=========================
Runtime fallback for Foundation - Product Classification. When the issue's
DS: key has no entry in SOCProductCategoryMap_V3, the classification chain
leaves SOCFramework.Product.category empty and Foundation - Normalize
Artifacts falls through to the generic contract section. This script scores
the issue's own populated field names against the installed lifecycle's
normalization contract and writes the resulting category onto the SOCFramework
contract so the correct band is selected for that issue.

The shipped map is never modified. An inferred category is a bridge, not a
promotion: the record written under SOCFramework.Product.Inferred names the
key that is missing so the map can be corrected by hand.

CORPUS
  SOCFrameworkNormalizeMap_<LIFECYCLE> already declares, per category, the
  issue.* fields that category consumes. That authored definition is the
  training corpus — no tenant data, no vendor pack sampling, nothing to
  regenerate. A lifecycle becomes classifiable the moment its normalization
  contract is installed.

SCORING
  Fields carried by half or more of the category definitions are structural
  rather than discriminative and are suppressed. What remains is scored
  IDF-weighted per category. A score below the floor is real signal that is
  not separable, and abstains rather than guessing.
"""

CONSTANT_PACK_VERSION = '3.14.1'
demisto.debug(f'pack id = soc-optimization-unified, pack version = {CONSTANT_PACK_VERSION}')

import json
import math
import re
from collections import Counter, defaultdict

# Framework plumbing and vendor identity. Present on every issue regardless of
# category, so they carry no signal and would only add a constant to every score.
ALWAYS_IGNORE = {
    "tags", "family_tags", "_vendor", "_product", "vendor", "product",
    "sourcebrand", "sourceinstance", "dbotpredictionprobability",
    "dbotclosed", "dbotcurrentdirtyfields", "dbotmirrordirection",
    "dbotmirrorid", "dbotmirrorinstance", "dbotmirrorlastsync",
    "dbotmirrortags", "dbotdirtyfields",
}

# Categories are authored lowercase in the normalization contract and
# capitalised in the product map. The map is read for its casing only, so an
# inferred value is indistinguishable from a mapped one downstream.
CATEGORY_MAP_LIST = "SOCProductCategoryMap_V3"

EMPTY = (None, "", [], {}, "null")


def base_issue_field(value):
    """Contract rows may index an array source (user_name.[0]); the field is the same."""
    return re.sub(r"\.?\[\d+\]$", "", str(value)).strip()


def ds_key(tag):
    """DS: tag to the map key form, matching Foundation - Product Classification."""
    raw = tag[3:] if tag.startswith("DS:") else tag
    chars = list(raw)
    for i, char in enumerate(chars):
        if not char.isalnum() and 0 < i < len(chars) - 1:
            chars[i] = "_"
    return "ds_" + "".join(chars).lower()


def resolve_list_name(lifecycle, override):
    if override:
        return override
    return f"SOCFrameworkNormalizeMap_{lifecycle.upper()}"


def load_contract(list_name):
    res = demisto.executeCommand("getList", {"listName": list_name})
    if not res:
        raise ValueError(f"getList returned no result for {list_name}")

    contents = res[0].get("Contents")
    if not contents:
        raise ValueError(f"List {list_name} has no contents")

    if isinstance(contents, str):
        if "not found" in contents.lower():
            raise ValueError(f"List {list_name} not found on tenant")
        try:
            return json.loads(contents)
        except json.JSONDecodeError as e:
            raise ValueError(f"List {list_name} is not valid JSON: {e}")
    return contents


def canonical_casing():
    """Lowercase category to the casing the product map already uses.

    Read-only. A category the map has never routed has no entry here and keeps
    the casing the normalization contract authored it with.
    """
    casing = {}
    try:
        data = load_contract(CATEGORY_MAP_LIST)
    except Exception as e:  # noqa: BLE001 — casing is cosmetic, never fatal
        demisto.debug(f"SOCFWInferProductCategory: no casing source: {e}")
        return casing
    for entry in (data or {}).values():
        if not isinstance(entry, dict):
            continue
        values = [entry.get("category")]
        values += list((entry.get("product_map") or {}).values())
        for val in values:
            if val:
                casing[str(val).lower()] = str(val)
    return casing


def corpus_from_contract(data, casing=None):
    """One labelled document per category: the fields that category consumes."""
    casing = casing or {}
    docs = []
    for cat, block in (data.get("categories") or {}).items():
        if str(cat).lower() == "generic" or not isinstance(block, dict):
            continue
        fields = {base_issue_field(m.get("issue_field"))
                  for m in (block.get("mappings") or [])
                  if isinstance(m, dict) and m.get("issue_field")}
        fields = {f for f in fields if f}
        if fields:
            docs.append((fields, casing.get(str(cat).lower(), str(cat))))
    return docs


def fit(docs, generic_frac):
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
    return {"per_cat": per_cat, "docfreq": docfreq, "ncat": ncat, "generic": generic}


def classify(signature, model):
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
        evidence[category] = sorted(hits, key=lambda x: (-x[1], x[0]))[:6]
    if not scores:
        return None, {}, []
    best = max(scores, key=scores.get)
    return best, scores, evidence[best]


def confidence_of(scores, best, floor):
    if best is None or not scores:
        return "none"
    top = scores[best]
    if max(scores.values()) <= 0.0:
        return "none"
    rest = sorted((v for k, v in scores.items() if k != best), reverse=True)
    runner = rest[0] if rest else 0.0
    if top < floor:
        return "weak"
    margin = top / runner if runner > 0 else float("inf")
    if top >= floor * 2 and margin >= 3:
        return "high"
    if margin >= 1.5:
        return "medium"
    return "low"


def issue_signature(incident):
    """Populated field names on this issue. Values are read for emptiness only."""
    custom_fields = incident.get("CustomFields") or {}
    return {str(f) for f, v in custom_fields.items() if v not in EMPTY}


def issue_ds_key(incident):
    custom_fields = incident.get("CustomFields") or {}
    tags = []
    for key in ("tags", "family_tags"):
        val = custom_fields.get(key)
        if isinstance(val, list):
            tags += [str(x) for x in val]
        elif val:
            tags.append(str(val))
    tag = next((t for t in tags if t.startswith("DS:")), None)
    return ds_key(tag) if tag else ""


def main():
    args = demisto.args()
    lifecycle = args.get("lifecycle") or "nist_ir"
    list_name = resolve_list_name(lifecycle, args.get("list_name"))
    floor = float(args.get("floor") or 10)
    generic_frac = float(args.get("generic_frac") or 0.5)

    record = {
        "lifecycle": lifecycle,
        "list_name": list_name,
        "floor": floor,
        "applied": False,
    }

    try:
        incident = demisto.incident() or {}
        record["product_key"] = issue_ds_key(incident)

        docs = corpus_from_contract(load_contract(list_name), canonical_casing())
        if not docs:
            raise ValueError(f"List {list_name} declares no category mappings")

        signature = issue_signature(incident)
        best, scores, evidence = classify(signature, fit(docs, generic_frac))
        level = confidence_of(scores, best, floor)

        record.update({
            "category": best,
            "level": level,
            "scores": scores,
            "evidence": [{"field": f, "weight": w} for f, w in evidence],
            "fields_scored": len(signature),
        })

        if level in ("high", "medium", "low"):
            record["applied"] = True
            demisto.setContext("SOCFramework.Product.category", best)
            demisto.setContext("SOCFramework.Product.confidence", "inferred")
            readable = (
                f"### SOC Framework — product category inferred\n"
                f"- key: `{record['product_key']}` (not in SOCProductCategoryMap_V3)\n"
                f"- category: **{best}** ({level}, score {scores.get(best)})\n"
                f"- evidence: {', '.join(f for f, _ in evidence)}\n\n"
                f"_Add `{record['product_key']}` to SOCProductCategoryMap_V3 to route "
                f"this source without inference._"
            )
        else:
            readable = (
                f"### SOC Framework — product category not inferred\n"
                f"- key: `{record['product_key']}` (not in SOCProductCategoryMap_V3)\n"
                f"- best guess: {best} at {scores.get(best)}, below floor {floor}\n\n"
                f"_Category left empty; Foundation - Normalize Artifacts uses the "
                f"generic contract section._"
            )

        # setContext, not CommandResults outputs. SOCFramework.Product already
        # exists by this point, and an outputs_prefix write on an occupied path
        # appends a second array element instead of merging — which would split
        # key and category across elements and break the single-scalar contract.
        demisto.setContext("SOCFramework.Product.Inferred", record)
        return_results(CommandResults(readable_output=readable))

    except Exception as e:  # noqa: BLE001 — Upon Trigger contract requires broad catch
        # Degrade to the pre-existing behaviour: category stays empty and
        # normalization uses the generic section. Never break classification.
        record["error"] = f"{type(e).__name__}: {e}"
        demisto.error(f"SOCFWInferProductCategory degraded: {record['error']}")
        demisto.setContext("SOCFramework.Product.Inferred", record)
        return_results(CommandResults(readable_output=(
            f"### ⚠️ SOCFWInferProductCategory — degraded (continuing)\n"
            f"- list: `{list_name}`\n"
            f"- error: `{record['error']}`"
        )))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
