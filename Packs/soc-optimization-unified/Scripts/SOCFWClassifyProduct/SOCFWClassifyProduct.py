"""
SOCFWClassifyProduct
====================
Resolves SOCFramework.Product.* for an issue in one task. Foundation - Product
Classification used to do this as a chain of a dozen playbook tasks; each task
is a separate engine step, and on a busy tenant every step waits in the queue,
so the chain cost far more than the work it did. Same inputs, same outputs.

  key        issue DS: tag, lowercased, inner non-alphanumerics replaced with _
  category   product_map[issue._product] for the key, else the key's category,
             else inferred from the lifecycle contract (SOCFWInferProductCategory)
  type, confidence, response, responses
             straight from the key's SOCProductCategoryMap_V3 entry

Nothing is written when SOCProductCategoryMap_V3 is missing, matching the old
chain, which ended there.
"""
import json
import re

import demistomock as demisto
from CommonServerPython import *

MAP_LIST = "SOCProductCategoryMap_V3"
EMPTY = (None, "", [], {})


def as_list(value):
    """Script args arrive as a list, a JSON string, or a comma-joined string."""
    if value in EMPTY:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in EMPTY]
    text = str(value).strip()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(v) for v in parsed if v not in EMPTY]
        except json.JSONDecodeError:
            pass
    return [p.strip() for p in text.split(",") if p.strip()]


def product_key(tags):
    """DS: tags to the map key, as the old chain built it: every tag containing
    'DS:', lowercased, each non-alphanumeric that is not the first or last
    character replaced with _, then joined with no separator."""
    picked = [t for t in tags if "ds:" in t.lower()]
    return "".join(re.sub(r"(?<=.)[^A-Za-z0-9](?=.)", "_", t.lower()) for t in picked)


def load_map():
    res = demisto.executeCommand("getList", {"listName": MAP_LIST})
    entry = res[0] if res and isinstance(res[0], dict) else {}
    raw = entry.get("Contents")
    if not raw or entry.get("Type") == entryTypes["error"] or "Item not found" in str(raw):
        return None
    data = json.loads(raw) if isinstance(raw, str) else raw
    return data if isinstance(data, dict) else None


def classify(tags, product, product_map):
    """Pure resolution. Returns the values to write; empty ones are left out."""
    key = product_key(tags)
    entry = product_map.get(key) if key else None
    entry = entry if isinstance(entry, dict) else {}

    category = (entry.get("product_map") or {}).get("".join(as_list(product))) \
        or entry.get("category")

    out = {"key": key, "category": category}
    for field in ("type", "confidence", "response", "responses"):
        out[field] = entry.get(field)
    return {k: v for k, v in out.items() if v not in EMPTY}


def main():
    args = demisto.args()
    lifecycle = args.get("lifecycle") or "nist_ir"
    try:
        product_map = load_map()
        if product_map is None:
            return_results(CommandResults(readable_output=(
                f"### SOC Framework — product not classified\n"
                f"- `{MAP_LIST}` is missing; nothing written")))
            return

        demisto.executeCommand("DeleteContext", {"key": "SOCFramework.Product"})
        values = classify(as_list(args.get("tags")), args.get("product"), product_map)
        for field, value in values.items():
            demisto.setContext(f"SOCFramework.Product.{field}", value)

        inferred = False
        if "category" not in values:
            # The inference script writes category and confidence itself.
            demisto.executeCommand("SOCFWInferProductCategory", {"lifecycle": lifecycle})
            inferred = True

        lines = [f"- key: `{values.get('key', '')}`"]
        lines += [f"- {f}: {values[f]}" for f in ("category", "type", "confidence", "response")
                  if f in values]
        if inferred:
            lines.append("- category: not in the map, inference ran (see its entry)")
        return_results(CommandResults(readable_output=(
            "### SOC Framework — product classified\n" + "\n".join(lines))))

    except Exception as e:  # noqa: BLE001 — classification must never stop Upon Trigger
        demisto.error(f"SOCFWClassifyProduct: {type(e).__name__}: {e}")
        return_results(CommandResults(readable_output=(
            f"### ⚠️ SOCFWClassifyProduct — failed (continuing)\n"
            f"- error: `{type(e).__name__}: {e}`\n"
            f"- SOCFramework.Product may be incomplete; normalization falls back to generic")))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
