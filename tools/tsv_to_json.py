#!/usr/bin/env python3
"""
Convert a CrowdStrike TSV export into a JSON array of flat objects
suitable for XSIAM HTTP Collector test ingest, with optional
theme-based anonymization (e.g. Marvel characters).

- Each TSV row -> one JSON object
- Every TSV header becomes a first-level JSON key
- Empty strings become null (JSON `null`)
- JSON-looking strings (e.g. device, files_accessed, network_accesses)
  are parsed back into real objects/arrays when possible.
- Special handling:
  - `mitre_attack`: truncated JSON-like string; we keep it as-is AND
    regex out tactic/technique fields and add them at first level, but
    we DO NOT overwrite existing `tactic`, `tactic_id`, etc.
  - `product`: if missing/empty, try to derive from `_product` (e.g. Falcon_Event -> epp);
    if `product` already exists, we leave it alone.

Usage examples:

  # vanilla export (no anonymization)
  python3 tools/tsv_to_json.py \
    --input "XQL-QUERY-124577 - 2025_11_11 (1).tsv" \
    --output tools/crowdstrike_sample_execution.json \
    --limit 10

  # same export, but anonymize users/hosts into Marvel characters
  python3 tools/tsv_to_json.py \
    --input "XQL-QUERY-124577 - 2025_11_11 (1).tsv" \
    --output tools/crowdstrike_sample_execution_marvel.json \
    --limit 10 \
    --theme marvel
"""

import csv
import json
import argparse
import re
from pathlib import Path
from typing import Optional, Dict, Any, Tuple


def smart_value(v: Optional[str]) -> Any:
    """
    Normalize and optionally parse JSON-like strings.

    - None stays None
    - String is stripped; if it becomes empty, return None
    - If a string starts with '{' or '[', try json.loads() to turn it
      into a dict/list (for fields like device, files_accessed, etc.).
      If parsing fails (e.g. truncated JSON like mitre_attack), keep
      the original string.
    """
    if v is None:
        return None

    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return None

        # Try to parse JSON-like fields back into objects
        if s.startswith("{") or s.startswith("["):
            try:
                return json.loads(s)
            except Exception:
                # Not valid JSON (e.g. truncated with "...")
                return s

        return s

    # Non-string types (ints, bools, etc.) pass through as-is
    return v


def extract_mitre_fields(mitre_val: Any) -> Dict[str, str]:
    """
    Extract MITRE tactic/technique fields from a JSON-like string such as:

      [{"pattern_id": 10358, "tactic_id": "TA0002", "technique_id"... "T1204",
        "tactic": "Execution", "technique": "User Execution"}]

    In your TSV, `mitre_attack` is a truncated string with "...", so we
    can't json.loads() it reliably. We use regex against the raw string
    to pull out just the values we care about.

    NOTE: This function expects the *raw string* for mitre_attack, not a dict.
    """
    if not isinstance(mitre_val, str):
        return {}

    s = mitre_val

    out: Dict[str, str] = {}

    m = re.search(r'"tactic"\s*:\s*"([^"]+)"', s)
    if m:
        out["tactic"] = m.group(1)

    m = re.search(r'"technique"\s*:\s*"([^"]+)"', s)
    if m:
        out["technique"] = m.group(1)

    m = re.search(r'"tactic_id"\s*:\s*"([^"]+)"', s)
    if m:
        out["tactic_id"] = m.group(1)

    m = re.search(r'"technique_id"\s*:\s*"([^"]+)"', s)
    if m:
        out["technique_id"] = m.group(1)

    return out


def derive_product(clean_row: Dict[str, Any]) -> None:
    """
    Ensure `product` is present.

    - If `product` exists and is non-empty, leave it as-is.
      (In your new TSV this is already "epp", which is correct.)
    - Else, if `_product` looks like a Falcon endpoint value, set product="epp".
    - Otherwise, leave it absent.
    """
    product_val = clean_row.get("product")
    if isinstance(product_val, str) and product_val.strip():
        # Already set (e.g., "epp") – don't touch it.
        clean_row["product"] = product_val.strip()
        return

    alt = clean_row.get("_product")
    if isinstance(alt, str):
        alt_str = alt.strip().lower()
    else:
        alt_str = ""

    if alt_str in ("falcon_event", "falcon event") or "falcon" in alt_str:
        clean_row["product"] = "epp"
    # else: leave as-is (no product)


# ---------- Themed anonymization helpers ----------

_MARVEL_CAST: Tuple[Tuple[str, str], ...] = (
    ("Tony Stark", "ironman"),
    ("Steve Rogers", "captainamerica"),
    ("Natasha Romanoff", "blackwidow"),
    ("Bruce Banner", "hulk"),
    ("Thor Odinson", "thor"),
    ("Clint Barton", "hawkeye"),
    ("Peter Parker", "spiderman"),
    ("T'Challa", "blackpanther"),
    ("Stephen Strange", "drstrange"),
    ("Wanda Maximoff", "scarletwitch"),
    ("Sam Wilson", "falcon"),
    ("James Rhodes", "war_machine"),
    ("Scott Lang", "antman"),
    ("Hope van Dyne", "wasp"),
    ("Carol Danvers", "captainmarvel"),
    ("Nick Fury", "nickfury"),
)

def _looks_like_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _get_pseudo_ipv4(original: str, state: Dict[str, Any]) -> str:
    """
    Map each real IPv4 to a stable fake IPv4 in a documentation range.
    Example outputs: 203.0.113.10, 203.0.113.11, ...

    We keep a mapping so the same original IP always gets the same fake IP.
    """
    ip_map: Dict[str, str] = state.setdefault("ip_map", {})
    if original in ip_map:
        return ip_map[original]

    # simple incrementing counter, starting at 10
    counter = state.get("ip_counter", 10)
    state["ip_counter"] = counter + 1

    # Build 203.0.113.X (RFC 5737 TEST-NET-3)
    last_octet = counter % 254 or 1
    fake_ip = f"203.0.113.{last_octet}"
    ip_map[original] = fake_ip
    return fake_ip


def _get_marvel_identity_for(
        original: str,
        state: Dict[str, Any],
) -> Tuple[str, str]:
    """
    Given an original identity string (username, email, etc.), return a
    stable (hero_name, hero_alias) pair using a per-run mapping.

    - state["identity_map"]: original -> (hero_name, hero_alias)
    - state["idx"]: next index in _MARVEL_CAST
    """
    id_map: Dict[str, Tuple[str, str]] = state.setdefault("identity_map", {})
    if original in id_map:
        return id_map[original]

    idx: int = state.get("idx", 0)
    hero = _MARVEL_CAST[idx % len(_MARVEL_CAST)]
    id_map[original] = hero
    state["idx"] = idx + 1
    return hero


def _marvel_email(alias: str) -> str:
    """
    Build a fun but obviously fake email address for the hero.
    """
    local = alias.replace(" ", "").replace("-", "").replace("'", "").lower()
    return f"{local}@avengers.local"


def _find_identity_in_nested(obj: Any) -> Optional[str]:
    """
    Look anywhere in the event for a likely identity string
    (user/account/principal/email).
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v:
                lk = k.lower()
                if "user" in lk or "account" in lk or "principal" in lk or "@" in v:
                    return v
            nested = _find_identity_in_nested(v)
            if nested:
                return nested
    elif isinstance(obj, list):
        for v in obj:
            nested = _find_identity_in_nested(v)
            if nested:
                return nested
    return None


def _anonymize_structure(
        obj: Any,
        key_name: str,
        hero_name: str,
        hero_alias: str,
        hero_host: str,
        hero_email: str,
        state: Dict[str, Any],
) -> Any:
    # ... dict/list handling unchanged ...

    if not isinstance(obj, str):
        return obj

    lk = key_name

    # --- User / account style fields ---
    if any(tok in lk for tok in ("user", "username", "account", "principal")):
        # ID-like fields -> ID tokens
        if "id" in lk or lk.endswith("_sid") or lk.endswith("sid"):
            return _next_pseudo_user_id(hero_alias, state)
        return hero_name

    # --- Email fields or email-looking values ---
    if "email" in lk or re.search(r".+@.+", obj):
        return hero_email

    # --- Host / device names ---
    if ("host" in lk and "name" in lk) or any(
            tok in lk for tok in ("hostname", "endpoint_host_name", "computer_name", "device_name")
    ):
        return hero_host

    # --- Domain-style fields ---
    if lk in ("logon_domain", "user_domain") or (lk.endswith("domain") and "\\" not in obj):
        return "AVENGERS"

    # --- IP address fields ---
    # If the key clearly looks like an IP field, or the value itself is an IPv4, anonymize it.
    if "ip" in lk or lk.endswith("_ip") or lk in ("src", "dst", "source_ip", "destination_ip"):
        if _looks_like_ipv4(obj):
            return _get_pseudo_ipv4(obj, state)
    elif _looks_like_ipv4(obj):
        # Fallback: whole value is an IPv4 even if key name is odd
        return _get_pseudo_ipv4(obj, state)

    # --- Full/display name fields ---
    if any(tok in lk for tok in ("full_name", "display_name")):
        return hero_name

    return obj



# ---------- Themed anonymization helpers ----------

_MARVEL_CAST: Tuple[Tuple[str, str], ...] = (
    ("Tony Stark", "ironman"),
    ("Steve Rogers", "captainamerica"),
    ("Natasha Romanoff", "blackwidow"),
    ("Bruce Banner", "hulk"),
    ("Thor Odinson", "thor"),
    ("Clint Barton", "hawkeye"),
    ("Peter Parker", "spiderman"),
    ("T'Challa", "blackpanther"),
    ("Stephen Strange", "drstrange"),
    ("Wanda Maximoff", "scarletwitch"),
    ("Sam Wilson", "falcon"),
    ("James Rhodes", "war_machine"),
    ("Scott Lang", "antman"),
    ("Hope van Dyne", "wasp"),
    ("Carol Danvers", "captainmarvel"),
    ("Nick Fury", "nickfury"),
)


def _get_marvel_identity_for(
        original: str,
        state: Dict[str, Any],
) -> Tuple[str, str]:
    """
    Given an original identity string (username, email, etc.), return a
    stable (hero_name, hero_alias) pair using a per-run mapping.

    - state["identity_map"]: original -> (hero_name, hero_alias)
    - state["idx"]: next index in _MARVEL_CAST
    """
    id_map: Dict[str, Tuple[str, str]] = state.setdefault("identity_map", {})
    if original in id_map:
        return id_map[original]

    idx: int = state.get("idx", 0)
    hero = _MARVEL_CAST[idx % len(_MARVEL_CAST)]
    id_map[original] = hero
    state["idx"] = idx + 1
    return hero


def _marvel_email(alias: str) -> str:
    """
    Build a fun but obviously fake email address for the hero.
    """
    local = alias.replace(" ", "").replace("-", "").replace("'", "").lower()
    return f"{local}@avengers.local"


def _next_pseudo_user_id(hero_alias: str, state: Dict[str, Any]) -> str:
    """
    Return a stable-ish anonymized user ID token for the given hero_alias.
    Example: ironman_uid_0001
    """
    counters: Dict[str, int] = state.setdefault("user_id_counters", {})
    n = counters.get(hero_alias, 1)
    counters[hero_alias] = n + 1
    return f"{hero_alias}_uid_{n:04d}"


def _find_identity_in_nested(obj: Any) -> Optional[str]:
    """
    Look anywhere in the event for a likely identity string
    (user/account/principal/email).
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v:
                lk = k.lower()
                if "user" in lk or "account" in lk or "principal" in lk or "@" in v:
                    return v
            nested = _find_identity_in_nested(v)
            if nested:
                return nested
    elif isinstance(obj, list):
        for v in obj:
            nested = _find_identity_in_nested(v)
            if nested:
                return nested
    return None


def _anonymize_structure(
        obj: Any,
        key_name: str,
        hero_name: str,
        hero_alias: str,
        hero_host: str,
        hero_email: str,
        state: Dict[str, Any],
) -> Any:
    """
    Recursively anonymize an object based on key name + value.

    - User IDs -> ID-like tokens (ironman_uid_0001)
    - User names -> hero_name (Tony Stark)
    - Emails -> hero_email
    - Hostnames -> hero_host
    - Domains -> AVENGERS
    """
    # Recurse into dicts
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            obj[k] = _anonymize_structure(
                obj[k],
                k.lower(),
                hero_name,
                hero_alias,
                hero_host,
                hero_email,
                state,
            )
        return obj

    # Recurse into lists
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i] = _anonymize_structure(
                v,
                key_name,  # list elements inherit parent key
                hero_name,
                hero_alias,
                hero_host,
                hero_email,
                state,
            )
        return obj

    # Only transform strings; leave everything else alone
    if not isinstance(obj, str):
        return obj

    lk = key_name

    # --- User / account style fields ---
    if any(tok in lk for tok in ("user", "username", "account", "principal")):
        # If this looks like an ID field (user_id, account_id, etc.), make it an ID-like token
        if "id" in lk or lk.endswith("_sid") or lk.endswith("sid"):
            return _next_pseudo_user_id(hero_alias, state)
        # Otherwise treat as a display/user name
        return hero_name

    # --- Email fields or email-looking values ---
    if "email" in lk or re.search(r".+@.+", obj):
        return hero_email

    # --- Host / device names ---
    # Covers hostname, host_name, host_names, *_endpoint_host_name, computer_name, device_name, etc.
    if ("host" in lk and "name" in lk) or any(
            tok in lk for tok in ("hostname", "endpoint_host_name", "computer_name", "device_name")
    ):
        return hero_host

    # --- Domain-style fields ---
    # logon_domain, user_domain, device.hostinfo.domain, etc.
    if lk in ("logon_domain", "user_domain") or (lk.endswith("domain") and "\\" not in obj):
        return "AVENGERS"

    # --- Full/display name fields ---
    if any(tok in lk for tok in ("full_name", "display_name")):
        return hero_name

    # Otherwise, leave the string as-is
    return obj


def apply_theme_anonymization(clean_row: Dict[str, Any], theme: str, state: Dict[str, Any]) -> None:
    """
    Apply theme-based anonymization in-place to a single event row.

    For now we support:
      - theme="marvel": user/account/email/hostname become Marvel-flavored.
    """
    if theme.lower() != "marvel":
        return

    # 1) Choose an identity source to drive the mapping.
    #    Prefer obvious user/account fields at top level, then email, then nested.
    candidate_identity: Optional[str] = None

    # First pass: top-level user/account-like keys
    for key, val in clean_row.items():
        if not isinstance(val, str) or not val:
            continue
        lk = key.lower()
        if "user" in lk or "account" in lk or "principal" in lk:
            candidate_identity = val
            break

    # Second pass: top-level emails
    if candidate_identity is None:
        for key, val in clean_row.items():
            if not isinstance(val, str):
                continue
            if "@" in val:
                candidate_identity = val
                break

    # Third pass: nested search
    if candidate_identity is None:
        candidate_identity = _find_identity_in_nested(clean_row)

    if candidate_identity is None:
        # Nothing to map – nothing to do
        return

    hero_name, hero_alias = _get_marvel_identity_for(candidate_identity, state)
    hero_host = f"{hero_alias}-endpoint".lower()
    hero_email = _marvel_email(hero_alias)

    # 2) Recursively anonymize the whole event
    _anonymize_structure(
        clean_row,
        "",
        hero_name,
        hero_alias,
        hero_host,
        hero_email,
        state,
    )


def tsv_to_json(
        input_path: str,
        output_path: str,
        limit: Optional[int] = None,
        theme: Optional[str] = None,
) -> None:
    in_path = Path(input_path)
    out_path = Path(output_path)

    if not in_path.exists():
        raise FileNotFoundError(f"Input TSV not found: {in_path}")

    records = []
    theme_state: Dict[str, Any] = {}  # reused across rows for stable mappings

    with in_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")

        for i, row in enumerate(reader, start=1):
            # 1) Clean/parse every field, keep all columns as first-level keys
            clean_row: Dict[str, Any] = {k: smart_value(v) for k, v in row.items()}

            # 2) MITRE extraction: add top-level tactic/technique fields
            #    but DO NOT overwrite fields already present in TSV
            raw_mitre_str = row.get("mitre_attack")  # use raw, unparsed string
            if isinstance(raw_mitre_str, str) and raw_mitre_str.strip():
                mitre_fields = extract_mitre_fields(raw_mitre_str)
                for k, v in mitre_fields.items():
                    clean_row.setdefault(k, v)

            # 3) Ensure `product` is present (prefer TSV product, fall back to _product->epp)
            derive_product(clean_row)

            # 4) Optional theme-based anonymization
            if theme:
                apply_theme_anonymization(clean_row, theme, theme_state)

            records.append(clean_row)

            if limit is not None and i >= limit:
                break

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print(
        f"[+] Converted {len(records)} row(s) from {in_path} → {out_path}"
        + (f" with theme={theme}" if theme else "")
    )


def main():
    parser = argparse.ArgumentParser(
        description="Convert CrowdStrike TSV export to JSON array for XSIAM HTTP Collector test ingest"
    )
    parser.add_argument("--input", required=True, help="Path to input TSV file")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of rows to convert (default: all rows)",
    )
    parser.add_argument(
        "--theme",
        choices=["marvel"],
        default=None,
        help="Optional anonymization theme (e.g. 'marvel') to rewrite identities",
    )
    args = parser.parse_args()

    tsv_to_json(args.input, args.output, args.limit, args.theme)


if __name__ == "__main__":
    main()
