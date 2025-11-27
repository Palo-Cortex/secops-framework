#!/usr/bin/env python3
import csv
import json
import argparse
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime


def smart_value(v: Optional[str]) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return None
        if s.startswith("{") or s.startswith("["):
            try:
                return json.loads(s)
            except Exception:
                return s
        return s
    return v


def extract_mitre_fields(mitre_val: Any) -> Dict[str, str]:
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
    product_val = clean_row.get("product")
    if isinstance(product_val, str) and product_val.strip():
        clean_row["product"] = product_val.strip()
        return
    alt = clean_row.get("_product")
    if isinstance(alt, str):
        alt_str = alt.strip().lower()
    else:
        alt_str = ""
    if alt_str in ("falcon_event", "falcon event") or "falcon" in alt_str:
        clean_row["product"] = "epp"


MARVEL_IDENTITIES: List[Tuple[str, str]] = [
    ("tony.stark", "Tony Stark"),
    ("steve.rogers", "Steve Rogers"),
    ("natasha.romanoff", "Natasha Romanoff"),
    ("bruce.banner", "Bruce Banner"),
    ("peter.parker", "Peter Parker"),
    ("carol.danvers", "Carol Danvers"),
    ("tchalla", "T'Challa"),
    ("wanda.maximoff", "Wanda Maximoff"),
    ("clint.barton", "Clint Barton"),
    ("sam.wilson", "Sam Wilson"),
]


def marvel_identity_for_row(row_index: int) -> Dict[str, str]:
    slug, full_name = MARVEL_IDENTITIES[(row_index - 1) % len(MARVEL_IDENTITIES)]
    upn = f"{slug}@marvel.local"
    sam = slug.split(".")[0].upper()
    return {
        "slug": slug,
        "full_name": full_name,
        "upn": upn,
        "sam": sam,
        "domain": "MARVEL",
    }


# Generic pattern scrubbing used across all nested structures
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://\S+")


def _anonymize_scalar(value: Any, ident: Dict[str, str], row_index: int) -> Any:
    if not isinstance(value, str):
        return value

    s = value

    # Emails -> Marvel UPN
    s = EMAIL_RE.sub(ident["upn"], s)

    # IPv4s -> documentation range
    s = IPV4_RE.sub(f"203.0.113.{row_index}", s)

    # URLs -> Marvel campaign URL
    s = URL_RE.sub(f"https://threats.marvel.example/campaign/{row_index}", s)

    return s


def _deep_scrub(obj: Any, ident: Dict[str, str], row_index: int) -> Any:
    """
    Recursively scrub dicts/lists/scalars so that any email/IP/URL
    anywhere in the structure is anonymized.
    """
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            obj[k] = _deep_scrub(obj[k], ident, row_index)
        return obj
    if isinstance(obj, list):
        for i in range(len(obj)):
            obj[i] = _deep_scrub(obj[i], ident, row_index)
        return obj
    return _anonymize_scalar(obj, ident, row_index)


def apply_marvel_scenario(
        clean_row: Dict[str, Any],
        row_index: int,
        category: str,
        campaign_id: Optional[str],
        stage: Optional[str],
) -> None:
    ident = marvel_identity_for_row(row_index)

    # Campaign metadata
    if campaign_id:
        clean_row["attack_campaign_id"] = campaign_id
    if stage:
        clean_row["attack_stage"] = stage

    # Identity
    clean_row["user_name"] = ident["sam"]
    clean_row["users"] = ident["full_name"]
    clean_row["user_principal"] = ident["upn"]
    if "user_id" in clean_row or campaign_id:
        clean_row["user_id"] = clean_row.get("user_id") or f"S-1-5-21-MARVEL-{row_index}"
    clean_row["honeytoken_user"] = None

    # Email-ish (Proofpoint-style) fields
    for key in [
        "recipient",
        "Recipient",
        "recipient_email",
        "target",
        "user",
        "clickers",
        "fromAddress",
        "headerFrom",
        "headerReplyTo",
        "replyToAddress",
        "toAddresses",
        "ccAddresses",
    ]:
        if key in clean_row:
            clean_row[key] = ident["upn"]

    # Account-style fields
    for prefix in [
        "source_account",
        "target_account",
        "additional_endpoint_account",
        "source_endpoint_account",
        "target_endpoint_account",
    ]:
        name_key = f"{prefix}_name"
        upn_key = f"{prefix}_upn"
        dom_key = f"{prefix}_domain"
        sam_key = f"{prefix}_sam_account_name"

        if name_key in clean_row:
            clean_row[name_key] = ident["sam"]
        if upn_key in clean_row:
            clean_row[upn_key] = ident["upn"]
        if dom_key in clean_row:
            clean_row[dom_key] = ident["domain"]
        if sam_key in clean_row:
            clean_row[sam_key] = ident["sam"]

    # Domain / hostname
    if "logon_domain" in clean_row:
        clean_row["logon_domain"] = ident["domain"]
    if "domain" in clean_row:
        clean_row["domain"] = ident["domain"]
    if "hostname" in clean_row and category == "endpoint":
        clean_row["hostname"] = f"{ident['sam']}-LT-{row_index:02d}"

    # IPs (explicit known fields)
    for ip_key in [
        "local_ip",
        "external_ip",
        "clickIP",
        "senderIP",
        "_final_reporting_device_ip",
        "_reporting_device_ip",
    ]:
        if ip_key in clean_row:
            clean_row[ip_key] = f"203.0.113.{row_index}"

    # IDs (explicit known fields)
    for id_key in [
        "cid",
        "agent_id",
        "id",
        "_id",
        "GUID",
        "guid",
        "threatID",
        "threatId",
        "campaignId",
        "messageID",
        "QID",
    ]:
        if id_key in clean_row:
            clean_row[id_key] = f"marvel-{id_key.lower()}-{row_index:08d}"

    # Links / URLs
    for url_key in ["falcon_host_link", "threatURL", "threatUrl", "url"]:
        if url_key in clean_row:
            clean_row[url_key] = f"https://threats.marvel.example/campaign/{row_index}"

    # User agent / xmailer can be normalized too
    if "userAgent" in clean_row:
        clean_row["userAgent"] = "Mozilla/5.0 (MarvelOS 1.0; Hero 64)"
    if "xmailer" in clean_row:
        clean_row["xmailer"] = "Marvel Mailer 1.0"

    # Finally, recursively scrub any remaining emails/IPs/URLs anywhere in the row
    _deep_scrub(clean_row, ident, row_index)


def parse_time(value: Any):
    if not isinstance(value, str):
        return None

    # Strip trailing Z if present (e.g. TAP ISO timestamps)
    v = value.rstrip("Z")

    # Try ISO with/without fractional seconds
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(v, fmt)
        except Exception:
            pass

    # Original formats (e.g. "Nov 12 2025 18:44:54")
    for fmt in ("%b %d %Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(v, fmt)
        except Exception:
            continue
    return None


def load_tsv_as_events(
        path: Path,
        category: str,
        scenario: Optional[str],
        campaign_id: Optional[str],
        stage: Optional[str],
        limit: Optional[int] = None,
) -> list:
    events = []
    if not path:
        return events

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row_idx, row in enumerate(reader, start=1):
            clean_row = {k: smart_value(v) for k, v in row.items()}

            # CrowdStrike MITRE extraction
            if "mitre_attack" in row and isinstance(row["mitre_attack"], str) and row["mitre_attack"].strip():
                mitre_fields = extract_mitre_fields(row["mitre_attack"])
                for k, v in mitre_fields.items():
                    clean_row.setdefault(k, v)

            # Only really relevant for endpoint/CrowdStrike
            if category == "endpoint":
                derive_product(clean_row)

            # Source category tag
            clean_row["attack_source_category"] = category

            # Scenario anon
            if scenario == "marvel":
                apply_marvel_scenario(clean_row, row_idx, category, campaign_id, stage)

            events.append(clean_row)
            if limit is not None and row_idx >= limit:
                break

    return events


def build_campaign(
        email_tsv: Optional[str],
        endpoint_tsv: Optional[str],
        output_path: str,
        scenario: Optional[str],
        campaign_id: Optional[str],
        limit: Optional[int],
) -> None:
    all_events = []

    if email_tsv:
        all_events.extend(
            load_tsv_as_events(Path(email_tsv), "email", scenario, campaign_id, "phishing", limit)
        )
    if endpoint_tsv:
        all_events.extend(
            load_tsv_as_events(Path(endpoint_tsv), "endpoint", scenario, campaign_id, "execution", limit)
        )

    # Sort by _time if possible (phishing should naturally come before execution)
    def sort_key(ev):
        t_raw = ev.get("_time")
        t = parse_time(t_raw)
        return t or datetime.min

    all_events.sort(key=sort_key)

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(all_events, f, indent=2, ensure_ascii=False)

    print(f"[+] Wrote {len(all_events)} campaign event(s) to {out_path}")


def main():
    ap = argparse.ArgumentParser(
        description="Build a multi-product attack campaign JSON from TSVs (e.g. Proofpoint + CrowdStrike)"
    )
    ap.add_argument("--email-tsv", help="Path to email/phishing TSV (e.g. Proofpoint)")
    ap.add_argument("--endpoint-tsv", help="Path to endpoint TSV (e.g. CrowdStrike EPP)")
    ap.add_argument("--output", required=True, help="Path to output campaign JSON")
    ap.add_argument(
        "--scenario",
        choices=["marvel"],
        default=None,
        help="Optional scenario/anonymization (e.g. 'marvel').",
    )
    ap.add_argument(
        "--campaign-id",
        default=None,
        help="Optional attack campaign id to tag rows with (e.g. 'marvel-attack-001').",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max rows per TSV to include.",
    )
    args = ap.parse_args()

    if not args.email_tsv and not args.endpoint_tsv:
        raise SystemExit("You must provide at least one of --email-tsv or --endpoint-tsv")

    build_campaign(
        args.email_tsv,
        args.endpoint_tsv,
        args.output,
        args.scenario,
        args.campaign_id,
        args.limit,
    )


if __name__ == "__main__":
    main()
