#!/usr/bin/env python3
"""
sanitize_tsv.py — Scan and sanitize TSV replay files for public repo safety.

Detects tenant identifiers, real IPs, real domains, API keys, XSIAM system
fields, and other data that should not appear in a public repository.

Usage:
    # Report mode (CI gate — default)
    python3 sanitize_tsv.py input_tsv/

    # Report on a single file
    python3 sanitize_tsv.py input_tsv/CrowdStrike-MITRE-Turla-Carbon-in-XSIAM.tsv

    # Fix mode — replace flagged values with safe equivalents, write to --output-dir
    python3 sanitize_tsv.py input_tsv/ --fix --output-dir input_tsv_sanitized/

    # Verbose — show every field checked
    python3 sanitize_tsv.py input_tsv/ -v

Exit codes:
    0 — No issues found
    1 — Issues found (report mode) or errors occurred
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — Safe patterns and known-dangerous patterns
# ─────────────────────────────────────────────────────────────────────────────

# RFC 5737 documentation IPs — explicitly safe for publication
SAFE_IP_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 private
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("0.0.0.0/32"),          # Unspecified
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
]

# RFC 2606 safe TLDs — domains under these TLDs are fictional by definition
SAFE_TLDS = {".local", ".example", ".invalid", ".test", ".localhost",
             ".example.com", ".example.net", ".example.org",
             ".internal", ".lan", ".localdomain"}

# Domains explicitly used in the BYOS lab — already public, safe
SAFE_DOMAINS = {
    "skt.local", "sktlocal.it", "brieftragerin.skt.local",
}

# XSIAM system fields that indicate an XSOAR export (not purpose-built)
# These fields leak tenant metadata when present as column headers
DANGEROUS_COLUMNS = {
    "_id", "_vendor", "_product", "_tenant_id", "_instance_id",
    "_customer_id", "_org_id", "_insert_id", "_log_source_id",
    "_collector_id", "_raw_log", "incident_id", "investigation_id",
    "demisto_created", "demisto_modified", "dbotMirrorId",
    "dbotMirrorDirection", "dbotMirrorInstance", "dbotCurrentDirtyFields",
    "dbotMirrorTags", "playbookId", "runStatus", "droppedCount",
    "linkedCount", "notableData", "xsoar_server_url", "account",
}

# Patterns that indicate real Palo Alto infrastructure
PAN_INFRA_PATTERNS = [
    re.compile(r"[a-z0-9\-]+\.xdr\.[a-z]+\.paloaltonetworks\.com", re.I),
    re.compile(r"[a-z0-9\-]+\.crtx\.[a-z]+\.paloaltonetworks\.com", re.I),
    re.compile(r"api-[a-z0-9\-]+\.xdr\.[a-z]+\.paloaltonetworks\.com", re.I),
    re.compile(r"paloaltonetworks\.com", re.I),
    re.compile(r"cortex\.paloaltonetworks\.com", re.I),
]

# Patterns that indicate API keys, tokens, or secrets
SECRET_PATTERNS = [
    re.compile(r"(?:api[_-]?key|auth[_-]?token|bearer|secret|password)"
               r"\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}", re.I),
    re.compile(r"Authorization:\s*[A-Za-z0-9+/=_\-]{16,}", re.I),
    re.compile(r"x-xdr-auth-id:\s*\d+", re.I),
    re.compile(r"DEMISTO_API_KEY", re.I),
]

# Real-looking XSIAM UUIDs (v4 format with specific prefix patterns)
REAL_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.I,
)

# Obviously fabricated IDs — these are safe (used in purpose-built files)
FABRICATED_ID_PATTERNS = [
    re.compile(r"TAP-GUID-", re.I),
    re.compile(r"TAP-\d{16}", re.I),
    re.compile(r"(a1b2c3|aabbcc|1234567|0000000|deadbeef)", re.I),
    re.compile(r"TURLA-", re.I),
]

# IP address extraction regex
IP_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Email address extraction regex
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
)

# Domain extraction regex (from URLs or bare references)
# Requires: at least two segments, final segment (TLD) must be 2+ alpha chars,
# must not be purely numeric (avoids IPs, timestamps, version strings)
DOMAIN_PATTERN = re.compile(
    r"(?:https?://)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,})"
    r"|"
    r"(?<![.\d/@])\b"
    r"([a-zA-Z][a-zA-Z0-9\-]*"
    r"(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)*"
    r"\.[a-zA-Z]{2,})\b"
)

# File extensions that are NOT domains — suppress false positives
NON_DOMAIN_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".ps1", ".py", ".js", ".json",
    ".xml", ".csv", ".tsv", ".txt", ".log", ".yml", ".yaml", ".md",
    ".html", ".css", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".gz", ".tar", ".png", ".jpg", ".gif", ".svg",
}

# ─────────────────────────────────────────────────────────────────────────────
# REPLACEMENT MAP — safe equivalents for fix mode
# ─────────────────────────────────────────────────────────────────────────────

# Counter for generating unique safe replacements
_replacement_counters = {"ip": 1, "domain": 1, "uuid": 1}
_replacement_cache = {}  # original -> replacement for consistency within a run


def _safe_ip_replacement(original: str) -> str:
    """Replace a real IP with a TEST-NET IP, consistent per run."""
    if original not in _replacement_cache:
        idx = _replacement_counters["ip"]
        _replacement_counters["ip"] += 1
        # Cycle through TEST-NET-1, TEST-NET-2, TEST-NET-3
        net_num = ((idx - 1) % 3) + 1
        host = ((idx - 1) // 3) + 1
        if net_num == 1:
            replacement = f"192.0.2.{min(host, 254)}"
        elif net_num == 2:
            replacement = f"198.51.100.{min(host, 254)}"
        else:
            replacement = f"203.0.113.{min(host, 254)}"
        _replacement_cache[original] = replacement
    return _replacement_cache[original]


def _safe_domain_replacement(original: str) -> str:
    """Replace a real domain with an RFC 2606 domain."""
    if original not in _replacement_cache:
        idx = _replacement_counters["domain"]
        _replacement_counters["domain"] += 1
        _replacement_cache[original] = f"vendor{idx}.example.com"
    return _replacement_cache[original]


def _safe_uuid_replacement(original: str) -> str:
    """Replace a real-looking UUID with an obviously fabricated one."""
    if original not in _replacement_cache:
        idx = _replacement_counters["uuid"]
        _replacement_counters["uuid"] += 1
        _replacement_cache[original] = (
            f"00000000-0000-4000-a000-{idx:012d}"
        )
    return _replacement_cache[original]


# ─────────────────────────────────────────────────────────────────────────────
# CHECK FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

class Finding:
    """A single sanitization finding."""

    def __init__(self, file: str, row: int, col: str, category: str,
                 value: str, message: str, severity: str = "ERROR"):
        self.file = file
        self.row = row
        self.col = col
        self.category = category
        self.value = value[:120]  # Truncate for display
        self.message = message
        self.severity = severity  # ERROR or WARN

    def __str__(self):
        loc = f"{self.file}:{self.row}"
        if self.col:
            loc += f" [{self.col}]"
        return f"  {self.severity}  {loc}  {self.category}: {self.message}  →  {self.value}"


def is_safe_ip(ip_str: str) -> bool:
    """Check if an IP address is in a safe (non-routable / documentation) range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in SAFE_IP_NETWORKS)
    except ValueError:
        return True  # Not a valid IP, skip


def is_safe_domain(domain: str) -> bool:
    """Check if a domain is safe for publication."""
    domain_lower = domain.lower().strip(".")
    # Check exact match in safe list
    if domain_lower in SAFE_DOMAINS:
        return True
    # Check if it ends with a safe TLD
    for tld in SAFE_TLDS:
        if domain_lower.endswith(tld.lstrip(".")):
            return True
        if f".{domain_lower}".endswith(tld):
            return True
    return False


def is_fabricated_id(value: str) -> bool:
    """Check if a UUID/GUID looks obviously fabricated (safe)."""
    return any(p.search(value) for p in FABRICATED_ID_PATTERNS)


def check_column_headers(filename: str, headers: list[str]) -> list[Finding]:
    """Check for XSIAM/XSOAR system field columns that indicate an unsanitized export."""
    findings = []
    for col in headers:
        col_lower = col.strip().lower()
        if col_lower in {c.lower() for c in DANGEROUS_COLUMNS}:
            findings.append(Finding(
                file=filename, row=0, col=col,
                category="SYSTEM_FIELD",
                value=col,
                message=f"XSOAR/XSIAM system column detected — indicates "
                        f"unsanitized platform export, not purpose-built data",
                severity="ERROR",
            ))
    return findings


def check_cell_value(filename: str, row_num: int, col_name: str,
                     value: str) -> list[Finding]:
    """Check a single cell value for sensitive data."""
    findings = []
    if not value or not value.strip():
        return findings

    # --- PAN infrastructure FQDNs ---
    for pattern in PAN_INFRA_PATTERNS:
        match = pattern.search(value)
        if match:
            findings.append(Finding(
                file=filename, row=row_num, col=col_name,
                category="PAN_INFRA",
                value=match.group(),
                message="Palo Alto Networks infrastructure identifier detected",
                severity="ERROR",
            ))

    # --- API keys and secrets ---
    for pattern in SECRET_PATTERNS:
        match = pattern.search(value)
        if match:
            findings.append(Finding(
                file=filename, row=row_num, col=col_name,
                category="SECRET",
                value=match.group()[:40] + "...",
                message="Possible API key, token, or secret detected",
                severity="ERROR",
            ))

    # --- IP addresses ---
    for ip_match in IP_PATTERN.finditer(value):
        ip_str = ip_match.group(1)
        if not is_safe_ip(ip_str):
            findings.append(Finding(
                file=filename, row=row_num, col=col_name,
                category="PUBLIC_IP",
                value=ip_str,
                message=f"Public IP outside safe documentation ranges "
                        f"(RFC 5737 / RFC 1918)",
                severity="ERROR",
            ))

    # --- Email domains ---
    for email_match in EMAIL_PATTERN.finditer(value):
        domain = email_match.group(1)
        if not is_safe_domain(domain):
            findings.append(Finding(
                file=filename, row=row_num, col=col_name,
                category="REAL_DOMAIN",
                value=f"*@{domain}",
                message="Email with non-safe domain — could identify "
                        "real organization",
                severity="ERROR",
            ))

    # --- Domains in URLs and bare references ---
    for domain_match in DOMAIN_PATTERN.finditer(value):
        domain = domain_match.group(1) or domain_match.group(2)
        if not domain:
            continue
        # Skip file extensions mistaken for domains
        ext = "." + domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if ext in NON_DOMAIN_EXTENSIONS:
            continue
        # Skip pure version strings (e.g., "537.36")
        if all(c.isdigit() or c == "." for c in domain):
            continue
        if not is_safe_domain(domain):
            # Skip if already caught by PAN_INFRA or EMAIL checks
            already_flagged = any(
                f.category in ("PAN_INFRA", "REAL_DOMAIN")
                and domain in f.value
                for f in findings
            )
            if not already_flagged:
                findings.append(Finding(
                    file=filename, row=row_num, col=col_name,
                    category="REAL_DOMAIN",
                    value=domain,
                    message="Non-safe domain detected — verify it is fictional",
                    severity="WARN",
                ))

    # --- Real-looking UUIDs (v4) ---
    for uuid_match in REAL_UUID_PATTERN.finditer(value):
        uuid_str = uuid_match.group()
        if not is_fabricated_id(uuid_str):
            # Only flag if the column suggests it's a system identifier
            id_cols = {"_id", "id", "incident_id", "investigation_id",
                       "alert_id", "case_id", "agent_id", "endpoint_id",
                       "external_id"}
            col_lower = col_name.lower().strip()
            if col_lower in id_cols or col_lower.startswith("_"):
                findings.append(Finding(
                    file=filename, row=row_num, col=col_name,
                    category="REAL_UUID",
                    value=uuid_str,
                    message="Real-looking v4 UUID in identifier column — "
                            "may be tenant-scoped",
                    severity="WARN",
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# ALLOWLIST — Load optional per-repo overrides
# ─────────────────────────────────────────────────────────────────────────────

def load_allowlist(path: Optional[str]) -> dict:
    """Load an allowlist JSON file with known-safe values to suppress."""
    if not path:
        return {"ips": [], "domains": [], "values": [], "columns": []}
    try:
        with open(path) as f:
            data = json.load(f)
        return {
            "ips": [str(v) for v in data.get("ips", [])],
            "domains": [str(v).lower() for v in data.get("domains", [])],
            "values": [str(v) for v in data.get("values", [])],
            "columns": [str(v).lower() for v in data.get("columns", [])],
        }
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: Could not load allowlist {path}: {e}", file=sys.stderr)
        return {"ips": [], "domains": [], "values": [], "columns": []}


def is_allowlisted(finding: Finding, allowlist: dict) -> bool:
    """Check if a finding is suppressed by the allowlist."""
    if finding.value in allowlist["values"]:
        return True
    if finding.category == "PUBLIC_IP" and finding.value in allowlist["ips"]:
        return True
    if finding.category == "REAL_DOMAIN":
        domain = finding.value.lstrip("*@").lower()
        if domain in allowlist["domains"]:
            return True
    if finding.category == "SYSTEM_FIELD":
        if finding.col.lower() in allowlist["columns"]:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# FILE PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

def scan_tsv(filepath: str, allowlist: dict,
             verbose: bool = False) -> list[Finding]:
    """Scan a single TSV file and return findings."""
    findings = []
    filename = os.path.basename(filepath)

    try:
        with open(filepath, newline="", encoding="utf-8") as f:
            # Sniff delimiter — support both TSV and CSV
            sample = f.read(4096)
            f.seek(0)
            tab_count = sample.count("\t")
            comma_count = sample.count(",")
            delimiter = "\t" if tab_count > comma_count else ","

            reader = csv.DictReader(f, delimiter=delimiter)
            if reader.fieldnames is None:
                findings.append(Finding(
                    file=filename, row=0, col="",
                    category="PARSE_ERROR",
                    value="",
                    message="Could not parse file headers",
                    severity="ERROR",
                ))
                return findings

            # Check column headers
            header_findings = check_column_headers(filename,
                                                   list(reader.fieldnames))
            findings.extend(header_findings)

            if verbose and not header_findings:
                print(f"  ✓  {filename}: Column headers clean "
                      f"({len(reader.fieldnames)} columns)")

            # Check each row
            for row_num, row in enumerate(reader, start=2):
                for col_name, value in row.items():
                    if col_name is None or value is None:
                        continue
                    cell_findings = check_cell_value(
                        filename, row_num, col_name, value
                    )
                    findings.extend(cell_findings)

                    if verbose and not cell_findings and value.strip():
                        pass  # Only print findings in verbose, not every clean cell

    except UnicodeDecodeError:
        # Try latin-1 fallback
        try:
            with open(filepath, newline="", encoding="latin-1") as f:
                reader = csv.DictReader(f, delimiter="\t")
                if reader.fieldnames:
                    findings.extend(
                        check_column_headers(filename, list(reader.fieldnames))
                    )
                    for row_num, row in enumerate(reader, start=2):
                        for col_name, value in row.items():
                            if col_name is None or value is None:
                                continue
                            findings.extend(
                                check_cell_value(filename, row_num,
                                                 col_name, value)
                            )
        except Exception as e:
            findings.append(Finding(
                file=filename, row=0, col="",
                category="PARSE_ERROR",
                value=str(e)[:80],
                message="Could not parse file",
                severity="ERROR",
            ))

    except Exception as e:
        findings.append(Finding(
            file=filename, row=0, col="",
            category="PARSE_ERROR",
            value=str(e)[:80],
            message="Error reading file",
            severity="ERROR",
        ))

    # Filter allowlisted findings
    findings = [f for f in findings if not is_allowlisted(f, allowlist)]

    return findings


def apply_fixes(filepath: str, output_path: str, allowlist: dict) -> int:
    """Read a TSV, replace flagged values with safe equivalents, write output."""
    fix_count = 0

    with open(filepath, newline="", encoding="utf-8") as f:
        content = f.read()

    # Replace PAN infrastructure FQDNs
    for pattern in PAN_INFRA_PATTERNS:
        for match in pattern.finditer(content):
            original = match.group()
            replacement = _safe_domain_replacement(original)
            content = content.replace(original, replacement)
            fix_count += 1

    # Replace unsafe IPs
    for ip_match in IP_PATTERN.finditer(content):
        ip_str = ip_match.group(1)
        if not is_safe_ip(ip_str):
            if ip_str not in [v for v in allowlist.get("ips", [])]:
                replacement = _safe_ip_replacement(ip_str)
                content = content.replace(ip_str, replacement)
                fix_count += 1

    # Replace real-looking UUIDs in system-field columns
    # (This is harder to do generically — we flag but manual review is safer)

    # Strip dangerous column headers by removing the column entirely
    lines = content.split("\n")
    if lines:
        headers = lines[0].split("\t")
        cols_to_remove = []
        for i, h in enumerate(headers):
            if h.strip().lower() in {c.lower() for c in DANGEROUS_COLUMNS}:
                if h.strip().lower() not in allowlist.get("columns", []):
                    cols_to_remove.append(i)
                    fix_count += 1

        if cols_to_remove:
            new_lines = []
            for line in lines:
                if not line.strip():
                    new_lines.append(line)
                    continue
                fields = line.split("\t")
                fields = [f for i, f in enumerate(fields)
                          if i not in cols_to_remove]
                new_lines.append("\t".join(fields))
            content = "\n".join(new_lines)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return fix_count


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan and sanitize TSV replay files for public repo safety.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "paths", nargs="+",
        help="TSV/CSV files or directories to scan",
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Apply automatic fixes and write sanitized files",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory for fixed files (default: overwrite in place)",
    )
    parser.add_argument(
        "--allowlist", default=None,
        help="Path to allowlist JSON (known-safe values to suppress)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed output for every file checked",
    )
    parser.add_argument(
        "--json-output", default=None,
        help="Write findings to JSON file (for CI integration)",
    )
    args = parser.parse_args()

    allowlist = load_allowlist(args.allowlist)

    # Collect files to scan
    files_to_scan = []
    for path in args.paths:
        p = Path(path)
        if p.is_dir():
            files_to_scan.extend(sorted(p.glob("*.tsv")))
            files_to_scan.extend(sorted(p.glob("*.csv")))
        elif p.is_file() and p.suffix.lower() in (".tsv", ".csv"):
            files_to_scan.append(p)
        else:
            print(f"WARNING: Skipping {path} (not a TSV/CSV file or directory)",
                  file=sys.stderr)

    if not files_to_scan:
        print("No TSV/CSV files found to scan.", file=sys.stderr)
        sys.exit(1)

    # Scan
    all_findings: list[Finding] = []
    print(f"\n{'='*70}")
    print(f"  SANITIZE TSV — Public Repo Safety Check")
    print(f"  Files: {len(files_to_scan)}  |  Mode: {'FIX' if args.fix else 'REPORT'}")
    print(f"{'='*70}\n")

    for filepath in files_to_scan:
        findings = scan_tsv(str(filepath), allowlist, args.verbose)
        all_findings.extend(findings)

        errors = [f for f in findings if f.severity == "ERROR"]
        warns = [f for f in findings if f.severity == "WARN"]

        if findings:
            status = "FAIL" if errors else "WARN"
            icon = "✗" if errors else "⚠"
            print(f"  {icon}  {filepath.name}  —  "
                  f"{len(errors)} error(s), {len(warns)} warning(s)")
            for f in findings:
                print(f"    {f}")
        else:
            print(f"  ✓  {filepath.name}  —  clean")

        # Apply fixes if requested
        if args.fix and findings:
            if args.output_dir:
                out_path = os.path.join(args.output_dir, filepath.name)
            else:
                out_path = str(filepath)
            fix_count = apply_fixes(str(filepath), out_path, allowlist)
            print(f"    → Fixed {fix_count} issue(s) → {out_path}")

    # Summary
    total_errors = sum(1 for f in all_findings if f.severity == "ERROR")
    total_warns = sum(1 for f in all_findings if f.severity == "WARN")
    print(f"\n{'─'*70}")
    if total_errors > 0:
        print(f"  RESULT: FAIL — {total_errors} error(s), "
              f"{total_warns} warning(s) across {len(files_to_scan)} file(s)")
        print(f"  Errors must be fixed before publishing to a public repo.")
    elif total_warns > 0:
        print(f"  RESULT: WARN — {total_warns} warning(s) across "
              f"{len(files_to_scan)} file(s)")
        print(f"  Warnings should be reviewed manually.")
    else:
        print(f"  RESULT: PASS — all {len(files_to_scan)} file(s) clean")
    print(f"{'─'*70}\n")

    # JSON output for CI
    if args.json_output:
        json_data = {
            "total_files": len(files_to_scan),
            "total_errors": total_errors,
            "total_warnings": total_warns,
            "result": "FAIL" if total_errors else ("WARN" if total_warns else "PASS"),
            "findings": [
                {
                    "file": f.file,
                    "row": f.row,
                    "column": f.col,
                    "category": f.category,
                    "value": f.value,
                    "message": f.message,
                    "severity": f.severity,
                }
                for f in all_findings
            ],
        }
        with open(args.json_output, "w") as jf:
            json.dump(json_data, jf, indent=2)
        print(f"  Findings written to {args.json_output}")

    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
