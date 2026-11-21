#!/usr/bin/env python3
"""Fail if test data uses a value that could belong to someone.

Tests, test data and replay scenarios may only use values that can never
belong to anyone: reserved domains (``example.com``, ``.example``, ``.test``,
``.invalid``, ``.local``), documentation and private IP ranges, and email
addresses at those domains. Anything else is flagged, unless
``policies/test_data_allowed.json`` lists it with a reason (a vendor console
host, a public adversary-emulation indicator).

Domains are recognised by common top-level domains, so a value under an
unusual TLD can slip past; review still applies.

Runs in the PR gate. Exit 1 with file:line and the value; exit 0 when clean.

Usage::

    python tools/check_test_data.py
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "policies" / "test_data_allowed.json"

TEST_FILES = (
    "Packs/*/Scripts/*/*_test*.py",
    "Packs/*/Scripts/*/test_data/*",
    "scenarios/*.yml",
    "tools/test_*.py",
)

RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".local", "example.com", "example.net", "example.org")
ALLOWED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # documentation (RFC 5737)
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",      # private (RFC 1918)
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "224.0.0.0/4", "100.64.0.0/10",                   # multicast, shared address space
))
TLDS = "com|net|org|io|co|us|uk|de|fr|it|ru|cn|info|biz|gov|edu|mil|xyz|top|cloud|app|dev"

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL = re.compile(r"[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)
DOMAIN = re.compile(rf"(?<![\w@.-])((?:[a-z0-9-]+\.)+(?:{TLDS}))(?![\w-])", re.IGNORECASE)


def _reserved_domain(domain: str) -> bool:
    return domain.lower().endswith(RESERVED_SUFFIXES)


def _exempt(value: str, allowed: dict[str, str]) -> bool:
    value = value.lower()
    return any(value == a or value.endswith("." + a) for a in allowed)


def _public_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not any(address in net for net in ALLOWED_NETWORKS)


def findings(text: str, allowed: dict[str, str]) -> list[tuple[int, str, str]]:
    """Return (line, value, kind) for each value outside the allowed set."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        emails = {m.group(1).lower() for m in EMAIL.finditer(line)}
        for domain in sorted(emails):
            if not _reserved_domain(domain) and not _exempt(domain, allowed):
                found.append((number, domain, "email domain"))
        for m in DOMAIN.finditer(line):
            domain = m.group(1).lower()
            if domain in emails or _reserved_domain(domain) or _exempt(domain, allowed):
                continue
            found.append((number, domain, "domain"))
        for ip in IPV4.findall(line):
            if _public_ip(ip) and not _exempt(ip, allowed):
                found.append((number, ip, "public IP address"))
    return found


def _test_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
    return [p for p in out.splitlines() if any(fnmatch.fnmatch(p, g) for g in TEST_FILES)]


def main() -> int:
    policy = json.loads(POLICY.read_text())
    allowed = {k.lower(): v for k, v in policy["allowed"].items()}
    skip = set(policy.get("skip_files", []))

    failures = []
    for rel in _test_files():
        if rel in skip:
            continue
        text = (REPO_ROOT / rel).read_text(errors="ignore")
        failures += [f"{rel}:{line}: {kind} {value}" for line, value, kind in findings(text, allowed)]

    if failures:
        print("TEST DATA OUTSIDE THE ALLOWED VALUES:")
        for f in failures:
            print(f"  {f}")
        print(
            "\nUse example.com, .example, .test, .invalid or .local names, and 192.0.2.0/24, "
            "198.51.100.0/24, 203.0.113.0/24 or private addresses. A value that must stay "
            "(a vendor host, a public emulation indicator) goes in policies/test_data_allowed.json "
            "with its reason.",
            file=sys.stderr,
        )
        return 1
    print("OK    test data uses only allowed values")
    return 0


if __name__ == "__main__":
    sys.exit(main())
