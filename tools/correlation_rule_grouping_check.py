#!/usr/bin/env python3
"""
correlation_rule_grouping_check.py

Single question: does this correlation rule map the correct fields to
group?  If not, what is missing?

Reads an XSIAM tenant export of correlation rules and, for each rule:
  - GROUPS:    Yes | No
  - On:        the canonical XSIAM Alert Field destinations the rule
               populates (the keys the case grouping engine buckets on)
  - Missing:   when the rule does not group, concrete suggestions for
               what to add or change in alert_fields

Grouping happens on the destination KEY in alert_fields -- the
snake_case API name like `actor_effective_username`, `agent_hostname`,
`action_local_ip`.  A custom destination key (e.g. `Suspicious_User`)
becomes a User Defined Field and the engine does not group on it.

USAGE

    python3 correlation_rule_grouping_check.py --input rules.json
    python3 correlation_rule_grouping_check.py --input rules.json --only-broken
    python3 correlation_rule_grouping_check.py --input rules.json \
        --format csv --output grouping.csv

EXIT CODES

    0   all rules group
    1   at least one rule does not group
    2   bad input
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Canonical XSIAM Alert Field destinations on which the case grouping
# engine buckets alerts.  Snake_case API names primary; display-name forms
# kept for UI exports.  Set derived from the framework's own SOC
# CrowdStrike Falcon - Endpoint Alerts rule and standard xdr_data entity
# schema.
# ---------------------------------------------------------------------------

ENTITY_ALERT_FIELDS = {
    # User
    "actor_effective_username", "actor_primary_username", "userid",
    "user_name", "username", "user_principal", "usersid",
    "User name",
    # Host
    "agent_hostname", "agent_id", "hostname", "host_name",
    "agent_device_domain", "domain",
    "Host Name", "Domain",
    # IP
    "action_local_ip", "action_remote_ip", "local_ip", "remote_ip",
    "remote_ips", "prenatsourceip", "postnatdestinationip",
    "Local IP", "Remote IP", "Host IP", "Remote Host",
    # Causality
    "causality_actor_causality_id", "aggregate_id",
}

# XDM paths XSIAM auto-translates to a canonical entity Alert Field when
# mapping_strategy is AUTO.  In AUTO rules the value is the XDM path even
# if the destination key is canonical, but a non-canonical destination
# can still result in grouping if XSIAM auto-fills via XDM.
XDM_TO_ENTITY_ALERT_FIELD = {
    "xdm.source.host.fqdn":           "domain",
    "xdm.source.host.hostname":       "agent_hostname",
    "xdm.source.host.ipv4_addresses": "action_local_ip",
    "xdm.source.ipv4":                "action_local_ip",
    "xdm.target.host.hostname":       "hostname",
    "xdm.target.ipv4":                "action_remote_ip",
    "xdm.target.host.ipv4_addresses": "action_remote_ip",
    "xdm.source.user.username":       "actor_effective_username",
}

# Common XQL output column names to suggested canonical entity Alert Field
# destinations.  Used only to suggest fixes.
SOURCE_TO_RECOMMENDED_ALERT_FIELD = {
    "user_name": "actor_effective_username",
    "username": "actor_effective_username",
    "actor_username": "actor_effective_username",
    "actor_effective_username": "actor_effective_username",
    "actor_primary_username": "actor_effective_username",
    "src_user": "actor_effective_username",
    "source_user": "actor_effective_username",
    "user": "actor_effective_username",
    "user_principal": "user_principal",
    "userid": "userid",
    "user_id": "userid",
    "host_name": "agent_hostname",
    "hostname": "agent_hostname",
    "agent_hostname": "agent_hostname",
    "src_host": "agent_hostname",
    "host_fqdn": "agent_hostname",
    "entity_hostname": "agent_hostname",
    "source_endpoint_host_name": "agent_hostname",
    "device_name": "agent_hostname",
    "local_ip": "action_local_ip",
    "src_ipv4": "action_local_ip",
    "action_local_ip": "action_local_ip",
    "src": "action_local_ip",
    "remote_ip": "action_remote_ip",
    "remote_ips": "action_remote_ip",
    "action_remote_ip": "action_remote_ip",
    "tgt_ipv4": "action_remote_ip",
    "dst": "action_remote_ip",
    "agent_device_domain": "agent_device_domain",
    "domain": "agent_device_domain",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MissingItem:
    """One concrete fix suggestion for a rule that does not group."""
    kind: str             # 'CHANGE' or 'ADD'
    source_field: str     # XQL column name
    current_dest: str     # destination key today, '<unmapped>' if ADD
    suggested_dest: str   # canonical Alert Field destination


@dataclass
class RuleReport:
    rule_name: str
    rule_id: str
    groups: bool
    groups_on: list[str] = field(default_factory=list)
    missing: list[MissingItem] = field(default_factory=list)
    note: str = ""        # one-line explanation when groups is False


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def load_rules(path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    if path.is_dir():
        for child in sorted(path.glob("*.json")):
            rules.extend(load_rules(child))
        for child in sorted(path.glob("*.ndjson")):
            rules.extend(load_rules(child))
        return rules
    if not path.exists():
        raise FileNotFoundError(f"Input not found: {path}")
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # NDJSON fallback
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rules.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return rules
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rules", "correlations", "data", "items", "results"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    raise ValueError(f"Unsupported JSON shape in {path}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_fields(rule: dict[str, Any]) -> list[tuple[str, Any]]:
    """
    Return [(destination_alert_field, source), ...].

    Tenant export and pack YAML use the dict shape {<destination>:
    <source>}, where the key is the XSIAM Alert Field that grouping
    happens on.  null source means the field is declared but unmapped.
    Older list shape with explicit dest/source keys is also tolerated.
    """
    af = rule.get("alert_fields")
    if af is None:
        return []
    if isinstance(af, dict):
        return [(k, v) for k, v in af.items() if v not in (None, "")]
    if isinstance(af, list):
        out: list[tuple[str, Any]] = []
        for item in af:
            if not isinstance(item, dict):
                continue
            dest = (item.get("alert_field") or item.get("xdm_field")
                    or item.get("name") or item.get("dest")
                    or item.get("destination"))
            src = (item.get("source_field") or item.get("value")
                   or item.get("source") or item.get("field"))
            if dest:
                out.append((dest, src))
        return out
    return []


def _xql_output_fields(rule: dict[str, Any]) -> list[str]:
    """Best-effort extraction of column names produced by the rule's XQL."""
    xql = rule.get("xql_query") or ""
    if not isinstance(xql, str) or not xql:
        return []
    fields: list[str] = []
    for m in re.finditer(r"\balter\s+([a-zA-Z_]\w*)\s*=", xql):
        fields.append(m.group(1))
    for m in re.finditer(r"\bfields\s+([a-zA-Z_][\w,\s]*)", xql):
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok and re.match(r"^[a-zA-Z_]\w*$", tok):
                fields.append(tok)
    for m in re.finditer(r"\bas\s+([a-zA-Z_]\w*)", xql):
        fields.append(m.group(1))
    seen: set[str] = set()
    out: list[str] = []
    for f in fields:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _is_enabled(rule: dict[str, Any]) -> bool:
    if "is_enabled" in rule:
        return bool(rule["is_enabled"])
    if "enabled" in rule:
        return bool(rule["enabled"])
    if "disabled" in rule:
        return not bool(rule["disabled"])
    return True


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------

def check_rule(rule: dict[str, Any]) -> RuleReport:
    name = (rule.get("rule_name") or rule.get("name")
            or rule.get("ruleName") or "<unnamed rule>")
    rid = str(rule.get("rule_id") or rule.get("ruleid")
              or rule.get("id") or rule.get("global_rule_id") or "")

    af = _alert_fields(rule)
    groups_on: list[str] = []
    for dest, src in af:
        if isinstance(dest, str) and dest in ENTITY_ALERT_FIELDS:
            if dest not in groups_on:
                groups_on.append(dest)
        elif isinstance(src, str) and src in XDM_TO_ENTITY_ALERT_FIELD:
            canonical = XDM_TO_ENTITY_ALERT_FIELD[src]
            if canonical not in groups_on:
                groups_on.append(canonical)

    groups_on.sort()
    rpt = RuleReport(
        rule_name=name,
        rule_id=rid,
        groups=bool(groups_on),
        groups_on=groups_on,
    )

    if rpt.groups:
        return rpt

    if not af:
        rpt.note = "alert_fields is empty"
        for src in _xql_output_fields(rule):
            suggested = SOURCE_TO_RECOMMENDED_ALERT_FIELD.get(src)
            if suggested:
                rpt.missing.append(MissingItem(
                    kind="ADD",
                    source_field=src,
                    current_dest="<unmapped>",
                    suggested_dest=suggested,
                ))
        if not rpt.missing:
            rpt.note = ("alert_fields is empty and the rule's XQL does "
                        "not expose entity-shaped columns")
    else:
        rpt.note = "destinations are not canonical entity Alert Fields"
        for dest, src in af:
            if not isinstance(dest, str):
                continue
            if dest in ENTITY_ALERT_FIELDS:
                continue
            if not isinstance(src, str):
                continue
            suggested = SOURCE_TO_RECOMMENDED_ALERT_FIELD.get(src)
            if suggested:
                rpt.missing.append(MissingItem(
                    kind="CHANGE",
                    source_field=src,
                    current_dest=dest,
                    suggested_dest=suggested,
                ))
    return rpt


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def render_text(reports: list[RuleReport], use_color: bool = True) -> str:
    out: list[str] = []
    pass_n = sum(1 for r in reports if r.groups)
    fail_n = len(reports) - pass_n
    out.append(f"Rules: {len(reports)}   groups: {pass_n}   "
               f"does not group: {fail_n}")
    out.append("")
    # Failing rules first, alphabetized
    sorted_reports = sorted(reports, key=lambda r: (r.groups, r.rule_name))
    for r in sorted_reports:
        tag = "GROUPS" if r.groups else "DOES NOT GROUP"
        c = (_GREEN if r.groups else _RED) if use_color else ""
        d = _DIM if use_color else ""
        rst = _RESET if use_color else ""
        out.append(f"{c}[{tag}]{rst}  {r.rule_name}"
                   f"  {d}id={r.rule_id or '-'}{rst}")
        if r.groups:
            out.append(f"    On: {', '.join(r.groups_on)}")
        else:
            out.append(f"    On: (none) -- {r.note}")
            if r.missing:
                # Pretty column widths
                w_src = max(len(m.source_field) for m in r.missing)
                w_cur = max(len(m.current_dest) for m in r.missing)
                out.append(f"    Missing:")
                for m in r.missing:
                    out.append(
                        f"      [{m.kind:<6}] "
                        f"{m.source_field:<{w_src}}  "
                        f"current={m.current_dest:<{w_cur}}  "
                        f"-> {m.suggested_dest!r}"
                    )
        out.append("")
    return "\n".join(out)


def render_json(reports: list[RuleReport]) -> str:
    payload = {
        "total":           len(reports),
        "groups":          sum(1 for r in reports if r.groups),
        "does_not_group":  sum(1 for r in reports if not r.groups),
        "reports":         [asdict(r) for r in reports],
    }
    return json.dumps(payload, indent=2)


def render_csv(reports: list[RuleReport]) -> str:
    """
    One row per rule.  Designed for sharing -- columns load straight
    into a pivot table or get filtered by 'groups=False' to triage.

    Columns:
        rule_name           rule display name
        rule_id             tenant rule id (string)
        groups              True | False
        groups_on           semicolon-separated canonical Alert Fields
        note                short reason when groups=False
        missing             pipe-delimited fix list, e.g.
                            'CHANGE Suspicious_User -> actor_effective_username
                             | ADD host_name -> agent_hostname'
    """
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "rule_name", "rule_id", "groups", "groups_on", "note", "missing",
    ])
    for r in sorted(reports, key=lambda r: (r.groups, r.rule_name)):
        missing_str = " | ".join(
            f"{m.kind} {m.source_field} (currently {m.current_dest})"
            f" -> {m.suggested_dest}"
            for m in r.missing
        )
        w.writerow([
            r.rule_name,
            r.rule_id,
            r.groups,
            "; ".join(r.groups_on),
            r.note,
            missing_str,
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="correlation_rule_grouping_check.py",
        description=(
            "Check whether each correlation rule in a tenant export maps "
            "fields to group on, and report what's missing for those that "
            "don't."
        ),
    )
    p.add_argument("--input", "-i", required=True, type=Path,
                   help="JSON/NDJSON file or directory of exports")
    p.add_argument("--output", "-o", type=Path, default=None,
                   help="Write to file instead of stdout")
    p.add_argument("--format", "-f",
                   choices=("text", "json", "csv"), default="text",
                   help="Output format (default: text)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color in text output")
    p.add_argument("--only-broken", action="store_true",
                   help="Show only rules that do not group")
    p.add_argument("--include-disabled", action="store_true",
                   help="Include disabled rules (default: skip them)")
    args = p.parse_args(argv)

    try:
        rules = load_rules(args.input)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not args.include_disabled:
        rules = [r for r in rules if _is_enabled(r)]

    reports = [check_rule(r) for r in rules]
    if args.only_broken:
        reports = [r for r in reports if not r.groups]

    if not reports:
        print("No rules to report.", file=sys.stderr)
        return 0

    if args.format == "text":
        text = render_text(reports, use_color=not args.no_color)
    elif args.format == "json":
        text = render_json(reports)
    else:
        text = render_csv(reports)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")

    return 1 if any(not r.groups for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
