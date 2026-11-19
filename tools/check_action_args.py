#!/usr/bin/env python3
"""Fail when an action names a vendor command or argument the vendor does not have.

Holds every response in ``SOCFrameworkActions_V3`` to ``policies/vendor_command_specs.json``
(built from demisto/content by ``tools/build_command_specs.py``):

  * the command must be defined by some integration or script, or be listed under
    ``unverified`` in the spec file with a reason
  * every argument name must be one the command takes (``using`` and the other
    platform arguments are always allowed)
  * every required argument without a default must be sent
  * a literal value (no ``${...}``) for an argument with a fixed set of values must
    be one of them
  * ``target_arg`` and every ``required_args`` entry must name an argument the
    response sends (the wrapper reads them by name)

The platform runs a command by its name, so the brand label on a response is not
checked. Where several integrations define a command, the response passes if it
fits the one whose id matches its brand label, or else any one that is not
deprecated. A response that only fits a deprecated integration is reported as a
warning, not a failure.

Exit 1 on any failure, 0 otherwise. Runs in ``check_contribution.py`` and the PR gate.

Usage::

    python3 tools/check_action_args.py
    python3 tools/check_action_args.py --verbose   # also list every response that passes
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTIONS = REPO_ROOT / "Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/SOCFrameworkActions_V3_data.json"
SPECS = REPO_ROOT / "policies" / "vendor_command_specs.json"
PLATFORM_BRANDS = {"Builtin"}
PLATFORM_ARGS = {"using", "execution-timeout", "extend-context", "ignore-outputs",
                 "retry-count", "retry-interval", "raw-response"}


def problems_against(definition: dict, inline_args: dict) -> list[str]:
    spec = definition.get("args") or {}
    given = {k: v for k, v in inline_args.items() if k not in PLATFORM_ARGS}
    out = [f"'{k}' is not an argument of this command" for k in sorted(set(given) - set(spec))]
    out += [f"required argument '{k}' is not sent" for k, a in sorted(spec.items())
            if a.get("required") and "default" not in a and k not in given]
    for k, v in sorted(given.items()):
        allowed = (spec.get(k) or {}).get("allowed")
        if allowed and isinstance(v, str) and v and "${" not in v and v not in allowed:
            out.append(f"'{k}' is '{v}'; the command takes one of {allowed}")
    return out


def check_response(brand: str, resp: dict, specs: dict) -> tuple[str, list[str]]:
    """('ok' | 'deprecated' | 'unverified' | 'fail', details)."""
    cmd = resp.get("command")
    args = resp.get("inline_args") or {}
    # The wrapper's pointers into inline_args must point at something.
    dangling = []
    target = resp.get("target_arg")
    if target and target not in args:
        dangling.append(f"target_arg '{target}' is not one of the response's arguments")
    dangling += [f"required_args names '{k}', which the response does not send"
                 for k in resp.get("required_args") or [] if k not in args]
    if dangling:
        return "fail", dangling
    defs = (specs.get("commands") or {}).get(cmd)
    if not defs:
        reason = (specs.get("unverified") or {}).get(cmd)
        if reason:
            return "unverified", [reason]
        return "fail", [f"command '{cmd}' is not defined by any integration or script in "
                        f"{specs.get('source', 'the spec file')}"]
    named = [d for d in defs if d.get("source") == brand]
    pool = named or [d for d in defs if not d.get("deprecated")] or defs
    results = [(d, problems_against(d, args)) for d in pool]
    fitting = [d for d, p in results if not p]
    if any(not d.get("deprecated") for d in fitting):
        return "ok", []
    if fitting:
        return "deprecated", [f"fits only {fitting[0]['source']}, which is deprecated"]
    best, probs = min(results, key=lambda x: len(x[1]))
    return "fail", [f"against {best['source']}: {p}" for p in probs]


def check(actions: dict, specs: dict) -> dict[str, list]:
    report: dict[str, list] = {"fail": [], "deprecated": [], "unverified": [], "ok": []}
    for action, entry in sorted(actions.items()):
        if not isinstance(entry, dict):
            continue
        for brand, resp in (entry.get("responses") or {}).items():
            if brand in PLATFORM_BRANDS or not isinstance(resp, dict):
                continue
            status, details = check_response(brand, resp, specs)
            report[status].append((action, brand, resp.get("command"), details))
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    report = check(json.loads(ACTIONS.read_text()), json.loads(SPECS.read_text()))

    for status, label in (("fail", "FAIL"), ("deprecated", "WARN"), ("unverified", "UNVERIFIED")):
        for action, brand, cmd, details in report[status]:
            print(f"{label}  {action} | {brand} | {cmd}")
            for d in details:
                print(f"        {d}")
    if args.verbose:
        for action, brand, cmd, _ in report["ok"]:
            print(f"ok    {action} | {brand} | {cmd}")
    counts = {k: len(v) for k, v in report.items()}
    print(f"check_action_args: {counts['ok']} ok, {counts['fail']} failing, "
          f"{counts['deprecated']} on deprecated integrations, {counts['unverified']} unverified")
    return 1 if report["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
