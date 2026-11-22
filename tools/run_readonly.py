#!/usr/bin/env python3
"""Run one read-only War Room command on a tenant issue and print what it returns.

For checking content on a lab tenant without a person typing the command in the
Playground (which, over the API, accepts a command and does nothing). Only
commands that read are run; anything that could change the tenant is refused
before any call is made, so changes stay with the person who owns the tenant.

    povkit exec deathstar -- python3 tools/run_readonly.py '!SOCFWConfig command=status'
    povkit exec deathstar -- python3 tools/run_readonly.py --issue 12345 '!getList listName="SOCFWTenantConfig"'

Without --issue the command runs on the newest issue that has no playbook
attached, so it cannot race a live run. The call is made once: a timed-out
call may still be running on the tenant, and a retry would run it twice.
Exit 1 when the command is refused or returns an error entry.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import urllib.request

# Commands that only read. SOCFWConfig writes only with apply=yes, so it is
# allowed without that argument.
READ_ONLY_COMMANDS = ("SOCFWConfig", "getList", "getUsers", "Print")
ERROR_ENTRY = 4


class RefusedError(Exception):
    """The command is not one this tool runs."""


def check_read_only(command: str) -> None:
    """Refuse anything but one read-only command: one line, an allowed name, and no apply= that writes."""
    if "\n" in command or "\r" in command:
        raise RefusedError("one command per run; it holds more than one line")
    if not command.startswith("!"):
        raise RefusedError("a command starts with !, e.g. !SOCFWConfig command=status")
    try:
        name, *arguments = shlex.split(command[1:])
    except ValueError as e:
        raise RefusedError(f"could not read the command's arguments: {e}") from None
    if name not in READ_ONLY_COMMANDS:
        raise RefusedError(f"{name} is not on the read-only list ({', '.join(READ_ONLY_COMMANDS)}); "
                           "run it yourself")
    for argument in arguments:
        key, _, value = argument.partition("=")
        if key.strip().lower() == "apply" and value.strip().lower() != "no":
            raise RefusedError("apply= writes to the tenant; run it yourself")


def pick_spare_issue(issues: list[dict]) -> str:
    """The id of the newest issue with no playbook attached; a command there cannot race a live run."""
    spare = [i for i in issues if not i.get("playbookId")]
    if not spare:
        raise RefusedError("no issue without a playbook among the newest issues; pass --issue")
    return str(max(spare, key=lambda i: int(i["id"]))["id"])


def call(creds: dict, path: str, payload: dict) -> object:
    """POST to the tenant's /xsoar API with the povkit key. No retry."""
    base = creds["DEMISTO_BASE_URL"].rstrip("/")
    if not base.startswith("https://"):
        raise RefusedError(f"the tenant URL must be https://, not {base.split(':', 1)[0]}:")
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        base + "/xsoar" + path,
        data=json.dumps(payload).encode(),
        headers={"Authorization": creds["DEMISTO_API_KEY"], "x-xdr-auth-id": str(creds["XSIAM_AUTH_ID"]),
                 "Content-Type": "application/json", "Accept": "application/json"},
        method="POST")
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - scheme checked above
        return json.loads(response.read() or b"null")


def entry_text(entry: dict) -> str:
    """An entry's contents as a person would read them in the War Room."""
    contents = entry.get("contents", entry.get("Contents"))
    return contents if isinstance(contents, str) else json.dumps(contents, indent=2)


def main() -> int:
    """Check the command, pick the issue, run the command once and print each entry it returns."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", help="one read-only command, e.g. '!SOCFWConfig command=status'")
    parser.add_argument("--issue", help="the issue to run it on (default: newest with no playbook)")
    args = parser.parse_args()

    try:
        check_read_only(args.command)
    except RefusedError as e:
        print(f"REFUSED  {e}", file=sys.stderr)
        return 1

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from tenant_env import tenant_credentials
    creds = tenant_credentials()

    try:
        issue = args.issue or pick_spare_issue(
            (call(creds, "/public/v1/incidents/search",
                  {"filter": {"page": 0, "size": 100, "sort": [{"field": "id", "asc": False}]}}) or {})
            .get("data") or [])
        entries = call(creds, "/public/v1/entry/execute/sync", {"investigationId": issue, "data": args.command})
    except RefusedError as e:
        print(f"REFUSED  {e}", file=sys.stderr)
        return 1
    print(f"issue {issue}: {args.command}\n")
    failed = False
    for entry in entries or []:
        failed = failed or entry.get("type", entry.get("Type")) == ERROR_ENTRY
        print(entry_text(entry))
        print()
    if not entries:
        print("(no entries returned)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
