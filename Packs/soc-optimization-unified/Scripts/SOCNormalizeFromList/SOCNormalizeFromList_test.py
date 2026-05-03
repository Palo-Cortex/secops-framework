"""
SOCNormalizeFromList_test
=========================
Standalone tests for the pure phase functions. Runs without XSIAM / demisto-sdk
by mocking demisto.* and importing only the pure helpers.

USAGE
    python3 SOCNormalizeFromList_test.py

WHAT IT VERIFIES
  - Source expression parsing: 'X' and 'X.[N]' both resolve correctly
  - Empty-source skipping (mappings only)
  - Stamps always write, including empty strings
  - Branched stamps filter by normalization_source
  - Mirrors read from the in-script accumulator (mappings just written)
  - End-to-end against the real SOCFrameworkNormalizeMap_V3 payload
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Stub `demisto` so we can import the module without sdk
class _Demisto:
    def debug(self, *a, **kw): pass
    def args(self): return {}
    def incident(self): return {}
    def executeCommand(self, *a, **kw): return [{"Contents": "{}"}]
    def setContext(self, *a, **kw): pass
demisto = _Demisto()
def return_error(msg): raise RuntimeError(msg)
def return_results(x): pass
class CommandResults:
    def __init__(self, **kw): self.kw = kw

# Inject into builtins so the module's top-level demisto.debug works
import builtins
builtins.demisto = demisto
builtins.return_error = return_error
builtins.return_results = return_results
builtins.CommandResults = CommandResults

sys.path.insert(0, str(Path(__file__).parent))
from SOCNormalizeFromList import (
    read_source, is_empty,
    apply_mappings, apply_stamps, apply_mirrors,
)

PASS, FAIL = "✓", "✗"
fails = []

def check(label, got, want):
    ok = got == want
    print(f"  {PASS if ok else FAIL} {label}")
    if not ok:
        fails.append((label, got, want))


# --- read_source ---
print("read_source:")
check("plain field", read_source({"x": "hello"}, "x"), "hello")
check("missing field", read_source({}, "x"), None)
check("indexed [0]", read_source({"x": ["a", "b"]}, "x.[0]"), "a")
check("indexed [1]", read_source({"x": ["a", "b"]}, "x.[1]"), "b")
check("indexed out of range", read_source({"x": ["a"]}, "x.[5]"), None)
check("indexed but not array", read_source({"x": "scalar"}, "x.[0]"), None)
check("indexed missing field", read_source({}, "x.[0]"), None)
check("dotted name not array", read_source({"a.b": "v"}, "a.b"), "v")

# --- is_empty ---
print("is_empty:")
check("None", is_empty(None), True)
check("empty str", is_empty(""), True)
check("empty list", is_empty([]), True)
check("empty dict", is_empty({}), True)
check("zero", is_empty(0), False)  # 0 is meaningful
check("False", is_empty(False), False)  # bool False is meaningful
check("populated str", is_empty("x"), False)

# --- apply_mappings ---
print("apply_mappings:")
section = {"mappings": [
    {"target": "Endpoint.hostname", "issue_field": "hostname", "shape": "flat"},
    {"target": "Artifacts.Process.PID", "issue_field": "pid.[0]", "shape": "structured"},
    {"target": "Endpoint.empty_field", "issue_field": "missing", "shape": "flat"},
]}
custom = {"hostname": "host1.local", "pid": [4242, 4243]}
writes, skipped = {}, {"empty": [], "filtered": []}
apply_mappings(section, custom, writes, skipped)
check("plain mapping written", writes.get("Endpoint.hostname"), "host1.local")
check("indexed mapping written", writes.get("Artifacts.Process.PID"), 4242)
check("missing field skipped", "Endpoint.empty_field" not in writes, True)
check("skipped count = 1", len(skipped["empty"]), 1)

# --- apply_stamps ---
print("apply_stamps:")
section = {"stamps": [
    {"target": "Endpoint.normalization_source", "value": "endpoint"},
    {"target": "Artifacts.Process.Verdict", "value": ""},  # empty stamp must write
]}
writes, skipped = {}, {"empty": [], "filtered": []}
apply_stamps(section, None, writes, skipped)
check("single stamp writes value", writes.get("Endpoint.normalization_source"), "endpoint")
check("empty-string stamp writes", "Artifacts.Process.Verdict" in writes, True)
check("empty-string stamp value is ''", writes["Artifacts.Process.Verdict"], "")

# --- apply_stamps with branching ---
print("apply_stamps (branched):")
section = {"stamps": [
    {"target": "Email.normalization_source", "value": "email"},
    {"target": "Email.normalization_source", "value": "mail_listener"},
]}

# No filter → skip
writes, skipped = {}, {"empty": [], "filtered": []}
apply_stamps(section, None, writes, skipped)
check("branched stamp without filter is skipped", "Email.normalization_source" not in writes, True)
check("filtered count = 1", len(skipped["filtered"]), 1)

# With matching filter → write
writes, skipped = {}, {"empty": [], "filtered": []}
apply_stamps(section, "mail_listener", writes, skipped)
check("branched stamp with matching filter writes", writes.get("Email.normalization_source"), "mail_listener")

# With non-matching filter → skip
writes, skipped = {}, {"empty": [], "filtered": []}
apply_stamps(section, "garbage", writes, skipped)
check("branched stamp with non-matching filter skipped", "Email.normalization_source" not in writes, True)

# --- apply_mirrors ---
print("apply_mirrors:")
section = {"mirrors": [
    {"target": "Artifacts.Email.From", "source": "Email.sender"},
    {"target": "Artifacts.Email.Missing", "source": "Email.missing"},
]}
writes = {"Email.sender": "alice@example.com"}
skipped = {"empty": [], "filtered": []}
apply_mirrors(section, writes, skipped)
check("mirror copies from in-script writes", writes.get("Artifacts.Email.From"), "alice@example.com")
check("mirror with empty source skipped", "Artifacts.Email.Missing" not in writes, True)


# --- END-TO-END against real SOCFrameworkNormalizeMap_V3_data.json ---
print("end-to-end (real list payload):")
LIST_PATH = Path(__file__).parents[2] / "Lists" / "SOCFrameworkNormalizeMap_V3" / "SOCFrameworkNormalizeMap_V3_data.json"
list_data = json.loads(LIST_PATH.read_text())

# Synthetic incident exercising endpoint normalizer
endpoint_custom = {
    "agent_hostname": "DESKTOP-ABC",
    "agent_id": "agent-uuid-001",
    "ostype": "Windows 10",
    "action_local_ip": "10.0.0.5",
    "agentid": "agent-uuid-001",
    "hostname": "desktop-abc.corp",
    "filesha256": ["abc123sha256deadbeef", "second-sha"],
    "filepath": ["/tmp/malware.exe"],
    "initiatorpid": [4242],
    "initiatedby": ["powershell.exe"],
    "hostip": ["10.0.0.5", "192.168.1.1"],
    "username": ["alice"],
    "module": ["xdr"],
    "action": ["BLOCKED"],
}
section = list_data["endpoint"]
writes, skipped = {}, {"empty": [], "filtered": []}
apply_mappings(section, endpoint_custom, writes, skipped)
apply_stamps(section, None, writes, skipped)
apply_mirrors(section, writes, skipped)

# Check key writes
check("E2E: Endpoint.hostname populated", writes.get("Endpoint.hostname"), "DESKTOP-ABC")
check("E2E: Artifacts.Hash takes [0]", writes.get("Artifacts.Hash"), "abc123sha256deadbeef")
check("E2E: Artifacts.Process.PID takes [0]", writes.get("Artifacts.Process.PID"), 4242)
check("E2E: Artifacts.Process.Name takes [0]", writes.get("Artifacts.Process.Name"), "powershell.exe")
check("E2E: stamp writes normalization_source", writes.get("Endpoint.normalization_source"), "endpoint")
check("E2E: empty Verdict stamp writes ''", writes.get("Artifacts.Process.Verdict"), "")

# Synthetic email incident
email_custom = {
    "emailsender": "phisher@evil.example",
    "emailrecipient": "victim@corp.example",
    "emailsubject": "URGENT: click now",
    "emailmessageid": "<msg-id-xyz>",
    "socfwemailthreattype": "phish",
    "socfwemailthreaturl": "http://evil.example/login",
}
section = list_data["email"]
writes, skipped = {}, {"empty": [], "filtered": []}
apply_mappings(section, email_custom, writes, skipped)
apply_stamps(section, "email", writes, skipped)  # specify branch
apply_mirrors(section, writes, skipped)

check("E2E email: flat sender from issue.emailsender", writes.get("Email.sender"), "phisher@evil.example")
check("E2E email: branched stamp wrote 'email'", writes.get("Email.normalization_source"), "email")
check("E2E email: mirror Artifacts.Email.From from Email.sender", writes.get("Artifacts.Email.From"), "phisher@evil.example")
check("E2E email: mirror Artifacts.Email.MessageID", writes.get("Artifacts.Email.MessageID"), "<msg-id-xyz>")
check("E2E email: mirror skipped if source empty (no Subject ever set)",
      writes.get("Artifacts.Email.Subject"), "URGENT: click now")  # subject is set, so this should populate

# --- Summary ---
print()
if fails:
    print(f"{FAIL} {len(fails)} test(s) failed:")
    for label, got, want in fails:
        print(f"    {label}: got={got!r} want={want!r}")
    sys.exit(1)
print(f"{PASS} all tests passed")
