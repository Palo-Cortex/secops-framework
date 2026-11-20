"""
SOCFWPrintWarRoom_test.py

Characterization tests: the issue War Room exported verbatim to one printable
HTML file. Entries are read once, unpaged, with the bare issue id; sorted
oldest first; capped with the cap stated; every body escaped; each entry
attributed to its user or else the playbook and task that wrote it; long
bodies truncated with the omission stated. No issue, or no entries, writes no
file and says why.

Run: pytest Scripts/SOCFWPrintWarRoom/SOCFWPrintWarRoom_test.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class Stop(Exception):
    """return_error ends the script on the tenant; here it raises."""


class DemistoException(Exception):
    pass


demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.DemistoException = DemistoException
csp.is_error = lambda entry: isinstance(entry, dict) and entry.get("Type") == 4
csp.get_error = lambda entry: entry.get("Contents")
csp.fileResult = lambda name, data: {"File": name, "Data": data}


def _return_error(msg):
    raise Stop(msg)


csp.return_error = _return_error
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWPrintWarRoom as pw  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


ISSUE = {"id": "20597", "name": "Masquerading <svchost>", "severity": 3, "status": 1,
         "owner": "", "created": "2026-11-20T22:30:00Z"}


def entry(created, contents="text", **extra):
    e = {"created": created, "contents": contents, "type": 1}
    e.update(extra)
    return e


class Tenant:
    def __init__(self):
        self.entries = []
        self.calls = []
        self.files = []
        self.results = []
        self.read_fails = False
        self.users = [{"Type": 1, "Contents": [{"email": "analyst@x"}]}]

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        if cmd == "core-api-post":
            if self.read_fails:
                return [{"Type": 4, "Contents": "403 forbidden"}]
            return [{"Type": 1, "Contents": {"response": {"entries": self.entries}}}]
        if cmd == "getUsers":
            if isinstance(self.users, Exception):
                raise self.users
            return self.users
        return [{"Type": 1, "Contents": None}]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "incident", lambda: dict(ISSUE), raising=False)
    monkeypatch.setattr(demisto, "results", tn.files.append, raising=False)
    monkeypatch.setattr(pw, "return_results", tn.results.append, raising=False)
    return tn


def page(t):
    assert len(t.files) == 1
    return t.files[0]["Data"].decode("utf-8")


# ── reading the War Room ─────────────────────────────────────────────────────

def test_entries_are_read_once_unpaged_with_the_bare_id(t):
    t.entries = [entry("2026-11-20T22:31:00Z")]
    pw.fetch_entries("20597")
    posts = [a for c, a in t.calls if c == "core-api-post"]
    assert posts == [{"uri": "/xsoar/public/v1/investigation/20597", "body": "{}"}]


def test_entries_come_back_oldest_first(t):
    t.entries = [entry("2026-11-20T22:33:00Z", "c"), entry("", "a"), entry("2026-11-20T22:31:00Z", "b")]
    got, truncated = pw.fetch_entries("1")
    assert [e["contents"] for e in got] == ["a", "b", "c"] and truncated is None


@pytest.mark.parametrize("reply", [
    {"Contents": {"entries": [{"contents": "x"}]}},
    {"response": {"entries": [{"contents": "x"}]}},
    {"entries": [{"contents": "x"}]},
])
def test_entries_are_found_wherever_the_reply_puts_them(t, monkeypatch, reply):
    monkeypatch.setattr(pw, "api", lambda uri, body: [reply])
    assert len(pw.fetch_entries("1")[0]) == 1


def test_over_the_cap_is_cut_and_says_so(t, monkeypatch):
    monkeypatch.setattr(pw, "MAX_ENTRIES", 3)
    t.entries = [entry(f"2026-11-20T22:3{i}:00Z", str(i)) for i in range(5)]
    got, truncated = pw.fetch_entries("1")
    assert [e["contents"] for e in got] == ["0", "1", "2"]
    assert truncated == ("Entry cap reached: this issue has 5 entries and only the first 3 "
                         "are included. This export is incomplete.")


def test_a_failed_read_raises(t):
    t.read_fails = True
    with pytest.raises(DemistoException, match="403 forbidden"):
        pw.fetch_entries("1")


# ── one entry ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("e,expected", [
    ({"contents": "  plain  "}, "plain"),
    ({"contents": "", "readableContents": "shown"}, "shown"),
    ({"contents": None}, ""),
    ({"contents": {"a": 1}}, '{\n  "a": 1\n}'),
    ({"contents": [1, 2]}, "[\n  1,\n  2\n]"),
])
def test_an_entry_body_becomes_text(e, expected):
    assert pw.entry_text(e) == (expected, False)


def test_a_long_entry_is_cut_and_says_so(monkeypatch):
    monkeypatch.setattr(pw, "MAX_ENTRY_CHARS", 10)
    text, cut = pw.entry_text({"contents": "x" * 25})
    assert cut and text.startswith("x" * 10)
    assert "[... 15 characters omitted from this entry. The full text is in the War Room on the issue.]" in text


@pytest.mark.parametrize("value,expected", [
    ("2026-11-20T22:31:05Z", "2026-11-20 22:31:05 UTC"),
    ("2026-11-20T17:31:05-05:00", "2026-11-20 22:31:05 UTC"),
    ("", "(no timestamp)"),
    (None, "(no timestamp)"),
    ("not a time", "not a time"),
])
def test_timestamps_are_utc_or_left_as_they_came(value, expected):
    assert pw.ts(value) == expected


def test_escaping_covers_markup_and_quotes():
    assert pw.esc('<b a="1">&</b>') == "&lt;b a=&quot;1&quot;&gt;&amp;&lt;/b&gt;"
    assert pw.esc(None) == ""


# ── who pressed it ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("users,expected", [
    ([{"Type": 1, "Contents": [{"email": "a@x", "username": "u"}]}], "a@x"),
    ([{"Type": 1, "Contents": [{"username": "u"}]}], "u"),
    ([{"Type": 1, "Contents": [{"name": "N"}]}], "N"),
    ([{"Type": 1, "Contents": [{}]}], "unknown"),
    ([{"Type": 1, "Contents": []}], "unknown"),
    ([{"Type": 4, "Contents": "denied"}], "unknown"),
    (RuntimeError("no"), "unknown"),
])
def test_the_exporter_is_named_when_the_platform_says_who(t, users, expected):
    t.users = users
    assert pw.current_user() == expected


# ── the page ─────────────────────────────────────────────────────────────────

def test_every_entry_is_on_the_page_in_order_and_escaped(t):
    t.entries = [
        entry("2026-11-20T22:32:00Z", "second <script>alert(1)</script>", user="analyst@x"),
        entry("2026-11-20T22:31:00Z", {"cmd": "powershell -enc <x>"}),
    ]
    pw.main()
    html = page(t)
    assert html.index("1.</span>2026-11-20 22:31:00 UTC") < html.index("2.</span>2026-11-20 22:32:00 UTC")
    assert "<script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "powershell -enc &lt;x&gt;" in html
    assert "Masquerading &lt;svchost&gt;" in html


@pytest.mark.parametrize("e,who", [
    (dict(user="analyst@x"), "analyst@x"),
    (dict(modified_by="lead@x"), "lead@x"),
    (dict(entryTask={"playbookName": "EP_IR_NIST - AI", "taskName": "Close Decision"}),
     "EP_IR_NIST - AI / Close Decision"),
    (dict(entryTask={"playbookName": "EP_IR_NIST - AI"}), "EP_IR_NIST - AI"),
    (dict(entryTask={"taskName": "Close Decision"}), "Close Decision"),
    ({}, "automation"),
])
def test_entries_without_a_user_are_attributed_to_their_playbook_and_task(t, e, who):
    t.entries = [entry("2026-11-20T22:31:00Z", **e)]
    pw.main()
    assert f"&mdash; {pw.esc(who)} <span" in page(t)


@pytest.mark.parametrize("e,kind", [
    (dict(type=4), "(error)"),
    (dict(type=99), "(type 99)"),
    (dict(type=1, category="artifact"), "(note, artifact)"),
    (dict(type=13, category="playbook"), "(playbook)"),
])
def test_each_entry_is_labelled_by_type_and_category(t, e, kind):
    t.entries = [dict(entry("2026-11-20T22:31:00Z"), **e)]
    pw.main()
    assert f'<span class="kind">{kind}</span>' in page(t)


def test_tags_empty_entries_and_long_entries_are_marked(t):
    t.entries = [
        entry("2026-11-20T22:31:00Z", "verdict", tags=["socfw-case-verdict", "socfw-superseded"]),
        entry("2026-11-20T22:32:00Z", ""),
        entry("2026-11-20T22:33:00Z", "\n".join(["line"] * 40)),
    ]
    pw.main()
    html = page(t)
    assert '<p class="tags">tags: socfw-case-verdict, socfw-superseded</p>' in html
    assert '<p class="empty">(empty entry)</p>' in html
    assert html.count('<section class="entry long">') == 1


def test_the_cover_names_the_issue_and_the_exporter(t):
    t.entries = [entry("2026-11-20T22:31:00Z")]
    pw.main()
    html = page(t)
    assert "<tr><th>Issue ID</th><td>20597</td></tr>" in html
    assert "<tr><th>Owner</th><td>unassigned</td></tr>" in html
    assert "<tr><th>Closed</th><td>not closed</td></tr>" in html
    assert "<tr><th>Entries</th><td>1</td></tr>" in html
    assert "<tr><th>Exported by</th><td>analyst@x</td></tr>" in html
    assert "INCOMPLETE EXPORT" not in html


def test_the_page_is_self_contained(t):
    t.entries = [entry("2026-11-20T22:31:00Z")]
    pw.main()
    html = page(t)
    assert html.startswith("<!DOCTYPE html>") and "<style>" in html
    for fetched in ("<script", "<link", "src=", "@import", "url("):
        assert fetched not in html


def test_a_capped_export_is_marked_incomplete_on_the_page_and_in_the_note(t, monkeypatch):
    monkeypatch.setattr(pw, "MAX_ENTRIES", 1)
    t.entries = [entry("2026-11-20T22:31:00Z"), entry("2026-11-20T22:32:00Z")]
    pw.main()
    assert "<strong>INCOMPLETE EXPORT.</strong>" in page(t)
    assert "🟠 Entry cap reached" in t.results[-1]["readable_output"]


# ── main ─────────────────────────────────────────────────────────────────────

def test_the_file_is_named_for_the_issue_and_the_note_says_where_it_is(t):
    t.entries = [entry("2026-11-20T22:31:00Z")]
    pw.main()
    name = t.files[0]["File"]
    assert name.startswith("WarRoom_Issue-20597_") and name.endswith("Z.html")
    out = t.results[-1]["readable_output"]
    assert out.startswith("✅ **Print War Room** - 1 entries exported to") and f"`{name}`" in out


def test_no_issue_writes_no_file_and_says_why(t, monkeypatch):
    monkeypatch.setattr(demisto, "incident", lambda: None, raising=False)
    pw.main()
    assert t.files == [] and not [c for c, a in t.calls if c == "core-api-post"]
    assert "no issue in scope" in t.results[-1]["readable_output"]


def test_no_entries_is_no_export_not_an_empty_one(t):
    pw.main()
    assert t.files == []
    out = t.results[-1]["readable_output"]
    assert "returned no entries" in out and "this is not an empty export, it is no export" in out


def test_a_failed_read_stops_with_the_reason(t):
    t.read_fails = True
    with pytest.raises(Stop, match="SOCFWPrintWarRoom failed: 403 forbidden"):
        pw.main()
    assert t.files == []
