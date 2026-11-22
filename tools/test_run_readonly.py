"""Tests for run_readonly: what it refuses before any call, and which issue it picks."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_readonly import RefusedError, check_read_only, pick_spare_issue  # noqa: E402


@pytest.mark.parametrize("command", [
    "!SOCFWConfig command=status",
    '!SOCFWConfig command=owner job="Auto Triage V3" owner=nobody@example.com',
    "!SOCFWConfig command=shadow action=soc-star-case actor=ai value=off apply=no",
    '!SOCFWConfig command=close comment="apply=yes is only text here"',
    '!getList listName="SOCFWTenantConfig"',
    "!getUsers",
    "!Print value=test",
])
def test_read_only_commands_are_allowed(command):
    """
    Given a command that only reads
    When it is checked
    Then it is allowed
    """
    check_read_only(command)


@pytest.mark.parametrize("command, reason", [
    ("!SOCFWConfig command=shadow action=soc-star-case actor=ai value=off apply=yes", "apply= writes"),
    ("!SOCFWConfig command=set vendor=Zscaler arg=using value=x APPLY=Yes", "apply= writes"),
    ("!SOCFWConfig command=mode mode=pov apply=true", "apply= writes"),
    ('!setList listName="SOCFWTenantConfig" listData="{}"', "setList is not on the read-only list"),
    ("!SOCCommandWrapper action=soc-isolate-endpoint", "SOCCommandWrapper is not on the read-only list"),
    ("SOCFWConfig command=status", "starts with !"),
    ("!SOCFWConfig command=status\n!setList listName=x listData=y", "more than one line"),
    ('!SOCFWConfig command=owner owner="unclosed', "could not read"),
])
def test_anything_that_could_write_is_refused(command, reason):
    """
    Given a command that writes, is not on the read-only list, or cannot be read as one command
    When it is checked
    Then it is refused with the reason, before any call is made
    """
    with pytest.raises(RefusedError, match=reason):
        check_read_only(command)


def test_the_newest_issue_without_a_playbook_is_picked():
    """
    Given issues with and without a playbook, in no particular order
    When the issue to run on is picked
    Then it is the newest one with no playbook attached
    """
    issues = [{"id": "90", "playbookId": ""}, {"id": "120", "playbookId": "EP_IR_NIST - AI"},
              {"id": "105"}, {"id": "99", "playbookId": None}]
    assert pick_spare_issue(issues) == "105"


def test_no_spare_issue_is_refused():
    """
    Given only issues with a playbook attached
    When the issue to run on is picked
    Then it is refused and asks for --issue
    """
    with pytest.raises(RefusedError, match="pass --issue"):
        pick_spare_issue([{"id": "1", "playbookId": "EP_IR_NIST - AI"}])


def test_a_tenant_url_that_is_not_https_is_refused():
    """
    Given tenant credentials whose URL is not https
    When the tool would call the tenant
    Then it refuses before opening anything
    """
    from run_readonly import call
    with pytest.raises(RefusedError, match="must be https://, not file:"):
        call({"DEMISTO_BASE_URL": "file:///etc/passwd", "DEMISTO_API_KEY": "k", "XSIAM_AUTH_ID": "1"},
             "/public/v1/incidents/search", {})
