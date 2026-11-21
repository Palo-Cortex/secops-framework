"""soc-fix-deps.yml runs with a write token: only trusted people, never a fork, never the PR's own code."""
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "soc-fix-deps.yml"


def _job():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["fix-deps"]


def _step_text(name_part):
    return "\n".join(str(s) for s in _job()["steps"] if name_part in str(s.get("name", "")))


def test_only_the_owner_members_and_collaborators_can_start_it():
    condition = _job()["if"]
    assert "author_association" in condition
    for role in ("OWNER", "MEMBER", "COLLABORATOR"):
        assert role in condition


def test_a_pull_request_from_a_fork_is_refused():
    assert "isCrossRepository" in _step_text("Get PR branch")


def test_the_dependency_tool_runs_from_main_not_from_the_pull_request():
    steps = _job()["steps"]
    trusted = [s for s in steps if s.get("with", {}).get("path") == ".trusted"]
    assert trusted and trusted[0]["with"]["ref"] == "main"
    assert trusted[0]["with"].get("persist-credentials") is False
    run = _step_text("Apply fix or pin")
    assert ".trusted/tools/check_dependency_versions.py" in run
    assert '"tools/check_dependency_versions.py"' not in run
