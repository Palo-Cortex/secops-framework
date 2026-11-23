"""
test_check_contribution_main.py

Characterisation tests for check_contribution.main(): which packs are in scope,
every command the gate runs and in what order, where it halts, the output it
prints and its exit code, compared with a golden file captured from the code
before main() was restructured. The scenarios reach every branch of main.

No tool really runs: subprocess.run is replaced, git diff answers from the
scenario, and a scenario names the commands that fail. Each scenario runs in an
empty directory holding only the packs and tool files it sets up.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest tools/test_check_contribution_main.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_contribution as cc  # noqa: E402

GOLDEN = HERE / "fixtures" / "check_contribution_main_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"
OPTIONAL_TOOLS = ("correlation_rule_preflight.py", "check_issue_field_targets.py", "playbook_condition_lint.py")


def s(*argv: str, **spec: object) -> dict:
    """A scenario: arguments, the packs on disk, what git diff reports, and the commands that fail."""
    return dict({"argv": list(argv), "packs": ["soc-alpha"], "diff": {"ACMR": ["Packs/soc-alpha/Scripts/a.py"]},
                 "fail": [], "tools": list(OPTIONAL_TOOLS), "sdk_errors": None, "files": []}, **spec)


TWO_PACKS = {"ACMR": ["Packs/soc-alpha/Scripts/a.py", "Packs/soc-beta/Lists/b.json", "README.md",
                      "Packs/soc-gone/x.yml", "Packs"],
             "A": ["Packs/soc-beta/Lists/b.json"]}

SCENARIOS = {
    # --input
    "input_missing": s("--input", "Packs/soc-nowhere"),
    "input_not_a_pack": s("--input", "Packs/soc-alpha/Scripts", files=["Packs/soc-alpha/Scripts/a.py"]),
    "input_passes_and_uploads": s("--input", "Packs/soc-alpha"),
    "input_no_upload": s("--input", "Packs/soc-alpha", "--no-upload"),
    "input_normalize_fails": s("--input", "Packs/soc-alpha", fail=["normalize_contribution"]),
    "input_normalize_fails_ci": s("--input", "Packs/soc-alpha", "--ci", fail=["normalize_contribution"]),
    # git diff scope
    "diff_no_packs": s(diff={}),
    "diff_git_unavailable": s(diff=None),
    "diff_nothing_new_skips_normalize": s(),
    "diff_two_packs_one_new": s(packs=["soc-alpha", "soc-beta"], diff=TWO_PACKS),
    "diff_copy_only_pack_is_normalized": s(packs=["soc-alpha", "soc-beta"],
                                           files=["Packs/soc-beta/Playbooks/EP_copy.yml",
                                                  "Packs/soc-beta/Lists/L_copy.json",
                                                  "Packs/no-metadata/Playbooks/X_copy.yml"]),
    "diff_new_and_copy_same_pack": s(diff={"ACMR": ["Packs/soc-alpha/a.yml"], "A": ["Packs/soc-alpha/a.yml"]},
                                     files=["Packs/soc-alpha/Playbooks/P_copy.yml"]),
    "diff_normalize_fails_one_of_two": s(packs=["soc-alpha", "soc-beta"],
                                         diff=dict(TWO_PACKS, A=TWO_PACKS["ACMR"]),
                                         fail=["normalize_contribution.py --input Packs/soc-beta"]),
    "diff_other_base": s("--base", "origin/release", "--no-upload"),
    # Per-pack checks
    "optional_tools_absent": s(tools=[]),
    "sdk_errors_reported": s(sdk_errors="BA101 something", fail=["fix_errors.py"]),
    "sdk_errors_empty": s(sdk_errors=""),
    "pack_prep_fails_ci": s("--ci", fail=["pack_prep.py"]),
    "every_per_pack_check_fails": s(packs=["soc-alpha", "soc-beta"], diff=TWO_PACKS,
                                    fail=["correlation_rule_preflight", "check_issue_field_targets",
                                          "playbook_condition_lint", "check_contracts", "run_pack_tests",
                                          "check_readme_coverage.py Packs/soc-beta"]),
    # Framework-wide checks
    "private_content_fails": s(fail=["check_private_content"]),
    "action_args_fail": s(fail=["check_action_args"]),
    "shadow_mode_fails": s(fail=["validate_shadow_mode"]),
    "docs_drift": s(fail=["prep_docs"]),
    # Upload
    "upload_fails": s(packs=["soc-alpha", "soc-beta"], diff=TWO_PACKS, fail=["upload_package.sh Packs/soc-alpha"]),
    "verify_fails": s(fail=["verify_tenant_content"]),
    "upload_and_verify_fail_ci": s("--ci", fail=["upload_package", "verify_tenant_content"]),
}


def _setup(spec: dict, root: Path) -> None:
    """Lay out the scenario's packs, tool files and loose files under root."""
    for pack in spec["packs"]:
        (root / "Packs" / pack).mkdir(parents=True, exist_ok=True)
        (root / "Packs" / pack / "pack_metadata.json").write_text("{}")
    (root / "tools").mkdir()
    for tool in spec["tools"]:
        (root / "tools" / tool).write_text("")
    if spec["sdk_errors"] is not None:
        (root / "output").mkdir()
        (root / "output" / "sdk_errors.txt").write_text(spec["sdk_errors"])
    for name in spec["files"]:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("")


def _fake_run(spec: dict, calls: list):
    """subprocess.run for the scenario: git diff from the spec, every other command recorded and failed on match."""
    def run(cmd: list, **_kwargs: object) -> subprocess.CompletedProcess:
        words = ["python" if c == sys.executable else str(c) for c in cmd]
        if words[0] == "git":
            if spec["diff"] is None:
                raise subprocess.CalledProcessError(128, cmd)
            diff_filter = words[-1].split("=", 1)[1]
            return subprocess.CompletedProcess(cmd, 0, "\n".join(spec["diff"].get(diff_filter, [])) + "\n", "")
        line = " ".join(words)
        calls.append(line)
        return subprocess.CompletedProcess(cmd, 1 if any(f in line for f in spec["fail"]) else 0)
    return run


def _run(name: str, root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> dict:
    """Run main() once for a scenario and record the commands, the output and the exit code."""
    spec = SCENARIOS[name]
    _setup(spec, root)
    calls: list = []
    monkeypatch.chdir(root)
    monkeypatch.setattr(cc, "_TTY", False)
    monkeypatch.setattr(cc.subprocess, "run", _fake_run(spec, calls))
    monkeypatch.setattr(sys, "argv", ["check_contribution.py", *spec["argv"]])
    with pytest.raises(SystemExit) as stopped:
        cc.main()
    # The gate prints each command, so the interpreter path is replaced as it is in calls.
    output = capsys.readouterr().out.replace(sys.executable, "python").splitlines()
    return {"exit": stopped.value.code, "calls": calls, "output": output}


def _golden() -> dict:
    """The recorded outcome of every scenario."""
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_main_matches_golden(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                             capsys: pytest.CaptureFixture) -> None:
    """
    Given a branch, its packs and tools, and the checks that fail
    When the contribution gate runs
    Then the commands it runs, its output and its exit code match the golden file
    """
    got = _run(name, tmp_path, monkeypatch, capsys)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False, sort_keys=True) == \
        json.dumps(_golden()[name], ensure_ascii=False, sort_keys=True)


def test_golden_has_no_stale_scenarios() -> None:
    """
    Given the golden file
    When its scenario names are compared with this file's
    Then each golden entry still has a scenario that produces it
    """
    assert set(_golden()) <= set(SCENARIOS)
