"""Act on the issue assessment in one playbook step.

EP_IR_NIST - AI used to run five tasks after the AI assessment, one after
another: promote the output, render it, then the emergency, elevate and close
decisions. Each task is its own engine step, and on a busy tenant every step
waits in the queue. This runs the same five scripts, in the same order, with
the same arguments, inside one step.

Each script still writes its own context and decision row. Their War Room
entries are posted again from here so the issue shows what it showed before.
A step that fails does not stop the next one, the same as continue-on-error on
the old tasks; the failure is posted as an error entry.
"""
import demistomock as demisto
from CommonServerPython import *

SOURCE_KEY = "Assessment.AI"

# (script, args, quiet). Promote ran as a quiet task before the merge, so its
# entries stay out of the War Room unless it fails; the rest posted normally.
STEPS = [
    ("SOCFWPromoteAssessment", {"phase": "Assessment", "promote": "true",
                                "source_key": SOURCE_KEY, "target_namespace": "Assessment"}, True),
    ("SOCFWRenderAssessment", {"source_key": SOURCE_KEY}, False),
    ("SOCFWEmergencyResponse", {"source_key": SOURCE_KEY}, False),
    ("SOCFWElevateCase", {"actor": "automation", "source_key": SOURCE_KEY}, False),
    ("SOCFWCloseDecision", {}, False),
]


def repost(entry):
    """A child entry as this script's own. EntryContext is dropped: the steps
    write context themselves, and posting it again would write it twice."""
    return {k: v for k, v in entry.items() if k != "EntryContext"}


def run_steps(execute=None):
    execute = execute or demisto.executeCommand
    entries, failed = [], []
    for script, args, quiet in STEPS:
        try:
            result = execute(script, args) or []
        except Exception as e:  # noqa: BLE001 — one failed step must not stop the rest
            failed.append(script)
            entries.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                            "Contents": f"{script} failed: {type(e).__name__}: {e}"})
            continue
        for entry in result if isinstance(result, list) else [result]:
            if not isinstance(entry, dict):
                continue
            is_error = entry.get("Type") == entryTypes["error"]
            if is_error:
                failed.append(script)
            if is_error or not quiet:
                entries.append(repost(entry))
    return entries, failed


def main():
    entries, failed = run_steps()
    if failed:
        demisto.error(f"SOCFWAssessmentDecisions: failed steps: {', '.join(failed)}")
    return_results(entries)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
