"""Layout button handler: the contract was incomplete.

Declares one optional argument so XSIAM opens a prompt with a single text box.
The analyst types why and submits; the note lands on the same row as the verdict
snapshot. A required argument leaves that prompt's Submit disabled, and the
feedback value itself is baked in here rather than passed from the button, which
is why there is a script per choice.
"""
import demistomock as demisto
from CommonServerPython import *


def main():
    note = (demisto.args() or {}).get("note") or ""
    res = demisto.executeCommand("SOCFWAssessmentFeedback",
                                 {"feedback": "missing_context", "note": note})
    if isError(res):
        return_error(f"Could not record feedback: {get_error(res)}")
        return
    return_results(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
