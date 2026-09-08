"""Layout button handler: the assessment was correct.

The note is optional here. An analyst confirming a good assessment should not
have to justify it, and a required argument leaves the prompt's Submit disabled.
The feedback value is baked in rather than passed from the button, which is why
there is a script per choice.
"""
import demistomock as demisto
from CommonServerPython import *


def main():
    note = (demisto.args() or {}).get("note") or ""
    res = demisto.executeCommand("SOCFWAssessmentFeedback",
                                 {"feedback": "correct", "note": note})
    if isError(res):
        return_error(f"Could not record feedback: {get_error(res)}")
        return
    return_results(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
