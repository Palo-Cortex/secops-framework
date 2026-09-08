"""Layout button handler: the assessment was correct.

Declares no arguments, so XSIAM runs it on click with no prompt. Confirming a
good assessment should cost one click; the sibling buttons take a note because
"wrong" and "missing context" are only useful with a reason attached.

The feedback value is baked in rather than passed from the button, which is why
there is a script per choice.
"""
import demistomock as demisto
from CommonServerPython import *


def main():
    res = demisto.executeCommand("SOCFWAssessmentFeedback", {"feedback": "correct"})
    if isError(res):
        return_error(f"Could not record feedback: {get_error(res)}")
        return
    return_results(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
