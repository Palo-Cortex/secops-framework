"""One line of standing guidance under the containment buttons.

A layout has no static-text section, and a button presents its options in the
War Room with nothing on the tab to say so. This is the smallest thing that puts
that where the analyst is looking when they click.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

HINT = (
    "<div style='font-size:12px;color:#777;padding:6px 2px;line-height:1.5;'>"
    "Options open in the <b>War Room</b> tab. Only actions with a reachable "
    "integration and complete arguments are offered; anything unavailable is "
    "listed there with the reason."
    "</div>"
)

if __name__ in ("__builtin__", "builtins", "__main__"):
    return_results({"ContentsFormat": formats["html"],
                    "Type": entryTypes["note"], "Contents": HINT})
