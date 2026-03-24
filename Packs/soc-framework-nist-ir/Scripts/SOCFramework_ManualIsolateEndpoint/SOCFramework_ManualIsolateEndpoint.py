import demistomock as demisto
from CommonServerPython import *


def main():
    args = demisto.args()
    endpoint_id = (args.get("endpoint_id") or "").strip()
    if not endpoint_id:
        ctx = demisto.context()
        endpoint_id = (
            demisto.get(ctx, "SOCFramework.Primary.Endpoint")
            or demisto.get(ctx, "SOCFramework.Artifacts.EndPointID")
            or ""
        )
    if not endpoint_id:
        return_error(
            "SOCFramework_ManualIsolateEndpoint: endpoint ID not found. "
            "Ensure SOCFramework.Primary.Endpoint is set in context."
        )
    result = demisto.executeCommand(
        "SOCCommandWrapper",
        {
            "action": "soc-isolate-endpoint",
            "Action_Actor": "analyst",
            "Phase": "Manual",
            "tags": "Shadow Mode,Manual Action",
        },
    )
    if is_error(result):
        return_error(
            f"SOCFramework_ManualIsolateEndpoint: {get_error(result)}"
        )
    return_results(CommandResults(
        readable_output=(
            f"Isolate request submitted for: `{endpoint_id}`\n"
            "Shadow mode read from SOCFrameworkActions_V3."
        )
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
