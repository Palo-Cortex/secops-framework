import demistomock as demisto
from CommonServerPython import *
import json
from datetime import datetime, timezone


def main():
    args = demisto.args()
    incidents = args.get('incidents', [])

    if isinstance(incidents, dict):
        incidents = [incidents]

    if not incidents:
        return_results('No incidents to write to dataset.')
        return

    rows = []
    for inc in incidents:
        rows.append({
            "case_id": inc.get("incident_id", "unknown"),
            "case_name": inc.get("name", ""),
            "aggregated_score": inc.get("aggregated_score"),
            "closed_timestamp": datetime.now(timezone.utc).isoformat(),
            "tag": "auto_triage_closed",
            "value_driver": "VD3"
        })

    # json.dumps handles all escaping — quotes, apostrophes, newlines, tabs
    payload = json.dumps(rows)

    result = execute_command(
        'xql-post-to-dataset',
        {
            'dataset_name': 'xsiam_socfw_ir_execution_raw',
            'data': payload
        }
    )

    return_results(CommandResults(
        readable_output=f'Wrote {len(rows)} auto-triage rows to dataset.'
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
