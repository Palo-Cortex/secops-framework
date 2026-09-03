"""Tell the analyst the case is being worked, before the verdict exists.

Case-scoped analysis runs on a schedule and waits for the case to settle, so
there is a window between the first issue arriving and any verdict appearing.
Without a marker the case looks abandoned, and an analyst cannot tell "nothing
has happened yet" from "nothing is going to happen".

Written once per case, not once per issue. The flag is read before writing, so a
case receiving four hundred issues gets one note rather than four hundred.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

STATUS_KEY = 'SOCFramework.Case.Status'


def api(uri, body):
    return demisto.executeCommand('core-api-post',
                                  {'uri': uri, 'body': json.dumps(body)})


def main():
    case_ref = demisto.get(demisto.context(),
                           'parentIncidentContext.incident.parentXDRIncident')
    if not case_ref:
        # Not grouped into a case yet. Nothing to annotate.
        return_results(CommandResults(readable_output=''))
        return

    try:
        res = api(f'/xsoar/public/v1/investigation/{case_ref}/context',
                  {'query': '${%s}' % STATUS_KEY})
        if isinstance(res, list):
            res = res[0] if res else {}
        existing = demisto.get(res, 'Contents.response') or \
            demisto.get(res, 'response')
        if existing:
            return_results(CommandResults(readable_output=''))
            return
    except Exception as e:
        demisto.debug(f'SOCFWCaseStatusNote: could not read case status: {e}')

    note = ('\U0001f7e6 **SOC Framework** — collecting evidence.\n\n'
            '  Each issue in this case is being normalized and enriched as it '
            'arrives.\n'
            '  Case analysis runs once the case stops changing, and posts a '
            'verdict here.')
    try:
        api('/xsoar/public/v1/entry/execute/sync',
            {'investigationId': case_ref,
             'data': f'!Set key={STATUS_KEY} value=collecting'})
        api('/xsoar/public/v1/entry/execute/sync',
            {'investigationId': case_ref, 'data': f'!Print value=`{note}`'})
        return_results(CommandResults(
            readable_output=f'Case status written to {case_ref}.'))
    except Exception as e:
        demisto.debug(f'SOCFWCaseStatusNote: could not write case status: {e}')
        return_results(CommandResults(readable_output=''))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
