"""Write a whole case contract to the parent case in one execution.

Runs inside a member issue of the case. setParentIncidentContext is the only
route that writes case context (!Set inside the case investigation panics), and
it stores every value as a string and every nested object as a JSON string, so a
contract has to go up leaf by leaf for its scalars to be readable as
${SOCFramework.Analysis.AI.verdict}. Doing that from a JOB script meant one HTTP
round trip per leaf - over thirty per case - which is what pushed the verdict
report past the platform's five-minute script limit. Here the loop runs
in-process: the JOB makes one call per case, and this script makes the thirty
writes without leaving the engine.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403


def render(value):
    """The string form of a leaf. Every value lands as a string regardless."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, separators=(',', ':'))
    if value is None:
        return ''
    return str(value)


def main():
    args = demisto.args()
    root = (args.get('root') or 'SOCFramework.Analysis.AI').strip('.')
    raw = args.get('contract')
    try:
        contract = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:
        return_error(f'SOCFWCaseContractWrite: contract is not JSON: {e}')
    if not isinstance(contract, dict) or not contract:
        return_error('SOCFWCaseContractWrite: contract is empty')

    written, failed = [], {}
    for leaf, value in contract.items():
        try:
            res = demisto.executeCommand('setParentIncidentContext',
                                         {'key': f'{root}.{leaf}', 'value': render(value)})
            entry = res[0] if isinstance(res, list) and res else res
            if isinstance(entry, dict) and entry.get('Type') == entryTypes['error']:
                failed[leaf] = str(entry.get('Contents'))[:80]
            else:
                written.append(leaf)
        except Exception as e:
            failed[leaf] = str(e)[:80]

    outputs = {'written': len(written), 'failed': len(failed), 'root': root}
    note = f'{len(written)} leaves written under {root}'
    if failed:
        note += '; failed: ' + ', '.join(f'{k} ({v})' for k, v in failed.items())
    return_results(CommandResults(
        outputs_prefix='SOCFramework.CaseContractWrite',
        outputs=outputs,
        readable_output=note))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
