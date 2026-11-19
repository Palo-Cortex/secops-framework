"""Pin one case to scalar context keys before the AI task runs.

XSIAM runs a task once per element when an argument resolves to an array. The
sub-playbook input accumulates across forEach iterations, so by the fourteenth
case `inputs.Case` is a fourteen-element array and every downstream task fires
fourteen times - a triangular series that produced 118 verdict entries for 16
cases, with later elements rendering under earlier cases' headers.

The fix is to stop passing objects and arrays to tasks. This script takes the
current iteration's case, writes each field to its own scalar key with
setContext, and clears the previous verdict. Everything downstream binds those
scalars, so there is no array left for a task to iterate.

Current means last: an accumulating input appends, so the newest element is this
iteration's.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

FIELDS = ('ID', 'IssueCount', 'Categories', 'Window', 'ShapeCoverage',
          'ContractCoverage', 'ShapeContracts', 'Payload')

# Fields of a previous verdict worth carrying forward. Not the whole contract -
# the story is long and the reasoner should re-derive it, not edit it.
PRIOR_FIELDS = ('verdict', 'confidence', 'response_recommended',
                'compromise_level', 'spread_level', 'primary_entity_name',
                'mitre_tactic', 'issue_count', 'analysed_at')


def current_case(raw):
    """Return the case object for this iteration, from whatever shape arrives."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            return {}
    if isinstance(raw, list):
        raw = raw[-1] if raw else {}
    return raw if isinstance(raw, dict) else {}


def read_prior_verdict(case_id):
    """Read the verdict this case already carries, if any.

    A growing case is re-analysed, and what an analyst wants is not a fresh
    opinion but what changed. Carrying the previous verdict forward lets the
    reasoner say "escalated from suspicious to malicious because C2 appeared on a
    second host" instead of silently replacing one answer with another.

    Reference only. The prompt is instructed to treat the evidence as
    authoritative and reassess independently, or a wrong first verdict anchors
    every run after it.
    """
    try:
        res = demisto.executeCommand('core-api-post', {
            'uri': f'/xsoar/public/v1/investigation/INCIDENT-{case_id}/context',
            'body': json.dumps({'query': '${SOCFramework.Analysis.AI}'}),
        })
        if isinstance(res, list):
            res = res[0] if res else {}
        prior = demisto.get(res, 'Contents.response') or \
            demisto.get(res, 'response') or {}
        if isinstance(prior, list):
            prior = prior[-1] if prior else {}
        if not isinstance(prior, dict) or not prior.get('verdict'):
            return {}
        return {k: prior.get(k) for k in PRIOR_FIELDS if prior.get(k) not in (None, '')}
    except Exception as e:
        demisto.debug(f'SOCFWCaseIterationSetup: no prior verdict readable: {e}')
        return {}


PLAN_PHASES = ('containment', 'eradication', 'recovery')


def action_catalogue():
    """The response actions the plans may name, from SOCFrameworkActions_V3.

    The prompt plans against this catalogue and nothing else, so a plan step can
    only ever name an action the Universal Command knows how to run on this
    tenant. It rides inside the payload rather than as a prompt input, so adding
    or removing an action changes nothing in the prompt configuration.
    """
    try:
        res = demisto.executeCommand('getList', {'listName': 'SOCFrameworkActions_V3'})
        raw = res[0].get('Contents') if isinstance(res, list) and res else res
        actions = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:
        demisto.debug(f'SOCFWCaseIterationSetup: action catalogue unavailable: {e}')
        return []
    out = []
    for name, row in actions.items():
        if not isinstance(row, dict) or row.get('phase') not in PLAN_PHASES:
            continue
        entry = {'action': name, 'phase': row['phase'],
                 'entity_scope': row.get('entity_scope') or ''}
        for flag in ('destroys_evidence', 'reversed_by'):
            if row.get(flag):
                entry[flag] = row[flag]
        out.append(entry)
    return sorted(out, key=lambda a: (a['phase'], a['action']))


def with_catalogue(payload):
    """Add available_actions to the payload JSON string, leaving it untouched on any failure."""
    try:
        obj = json.loads(payload or '{}')
        if not isinstance(obj, dict):
            return payload
        obj['available_actions'] = action_catalogue()
        return json.dumps(obj, separators=(',', ':'))
    except Exception as e:
        demisto.debug(f'SOCFWCaseIterationSetup: payload left without catalogue: {e}')
        return payload


def main():
    case = current_case(demisto.args().get('case'))

    if not case.get('ID'):
        return_error(
            'SOCFWCaseIterationSetup: no case resolved from the iteration input. '
            'The AI task would run with empty variables and return an '
            'inconclusive verdict that reads like reasoning. Stopping instead.')

    # Assign, never append. setContext replaces; command outputs accumulate, and
    # an accumulated key is what makes a downstream task iterate.
    for f in FIELDS:
        value = case.get(f)
        if isinstance(value, (dict, list)):
            value = json.dumps(value, separators=(',', ':'))
        if f == 'Payload':
            value = with_catalogue(value)
        demisto.setContext(f'CaseIter.{f}', value if value is not None else '')

    # Comma-joined scalar, deliberately. An array argument makes XSIAM run the
    # consuming task once per element - the trap that produced 118 entries for
    # 16 cases - so the sibling list travels as a string and is split on arrival.
    sibs = case.get('Siblings') or []
    demisto.setContext(
        'CaseIter.Siblings',
        ','.join(str(x) for x in sibs) if isinstance(sibs, list) else str(sibs or ''))

    prior = read_prior_verdict(case.get('ID'))
    demisto.setContext('CaseIter.PriorVerdict',
                       json.dumps(prior, separators=(',', ':')) if prior else '')

    # Each iteration reasons from scratch. Without this a later case can read an
    # earlier case's verdict, and a re-analysed case keeps its first answer.
    try:
        demisto.executeCommand('DeleteContext', {'key': 'Analysis.AI'})
    except Exception as e:
        demisto.debug(f'SOCFWCaseIterationSetup: could not clear Analysis.AI: {e}')

    shapes = 0
    try:
        shapes = len((json.loads(case.get('Payload') or '{}')).get('shapes') or [])
    except Exception:
        pass

    return_results(CommandResults(
        readable_output=tableToMarkdown('Case pinned for analysis', [{
            'case_id': case.get('ID'),
            'issues': case.get('IssueCount'),
            'shapes': shapes,
            'payload bytes': len(str(case.get('Payload') or '')),
            'prior verdict': prior.get('verdict') or 'none',
        }])))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
