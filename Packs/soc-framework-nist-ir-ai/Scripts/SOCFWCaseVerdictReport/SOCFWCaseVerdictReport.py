"""Render one case verdict to the War Room and build its execution row.

Runs inside SOC Case Analysis Phase, after the AI task, once per case. Two jobs:
the operator-facing entry, and the dataset row that carries the verdict.

The row has to be built here rather than in SOCFWBuildCasePayload, because that
runs before the analysis and can only describe what was sent, never what was
concluded.

War Room rendering facts this relies on: markdown and emoji render, HTML does
not, whitespace is preserved in a monospace face so columns align, and an entry
past roughly 25-30 lines trips the truncation warning. The story array is the
part analysts read, so it gets the line budget and everything else is kept tight.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

VERDICT_MARK = {
    'malicious': '🔴',
    'suspicious': '🟠',
    'benign': '🟢',
    'inconclusive': '⚪',
}

CONFIDENCE_MARK = {'high': '●●●', 'medium': '●●○', 'low': '●○○'}

# Past this the entry trips XSIAM's Partial View truncation.
MAX_STORY_LINES = 12


VERDICT_TAG = 'socfw-case-verdict'
SUPERSEDED_TAG = 'socfw-superseded'


def api(uri, body):
    """POST to the XSOAR API from inside a playbook via the Core REST API."""
    return demisto.executeCommand('core-api-post',
                                  {'uri': uri, 'body': json.dumps(body)})


def supersede_prior(case_id):
    """Mark earlier verdict entries on this case as superseded.

    Entries cannot be deleted - the delete endpoints return 303 - so the current
    verdict is made findable by tag instead. Without this a re-analysed case
    accumulates verdicts with no indication which one is live.
    """
    inv = f'INCIDENT-{case_id}'
    tagged = 0
    try:
        res = api(f'/xsoar/public/v1/investigation/{inv}', {'pageSize': 200, 'page': 0})
        if isinstance(res, list):
            res = res[0] if res else {}
        entries = demisto.get(res, 'Contents.response.entries') or \
            demisto.get(res, 'response.entries') or []
        for e in entries:
            tags = e.get('tags') or []
            if VERDICT_TAG in tags and SUPERSEDED_TAG not in tags:
                api('/xsoar/public/v1/entry/tags',
                    {'id': e.get('id'), 'investigationId': inv,
                     'tags': tags + [SUPERSEDED_TAG]})
                tagged += 1
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: could not supersede prior entries: {e}')
    return tagged


def load_analysis_contract():
    """Return the analysis write targets declared by SOCFrameworkPhaseContract_V3.

    The field list is not this script's to choose. Hard-coding it creates a
    second definition of the analysis contract that drifts the first time the
    schema changes; reading it means a new field propagates by re-emitting the
    List, with no code change here.
    """
    try:
        raw = demisto.executeCommand('getList',
                                     {'listName': 'SOCFrameworkPhaseContract_V3'})
        if isinstance(raw, list):
            raw = raw[0] if raw else {}
        contents = raw.get('Contents')
        d = json.loads(contents) if isinstance(contents, str) else contents
        return (d.get('writes_by_phase') or {}).get('analysis') or []
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: phase contract unreadable: {e}')
        return []


def write_case_contract(case_id, ai, case, payload):
    """Write the case-scoped analysis contract to the case context.

    Seeded from the phase contract so every declared target exists with its typed
    init value. That preserves the absent / at-init / populated distinction:
    Containment can tell "analysis never ran" from "analysis ran and found
    nothing", which a sparse dict would collapse.

    The prompt produces 17 of the 22 declared targets. The rest are deterministic
    case facts, and Containment reads two of them - case_score and
    case_host_count - so a contract built from AI output alone would hand it
    empties.
    """
    spec = load_analysis_contract()
    if not spec:
        return False, 'phase contract unavailable'

    # Deterministic targets, from the case record rather than the model.
    deterministic = {
        'Analysis.case_issue_count': case.get('IssueCount'),
        'Analysis.case_host_count': len(payload.get('hosts') or []),
        'Analysis.case_user_count': payload.get('user_count'),
        'Analysis.case_score': payload.get('predicted_score'),
        'Analysis.global_hash_prevalence_count': len(payload.get('file_hashes') or []),
    }

    contract = {}
    populated = 0
    for w in spec:
        target = w.get('target') or ''
        leaf = target.split('.', 1)[1] if '.' in target else target
        value = w.get('init')
        if target in deterministic and deterministic[target] is not None:
            value = deterministic[target]
            populated += 1
        elif leaf in ai and ai.get(leaf) not in (None, ''):
            value = ai.get(leaf)
            populated += 1
        contract[leaf] = value

    contract['analysed_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    contract['analysed_by'] = 'ai'

    # Shadow: the AI verdict lands under Analysis.AI on the case, not bare
    # Analysis. There is no deterministic case producer to compare against yet,
    # so writing to Analysis would make the first AI output authoritative by
    # default. Promotion is SOCPromoteAIPhaseOutput's decision, not this one.
    inv = f'INCIDENT-{case_id}'
    blob = json.dumps(contract, separators=(',', ':'))
    try:
        # Delete first - Set appends on repeat, which would turn verdict into an
        # array on the second analysis and break every consumer.
        api('/xsoar/public/v1/entry/execute/sync',
            {'investigationId': inv, 'data': '!DeleteContext key=SOCFramework.Analysis.AI'})
        api('/xsoar/public/v1/entry/execute/sync',
            {'investigationId': inv,
             'data': f'!Set key=SOCFramework.Analysis.AI value=`{blob}`'})
        return True, f'{populated}/{len(spec)} targets populated'
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: case contract write failed: {e}')
        return False, str(e)[:100]


def post_to_case(case_id, markdown):
    """Write the verdict entry to the case's own War Room.

    The JOB runs in its own investigation, so a return_results here lands where
    no analyst looks. A case investigation accepts entries addressed as
    INCIDENT-<case_id>, and core-api-post reaches it from inside the JOB.

    Never fatal. A case that cannot be written to still has its dataset row and
    its entry in the JOB War Room.
    """
    payload = json.dumps({
        'investigationId': f'INCIDENT-{case_id}',
        'data': markdown,
    })
    try:
        demisto.executeCommand('core-api-post', {
            'uri': '/xsoar/public/v1/entry/execute/sync',
            'body': payload,
        })
        return True, ''
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: could not write to case {case_id}: {e}')
        return False, str(e)[:120]


def as_obj(value):
    """Coerce a context value to a dict.

    A list arrives when a key accumulated across forEach iterations instead of
    being assigned. Take the last element - that is this iteration's output -
    rather than letting a list reach .get() and read as a missing verdict.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return {}
    if isinstance(value, list):
        value = value[-1] if value else {}
    return value if isinstance(value, dict) else {}


def main():
    args = demisto.args()

    # Read the verdict from context rather than taking it as a task argument.
    # An array argument makes XSIAM run the task once per element, and a
    # Stringify transformer does not collapse that - it applies per element. The
    # accumulated Analysis.AI was firing this task once per case seen so far.
    ai = as_obj(args.get('ai_output')) or \
        as_obj(demisto.get(demisto.context(), 'Analysis.AI'))

    # Scalars only. An object or array argument makes XSIAM run this task once
    # per element, which is what produced 118 entries for 16 cases.
    case_id = str(args.get('case_id') or 'unknown')
    case = {
        'ID': case_id,
        'IssueCount': args.get('issue_count'),
        'Categories': args.get('categories'),
        'ShapeCoverage': as_obj(args.get('shape_coverage')),
        'ContractCoverage': as_obj(args.get('contract_coverage')),
        'Payload': args.get('payload') or '',
    }
    verdict = str(ai.get('verdict') or '').lower() or 'inconclusive'
    confidence = str(ai.get('confidence') or '').lower()
    responded = ai.get('response_recommended')

    mark = VERDICT_MARK.get(verdict, '⚪')
    conf = CONFIDENCE_MARK.get(confidence, '○○○')

    shape_cov = case.get('ShapeCoverage') or {}
    contract_cov = case.get('ContractCoverage') or {}
    categories = case.get('Categories') or []
    if isinstance(categories, str):
        try:
            categories = json.loads(categories)
        except Exception:
            categories = [c.strip() for c in categories.split(',') if c.strip()]

    lines = [
        f"{mark} **CASE {case_id}** — {verdict.upper()}   {conf} {confidence or 'unknown'}",
        "",
        f"  issues        {case.get('IssueCount')}"
        f"   ·  shapes {shape_cov.get('kept')}/{shape_cov.get('total')}"
        f"   ·  contract {contract_cov.get('pct')}%",
        f"  categories    {', '.join(categories) if categories else '—'}",
        f"  response      {'recommended' if responded else 'not recommended'}",
    ]

    scope = [
        ('compromise', ai.get('compromise_level')),
        ('spread', ai.get('spread_level')),
        ('persistence', ai.get('persistence_type')),
        ('primary', ai.get('primary_entity_name')),
        ('mitre', ai.get('mitre_tactic')),
    ]
    scope = [(k, v) for k, v in scope if v]
    if scope:
        lines.append("")
        for k, v in scope:
            lines.append(f"  {k:<13} {v}")

    story = ai.get('story') or []
    if isinstance(story, str):
        story = [story]
    if story:
        lines.append("")
        lines.append("  **ANALYSIS**")
        shown = story[:MAX_STORY_LINES]
        for i, step in enumerate(shown, 1):
            lines.append(f"  {i}. {step}")
        if len(story) > len(shown):
            lines.append(f"  … {len(story) - len(shown)} further step(s) omitted")

    if verdict == 'inconclusive' and not story:
        lines.append("")
        lines.append("  ⚫ No reasoning returned. Check the prompt inputs resolved — "
                     "an empty payload produces this exact result.")

    # The execution row, now carrying what was concluded rather than only what
    # was sent. event_type matches the existing convention (dedup, auto_triage,
    # ai_reasoning) so the dataset stays queryable by type.
    row = {
        'event_type': 'case_analysis',
        'lifecycle': 'NIST_IR',
        'phase': 'analysis',
        'action_actor': 'ai',
        'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'case_id': case_id,
        'issue_count': case.get('IssueCount'),
        'distinct_shapes': shape_cov.get('total'),
        'shapes_kept': shape_cov.get('kept'),
        'shape_issue_coverage_pct': shape_cov.get('issue_coverage_pct'),
        'contract_coverage_pct': contract_cov.get('pct'),
        'contract_covered_issues': contract_cov.get('covered_issues'),
        'contract_total_issues': contract_cov.get('total_issues'),
        'payload_bytes': len(str(case.get('Payload') or '')),
        'categories': categories,
        'verdict': verdict,
        'confidence': confidence,
        'response_recommended': bool(responded),
        'compromise_level': ai.get('compromise_level'),
        'compromise_decision': ai.get('compromise_decision'),
        'spread_level': ai.get('spread_level'),
        'persistence_type': ai.get('persistence_type'),
        'primary_entity_id': ai.get('primary_entity_id'),
        'primary_entity_name': ai.get('primary_entity_name'),
        'primary_entity_type': ai.get('primary_entity_type'),
        'primary_entity_user': ai.get('primary_entity_user'),
        'case_category': ai.get('case_category'),
        'mitre_tactic': ai.get('mitre_tactic'),
        'mitre_tactic_id': ai.get('mitre_tactic_id'),
        'mitre_technique': ai.get('mitre_technique'),
        'mitre_technique_id': ai.get('mitre_technique_id'),
        # Cost accounting. XQL returns its own charge; the AI call does not, so
        # this is the only place the prompt's size is recorded. Bytes are exact,
        # tokens are a /4 estimate, and output is what came back - together they
        # bound the per-case AI spend well enough to budget from.
        'prompt_input_bytes': len(str(case.get('Payload') or '')),
        'prompt_input_tokens_est': len(str(case.get('Payload') or '')) // 4,
        'prompt_output_bytes': len(json.dumps(ai, separators=(',', ':'))),
        'prompt_output_tokens_est': len(json.dumps(ai, separators=(',', ':'))) // 4,
        'story_steps': len(story),
        'reasoning_status': 'promoted' if story else 'no_output',
    }

    # The entry belongs on the case, not in the JOB's own War Room. Wrap the
    # rendered block so the receiving investigation prints it verbatim.
    body = '\n'.join(lines)
    superseded = supersede_prior(case_id)
    written, err = post_to_case(case_id, f'!Print value=`{body}`')
    try:
        payload_obj = json.loads(case.get('Payload') or '{}')
    except Exception:
        payload_obj = {}
    contract_written, contract_note = write_case_contract(case_id, ai, case, payload_obj)
    row['case_warroom_written'] = written
    row['case_contract_written'] = contract_written
    row['case_contract_note'] = contract_note
    row['prior_verdicts_superseded'] = superseded

    demisto.setContext('CaseAnalysis.ExecutionRow', row)
    demisto.setContext('CaseAnalysis.case_id', case_id)
    demisto.setContext('CaseAnalysis.verdict', verdict)

    trace = (f"\n\n  ↳ case {case_id}: War Room entry written"
             f"{f', contract {contract_note}' if contract_written else f', CONTRACT WRITE FAILED ({contract_note})'}"
             f"{f', {superseded} prior verdict(s) superseded' if superseded else ''}"
             if written else f"\n\n  ⚫ case War Room write failed: {err}")
    return_results(CommandResults(readable_output=body + trace))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
