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
    """POST to the XSOAR API from inside a playbook via the Core REST API.

    core-api-post does not raise on a failed call, so a write that never landed
    used to return success. Every caller now gets the response and can tell.
    """
    res = demisto.executeCommand('core-api-post',
                                 {'uri': uri, 'body': json.dumps(body)})
    entry = res[0] if isinstance(res, list) and res else res
    if isinstance(entry, dict) and entry.get('Type') == entryTypes['error']:
        raise DemistoException(str(entry.get('Contents'))[:200])
    return res


def supersede_prior(case_id):
    """Mark earlier verdict entries on this case as superseded.

    Entries cannot be deleted - the delete endpoints return 303 - so the current
    verdict is made findable by tag instead. Without this a re-analysed case
    accumulates verdicts with no indication which one is live.
    """
    inv = str(case_id)
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
    # Written from a member issue with setParentIncidentContext, not from the
    # case. Executing !Set inside a case investigation returns a nil pointer
    # panic, so the case is reached upward from one of its issues instead.
    issue = member_issue(case_id, payload)
    if not issue:
        return False, 'no member issue to write from'

    # The value rides a command line inside backticks, so a backtick or newline
    # in free text - compromise_decision, story - terminates it early. That fails
    # as a normal entry rather than an error entry, which is why this used to
    # report success while writing nothing.
    blob = (json.dumps(contract, separators=(',', ':'))
            .replace('`', "'").replace('\r', ' ').replace('\n', ' '))
    try:
        res = api('/xsoar/public/v1/entry/execute/sync',
                  {'investigationId': issue,
                   'data': f'!setParentIncidentContext key=SOCFramework.Analysis.AI '
                           f'value=`{blob}`'})
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: case contract write failed: {e}')
        return False, str(e)[:100]

    # Confirm from the response rather than from the absence of an exception.
    entry = res[0] if isinstance(res, list) and res else res
    said = str((entry or {}).get('Contents') or '')
    if 'set' not in said.lower():
        demisto.debug(f'SOCFWCaseVerdictReport: contract not set: {said[:200]}')
        return False, f'not set: {said[:80]}'
    return True, f'{populated}/{len(spec)} targets populated'


def member_issue(case_id, payload):
    """An issue investigation belonging to this case, to write upward from.

    A case investigation accepts entries but not command execution - !Set inside
    one returns a nil pointer panic. setParentIncidentContext run from a member
    issue reaches the case instead, which is the only route that works.
    """
    for shape in (payload.get('shapes') or []):
        sid = shape.get('contract_from') or shape.get('sample_alert_id')
        if sid:
            return str(sid)
    try:
        res = api('/xsoar/public/v1/incidents/search',
                  {'filter': {'page': 0, 'size': 1,
                              'query': f'caseid:{case_id}'}})
        entry = res[0] if isinstance(res, list) and res else res
        contents = (entry or {}).get('Contents')
        if isinstance(contents, str):
            contents = json.loads(contents)
        # core-api-post nests the API body under response on some paths and
        # returns it bare on others.
        for node in (contents, (contents or {}).get('response')):
            data = (node or {}).get('data') if isinstance(node, dict) else None
            if data:
                return str(data[0].get('id'))
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: no member issue for {case_id}: {e}')
    return ''


def post_to_case(case_id, markdown):
    """Write the verdict entry to the case's own War Room.

    The JOB runs in its own investigation, so a return_results here lands where
    no analyst looks.

    Uses /entry, not /entry/execute/sync. The sync endpoint's `data` field is a
    command line, so markdown beginning with "##" was parsed as a command and
    wrote nothing, while core-api-post's silence let the caller report success.

    Never fatal. A case that cannot be written to still has its dataset row.
    """
    try:
        api('/xsoar/public/v1/entry', {
            'investigationId': str(case_id),
            'data': markdown,
            'markdown': True,
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

    # Context before War Room. The contract is what downstream phases and the
    # case layout read; the entry is for a human. If only one lands, it should
    # be the one the framework depends on.
    #
    # A run that produced no story writes neither. Flash returns an empty object
    # often enough that publishing an inconclusive contract would overwrite a
    # good verdict from an earlier attempt - last write wins in the context.
    # Payload arrives as a dict when the JOB passes it through context and as a
    # string when it round-trips through an argument. json.loads on a dict raises,
    # which silently produced an empty payload - and with no shapes there was no
    # member issue, so the contract and the title both went unwritten while the
    # War Room entry succeeded.
    raw_payload = case.get('Payload')
    if isinstance(raw_payload, dict):
        payload_obj = raw_payload
    else:
        try:
            payload_obj = json.loads(raw_payload or '{}')
        except Exception:
            payload_obj = {}

    has_verdict = bool(story)
    marked, mark_note = False, 'no verdict'
    if has_verdict:
        contract_written, contract_note = write_case_contract(
            case_id, ai, case, payload_obj)
        written, err = post_to_case(case_id, body)
        issue = member_issue(case_id, payload_obj)
        if issue:
            marked, mark_note = mark_case_title(case_id, issue)
    else:
        contract_written, contract_note = False, 'no verdict to publish'
        written, err = False, 'no verdict to publish'

    row['case_warroom_written'] = written
    row['case_contract_written'] = contract_written
    row['case_contract_note'] = contract_note
    row['prior_verdicts_superseded'] = superseded
    row['case_title_marked'] = marked
    row['case_title_note'] = mark_note

    demisto.setContext('CaseAnalysis.ExecutionRow', row)
    demisto.setContext('CaseAnalysis.case_id', case_id)
    demisto.setContext('CaseAnalysis.verdict', verdict)

    if not has_verdict:
        trace = "\n\n  ⚫ no verdict produced — nothing published to the case"
    elif written:
        trace = (f"\n\n  ↳ case {case_id}: contract {contract_note}, War Room entry written"
                 f"{f', title {mark_note}' if marked else ''}"
                 f"{f', {superseded} prior verdict(s) superseded' if superseded else ''}")
    else:
        trace = f"\n\n  ⚫ case write failed: {err}"
    return_results(CommandResults(readable_output=body + trace))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


# A visible mark on the case title so an analyst scanning the case list can see
# which cases the reasoner has already worked.
AI_MARK = '\u2731'


def mark_case_title(case_id, issue):
    """Prefix the case title once, from a member issue.

    The case title in XSIAM is `description`. setParentIncidentFields rejects
    `name` outright and accepts `description`; `incident_name` is the generated
    "X along with N other issues" string and is not what the UI shows.

    Idempotent by checking the current title rather than a flag, so a case
    analysed three times carries one mark and a hand-edited title stays correct.
    """
    try:
        body = json.dumps({'request_data': {'filters': [
            {'field': 'incident_id_list', 'operator': 'in',
             'value': [str(case_id)]}]}})
        res = demisto.executeCommand(
            'core-api-post',
            {'uri': '/public_api/v1/incidents/get_incidents/', 'body': body})
        if isinstance(res, list):
            res = res[0] if res else {}
        rows = (demisto.get(res, 'response.reply.incidents')
                or demisto.get(res, 'reply.incidents') or [])
        row = rows[0] if rows else {}
        title = str(row.get('description') or row.get('incident_name') or '').strip()
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: cannot read case title: {e}')
        return False, str(e)[:80]

    if not title:
        return False, 'case title unavailable'
    if title.startswith(AI_MARK):
        return True, 'already marked'

    marked = f'{AI_MARK} {title}'.replace('"', "'")
    try:
        api('/xsoar/public/v1/entry/execute/sync',
            {'investigationId': str(issue),
             'data': f'!setParentIncidentFields description="{marked}"'})
        return True, 'marked'
    except Exception as e:
        demisto.debug(f'SOCFWCaseVerdictReport: case retitle failed: {e}')
        return False, str(e)[:80]
