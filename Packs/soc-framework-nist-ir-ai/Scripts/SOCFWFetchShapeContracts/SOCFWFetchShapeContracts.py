"""Attach the SOC Framework contract to each alert shape in a case payload.

The aggregates describe what happened using raw XDM columns. The contract is
the normalized surface everything downstream is supposed to read, and it carries
what XDM does not - the resolved identity, MITRE tactic ids, enrichment
provenance, and the vendor routing an action would dispatch on.

One fetch per shape, not per issue. Shapes are bounded by variety rather than
volume, so a campaign of a thousand near-identical issues costs the same handful
of fetches as a small case. getContext is in-process and reads investigation
context, so this spends no XQL quota.

The whole SOCFramework subtree is taken rather than named fields. That is what
lets a schema change flow through: add a row to the normalize map, re-emit, and
the new artifact appears in the payload without touching this script.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403


# Reputation and threat intelligence roots kept alongside the contract. The
# contract records that an enrichment lane fired, not what it concluded - the
# verdict itself lands in these standard roots. "One hash on three hosts" is a
# useful signal; "one hash on three hosts that WildFire scores malicious" is a
# much stronger one, and that is exactly the distinction case scope turns on.
#
# Whois (11,935 bytes) and DBotFindSimilarIncidents (7,527) are deliberately
# excluded - they are the bulk of a context and carry nothing the reasoner needs.
# What travels with each shape. The contract carries normalization and
# enrichment provenance that is invaluable for debugging the normalizer and
# worthless to a reasoner: measured on a 40-shape case, NormalizeFromList alone
# was 64% of 369 KB, and the whole payload reached ~94,000 tokens and returned an
# empty verdict. Artifacts, Product and Intel are the evidence; the rest is
# scaffolding.
CONTRACT_KEEP = ('Artifacts', 'Product', 'Intel', 'lifecycle')

# Issues tried per shape before giving up on a contract. Bounded so a shape with
# a thousand uncontracted issues cannot consume the run.
MAX_CANDIDATES = 5

# Default roots. A customer running Recorded Future, GTI or any other feed writes
# its own context root, so the set is configurable rather than fixed here - the
# same reason the analysis field list is read from the phase contract instead of
# being typed into a script.
DEFAULT_INTEL_ROOTS = ('DBotScore', 'File', 'IP', 'Domain', 'URL', 'WildFire',
                       'AttackPattern', 'Tactic')


def intel_roots(arg):
    """Resolve which context roots carry threat intelligence.

    Passed in from SOCOptimizationConfig_V3 so a customer adding a feed adds a
    root rather than editing this script. Falls back to the defaults, because a
    missing config should degrade to the shipped behaviour rather than silently
    strip all intelligence from the payload.
    """
    if isinstance(arg, str):
        arg = [r.strip() for r in arg.replace(',', ' ').split() if r.strip()]
    if isinstance(arg, list) and arg:
        return tuple(str(r) for r in arg)
    return DEFAULT_INTEL_ROOTS


def fetch_contract(issue_id, roots=DEFAULT_INTEL_ROOTS):
    """Read one issue's SOCFramework contract via getContext.

    getContext returns the entire context as a JSON *string*, and returns it for
    the requested id rather than the calling investigation. Parsing it as a dict
    yields nothing and reads as "no contract", which is the quiet failure worth
    avoiding here.
    """
    try:
        raw = demisto.executeCommand('getContext', {'id': str(issue_id)})
    except Exception as e:
        return None, f'getContext failed: {e}'

    if isinstance(raw, list):
        raw = raw[0] if raw else {}
    if isinstance(raw, dict):
        raw = raw.get('Contents', raw)
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception as e:
            return None, f'unparseable getContext payload: {e}'
    if not isinstance(raw, dict):
        return None, 'unexpected getContext shape'

    ctx = raw.get('context') or {}
    contract = ctx.get('SOCFramework')
    if not contract:
        return None, 'no SOCFramework contract on this issue'

    # Only the evidence. The contract also carries normalization and enrichment
    # provenance - invaluable for debugging the normalizer, worthless to a
    # reasoner. Measured on a 40-shape case, NormalizeFromList alone was 64% of
    # 369 KB, and the prompt was rejected at 385,102 characters against a
    # 100,000 limit.
    contract = {k: v for k, v in contract.items() if k in CONTRACT_KEEP}

    # Reputation and threat intelligence. The contract records that an
    # enrichment lane fired; these roots are what it concluded.
    intel = {}
    for root in roots:
        value = ctx.get(root)
        if value not in (None, '', [], {}):
            intel[root] = value
    if intel:
        contract['Intel'] = intel

    return contract, ''


def main():
    args = demisto.args()

    payloads = args.get('payloads')
    if isinstance(payloads, str):
        try:
            payloads = json.loads(payloads)
        except Exception:
            payloads = []
    if isinstance(payloads, dict):
        payloads = [payloads]
    payloads = payloads or []

    # Budget is per case, so one large case cannot starve the rest of the run.
    max_per_case = int(args.get('max_fetches_per_case') or 40)
    roots = intel_roots(args.get('intel_roots'))
    # Deferrals per case before analysing anyway. A transient fetch error is worth
    # waiting on; a case that fails the same way every run must not be stuck
    # forever, so after this many attempts it is analysed with whatever resolved
    # and the coverage is declared in the payload.
    max_deferrals = int(args.get('max_deferrals') or 2)
    # Below the platform's 100,000 hard limit, leaving room for the prompt body
    # and the other five inputs.
    max_payload_chars = int(args.get('max_payload_chars') or 80000)

    analysed, deferred = [], []
    summary, misses = [], []
    total_fetches = 0

    for p in payloads:
        try:
            payload = json.loads(p.get('Payload') or '{}')
        except Exception:
            payload = {}
        shapes = payload.get('shapes') or []
        sampled = [sh for sh in shapes if sh.get('sample_alert_id')
                   or sh.get('candidate_ids')]

        prior_deferrals = int(p.get('PriorDeferrals') or 0)
        with_contract = 0
        transient = 0
        structural = 0

        for shape in sampled[:max_per_case]:
            candidates = shape.get('candidate_ids') or [shape.get('sample_alert_id')]
            if not isinstance(candidates, list):
                candidates = [candidates]
            candidates = [c for c in candidates if c][:MAX_CANDIDATES]

            contract, err = None, 'no candidate issues for this shape'
            for sid in candidates:
                contract, err = fetch_contract(sid, roots)
                total_fetches += 1
                if contract:
                    shape['contract_from'] = sid
                    break
            sid = shape.get('contract_from') or (candidates[0] if candidates else None)
            shape.pop('candidate_ids', None)

            if contract:
                shape['contract'] = contract
                with_contract += 1
            elif str(err).startswith('no SOCFramework'):
                structural += 1
                shape['contract_status'] = 'absent'
                misses.append({'case_id': p.get('ID'), 'sample_alert_id': sid,
                               'kind': 'structural', 'reason': err})
            else:
                transient += 1
                shape['contract_status'] = 'fetch_failed'
                misses.append({'case_id': p.get('ID'), 'sample_alert_id': sid,
                               'kind': 'transient', 'reason': err})

        over_budget = len(sampled) > max_per_case
        resolvable = with_contract + structural
        coverage = round(100.0 * with_contract / resolvable, 1) if resolvable else 0.0

        # Defer only when we do not know what a shape carried, and only while
        # there is reason to think a retry helps. There is no coverage threshold:
        # thin evidence is declared in the payload and the prompt is instructed to
        # weigh it, which it does - a case at 16.7% coverage still produced a
        # correct, well-evidenced verdict. A hard gate discards a good answer to
        # avoid a hypothetical bad one.
        if transient and prior_deferrals < max_deferrals:
            deferred.append({'case_id': p.get('ID'), 'shapes': len(shapes),
                             'attempt': prior_deferrals + 1,
                             'reason': f'{transient} contract fetch(es) failed'})
            continue

        # Hard platform limit: the LLM rejects a prompt over 100,000 characters
        # outright - "prompt length 385102 exceeds maximum allowed length". A
        # shape cap cannot guarantee that, because per-shape size varies with the
        # contract. Drop the lowest-occurrence shapes until the payload fits and
        # say how many were dropped, so a truncated case is never silently
        # truncated.
        kept_shapes = shapes[:max_per_case]
        dropped_for_budget = 0
        while kept_shapes:
            trial = dict(payload)
            trial['shapes'] = kept_shapes
            if len(json.dumps(trial, separators=(',', ':'))) <= max_payload_chars:
                break
            kept_shapes.pop()
            dropped_for_budget += 1
        if dropped_for_budget:
            payload['coverage_note'] = (
                f'{dropped_for_budget} lowest-occurrence shape(s) dropped to fit '
                f'the {max_payload_chars} character prompt limit. '
                f'{len(kept_shapes)} of {len(shapes)} carried.')

        payload['shapes'] = kept_shapes
        payload['shape_contract_coverage_pct'] = coverage
        payload['shapes_analysed'] = len(kept_shapes)
        payload['shapes_in_case'] = len(shapes)
        if over_budget:
            payload['coverage_note'] = (
                f'{len(shapes)} shapes in case, {max_per_case} carried. Highest '
                f'occurrence counts first.')
        if transient:
            payload['coverage_note'] = (
                f'{transient} shape(s) could not be read after '
                f'{prior_deferrals + 1} attempt(s). Analysed without them.')

        p['Payload'] = json.dumps(payload, separators=(',', ':'))
        p['ShapeContracts'] = {'with_contract': with_contract,
                               'absent': structural,
                               'unreadable': transient,
                               'shapes': len(shapes),
                               'coverage_pct': coverage}
        analysed.append(p)
        summary.append({'case_id': p.get('ID'), 'shapes': len(shapes),
                        'with contract': with_contract, 'absent': structural,
                        'unreadable': transient, 'coverage %': coverage,
                        'payload bytes': len(p['Payload'])})

    demisto.setContext('SOCFramework.Case.Payloads', analysed)
    demisto.setContext('SOCFramework.Case.Deferred', deferred)

    readable = tableToMarkdown('Shape contracts', summary) if summary \
        else '**No case had full contract coverage this run.**'
    readable += f'\n\ngetContext calls: {total_fetches}'
    if deferred:
        readable += '\n\n' + tableToMarkdown(
            'Deferred — not analysed, will be reselected next run', deferred)
    if misses:
        readable += '\n\n' + tableToMarkdown('Shapes without a contract',
                                              misses[:20])

    return_results(CommandResults(readable_output=readable))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
