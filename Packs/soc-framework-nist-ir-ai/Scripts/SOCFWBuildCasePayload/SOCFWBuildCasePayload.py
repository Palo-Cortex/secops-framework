"""Partition the case aggregates into one payload per case.

The four XQL aggregates run once across every candidate case, so this script
splits their result sets by incident_id and assembles the structured payload the
case analysis prompt consumes.

The collapse is what makes case scope affordable. A case of N issues reduces to
the number of distinct alert shapes, hosts, hashes and addresses it contains,
which is bounded by variety rather than by issue count: measured at 76 issues to
6 KB, and a campaign is more uniform than a mixed case, not less. Occurrence
counts are carried through because volume per shape is evidence of intensity,
and first_seen ordering is what carries a cross-category pivot.

Truncation is never silent. When a case exceeds max_shapes the payload records
how many shapes were kept and what share of the case's issues they cover.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

# Result sets are located by the query_name set on each aggregate task.
QUERY_NAMES = {
    'shapes': 'socfw_case_shapes',
    'entities': 'socfw_case_entities',
    'coverage': 'socfw_case_coverage',
}

# Array fields arrive joined rather than expanded, because arrayexpand drops the
# row when the field is null and expanding two array fields multiplies rows.
ARRAY_DELIM = '|'


def collect_results(context):
    """Pull the XQL result rows out of context, keyed by our query names.

    The XQL integration nests results under its own output root and the exact
    shape varies by version, so walk the context rather than hard-coding a path
    that would fail silently as an empty result set.

    Also returns the top-level roots the matches were found under, so the raw
    rows can be dropped once collapsed. Walking is what makes that precise: the
    roots are observed rather than guessed.
    """
    found = {key: [] for key in QUERY_NAMES}
    roots = set()
    cost = {'queries': 0, 'cost_charged': 0.0, 'rows_returned': 0,
            'remaining_quota': None}

    for root_key, subtree in (context or {}).items():
        stack = [subtree]
        seen = 0
        while stack and seen < 10000:
            node = stack.pop()
            seen += 1
            if isinstance(node, dict):
                name = node.get('query_name') or node.get('QueryName')
                results = node.get('results') or node.get('Results')
                if name and isinstance(results, list):
                    for key, qname in QUERY_NAMES.items():
                        if name == qname:
                            found[key].extend(results)
                            roots.add(root_key)
                            # Every XQL reply carries its own charge. Quota is
                            # the real budget, not query count, so record what
                            # this run actually spent rather than counting calls.
                            cost['queries'] += 1
                            cost['rows_returned'] += len(results)
                            charged = node.get('query_cost_charged')
                            if isinstance(charged, dict):
                                cost['cost_charged'] += sum(
                                    float(v or 0) for v in charged.values())
                            elif charged is not None:
                                cost['cost_charged'] += float(charged or 0)
                            rq = node.get('remaining_quota')
                            if rq is not None:
                                cost['remaining_quota'] = float(rq)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)

    cost['cost_charged'] = round(cost['cost_charged'], 6)
    return found, roots, cost


def drop_raw_results(roots):
    """Clear the raw aggregate rows once they are collapsed.

    A run covering many cases pulls every alert row for all of them into JOB
    context and none of it is needed past this point, since the payloads carry
    the collapsed form. Never clear the whole context: SOCFramework.Case.* has
    to survive for the analysis step.
    """
    dropped = []
    for root in sorted(roots):
        if str(root).startswith('SOCFramework'):
            continue
        try:
            demisto.executeCommand('DeleteContext', {'key': root})
            dropped.append(root)
        except Exception as e:
            demisto.debug(f'SOCFWBuildCasePayload: could not clear {root}: {e}')
    return dropped


def by_case(rows):
    out = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        cid = row.get('incident_id')
        if cid is None:
            continue
        out.setdefault(str(cid), []).append(
            {k: v for k, v in row.items() if k != 'incident_id'})
    return out


def main():
    args = demisto.args()
    max_shapes = int(args.get('max_shapes') or 40)
    # Noise is many issues of one shape - two hundred scan alerts from one
    # address clears an issue-count floor and is worth nothing. Distinct shapes
    # is the discriminator, and it is known here, before the expensive step. The
    # aggregate has already been paid for; the AI call has not.
    min_shapes = int(args.get('min_shapes') or 2)
    # Volume separates a campaign from noise. Both are single-shape - four
    # hundred phishing emails are one shape with a high count, and so are two
    # hundred scan alerts. Shape count alone would skip the campaign, which is
    # the case case-scope exists for. Above this issue count a single-shape case
    # is analysed regardless.
    campaign_issues = int(args.get('campaign_issues') or 20)

    candidates = args.get('candidates')
    if isinstance(candidates, str):
        try:
            candidates = json.loads(candidates)
        except Exception:
            candidates = []
    if isinstance(candidates, dict):
        candidates = [candidates]
    candidates = candidates or []

    results, roots, cost = collect_results(demisto.context())
    shapes = by_case(results['shapes'])
    entities = by_case(results['entities'])
    coverage_rows = by_case(results['coverage'])

    payloads = []
    uncontracted = []
    single_shape = []
    for cand in candidates:
        cid = str(cand.get('case_id'))

        # Only issues that ran an entry-point playbook carry a contract. A case
        # with none of them was never touched by the framework, and analysing it
        # from vendor fields alone would look healthy while being ungrounded.
        cov = (coverage_rows.get(cid) or [{}])[0]
        cov_total = int(cov.get('n') or cand.get('alert_count') or 0)
        cov_ok = int(cov.get('covered_issues') or 0)
        cov_pct = round(100.0 * cov_ok / cov_total, 1) if cov_total else 0.0
        if cov_ok == 0:
            uncontracted.append({'case_id': cid, 'issues': cov_total,
                                 'issue_domain': cov.get('issue_domain'),
                                 'incident_domain': cand.get('incident_domain')})
            continue

        case_shapes = sorted(shapes.get(cid, []),
                             key=lambda r: int(r.get('n') or 0), reverse=True)

        total_in_shapes = sum(int(r.get('n') or 0) for r in case_shapes)
        kept = case_shapes[:max_shapes]
        kept_n = sum(int(r.get('n') or 0) for r in kept)
        coverage = round(100.0 * kept_n / total_in_shapes, 1) if total_in_shapes else 100.0

        seen = [int(r['first_seen']) for r in case_shapes if r.get('first_seen')]
        last = [int(r['last_seen']) for r in case_shapes if r.get('last_seen')]

        # dataset = issues names these xdm.issue.*; the alerts dataset spelling
        # is kept as a fallback so a tenant mid-transition does not go blank.
        # The shape key is host-stripped so one technique is one shape rather
        # than one per host - three hosts otherwise multiply every technique by
        # three, which is how a 531-issue case reached 42 shapes and had 30
        # dropped by the character budget. Host is an attribute of the shape, not
        # a shape multiplier.
        for r in case_shapes:
            names = r.pop('issue_names', None)
            if isinstance(names, list) and names:
                r['issue_name_sample'] = names[0]
                r['distinct_issue_names'] = len(set(names))

        sources = sorted({(r.get('source_tag') or r.get('alert_source'))
                          for r in case_shapes
                          if (r.get('source_tag') or r.get('alert_source'))})

        # One correlated row per host/hash/address combination. Split the joined
        # array fields back out, keeping the association the row carries.
        case_hosts, case_hashes, case_ips = {}, {}, {}
        for row in entities.get(cid, []):
            n = int(row.get('n') or 0)
            host = row.get('host_name')
            if host:
                h = case_hosts.setdefault(
                    host, {'host_name': host, 'endpoint_id': row.get('endpoint_id'),
                           'n': 0, 'hashes': set(), 'ips': set()})
                h['n'] += n
            for sha in str(row.get('sha') or '').split(ARRAY_DELIM):
                if sha:
                    case_hashes[sha] = case_hashes.get(sha, 0) + n
                    if host:
                        case_hosts[host]['hashes'].add(sha)
            for ip in str(row.get('lip') or '').split(ARRAY_DELIM):
                if ip:
                    case_ips[ip] = case_ips.get(ip, 0) + n
                    if host:
                        case_hosts[host]['ips'].add(ip)
        host_rows = sorted(
            [{'host_name': h['host_name'], 'endpoint_id': h['endpoint_id'],
              'n': h['n'], 'hashes': sorted(h['hashes']), 'ips': sorted(h['ips'])}
             for h in case_hosts.values()],
            key=lambda r: r['n'], reverse=True)
        hash_rows = sorted([{'file_sha256': k, 'n': v} for k, v in case_hashes.items()],
                           key=lambda r: r['n'], reverse=True)
        ip_rows = sorted([{'local_ip': k, 'n': v} for k, v in case_ips.items()],
                         key=lambda r: r['n'], reverse=True)

        payload = {
            'case_id': cid,
            'issue_count': cand.get('alert_count'),
            'host_count': cand.get('host_count'),
            'user_count': cand.get('user_count'),
            'predicted_score': cand.get('predicted_score'),
            'severity': cand.get('severity'),
            'users': cand.get('users') or [],
            'shapes': kept,
            'hosts': host_rows,
            'file_hashes': hash_rows,
            'ips': ip_rows,
        }

        if len(case_shapes) < min_shapes and cov_total < campaign_issues:
            single_shape.append({'case_id': cid, 'issues': cov_total,
                                 'shapes': len(case_shapes),
                                 'top_shape': (case_shapes[0].get('alert_name')
                                               or case_shapes[0].get('xdm.issue.name'))
                                 if case_shapes else None})
            continue

        payloads.append({
            'ID': cid,
            'IssueCount': cand.get('alert_count'),
            'Categories': sources,
            'Window': {'first_seen': min(seen) if seen else None,
                       'last_seen': max(last) if last else None},
            'ShapeCoverage': {'kept': len(kept), 'total': len(case_shapes),
                              'issue_coverage_pct': coverage},
            'ContractCoverage': {'covered_issues': cov_ok, 'total_issues': cov_total,
                                 'pct': cov_pct},
            'Payload': json.dumps(payload, separators=(',', ':')),
        })

    # Raw rows are dead weight once collapsed, and a many-case run carries every
    # alert row for every case. Drop them before the analysis step reads context.
    dropped = drop_raw_results(roots)

    summary = [{'case_id': p['ID'], 'issues': p['IssueCount'],
                'contract %': p['ContractCoverage']['pct'],
                'shapes kept': p['ShapeCoverage']['kept'],
                'of': p['ShapeCoverage']['total'],
                'issue coverage %': p['ShapeCoverage']['issue_coverage_pct'],
                'payload bytes': len(p['Payload'])} for p in payloads]

    readable = tableToMarkdown('Case payloads', summary) if summary \
        else '**No candidate cases had aggregate results.**'
    if uncontracted:
        readable += '\n\n' + tableToMarkdown(
            'Skipped — no contracted issues (entry point never ran)', uncontracted)
    if single_shape:
        readable += '\n\n' + tableToMarkdown(
            f'Skipped — fewer than {min_shapes} shapes and under {campaign_issues} '
            f'issues (repetition, not a campaign)',
            single_shape)
    if dropped:
        readable += f"\n\nCleared raw aggregate context: {', '.join(dropped)}"

    # Execution rows follow the SOC Framework convention: one run-level row and
    # one row per case, posted to xsiam_socfw_ir_execution_raw by the next task.
    # Query cost travels with the run row so cadence can be tuned from evidence
    # rather than guessed.
    stats = demisto.get(demisto.context(), 'SOCFramework.Case.SelectStats') or {}
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    rows = [{
        'event_type': 'case_analysis_run',
        'lifecycle': 'NIST_IR',
        'phase': 'analysis',
        'action_actor': 'framework',
        'timestamp': now,
        'cases_scanned': stats.get('scanned'),
        'cases_candidates': stats.get('candidates'),
        'cases_analysed': len(payloads),
        'cases_uncontracted': len(uncontracted),
        'cases_single_shape': len(single_shape),
        'skipped_unchanged': stats.get('skipped_unchanged'),
        'skipped_terminal': stats.get('skipped_terminal'),
        'skipped_out_of_domain': stats.get('skipped_out_of_domain'),
        'reselected_for_coverage': stats.get('reselected_for_coverage'),
        'domain': stats.get('domain'),
        'xql_queries': cost['queries'],
        'xql_cost_charged': cost['cost_charged'],
        'xql_rows_returned': cost['rows_returned'],
        'xql_remaining_quota': cost['remaining_quota'],
    }]
    for p in payloads:
        rows.append({
            'event_type': 'case_analysis',
            'lifecycle': 'NIST_IR',
            'phase': 'analysis',
            'action_actor': 'framework',
            'timestamp': now,
            'case_id': p['ID'],
            'issue_count': p['IssueCount'],
            'distinct_shapes': p['ShapeCoverage']['total'],
            'shapes_kept': p['ShapeCoverage']['kept'],
            'shape_issue_coverage_pct': p['ShapeCoverage']['issue_coverage_pct'],
            'contract_covered_issues': p['ContractCoverage']['covered_issues'],
            'contract_total_issues': p['ContractCoverage']['total_issues'],
            'contract_coverage_pct': p['ContractCoverage']['pct'],
            'payload_bytes': len(p['Payload']),
            'categories': p['Categories'],
        })

    # setContext assigns; CommandResults outputs append. Downstream tasks read
    # these paths directly, so assign and keep return_results for display only.
    demisto.setContext('SOCFramework.Case.Payloads', payloads)
    demisto.setContext('SOCFramework.Case.Uncontracted', uncontracted)
    demisto.setContext('SOCFramework.Case.SingleShape', single_shape)
    demisto.setContext('SOCFramework.Case.ExecutionRows', rows)
    demisto.setContext('SOCFramework.Case.QueryCost', cost)

    readable += (f"\n\nXQL: {cost['queries']} queries, "
                 f"{cost['cost_charged']} charged, "
                 f"{cost['rows_returned']} rows, "
                 f"remaining quota {cost['remaining_quota']}")

    return_results(CommandResults(readable_output=readable))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
