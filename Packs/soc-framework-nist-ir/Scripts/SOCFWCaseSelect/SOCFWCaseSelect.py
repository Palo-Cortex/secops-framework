"""Select cases eligible for case-scoped analysis this JOB run.

A JOB is out of band. It does not depend on issue-level automation marking
anything: candidacy is decided from case state alone. `alert_count` is the
signal rather than `modification_time`, because a count delta unambiguously
means new issues joined the case, while modification_time also moves for
edits, comments and status changes.

The watermark survives the JOB investigation in a List, since JOB context is
discarded at closeInvestigation.
"""

import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

GET_INCIDENTS_URI = '/public_api/v1/incidents/get_incidents'
WATERMARK_LIST = 'SOCFWCaseWatermark_V3'

# get_incidents caps a page at 100 rows regardless of what is asked for.
MAX_PAGE = 100

TERMINAL_STATUSES = {'resolved', 'resolved_threat_handled', 'resolved_known_issue',
                     'resolved_duplicate', 'resolved_false_positive',
                     'resolved_auto_resolve', 'resolved_other'}

# Domain scopes the lifecycle. NIST IR runs on security cases; posture cases
# have their own lifecycle and never run the NIST IR entry point, so they carry
# no contract by design rather than by fault. The case field and the issue field
# spell the value differently - DOMAIN_SECURITY on the case, SECURITY on the
# issue - so they are not interchangeable in a filter.
DEFAULT_DOMAIN = 'DOMAIN_SECURITY'


def read_watermark(rows):
    """Build {case_id: {alert_count, covered_issues, total_issues}} from the
    execution dataset.

    Not a List. A pack-installed List is system-owned and a JOB cannot write to
    it - setList returns "Item is system and cannot be modified (100001)" - so
    the watermark silently never persisted and every run re-analysed every case.

    The dataset already records what was analysed, so it is the watermark. One
    aggregate ahead of selection replaces a write the platform will not allow.
    """
    if isinstance(rows, str):
        try:
            rows = json.loads(rows)
        except Exception:
            return {}
    if isinstance(rows, dict):
        rows = [rows]
    out = {}
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        cid = str(r.get('case_id') or '')
        if not cid:
            continue
        out[cid] = {
            'alert_count': int(r.get('analysed_issue_count') or 0),
            'covered_issues': int(r.get('analysed_covered_issues') or 0),
            'total_issues': int(r.get('analysed_total_issues') or 0),
            'analyses': int(r.get('analyses') or 0),
        }
    return out


def fetch_page(search_from, batch_size, cutoff_ms):
    # modification_time, not creation_time. A case that was created twelve days
    # ago and is still receiving issues falls outside a creation-time window and
    # stops being reconsidered while it is still active - the exact case that most
    # needs re-analysis goes dark.
    body = json.dumps({
        'request_data': {
            'filters': [{'field': 'modification_time', 'operator': 'gte',
                         'value': cutoff_ms}],
            'search_from': int(search_from),
            'search_to': int(search_from) + int(batch_size),
        }
    })
    result = execute_command('core-api-post',
                             {'uri': GET_INCIDENTS_URI, 'body': body})
    if isinstance(result, list):
        result = result[0] if result else {}
    incidents = demisto.get(result, 'response.reply.incidents')
    if incidents is None:
        incidents = demisto.get(result, 'reply.incidents')
    return incidents or []


def main():
    args = demisto.args()
    batch_size = min(int(args.get('batch_size') or 100), MAX_PAGE)
    max_batches = int(args.get('max_batches') or 20)
    window_hours = int(args.get('window_hours') or 24)
    domain = (args.get('domain') or DEFAULT_DOMAIN).strip()
    # A single-issue case is per-issue analysis wearing a case label, and the
    # per-category prompts already do that job. On one production window 32,466
    # of 42,118 cases held exactly one issue - 77% of calls for none of what case
    # scope exists to find.
    min_issues = int(args.get('min_issues') or 2)
    min_score = float(args.get('min_score') or 0)
    # A case that keeps receiving issues would otherwise be re-analysed on every
    # run for as long as it grows. Past this many analyses the verdict is
    # unlikely to move on volume alone, so stop paying for it - the case is still
    # visible, still open, and a human can reopen the question.
    max_analyses = int(args.get('max_analyses') or 2)
    # Wait for a case to stop moving before analysing it. A case analysed while
    # still filling produces a partial verdict and then needs re-analysing, so
    # early analysis costs more runs and returns a worse contract. Analysing once,
    # late, beats analysing three times, early.
    settle_minutes = int(args.get('settle_minutes') or 15)
    # Unless it never goes quiet. Past this age it is analysed as it stands, so a
    # continuously active case still gets a verdict - and well inside the six-hour
    # auto-close window, or the closure veto never applies.
    max_wait_minutes = int(args.get('max_wait_minutes') or 120)

    cutoff_ms = int((datetime.utcnow() - timedelta(hours=window_hours)).timestamp() * 1000)
    watermark = read_watermark(args.get('watermark_rows'))

    candidates = []
    scanned = 0
    skipped_unchanged = 0
    skipped_terminal = 0
    skipped_domain = 0
    skipped_small = 0
    skipped_low_score = 0
    skipped_max_analyses = 0
    skipped_settling = 0
    recheck_coverage = 0
    search_from = 0

    for batch in range(max_batches):
        try:
            incidents = fetch_page(search_from, batch_size, cutoff_ms)
        except Exception as e:
            if batch == 0:
                return_error(f'get_incidents failed on the first page; nothing was '
                             f'scanned. This is an API or auth failure, not an empty '
                             f'backlog. Underlying error: {e}')
            demisto.debug(f'SOCFWCaseSelect: page {batch} failed after {scanned} cases: {e}')
            break

        if not incidents:
            break

        for inc in incidents:
            scanned += 1
            try:
                case_id = str(inc.get('incident_id'))
                alert_count = int(inc.get('alert_count') or 0)
                status = str(inc.get('status') or '').lower()

                if domain and str(inc.get('incident_domain') or '') != domain:
                    skipped_domain += 1
                    continue

                if status in TERMINAL_STATUSES:
                    skipped_terminal += 1
                    continue

                if alert_count < min_issues:
                    skipped_small += 1
                    continue

                score = inc.get('predicted_score')
                if min_score and score is not None and float(score) < min_score:
                    skipped_low_score += 1
                    continue

                # Two independent reasons to re-analyse. New issues joining the
                # case advance alert_count. Issues that were still executing on
                # the last run land their contracts afterwards, which advances
                # coverage without touching alert_count - so an incomplete
                # coverage record from last time is itself a reason to return.
                # This is why the race needs no detection: playbook_run_status
                # reads null both for "never ran" and "still running", and the
                # two are indistinguishable at selection time.
                now_ms = int(datetime.utcnow().timestamp() * 1000)
                modified = int(inc.get('modification_time') or 0)
                created = int(inc.get('creation_time') or 0)
                quiet_for = (now_ms - modified) / 60000.0 if modified else 0
                age = (now_ms - created) / 60000.0 if created else 0
                if quiet_for < settle_minutes and age < max_wait_minutes:
                    skipped_settling += 1
                    continue

                wm = watermark.get(case_id)
                if wm is not None and wm.get('analyses', 0) >= max_analyses:
                    skipped_max_analyses += 1
                    continue
                if wm is not None:
                    grew = alert_count > wm['alert_count']
                    incomplete = (wm['total_issues'] > 0
                                  and wm['covered_issues'] < wm['total_issues'])
                    if not grew and not incomplete:
                        skipped_unchanged += 1
                        continue
                    if not grew and incomplete:
                        recheck_coverage += 1

                candidates.append({
                    'case_id': case_id,
                    'alert_count': alert_count,
                    'incident_domain': inc.get('incident_domain'),
                    'host_count': inc.get('host_count'),
                    'user_count': inc.get('user_count'),
                    'hosts': inc.get('hosts') or [],
                    'users': inc.get('users') or [],
                    'predicted_score': inc.get('predicted_score'),
                    'severity': inc.get('severity'),
                    'status': status,
                    'creation_time': inc.get('creation_time'),
                    'modification_time': inc.get('modification_time'),
                    'prior_watermark': watermark.get(case_id),
                })
            except Exception as e:
                demisto.debug(f'SOCFWCaseSelect: skipping malformed case: {e}')

        if len(incidents) < batch_size:
            break
        search_from += batch_size

    # The filter is interpolated straight into the aggregate queries, so it must
    # be bare integers. An empty run still needs a syntactically valid list.
    ids = [c['case_id'] for c in candidates if str(c['case_id']).isdigit()]
    candidate_filter = ', '.join(ids) if ids else '-1'

    stats = {
        'scanned': scanned,
        'candidates': len(candidates),
        'skipped_unchanged': skipped_unchanged,
        'skipped_terminal': skipped_terminal,
        'skipped_out_of_domain': skipped_domain,
        'skipped_single_issue': skipped_small,
        'skipped_low_score': skipped_low_score,
        'skipped_max_analyses': skipped_max_analyses,
        'skipped_settling': skipped_settling,
        'reselected_for_coverage': recheck_coverage,
        'min_issues': min_issues,
        'min_score': min_score,
        'domain': domain,
    }
    # setContext assigns; CommandResults outputs APPEND, which turns a scalar
    # into a one-element array. CandidateFilter is interpolated straight into
    # the aggregate queries, so an array renders as ["48805, 48799"] and XQL
    # cannot parse it. Assign here, and keep return_results for display only.
    demisto.setContext('SOCFramework.Case.Candidates', candidates)
    demisto.setContext('SOCFramework.Case.CandidateFilter', candidate_filter)
    demisto.setContext('SOCFramework.Case.SelectStats', stats)

    return_results(CommandResults(
        readable_output=tableToMarkdown('Case selection', [stats]),
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
