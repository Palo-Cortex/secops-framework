"""Select cases eligible for case-scoped analysis this JOB run.

A JOB is out of band. It does not depend on issue-level automation marking
anything: candidacy is decided from case state alone. `alert_count` is the
signal rather than `modification_time`, because a count delta unambiguously
means new issues joined the case, while modification_time also moves for
edits, comments and status changes.

The watermark comes from the execution dataset, not a List. JOB context is
discarded at closeInvestigation and a pack-installed List is system-owned, so
the dataset is the only surface that survives a run. See read_watermark.
"""

import ast
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

GET_INCIDENTS_URI = '/public_api/v1/incidents/get_incidents'

# get_incidents caps a page at 100 rows regardless of what is asked for.
MAX_PAGE = 100

# Allow-list, not an exclusion list. The previous TERMINAL_STATUSES enumerated
# what to skip, which fails OPEN: resolved_security_testing was missing from it
# and closed cases were re-analysed until someone noticed (candidates 13->2,
# terminal skips 29->41). Any status XSIAM adds, or any resolution variant
# nobody enumerated, gets analysed by default under that design.
#
# Inverted, the failure mode is a case that should have been analysed being
# skipped, which shows up in skipped_ineligible_status with the status named,
# rather than an unbounded spend on closed cases that shows up nowhere.
# Actively-worked statuses only.
ELIGIBLE_STATUSES = {'new', 'under_investigation'}


# Domain scopes the lifecycle. NIST IR runs on security cases; posture cases
# have their own lifecycle and never run the NIST IR entry point, so they carry
# no contract by design rather than by fault. The case field and the issue field
# spell the value differently - DOMAIN_SECURITY on the case, SECURITY on the
# issue - so they are not interchangeable in a filter.
DEFAULT_DOMAIN = 'DOMAIN_SECURITY'


# Sibling detection tolerance. Cases *opened* inside this window of each other,
# sharing a host or a user, are treated as one intrusion. Small on purpose: the
# split is a batch of issues opening several cases seconds apart, and a wide
# window silently merges unrelated incidents that recur on the same hosts.
DEFAULT_SIBLING_WINDOW_MINUTES = 15


def _norm_host(value):
    """Strip the platform's NO_HOST: prefix from an unresolved endpoint.

    An endpoint that never resolved to an asset is still the same endpoint
    across two cases, and dropping the prefix is what lets them bridge on it.
    """
    text = str(value or '').strip()
    if ':' in text:
        text = text.split(':', 1)[1]
    return text.lower()


def find_siblings(cases, window_minutes):
    """Group cases that are one intrusion split across several case records.

    The platform can open more than one case for a single intrusion when a
    batch of issues lands together. Observed on a replay: two cases created
    three seconds apart, sharing all three hosts, the same user and the same
    five minute window, with neither holding an artifact the other lacked.

    Analysed separately each gets a defensible verdict over half an intrusion -
    one saw initial access and persistence with no lateral movement mechanism,
    the other saw lateral movement with no origin. Neither verdict is wrong and
    neither is usable, and nothing in either case says the other exists.

    Bridged on a shared host or user plus closely spaced creation times. Both
    are already on the get_incidents payload, so this costs no query.

    Creation proximity, deliberately, not an overlap of creation..modification.
    modification_time advances every time anything touches a case, including
    this JOB re-analysing it, so an interval test makes every active case
    overlap every other one - measured on a lab tenant it collapsed ten separate
    replays of the same scenario on the same three hosts into a single group.
    A split shows up as cases opened seconds apart from one batch of issues,
    which is what this tests and all it tests.

    Runs over every in-domain case scanned, not just the candidates: a sibling
    that was skipped as terminal or unchanged is still where half the evidence
    is, and the analyst still needs the pointer to it.
    """
    window_ms = max(0, int(window_minutes)) * 60000
    parent = {}

    def find(node):
        while parent.get(node, node) != node:
            parent[node] = parent.get(parent[node], parent[node])
            node = parent[node]
        return node

    keyed = []
    for case in cases or []:
        cid = str(case.get('case_id') or '')
        if not cid:
            continue
        parent.setdefault(cid, cid)
        hosts = {_norm_host(h) for h in (case.get('hosts') or [])}
        users = {str(u).strip().lower() for u in (case.get('users') or [])}
        keyed.append((cid, hosts - {''}, users - {''},
                      int(case.get('creation_time') or 0)))

    for i, (cid_a, hosts_a, users_a, born_a) in enumerate(keyed):
        for cid_b, hosts_b, users_b, born_b in keyed[i + 1:]:
            if not born_a or not born_b:
                continue
            if abs(born_a - born_b) > window_ms:
                continue
            if not (hosts_a & hosts_b) and not (users_a & users_b):
                continue
            root_a, root_b = find(cid_a), find(cid_b)
            if root_a != root_b:
                parent[root_a] = root_b

    grouped = {}
    for cid, _h, _u, _born in keyed:
        grouped.setdefault(find(cid), []).append(cid)
    return {cid: sorted(group)
            for group in grouped.values() if len(group) > 1
            for cid in group}


def read_watermark(rows):
    """Build {case_id: {alert_count, covered_issues, total_issues}} from the
    execution dataset.

    Not a List. A pack-installed List is system-owned and a JOB cannot write to
    it - setList returns "Item is system and cannot be modified (100001)" - so
    the watermark silently never persisted and every run re-analysed every case.

    The dataset already records what was analysed, so it is the watermark. One
    aggregate ahead of selection replaces a write the platform will not allow.

    Arrives double-encoded: the task binding Stringifies the XQL result array,
    so this is a JSON string holding a list of JSON strings, not a list of
    dicts. Both levels have to be parsed, and anything still unusable has to be
    reported rather than skipped.
    """
    note = ''
    if isinstance(rows, str):
        parsed, errors = None, []
        for loader in (json.loads, ast.literal_eval):
            try:
                parsed = loader(rows.strip())
                break
            except Exception as exc:
                errors.append(f'{loader.__name__}: {exc}')
        if parsed is None:
            # Returning {} silently here is what made every case look new. The
            # watermark suppressed nothing, 13 cases re-analysed every five
            # minutes, one case reached 48 attempts in an afternoon, and
            # skipped_unchanged sat at 0 with nothing anywhere saying why. A
            # watermark that fails to arrive has to be louder than one that
            # legitimately has no rows.
            return {}, 'unparseable watermark rows — ' + '; '.join(errors)[:200]
        rows = parsed
        # Stringify can hand back a Python repr rather than JSON, which json
        # alone cannot read. Recorded so a working-but-odd path is still visible.
        if not isinstance(rows, (list, dict)):
            return {}, f'watermark rows parsed to {type(rows).__name__}, expected list'
    if isinstance(rows, dict):
        rows = [rows]
    out = {}
    dropped_shape = 0
    dropped_unknown = 0
    for r in rows or []:
        # Stringify applied to an array of objects yields an array of JSON
        # STRINGS, so the outer parse returns list[str] and every element fails
        # an isinstance(dict) test. Dropping them silently is what held
        # watermark_cases at 0 while 85 rows sat in the argument - the outer
        # parse succeeded, so the unparseable guard above never fired and
        # watermark_note stayed empty. Nothing anywhere said the watermark was
        # gone, and with no watermark nothing is ever suppressed: one case
        # reached 919 attempts against a max_attempts of 6.
        if isinstance(r, str):
            for loader in (json.loads, ast.literal_eval):
                try:
                    r = loader(r.strip())
                    break
                except Exception:
                    continue
        if not isinstance(r, dict):
            dropped_shape += 1
            continue
        cid = str(r.get('case_id') or '')
        if not cid:
            dropped_shape += 1
            continue
        # Written by a verdict report whose case_id binding did not resolve.
        # These aggregate into one bucket belonging to no case, which can only
        # suppress the wrong thing or nothing at all, so they are not evidence.
        if cid == 'unknown':
            dropped_unknown += 1
            continue
        out[cid] = {
            'alert_count': int(r.get('analysed_issue_count') or 0),
            'covered_issues': int(r.get('analysed_covered_issues') or 0),
            'total_issues': int(r.get('analysed_total_issues') or 0),
            'analyses': int(r.get('analyses') or 0),
            'attempts': int(r.get('attempts') or 0),
        }
    # A watermark that arrives and is then discarded has to be as loud as one
    # that fails to arrive. Silence here is exactly what cost the suppression:
    # rows present, every one dropped, note empty, and no signal anywhere until
    # the attempt counts were read straight out of the dataset by hand.
    notes = [note] if note else []
    if dropped_shape:
        notes.append(f'{dropped_shape} watermark row(s) unusable after parse')
    if dropped_unknown:
        notes.append(f'{dropped_unknown} row(s) skipped with case_id=unknown')
    if not out and (rows or []):
        notes.append(f'{len(rows)} row(s) received but watermark is empty — '
                     'nothing will be suppressed this run')
    return out, '; '.join(notes)


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
    max_attempts = int(args.get('max_attempts') or 6)
    # Unless it never goes quiet. Past this age it is analysed as it stands, so a
    # continuously active case still gets a verdict - and well inside the six-hour
    # auto-close window, or the closure veto never applies.
    max_wait_minutes = int(args.get('max_wait_minutes') or 120)
    sibling_window_minutes = int(args.get('sibling_window_minutes')
                                 or DEFAULT_SIBLING_WINDOW_MINUTES)

    cutoff_ms = int((datetime.utcnow() - timedelta(hours=window_hours)).timestamp() * 1000)
    watermark, watermark_note = read_watermark(args.get('watermark_rows'))

    candidates = []
    seen_cases = []
    scanned = 0
    skipped_unchanged = 0
    skipped_status = 0
    status_breakdown = {}
    skipped_domain = 0
    skipped_small = 0
    skipped_low_score = 0
    skipped_max_analyses = 0
    skipped_max_attempts = 0
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

                # Recorded before every later skip. A sibling that is terminal,
                # settling or unchanged is still where half the evidence sits,
                # and the case being analysed still needs the pointer to it.
                seen_cases.append({
                    'case_id': case_id,
                    'hosts': inc.get('hosts') or [],
                    'users': inc.get('users') or [],
                    'creation_time': inc.get('creation_time'),
                    'modification_time': inc.get('modification_time'),
                })

                if status not in ELIGIBLE_STATUSES:
                    skipped_status += 1
                    status_breakdown[status or '(empty)'] = \
                        status_breakdown.get(status or '(empty)', 0) + 1
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
                if wm is not None and wm.get('attempts', 0) >= max_attempts:
                    skipped_max_attempts += 1
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

    # One intrusion can occupy several cases. Declaring the link is not the
    # same as merging them, and is deliberately the smaller step: a verdict that
    # knows it is looking at part of an intrusion is honest, where a merged
    # payload doubles the shape count against a character budget that is already
    # the binding constraint.
    siblings = find_siblings(seen_cases, sibling_window_minutes)
    for cand in candidates:
        group = siblings.get(str(cand['case_id'])) or []
        others = [c for c in group if c != str(cand['case_id'])]
        if others:
            cand['siblings'] = others

    stats = {
        'scanned': scanned,
        'candidates': len(candidates),
        'skipped_unchanged': skipped_unchanged,
        'skipped_ineligible_status': skipped_status,
        # Named, not just counted. An allow-list fails closed, so a status
        # nobody anticipated stops being analysed silently - this is the only
        # place that would say so.
        'skipped_status_breakdown': ', '.join(
            f'{k}={v}' for k, v in sorted(status_breakdown.items())) or None,
        'eligible_statuses': ', '.join(sorted(ELIGIBLE_STATUSES)),
        'skipped_out_of_domain': skipped_domain,
        'skipped_single_issue': skipped_small,
        'skipped_low_score': skipped_low_score,
        'skipped_max_analyses': skipped_max_analyses,
        'skipped_max_attempts': skipped_max_attempts,
        'skipped_settling': skipped_settling,
        'reselected_for_coverage': recheck_coverage,
        'watermark_cases': len(watermark),
        'watermark_note': watermark_note or None,
        'sibling_groups': len({tuple(g) for g in siblings.values()}),
        'cases_with_siblings': sum(1 for c in candidates if c.get('siblings')),
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
