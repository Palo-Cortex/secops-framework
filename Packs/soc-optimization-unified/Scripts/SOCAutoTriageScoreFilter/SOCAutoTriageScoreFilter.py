import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time


# 100 is the get_incidents per-request ceiling. War-room arrays may show a
# cosmetic truncation note at this size; it does not affect processing.
BATCH_SIZE = 100
GET_INCIDENTS_URI = '/public_api/v1/incidents/get_incidents'
UPDATE_INCIDENT_URI = '/public_api/v1/incidents/update_incident'
# update_incident has NO bulk mode: posting incident_id_list returns
# 400 "incident_id field is missing or incorrect" (verified against tenant,
# Jun 2026). We close one ID per call, in a tight Python loop here rather than a
# playbook forEach, to avoid per-iteration context spin-up.
RESOLVE_STATUS = 'resolved_other'
RESOLVE_COMMENT = ('SOC Framework Auto Triage: case exceeded age threshold, '
                   'aggregated_score below threshold, no analyst activity '
                   'detected. Auto-closed by JOB.')
API_URI = GET_INCIDENTS_URI  # back-compat alias
# Per-run wall-clock budget. Two O(n) costs share it: offset pagination during
# fetch (deep search_from makes get_incidents progressively slower) and the
# per-case close loop (one update_incident call each). When the budget is hit
# the run stops cleanly and returns what it has — partial progress is safe
# because closed cases leave status=new and the next scheduled run resumes.
#
# MUST stay safely under the script's automation timeout (Settings > the
# automation's timeout). Leave ~10% headroom for the dataset write + return.
# Current automation timeout: 600s.
MAX_RUNTIME_SECONDS = 540
FIELDS = [
    'incident_id', 'aggregated_score', 'creation_time',
    'status', 'starred', 'manual_score'
]


def close_case(incident_id):
    """Close one case via update_incident (single incident_id — the API rejects
    incident_id_list). Returns (success: bool, error_message: str). Never raises;
    one failed close must not abort the rest of the batch."""
    body = json.dumps({
        'request_data': {
            'incident_id': str(incident_id),
            'update_data': {
                'status': RESOLVE_STATUS,
                'resolve_comment': RESOLVE_COMMENT
            }
        }
    })
    try:
        execute_command('core-api-post', {'uri': UPDATE_INCIDENT_URI, 'body': body})
        return True, ''
    except Exception as e:
        return False, str(e)


def _to_float(value):
    """Best-effort float; returns None if not parseable."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _is_unstarred(value):
    """Positively confirm a case is NOT starred.

    Destructive-action guard: this must FAIL CLOSED. It returns True only when
    the value can be unambiguously read as 'not starred'. Anything we cannot
    confirm (None, missing, unexpected type, any truthy/starred representation)
    returns False, so the case is skipped rather than closed.
    """
    if isinstance(value, bool):
        return value is False
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return value.strip().lower() in ('false', '0', 'no')
    return False


def fetch_batch(cutoff_ms: int, search_from: int, batch_size: int) -> dict:
    """Fetch one page of unstarred New incidents created at or before cutoff_ms.

    OFFSET pagination. get_incidents has NO sort capability — any sort_by_*
    key in request_data is silently ignored (verified against the tenant API,
    Jun 2026), so results come back in arbitrary order. Keyset pagination on
    creation_time is therefore unsafe: on an unordered page, advancing a cursor
    below the page's minimum creation_time skips every un-returned row above it,
    which is exactly how the age-eligible low-score backlog went unscanned.
    Plain offset pagination (fixed filter, growing search_from) is the only way
    to cover the whole age-eligible set when the API will not order results.
    Deep offsets do get progressively slower, but max_batches bounds the cost
    and closed cases drop out of status=new between runs, so the offset window
    keeps advancing through fresh cases run over run.

    Contract notes (confirmed against tenant, Jun 2026):
      - status enum is case-insensitive here: both "new" and "New" match (the
        earlier "New matches zero rows" claim was wrong).
      - `in` operator -> array value; `lte` -> scalar value.
      - creation_time is epoch milliseconds; filterable server-side.
      - aggregated_score is NOT filterable server-side -> gated client-side.
    """
    body = json.dumps({
        'request_data': {
            'filters': [
                {'field': 'status', 'operator': 'in', 'value': ['new']},
                {'field': 'starred', 'operator': 'in', 'value': [False]},
                {'field': 'creation_time', 'operator': 'lte', 'value': int(cutoff_ms)},
            ],
            'fields': FIELDS,
            'search_from': int(search_from),
            'search_to': int(search_from) + int(batch_size)
        }
    })
    result = execute_command('core-api-post', {'uri': API_URI, 'body': body})
    if isinstance(result, list):
        result = result[0] if result else {}
    return result


def main():
    args = demisto.args()

    # Policy default is 40 (close cases scored 40 or below). The JOB should still
    # pass score_threshold explicitly so the policy lives in one obvious place.
    threshold = args.get('score_threshold', '40')
    window_hours = args.get('window_hours', '6')
    # max_batches caps offset depth per run. With offset pagination each batch
    # is O(offset), so this is a COST ceiling, not a "drain the whole backlog in
    # one run" knob — large backlogs drain over repeated scheduled runs as closed
    # cases leave status=new. Keep it modest (deepest offset = max_batches*100);
    # the wall-clock guard (MAX_RUNTIME_SECONDS) is the real timeout backstop.
    max_batches = args.get('max_batches', '20')

    threshold = _to_float(threshold)
    if threshold is None:
        return_error(f'Invalid score_threshold value: {args.get("score_threshold")}')

    window_hours = _to_float(window_hours)
    if window_hours is None:
        return_error(f'Invalid window_hours value: {args.get("window_hours")}')

    try:
        max_batches = int(max_batches)
    except (ValueError, TypeError):
        max_batches = 20
    if max_batches < 1:
        max_batches = 20

    # batch_size is tunable but hard-capped at the get_incidents per-request
    # ceiling of 100, and floored at 1. Junk/blank falls back to BATCH_SIZE.
    try:
        batch_size = int(args.get('batch_size', BATCH_SIZE))
    except (ValueError, TypeError):
        batch_size = BATCH_SIZE
    batch_size = max(1, min(batch_size, BATCH_SIZE))

    # dry_run = Shadow Mode for triage: select eligible cases and report what
    # WOULD close, but emit nothing to the close path so the JOB closes nothing.
    dry_run = str(args.get('dry_run', 'false')).strip().lower() in ('true', '1', 'yes')

    # creation_time from the API is epoch milliseconds (13-digit).
    cutoff_ms = int((time.time() - (window_hours * 3600)) * 1000)

    passed = []
    skipped = []
    total_scanned = 0
    batches_run = 0
    search_from = 0  # offset into the age-eligible result set; grows each batch
    run_start = time.time()
    budget_hit = False

    for batch_num in range(max_batches):
        # Wall-clock guard: stop before the Docker automation timeout. Returning
        # partial progress is safe — the JOB closes what we found, those cases
        # leave status=new, and the next run resumes from a shallow offset.
        if time.time() - run_start > MAX_RUNTIME_SECONDS:
            budget_hit = True
            demisto.debug(f'Runtime budget {MAX_RUNTIME_SECONDS}s hit after '
                          f'{batches_run} batches; stopping with partial progress.')
            break
        try:
            result = fetch_batch(cutoff_ms, search_from, batch_size)
        except Exception as e:
            # If the very first fetch fails we have scanned nothing — that is an
            # auth/API failure (e.g. 401 unauthorized), NOT an empty backlog.
            # Surface it loudly; a silent zero here is indistinguishable from
            # "nothing to close" and hid a gateway 401 for an entire session.
            if batches_run == 0:
                return_error(f'get_incidents failed on the first batch; nothing was '
                             f'scanned. This is an API/auth failure, not an empty '
                             f'backlog. Underlying error: {e}')
            # Mid-run failure: stop and report what we have, but make the partial
            # state explicit rather than swallowing it.
            demisto.debug(f'Batch {batch_num} API call failed after {batches_run} '
                          f'batches: {e}')
            break

        incidents = demisto.get(result, 'response.reply.incidents')
        if not incidents:
            incidents = demisto.get(result, 'reply.incidents')
        if not incidents:
            demisto.debug(f'Batch {batch_num}: no incidents returned, stopping.')
            break

        batches_run += 1
        total_scanned += len(incidents)

        for inc in incidents:
            # One malformed incident must never abort the run and leave the rest
            # of the backlog unprocessed.
            try:
                incident_id = inc.get('incident_id', 'unknown')
                aggregated_score = _to_float(inc.get('aggregated_score'))
                manual_score = inc.get('manual_score')
                creation_time = inc.get('creation_time', 0)
                try:
                    creation_time = int(creation_time)
                except (ValueError, TypeError):
                    creation_time = 0

                # HARD SAFETY BACKSTOP — never auto-close a starred case.
                # This does not trust the server-side starred filter; it
                # independently confirms the case is unstarred and fails closed
                # if it cannot. Checked first so a starred case can never reach
                # any close path regardless of score/age.
                if not _is_unstarred(inc.get('starred')):
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': aggregated_score,
                        'reason': f"starred guard: starred={inc.get('starred')!r} not confirmed unstarred"
                    })
                    continue

                # HARD SAFETY BACKSTOP — never close a case that isn't still 'new'.
                # Mirrors the starred backstop: does not trust the server-side
                # status filter, re-confirms from the returned record, and fails
                # closed. An in-progress / under-investigation / resolved case can
                # never reach the close call even if the server filter ever returns
                # one. Confirmed: get_incidents returns status as lowercase 'new'.
                status_val = str(inc.get('status', '')).strip().lower()
                if status_val != 'new':
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': aggregated_score,
                        'reason': f"status guard: status={inc.get('status')!r} not confirmed 'new'"
                    })
                    continue

                # Skip if an analyst manually scored it (null unless set).
                if manual_score is not None:
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': aggregated_score,
                        'reason': f'manual_score is set ({manual_score})'
                    })
                    continue

                # Skip if the score is missing. RECORDED (was a silent continue):
                # a silent drop here made 201 scanned / 0 passed / 0 skipped
                # indistinguishable from "missing score field" vs "above
                # threshold" and hid the real cause for a whole session.
                if aggregated_score is None:
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': None,
                        'reason': 'aggregated_score missing/None on returned case'
                    })
                    continue

                # Skip if the score is above threshold. RECORDED for the same reason.
                if aggregated_score > threshold:
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': aggregated_score,
                        'reason': f'aggregated_score {aggregated_score} > threshold {threshold}'
                    })
                    continue

                # Defensive client-side age guard (the server-side filter already
                # constrains this, but never auto-close something inside the window).
                if creation_time > cutoff_ms:
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': aggregated_score,
                        'reason': f'creation_time {creation_time} is within {window_hours}h window'
                    })
                    continue

                passed.append(inc)
            except Exception as e:
                demisto.debug(f"Skipping incident {inc.get('incident_id', 'unknown')}: {e}")
                continue

        # A short page means the age-eligible set is exhausted.
        if len(incidents) < batch_size:
            break
        # Advance the offset to the next page (filter and order are stable within
        # a run because nothing is closed until the script returns).
        search_from += batch_size

    # --- Close phase ---------------------------------------------------------
    # Close each passing case here, in-process, one update_incident call per ID
    # (the API has no bulk close). Doing it in this loop instead of a playbook
    # forEach avoids per-iteration context spin-up — the old task 8 bottleneck
    # that selected ~1,300/run but only closed dozens. Each dataset row is now
    # keyed to the ACTUAL close result, so the dataset stops over-counting
    # un-closed cases that get re-selected every run.
    rows = []
    closed_ok = []
    closed_fail = []

    for inc in passed:
        incident_id = str(inc.get('incident_id', ''))
        if not incident_id:
            continue

        if dry_run:
            # Select only — close nothing. Row tagged shadow so the shadow
            # value-metrics path can show what WOULD have closed.
            success, err = True, ''
        else:
            # Same wall-clock budget guards the (slower) close loop. Unclosed
            # passers stay status=new; the next scheduled run resumes them.
            if time.time() - run_start > MAX_RUNTIME_SECONDS:
                budget_hit = True
                demisto.debug(f'Runtime budget hit during close phase after '
                              f'{len(closed_ok)} closes; stopping with partial progress.')
                break
            success, err = close_case(incident_id)

        if success:
            closed_ok.append(incident_id)
        else:
            closed_fail.append({'incident_id': incident_id, 'error': err})

        rows.append({
            'timestamp': str(int(time.time())),
            'event_type': 'auto_triage',
            'universal_command': 'auto_close_incident',
            'action_taken': 'auto_triage_would_close' if dry_run else 'auto_triage_closed',
            'action_status': 'dry_run' if dry_run else ('success' if success else 'error'),
            'execution_mode': 'shadow' if dry_run else 'production',
            'shadow_mode_state': 'shadow' if dry_run else 'not_applicable',
            'lifecycle': 'AUTO_TRIAGE',
            'phase': 'triage',
            'incident_id': incident_id,
            'aggregated_score': str(inc.get('aggregated_score', '')),
            'tags': ['auto_triage_would_close' if dry_run else 'auto_triage_closed'],
            'has_error': (not dry_run and not success),
            'error_type': '' if (dry_run or success) else 'update_incident_failed',
            'error_message': '' if (dry_run or success) else err
        })

    # One dataset write per run with the actual per-case outcomes.
    if rows:
        try:
            execute_command(
                'xql-post-to-dataset',
                {
                    'using': 'socfw_ir_execution',
                    'using-brand': 'System XQL HTTP Collector',
                    'JSON': json.dumps(rows)
                }
            )
        except Exception as e:
            demisto.debug(f'Dataset write failed: {e}')

    outputs = {
        'dry_run': dry_run,
        'skipped_incidents': skipped,
        'passed_count': len(passed),
        'closed_count': len(closed_ok),
        'failed_count': len(closed_fail),
        'closed_ids': closed_ok[:500],      # capped sample for visibility
        'failed': closed_fail[:200],        # capped sample for visibility
        'skipped_count': len(skipped),
        'total_scanned': total_scanned,
        'batches_run': batches_run,
        'budget_hit': budget_hit
    }
    if dry_run:
        outputs['would_close_count'] = len(passed)
        outputs['would_close_ids'] = closed_ok[:500]

    budget_note = (' [runtime budget hit — partial run, next run resumes]'
                   if budget_hit else '')

    if dry_run:
        readable = (
            f'DRY RUN — would close {len(passed)} case(s); closed 0. '
            f'{len(skipped)} skipped (threshold: {threshold}, window: {window_hours}h, '
            f'scanned: {total_scanned} across {batches_run} batches){budget_note}. '
            f'Set dry_run=false to close for real.'
        )
    else:
        readable = (
            f'Auto triage: closed {len(closed_ok)}, failed {len(closed_fail)}, '
            f'{len(skipped)} skipped (threshold: {threshold}, window: {window_hours}h, '
            f'scanned: {total_scanned} across {batches_run} batches){budget_note}'
        )

    return_results(CommandResults(
        outputs_prefix='AutoTriage',
        outputs=outputs,
        readable_output=readable
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
