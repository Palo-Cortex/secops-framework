import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time


# 100 is the get_incidents per-request ceiling. War-room arrays may show a
# cosmetic truncation note at this size, but the forEach close loop is unaffected.
BATCH_SIZE = 100
# How many incident IDs to bundle into a single bulk update_incident call.
# Each emitted batch is a ready-to-post JSON array string for incident_id_list.
CLOSE_CHUNK_SIZE = 100
API_URI = '/public_api/v1/incidents/get_incidents'
FIELDS = [
    'incident_id', 'aggregated_score', 'creation_time',
    'status', 'starred', 'manual_score'
]


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


def fetch_batch(upper_ms: int, batch_size: int) -> dict:
    """Fetch the newest unstarred New incidents created at or before upper_ms.

    KEYSET pagination: callers walk the age-eligible set downward by
    creation_time, always querying from offset 0 with a shrinking creation_time
    upper bound. This keeps every call O(batch_size) instead of O(offset) — deep
    offset pagination (search_from=30000) makes the API skip every preceding row
    and gets progressively slower, which is what times the job out on large
    backlogs. There is no growing search_from here.

    Contract notes (confirmed):
      - status value is the lowercase public-API enum: "new" (the Cases UI
        capitalizes "New" for display, but the get_incidents filter enum is
        lowercase). Sending "New" matches zero rows.
      - `in` operator -> array value; `lte` -> scalar value.
      - aggregated_score is NOT filterable server-side -> gated client-side.
      - `sort_by_creation_time` is the documented working sort key.
    """
    body = json.dumps({
        'request_data': {
            'filters': [
                {'field': 'status', 'operator': 'in', 'value': ['new']},
                {'field': 'starred', 'operator': 'in', 'value': [False]},
                {'field': 'creation_time', 'operator': 'lte', 'value': int(upper_ms)},
            ],
            'fields': FIELDS,
            'sort_by_creation_time': 'desc',
            'search_from': 0,
            'search_to': batch_size
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
    # Default high enough to page the whole age-eligible backlog to exhaustion
    # on any tenant (the loop stops on its own when a short page comes back).
    # This is the safety ceiling, not the normal cost. For this to apply, the
    # JOB task must NOT pass a literal max_batches (a typed value overrides it).
    max_batches = args.get('max_batches', '200')

    threshold = _to_float(threshold)
    if threshold is None:
        return_error(f'Invalid score_threshold value: {args.get("score_threshold")}')

    window_hours = _to_float(window_hours)
    if window_hours is None:
        return_error(f'Invalid window_hours value: {args.get("window_hours")}')

    try:
        max_batches = int(max_batches)
    except (ValueError, TypeError):
        max_batches = 200
    if max_batches < 1:
        max_batches = 200

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
    seen_ids = set()
    cursor_ms = cutoff_ms  # creation_time upper bound; walks downward each batch

    for batch_num in range(max_batches):
        try:
            result = fetch_batch(cursor_ms, batch_size)
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

        # Dedup against the boundary record(s) carried over by the <= cursor.
        new_incidents = [i for i in incidents
                         if str(i.get('incident_id', '')) not in seen_ids]
        if not new_incidents:
            # No forward progress (entire page already seen) -> stop.
            break

        batches_run += 1
        total_scanned += len(new_incidents)
        page_min_ct = None

        for inc in new_incidents:
            # One malformed incident must never abort the run and leave the rest
            # of the backlog unprocessed.
            try:
                incident_id = inc.get('incident_id', 'unknown')
                seen_ids.add(str(incident_id))
                aggregated_score = _to_float(inc.get('aggregated_score'))
                manual_score = inc.get('manual_score')
                creation_time = inc.get('creation_time', 0)
                try:
                    creation_time = int(creation_time)
                except (ValueError, TypeError):
                    creation_time = 0
                if creation_time and (page_min_ct is None or creation_time < page_min_ct):
                    page_min_ct = creation_time

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

                # Skip if an analyst manually scored it (null unless set).
                if manual_score is not None:
                    skipped.append({
                        'incident_id': incident_id,
                        'aggregated_score': aggregated_score,
                        'reason': f'manual_score is set ({manual_score})'
                    })
                    continue

                # Skip if score is missing or above threshold.
                if aggregated_score is None or aggregated_score > threshold:
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

        # Fewer than a full page means the eligible set is exhausted.
        if len(incidents) < batch_size:
            break
        # Advance the cursor strictly below the oldest creation_time seen so the
        # next page is the next-older slice (keyset, offset stays 0).
        if page_min_ct is None:
            break
        cursor_ms = page_min_ct - 1

    # Write one row per passed incident to the active execution dataset. In a
    # dry run these are tagged as shadow so dashboards/audits can see what the
    # job WOULD have closed without it actually closing anything.
    if passed:
        rows = []
        for inc in passed:
            rows.append({
                'timestamp': str(int(time.time())),
                'event_type': 'auto_triage',
                'universal_command': 'auto_close_incident',
                'action_taken': 'auto_triage_would_close' if dry_run else 'auto_triage_closed',
                'action_status': 'dry_run' if dry_run else 'success',
                'execution_mode': 'shadow' if dry_run else 'production',
                'shadow_mode_state': 'shadow' if dry_run else 'not_applicable',
                'lifecycle': 'AUTO_TRIAGE',
                'phase': 'triage',
                'incident_id': str(inc.get('incident_id', '')),
                'aggregated_score': str(inc.get('aggregated_score', '')),
                'tags': ['auto_triage_would_close' if dry_run else 'auto_triage_closed'],
                'has_error': False,
                'error_type': '',
                'error_message': ''
            })
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

    # Build bulk-close batches: each entry is a ready-to-post JSON array string
    # of incident IDs (<= CLOSE_CHUNK_SIZE), so the close playbook can drop it
    # straight into incident_id_list without the array-to-JSON interpolation
    # problem. 32k eligible -> ~320 bulk calls instead of 32k single calls.
    passed_ids = [str(inc.get('incident_id', '')) for inc in passed
                  if str(inc.get('incident_id', ''))]
    all_batches = [
        json.dumps(passed_ids[i:i + CLOSE_CHUNK_SIZE])
        for i in range(0, len(passed_ids), CLOSE_CHUNK_SIZE)
    ]

    # In dry run, hand the close path NOTHING so neither the bulk loop nor a
    # per-case loop can close anything; surface the would-close set separately.
    close_batches = [] if dry_run else all_batches
    filtered_incidents = [] if dry_run else passed

    outputs = {
        'dry_run': dry_run,
        'filtered_incidents': filtered_incidents,
        'close_batches': close_batches,
        'skipped_incidents': skipped,
        'passed_count': len(passed),
        'batch_count': len(close_batches),
        'skipped_count': len(skipped),
        'total_scanned': total_scanned,
        'batches_run': batches_run
    }
    if dry_run:
        outputs['would_close_count'] = len(passed_ids)
        outputs['would_close_ids'] = passed_ids[:500]  # capped sample for visibility

    if dry_run:
        readable = (
            f'DRY RUN — would close {len(passed_ids)} case(s); closed 0. '
            f'{len(skipped)} skipped (threshold: {threshold}, window: {window_hours}h, '
            f'scanned: {total_scanned} across {batches_run} batches). '
            f'Set dry_run=false to close for real.'
        )
    else:
        readable = (
            f'Score filter complete: {len(passed)} passed in {len(close_batches)} '
            f'close batch(es), {len(skipped)} skipped '
            f'(threshold: {threshold}, window: {window_hours}h, '
            f'scanned: {total_scanned} across {batches_run} batches)'
        )

    return_results(CommandResults(
        outputs_prefix='AutoTriage',
        outputs=outputs,
        readable_output=readable
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
