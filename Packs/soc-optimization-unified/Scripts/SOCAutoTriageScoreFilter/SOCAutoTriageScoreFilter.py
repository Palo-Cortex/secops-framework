import json
import time


# 100 is the get_incidents per-request ceiling. War-room arrays may show a
# cosmetic truncation note at this size, but the forEach close loop is unaffected.
BATCH_SIZE = 100
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


def fetch_batch(search_from: int, cutoff_ms: int) -> dict:
    """Fetch one batch of unstarred New incidents created on/before cutoff_ms,
    oldest first.

    The age gate is pushed SERVER-SIDE via a creation_time `lte` filter so the
    result set only ever contains age-eligible cases. We then walk that set
    NEWEST-first: the oldest unstarred New cases skew high-score (low-score cases
    get auto-closed and age out), so oldest-first would burn the scan budget on
    cases that never qualify. Newest-of-the-eligible-first reaches closeable
    cases sooner; a full drain still requires paging to exhaustion (raise
    max_batches), which is unaffected by sort order.

    Contract notes (confirmed):
      - status value is case-sensitive: "New".
      - `in` operator -> array value; `lte`/`eq` -> scalar value.
      - aggregated_score is NOT filterable server-side -> gated client-side.
      - `sort_by_creation_time` is the documented working sort key.
    """
    body = json.dumps({
        'request_data': {
            'filters': [
                {'field': 'status', 'operator': 'in', 'value': ['New']},
                {'field': 'starred', 'operator': 'in', 'value': [False]},
                {'field': 'creation_time', 'operator': 'lte', 'value': int(cutoff_ms)},
            ],
            'fields': FIELDS,
            'sort_by_creation_time': 'desc',
            'search_from': search_from,
            'search_to': search_from + BATCH_SIZE
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
    # Generous default; with the server-side age filter the eligible set is small,
    # but this guarantees a busy tenant's backlog is fully walked in one run.
    max_batches = args.get('max_batches', '50')

    threshold = _to_float(threshold)
    if threshold is None:
        return_error(f'Invalid score_threshold value: {args.get("score_threshold")}')

    window_hours = _to_float(window_hours)
    if window_hours is None:
        return_error(f'Invalid window_hours value: {args.get("window_hours")}')

    try:
        max_batches = int(max_batches)
    except (ValueError, TypeError):
        max_batches = 50

    # creation_time from the API is epoch milliseconds (13-digit).
    cutoff_ms = int((time.time() - (window_hours * 3600)) * 1000)

    passed = []
    skipped = []
    total_scanned = 0
    batches_run = 0

    for batch_num in range(max_batches):
        search_from = batch_num * BATCH_SIZE
        try:
            result = fetch_batch(search_from, cutoff_ms)
        except Exception as e:
            demisto.debug(f'Batch {batch_num} API call failed: {e}')
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
        if len(incidents) < BATCH_SIZE:
            break

    # Write one row per passed incident to the active execution dataset.
    if passed:
        rows = []
        for inc in passed:
            rows.append({
                'timestamp': str(int(time.time())),
                'event_type': 'auto_triage',
                'universal_command': 'auto_close_incident',
                'action_taken': 'auto_triage_closed',
                'action_status': 'success',
                'execution_mode': 'production',
                'shadow_mode_state': 'not_applicable',
                'lifecycle': 'AUTO_TRIAGE',
                'phase': 'triage',
                'incident_id': str(inc.get('incident_id', '')),
                'aggregated_score': str(inc.get('aggregated_score', '')),
                'tags': ['auto_triage_closed'],
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

    return_results(CommandResults(
        outputs_prefix='AutoTriage',
        outputs={
            'filtered_incidents': passed,
            'skipped_incidents': skipped,
            'passed_count': len(passed),
            'skipped_count': len(skipped),
            'total_scanned': total_scanned,
            'batches_run': batches_run
        },
        readable_output=(
            f'Score filter complete: {len(passed)} passed, {len(skipped)} skipped '
            f'(threshold: {threshold}, window: {window_hours}h, '
            f'scanned: {total_scanned} across {batches_run} batches)'
        )
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
