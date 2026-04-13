import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time


BATCH_SIZE = 100
API_URI = '/public_api/v1/incidents/get_incidents'
FIELDS = [
    'incident_id', 'aggregated_score', 'creation_time',
    'status', 'starred', 'manual_score'
]


def fetch_batch(search_from: int) -> dict:
    """Fetch one batch of unstarred new incidents sorted by creation_time asc."""
    body = json.dumps({
        'request_data': {
            'filters': [
                {'field': 'status', 'operator': 'eq', 'value': 'new'},
                {'field': 'starred', 'operator': 'eq', 'value': False}
            ],
            'fields': FIELDS,
            'sort': {'field': 'creation_time', 'keyword': 'asc'},
            'search_from': search_from,
            'search_to': search_from + BATCH_SIZE
        }
    })
    result = execute_command('core-api-post', {'uri': API_URI, 'body': body})
    # execute_command returns the response dict directly
    if isinstance(result, list):
        result = result[0] if result else {}
    return result


def main():
    args = demisto.args()

    threshold = args.get('score_threshold', '30')
    window_hours = args.get('window_hours', '6')
    max_batches = args.get('max_batches', '5')

    try:
        threshold = float(threshold)
    except (ValueError, TypeError):
        return_error(f'Invalid score_threshold value: {threshold}')

    try:
        window_hours = float(window_hours)
    except (ValueError, TypeError):
        return_error(f'Invalid window_hours value: {window_hours}')

    try:
        max_batches = int(max_batches)
    except (ValueError, TypeError):
        max_batches = 5

    # creation_time from the API is in milliseconds
    cutoff_ms = (time.time() - (window_hours * 3600)) * 1000

    passed = []
    skipped = []
    total_scanned = 0
    batches_run = 0

    for batch_num in range(max_batches):
        search_from = batch_num * BATCH_SIZE
        try:
            result = fetch_batch(search_from)
        except Exception as e:
            demisto.debug(f'Batch {batch_num} API call failed: {e}')
            break

        # Navigate response structure: response.reply.incidents
        incidents = demisto.get(result, 'response.reply.incidents')
        if not incidents:
            # Also try reply.incidents in case response wrapper absent
            incidents = demisto.get(result, 'reply.incidents')
        if not incidents:
            demisto.debug(f'Batch {batch_num}: no incidents returned, stopping.')
            break

        batches_run += 1
        total_scanned += len(incidents)

        for inc in incidents:
            incident_id = inc.get('incident_id', 'unknown')
            aggregated_score = inc.get('aggregated_score')
            manual_score = inc.get('manual_score')
            creation_time = inc.get('creation_time', 0)

            # Skip if analyst has touched it
            if manual_score is not None:
                skipped.append({
                    'incident_id': incident_id,
                    'aggregated_score': aggregated_score,
                    'reason': f'manual_score is set ({manual_score})'
                })
                continue

            # Skip if score is above threshold or missing
            if aggregated_score is None or float(aggregated_score) > threshold:
                # Don't hold — just count and move on
                continue

            # Skip if within the triage window — too recent to auto-close
            if creation_time > cutoff_ms:
                skipped.append({
                    'incident_id': incident_id,
                    'aggregated_score': aggregated_score,
                    'reason': f'creation_time {creation_time} is within {window_hours}h window'
                })
                continue

            passed.append(inc)

        # If this batch had fewer than BATCH_SIZE results, no more pages
        if len(incidents) < BATCH_SIZE:
            break

    # Write one row per passed incident to dataset
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
                    'JSON': json.dumps(rows),
                    'using': 'socfw_ir_execution'
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
