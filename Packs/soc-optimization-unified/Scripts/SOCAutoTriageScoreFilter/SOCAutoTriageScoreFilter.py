import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time


def main():
    args = demisto.args()

    incidents = args.get('incidents', [])
    threshold = args.get('score_threshold', '30')
    window_hours = args.get('window_hours', '6')

    # Ensure list — handle string (CLI), dict (single), or list
    if isinstance(incidents, str):
        try:
            incidents = json.loads(incidents)
        except Exception:
            return_error(f'Could not parse incidents as JSON: {incidents[:100]}')
    if isinstance(incidents, dict):
        incidents = [incidents]

    if not incidents:
        return_results(CommandResults(
            outputs_prefix='AutoTriage',
            outputs={
                'filtered_incidents': [],
                'skipped_incidents': [],
                'passed_count': 0,
                'skipped_count': 0
            },
            readable_output='No incidents to evaluate.'
        ))
        return

    try:
        threshold = float(threshold)
    except (ValueError, TypeError):
        return_error(f'Invalid score_threshold value: {threshold}')

    try:
        window_hours = float(window_hours)
    except (ValueError, TypeError):
        return_error(f'Invalid window_hours value: {window_hours}')

    # creation_time from the API is in milliseconds
    cutoff_ms = (time.time() - (window_hours * 3600)) * 1000

    passed = []
    skipped = []

    for inc in incidents:
        incident_id = inc.get('incident_id', 'unknown')
        aggregated_score = inc.get('aggregated_score')
        manual_score = inc.get('manual_score')
        creation_time = inc.get('creation_time', 0)

        # Skip if within the triage window — too recent to auto-close
        if creation_time > cutoff_ms:
            skipped.append({
                'incident_id': incident_id,
                'aggregated_score': aggregated_score,
                'reason': f'creation_time {creation_time} is within {window_hours}h window'
            })
            continue

        # Skip if analyst has manually set a score
        if manual_score is not None:
            skipped.append({
                'incident_id': incident_id,
                'aggregated_score': aggregated_score,
                'reason': 'manual_score set — analyst touched this case'
            })
            continue

        # Skip if score is above threshold or missing
        if aggregated_score is None or float(aggregated_score) > threshold:
            skipped.append({
                'incident_id': incident_id,
                'aggregated_score': aggregated_score,
                'reason': f'aggregated_score {aggregated_score} exceeds threshold {threshold}'
            })
            continue

        passed.append(inc)

    return_results(CommandResults(
        outputs_prefix='AutoTriage',
        outputs={
            'filtered_incidents': passed,
            'skipped_incidents': skipped,
            'passed_count': len(passed),
            'skipped_count': len(skipped)
        },
        readable_output=(
            f'Score filter complete: {len(passed)} passed, {len(skipped)} skipped '
            f'(threshold: {threshold}, window: {window_hours}h)'
        )
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
