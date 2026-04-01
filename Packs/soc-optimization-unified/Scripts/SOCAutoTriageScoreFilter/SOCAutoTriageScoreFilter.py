import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()

    incidents = args.get('incidents', [])
    threshold = args.get('score_threshold', '30')

    # Ensure list
    if isinstance(incidents, dict):
        incidents = [incidents]

    # Cast threshold — config stores as string, float handles decimals
    try:
        threshold = float(threshold)
    except (ValueError, TypeError):
        return_error(f'Invalid score_threshold value: {threshold}')

    passed = []
    skipped = []

    for inc in incidents:
        incident_id = inc.get('incident_id', 'unknown')
        aggregated_score = inc.get('aggregated_score')
        manual_score = inc.get('manual_score')

        # Skip if analyst has manually set a score — do not auto-close
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
            f'(threshold: {threshold})'
        )
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
