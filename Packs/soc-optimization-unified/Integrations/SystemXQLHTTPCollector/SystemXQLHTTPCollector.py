try:
    import demistomock as demisto  # type: ignore
except Exception:
    # In XSOAR/XSIAM runtime, demisto is already available
    pass

try:
    from CommonServerPython import *  # type: ignore
    from CommonServerPython import register_module_line, __line__  # type: ignore
except Exception:
    # In tenant runtime, CommonServerPython is implicitly available
    # If these debug helpers are not available, make them no-ops
    def register_module_line(*args, **kwargs):
        return None

    def __line__():
        return 0

import json


def test_module_command() -> str:
    """
    A placeholder function to implement testing - doesn't actually do anything (yet).

    Returns:
        (str) 'ok' if success.
    """
    return 'ok'

def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            return_results(test_module_command())

        elif command == 'xql-post-to-dataset':
            VENDOR = args.get('vendor') if args.get('vendor') else params.get('vendor')
            PRODUCT = args.get('product') if args.get('product') else params.get('product')

            events = json.loads(args.get('JSON'))
            events = json.loads(args.get('JSON'))
            events = events if type(events) == list else [events]

            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

