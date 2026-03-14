# Load these for testing, but ignore in operation
# Universal Command allows multiple Vendor commands to be used by a single Universal Command
import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore
# This is a helper script designed to be used with the "[BETA] MSGraph Endpoint Alert Layout". This populates a dynamic section of the layout with the most current host record,
# as extracted from the Microsoft Defender for Endpoint integration, using the microsoft-atp-get-machine-details command

def main():
    try:
        context_data = demisto.alert()
        agent_id = context_data['CustomFields']['agentid']
        host_context = execute_command('microsoft-atp-get-machine-details', {'machine_id': agent_id})
        host_record = host_context[0]

        return_results(host_record)

    except Exception as e:
        error_statement = "🔴 There has been an issue gathering host details. Please ensure the Microsoft Defender for Endpoint automation integration is enabled, and please verify that the displayDefenderHostDetails automation has been updated beyond placeholder status.\n"
        error_statement += "\n\n\nException thrown: " + str(e)
        return_results(error_statement)

if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
