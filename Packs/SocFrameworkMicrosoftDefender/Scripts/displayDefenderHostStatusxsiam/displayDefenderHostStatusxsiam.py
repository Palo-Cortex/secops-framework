# Load these for testing, but ignore in operation
# Universal Command allows multiple Vendor commands to be used by a single Universal Command
import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore
# This is a helper script designed to be used with the "[BETA] MSGraph Endpoint Alert Layout". This populates a dynamic section of the layout with the most current host record,
# as extracted from the Microsoft Defender for Endpoint integration, using the microsoft-atp-get-machine-details command

def main():
    try:
        context_data = demisto.alert()
        full_context = demisto.context()
        agent_id = context_data['CustomFields']['agentid']


        try:
            machine_action = full_context['MicrosoftATP']['MachineAction'] #[-1]['Type'] #full_context['MicrosoftATP']['MachineAction'][-1]['Type']
            if isinstance(machine_action, list):
                last_action_type = machine_action[-1]['Type']
                last_action_time = machine_action[-1]['CreationDateTimeUtc']
            else:
                last_action_type = machine_action['Type']
                last_action_time = machine_action['CreationDateTimeUtc']

        except Exception as e:
            last_action_type = "None"

        if last_action_type == "Isolate":
            last_action = "🚫 Isolate (UTC: " + last_action_time + ")"
        elif last_action_type == "Unisolate":
            last_action = "🟢 Unisolate (UTC: " + last_action_time + ")"
        else:
            last_action = "None"

        # Note, this has not been implemented or tested yet. Just a placeholder.
        host_record = execute_command('microsoft-atp-get-machine-details', {'machine_id': agent_id})
        last_seen = host_record[0]['lastSeen']
        risk_score = host_record[0]['riskScore']
        if risk_score == "Low":
            risk_score = "🟢 Low"
        elif risk_score == "Medium":
            risk_score = "🟡 Medium"
        elif risk_score == "Informational":
            risk_score = "🔵 Informational"
        elif risk_score == "High":
            risk_score = "🔴 High"
        else:
            risk_score = "🟤 Unknown or None"

        # All of this needs to be re-written based on MSFT Machine details format
        host_name = host_record[0]['computerDnsName']
        host_status = host_record[0]['healthStatus']
        if host_status == "Active":
            host_status = "🟢 Active"
        elif host_status == "Misconfigured":
            host_status = "🟡 Misconfigured"
        elif host_status == "Inactive":
            host_status = "🔴 Inactive"
        else:
            host_status = "🟤 Unknown or Offline"

        host_current_local_ip = host_record[0]['lastIpAddress']
        host_current_external_ip = host_record[0]['lastExternalIpAddress']
        host_os = host_record[0]['osPlatform']
        host_snippet = "Hostname: " + host_name + "\n" + "MDE Risk Score: " + risk_score + "\n" + "MDE Status: " + host_status + "\n" + "Last XSIAM Action: " + last_action + "\n" + "Last Seen: " + last_seen + "\n" + "Current Local IP: " + host_current_local_ip + "\n" + "Current External IP: " + host_current_external_ip + "\n" + "OS: " + host_os
        return_results(host_snippet)

    except Exception as e:
        error_statement = "🔴 There has been an issue gathering host status. Please ensure the Microsoft Defender for Endpoint automation integration is enabled, and please verify that agentid exists and is populated in the issue/alert context. Check WarRoom for more details.\n"
        error_statement += "\n\n\n\n\n\nException thrown: " + str(e)
        return_results(error_statement)

if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
