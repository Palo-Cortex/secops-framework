import demistomock as demisto
from CommonServerPython import *


def score_identity_incident(args: dict) -> CommandResults:
    """
    Evaluates identity enrichment outputs and sets Analysis context keys.

    Scoring tiers:
      CRITICAL  — Identity provider event present (MFA deactivation, admin role,
                  SP credential addition) + auth failures
      HIGH      — Auth failures >= 10 across 3+ targets, OR forwarding rule created
      MEDIUM    — Auth failures present but below threshold, OR anomalous M365 activity
      LOW       — Single-source signal, no corroborating events

    Value Driver: VD1 (MTTD quality), VD3 (eliminate manual triage)
    SOC Challenge: Repetitive Workflows, Analyst Fatigue
    """

    # --- Inputs ---
    auth_failures = int(args.get('auth_failures') or 0)
    identity_event_count = int(args.get('identity_event_count') or 0)
    identity_event_types = args.get('identity_event_types') or []
    if isinstance(identity_event_types, str):
        identity_event_types = [identity_event_types]

    forwarding_rules_created = int(args.get('forwarding_rules_created') or 0)
    file_downloads = int(args.get('file_downloads') or 0)
    primary_entity_value = args.get('primary_entity_value', '')
    mitre_tactic = args.get('mitre_tactic', 'Credential Access')
    mitre_tactic_id = args.get('mitre_tactic_id', 'TA0006')
    case_user_count = int(args.get('case_user_count') or 1)
    case_host_count = int(args.get('case_host_count') or 1)

    # --- High-value identity event types that escalate to CRITICAL ---
    critical_event_types = {
        'user.mfa.factor.deactivate',
        'group.user.add',
        'Add service principal credentials',
        'Add service principal',
        'Add member to role',
        'user.session.impersonation.grant',
    }

    high_event_types = {
        'user.account.update_password',
        'Add application credentials',
        'Update application',
        'Reset user password',
    }

    has_critical_identity_event = bool(
        set(identity_event_types) & critical_event_types
    )
    has_high_identity_event = bool(
        set(identity_event_types) & high_event_types
    )
    has_forwarding_rule = forwarding_rules_created >= 1
    has_mass_download = file_downloads >= 50
    has_auth_spray = auth_failures >= 10

    # --- Scoring ---
    if has_critical_identity_event:
        verdict = 'malicious'
        confidence = 'high'
        compromise_decision = 'confirmed'
        compromise_level = 'critical'
        case_score = 95
        spread_level = 'lateral' if has_forwarding_rule or has_mass_download else 'isolated'
        response_recommended = 'true'

    elif has_forwarding_rule:
        verdict = 'malicious'
        confidence = 'high'
        compromise_decision = 'confirmed'
        compromise_level = 'high'
        case_score = 85
        spread_level = 'lateral'
        response_recommended = 'true'

    elif has_auth_spray and has_high_identity_event:
        verdict = 'malicious'
        confidence = 'medium'
        compromise_decision = 'suspected'
        compromise_level = 'high'
        case_score = 75
        spread_level = 'isolated'
        response_recommended = 'true'

    elif has_auth_spray or has_high_identity_event or has_mass_download:
        verdict = 'suspicious'
        confidence = 'medium'
        compromise_decision = 'suspected'
        compromise_level = 'medium'
        case_score = 55
        spread_level = 'isolated'
        response_recommended = 'true'

    elif identity_event_count > 0:
        verdict = 'suspicious'
        confidence = 'low'
        compromise_decision = 'suspected'
        compromise_level = 'low'
        case_score = 35
        spread_level = 'isolated'
        response_recommended = 'false'

    else:
        verdict = 'benign'
        confidence = 'high'
        compromise_decision = 'none'
        compromise_level = 'low'
        case_score = 10
        spread_level = 'isolated'
        response_recommended = 'false'

    # --- Build context ---
    analysis_context = {
        'verdict': verdict,
        'confidence': confidence,
        'compromise_decision': compromise_decision,
        'compromise_level': compromise_level,
        'case_score': case_score,
        'signal_type': 'identity_threat',
        'spread_level': spread_level,
        'response_recommended': response_recommended,
        'primary_entity_id': primary_entity_value,
        'primary_entity_type': 'user',
        'mitre_tactic': mitre_tactic,
        'mitre_tactic_id': mitre_tactic_id,
        'case_user_count': case_user_count,
        'case_host_count': case_host_count,
    }

    # Warroom summary
    warroom_msg = (
        f"## SOC Framework — Identity Analysis Verdict\n\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| Actor | `{primary_entity_value}` |\n"
        f"| Verdict | **{verdict.upper()}** |\n"
        f"| Confidence | {confidence} |\n"
        f"| Compromise decision | {compromise_decision} |\n"
        f"| Compromise level | {compromise_level} |\n"
        f"| Case score | {case_score}/100 |\n"
        f"| Spread level | {spread_level} |\n"
        f"| Response recommended | {response_recommended} |\n"
        f"| MITRE tactic | {mitre_tactic} ({mitre_tactic_id}) |\n"
        f"| Affected users | {case_user_count} |\n"
        f"| Affected hosts | {case_host_count} |\n\n"
        f"**Corroborating signals:**\n"
        f"- Auth failures (24h): {auth_failures}\n"
        f"- Identity provider events: {identity_event_count} "
        f"({', '.join(identity_event_types[:5]) if identity_event_types else 'none'})\n"
        f"- Forwarding rules created: {forwarding_rules_created}\n"
        f"- File downloads: {file_downloads}\n"
    )

    return CommandResults(
        outputs_prefix='Analysis',
        outputs=analysis_context,
        readable_output=warroom_msg,
        raw_response=analysis_context,
    )


def main():
    try:
        args = demisto.args()
        result = score_identity_incident(args)
        return_results(result)
    except Exception as e:
        return_error(f'SOCFramework_IdentityScoreAnalysis failed: {str(e)}')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
