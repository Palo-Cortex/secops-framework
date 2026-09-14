# Entra ID (microsoft-entra-id) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/microsoft-entra-id/microsoft-entra-id-signins.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/microsoft-entra-id/microsoft-entra-id-signins.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `microsoft-entra-id` |
| product | `Entra ID` |
| data_source | `msft_azure_ad_raw` |
| category | `Identity` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `id` | `string` |  | declared |  |
| `correlationid` | `string` |  | declared |  |
| `createddatetime` | `string` |  | declared |  |
| `userprincipalname` | `string` |  | declared |  |
| `userdisplayname` | `string` |  | declared |  |
| `userid` | `string` |  | declared |  |
| `usertype` | `string` |  | declared |  |
| `appdisplayname` | `string` |  | declared |  |
| `appid` | `string` |  | declared |  |
| `resourcedisplayname` | `string` |  | declared |  |
| `ipaddress` | `string` |  | declared |  |
| `autonomoussystemnumber` | `int` |  | declared |  |
| `clientappused` | `string` |  | declared |  |
| `isinteractive` | `boolean` |  | declared |  |
| `conditionalaccessstatus` | `string` |  | declared |  |
| `risklevelduringsignin` | `string` |  | declared |  |
| `risklevelaggregated` | `string` |  | declared |  |
| `riskstate` | `string` |  | declared |  |
| `riskdetail` | `string` |  | declared |  |
| `riskeventtypes_v2` | `json` | ✓ | declared |  |
| `status` | `json` |  | declared |  |
| `location` | `json` |  | declared |  |
| `devicedetail` | `json` |  | declared |  |

## Correlation Rules

### SOC Identity - Entra ID Suspicious Sign-In

| Field | Value |
|---|---|
| global_rule_id | `SOC Identity - Entra ID Suspicious Sign-In` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for Entra ID sign-in events with risk indicators: failed authentication, elevated risk level during sign-in, or an active risk state. Canonicalizes the user principal email-first as the identity grouping pivot and maps the source IP, application, resource, risk and conditional-access context. XSIAM native behavioral identity analytics also fire on this data after baseline learning; this rule fires on field values immediately.

**Tags:** `SOCFramework`, `Detection`, `Identity`, `EntraID`, `T1078`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `alert_category` |
| user_defined_severity | `alert_severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `correlationid` |

Preserved from the shipped rule.

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `agent_device_domain` | `domain_part` | `computed` |  |
| `action_remote_ip` | `action_remote_ip` | `computed` |  |
| `vendor` | `vendor_name` | `computed` |  |
| `product` | `product_name` | `computed` |  |
| `user_principal` | `userprincipalname` | `raw` |  |
| `userid` | `userprincipalname` | `raw` |  |
| `usersid` | `userid` | `raw` |  |
| `socfwidentityaction` | `sign_in_action` | `computed` |  |
| `socfwidentityapp` | `appdisplayname` | `raw` |  |
| `socfwidentityresource` | `resourcedisplayname` | `raw` |  |
| `socfwidentityrisk` | `risklevelduringsignin` | `raw` |  |
| `socfwidentityriskstate` | `riskstate` | `raw` |  |
| `socfwidentitylocation` | `location_str` | `computed` |  |
| `socfwidentitycondaccess` | `conditionalaccessstatus` | `raw` |  |
| `socfwidentityerrorcode` | `error_code_str` | `computed` |  |
| `socfwidentityfailurereason` | `failure_reason` | `computed` |  |
| `mitretacticid` | `mitre_tactic_id` | `computed` |  |
| `mitretacticname` | `mitre_tactic` | `computed` |  |
| `mitretechniqueid` | `mitre_ids_str` | `computed` |  |
| `mitretechniquename` | `mitre_ids_str` | `computed` |  |
| `actor_effective_username` | `actor_effective_username` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `originalalertsource` | `originalalertsource` | `computed` |  |
| `externallink` | `externallink` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `agent_hostname` | `agent_hostname` | `computed` |  |
| `agent_id` | `agent_id` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `socfwidentityuserdisplayname` | `idr_display_name` | `cie` |  |
| `entra_sign_in_id` | `entra_sign_in_id` | `computed` |  |
| `entra_risk_detail` | `entra_risk_detail` | `computed` |  |
| `entra_risk_events` | `entra_risk_events` | `computed` |  |
| `entra_client_app` | `entra_client_app` | `computed` |  |
| `entra_is_interactive` | `entra_is_interactive` | `computed` |  |
| `entra_user_type` | `entra_user_type` | `computed` |  |
| `entra_asn` | `entra_asn` | `computed` |  |
| `tags` | `alert_tags` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Microsoft", product_name = "Entra ID"

// Extract nested status fields (status is a JSON string)
| alter
    error_code     = json_extract_scalar(status, "$.errorCode"),
    failure_reason = json_extract_scalar(status, "$.failureReason")

// Gate: only fire on events with risk indicators
// 1. Failed auth (errorCode != 0)
// 2. Risk level elevated during sign-in
// 3. Risk state indicates active risk
| filter (
    error_code != "0"
    or risklevelduringsignin not in ("none", "")
    or riskstate not in ("none", "")
)

// Exclude baseline normal events (no risk, successful)
| filter not (error_code = "0" and risklevelduringsignin = "none" and riskstate = "none")

// Alert severity based on risk level
| alter
    alert_severity = if(
        risklevelduringsignin = "high", "SEV_050_CRITICAL",
        risklevelduringsignin = "medium", "SEV_040_HIGH",
        error_code != "0", "SEV_030_MEDIUM",
        "SEV_020_LOW"
    ),
    alert_category = "Identity Security",
    sign_in_action = if(
        error_code != "0", "failed_sign_in",
        risklevelduringsignin = "high", "risky_sign_in",
        risklevelduringsignin = "medium", "risky_sign_in",
        "suspicious_sign_in"
    ),
    alert_name = concat(
        "[Identity] ",
        coalesce(userprincipalname, userdisplayname, "Unknown"),
        if(error_code != "0",
            concat(" - Failed Auth (", error_code, ") to ", coalesce(appdisplayname, "Unknown App")),
            concat(" - Risky Sign-In (", coalesce(risklevelduringsignin, "unknown"), ") to ", coalesce(appdisplayname, "Unknown App"))
        )
    ),
    alert_description = concat(
        if(error_code != "0", "Failed authentication", "Risky sign-in detected"),
        " | User: ", coalesce(userprincipalname, "Unknown"),
        " | App: ", coalesce(appdisplayname, "Unknown"),
        " | IP: ", coalesce(ipaddress, "Unknown"),
        " | Risk: ", coalesce(risklevelduringsignin, "none"),
        " | Location: ", coalesce(json_extract_scalar(location, "$.countryOrRegion"), "Unknown")
    )

// Location as flat string for alert_fields
| alter location_str = concat(
    coalesce(json_extract_scalar(location, "$.city"), ""),
    ", ",
    coalesce(json_extract_scalar(location, "$.state"), ""),
    ", ",
    coalesce(json_extract_scalar(location, "$.countryOrRegion"), "")
)

// Domain extraction from UPN
| alter domain_part = arrayindex(split(userprincipalname, "@"), 1)

// Error code as string for alert_fields
| alter error_code_str = to_string(error_code)

// MITRE ATT&CK — Identity events are Valid Accounts / Initial Access
| alter
    mitre_tactic       = "Initial Access",
    mitre_tactic_id    = "TA0001",
    mitre_technique    = "Valid Accounts",
    mitre_technique_id = "T1078",
    mitre_ids_str      = "T1078 - Valid Accounts"

// ============================================================
// ADDITIVE — canonical core, identity block, tags. Nothing above changes.
// ============================================================
| alter
        original_upn = userprincipalname
| alter
        user_principal = userprincipalname,
        user_name      = lowercase(userprincipalname),
        display_name   = userdisplayname

| alter
        vendor              = vendor_name,
        product             = product_name,
        originalalertid     = coalesce(correlationid, id),
        originalalertname   = alert_name,
        originalalertsource = "Microsoft Entra ID - Sign-in Logs",
        externallink        = null,
        severity            = if(
            alert_severity = "SEV_050_CRITICAL", "Critical",
            alert_severity = "SEV_040_HIGH",     "High",
            alert_severity = "SEV_030_MEDIUM",   "Medium",
            "Low"),
        agent_hostname      = null,
        agent_id            = null,
        action_local_ip     = null,
        action_remote_ip    = ipaddress,
        actor_effective_username = lowercase(userprincipalname),
  agent_device_domain      = domain_part

| alter entra_sign_in_id   = id,
        entra_risk_detail  = riskdetail,
        entra_risk_events  = to_string(riskeventtypes_v2),
        entra_client_app   = clientappused,
        entra_is_interactive = isinteractive,
        entra_user_type    = usertype,
        entra_asn          = to_string(autonomoussystemnumber)

// Tag injection — DS:Microsoft/Entra ID → ds_microsoft_entra_id
| alter alert_tags = arraycreate("DS:Microsoft/Entra ID", "DOM:Security")
```
