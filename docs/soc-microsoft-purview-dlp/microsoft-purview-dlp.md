# Data Loss Prevention (microsoft-purview) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/microsoft-purview-dlp/microsoft-purview-dlp.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/microsoft-purview-dlp/microsoft-purview-dlp.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `microsoft-purview` |
| product | `Data Loss Prevention` |
| data_source | `msft_graph_security_alerts_raw` |
| category | `DLP` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `id` | `string` |  | declared |  |
| `title` | `string` |  | declared |  |
| `description` | `string` |  | declared |  |
| `category` | `string` |  | declared |  |
| `severity` | `string` |  | declared |  |
| `status` | `string` |  | declared |  |
| `serviceSource` | `string` |  | declared |  |
| `detectionSource` | `string` |  | declared |  |
| `productName` | `string` |  | declared |  |
| `providerAlertId` | `string` |  | declared |  |
| `alertWebUrl` | `string` |  | declared |  |
| `incidentId` | `string` |  | declared |  |
| `tenantId` | `string` |  | declared |  |
| `firstActivityDateTime` | `string` |  | declared |  |
| `lastActivityDateTime` | `string` |  | declared |  |
| `alertPolicyId` | `string` |  | declared |  |
| `mitreTechniques` | `json` | ✓ | declared |  |
| `evidence` | `json` | ✓ | declared | @odata.type, userAccount, fileDetails, mdeDeviceId, detectionStatus, recipien... |

## Correlation Rules

### SOC Purview DLP - Policy Alert

| Field | Value |
|---|---|
| global_rule_id | `SOC Purview DLP - Policy Alert` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for each Microsoft Purview Data Loss Prevention alert in the Microsoft Graph Security feed (serviceSource = dataLossPrevention). Parses the Graph evidence for the acting user, the file, the message (email DLP) and the cloud app (SharePoint / OneDrive / Exchange), canonicalizes the user email-first as the grouping pivot, and groups with Defender alerts of the same Defender incident via the synthetic causality id. Injects DS:Microsoft/Data Loss Prevention and DOM:Security so Foundation Product Classification routes to DLP.

**Tags:** `SOCFramework`, `Passthrough`, `DLP`, `MicrosoftPurview`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `tactic` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `providerAlertId` |

providerAlertId is Graph's per-alert unique id. Hourly suppression
absorbs back-to-back polls of the same alert.

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor` | `computed` |  |
| `product` | `product` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `originalalertsource` | `originalalertsource` | `computed` |  |
| `externallink` | `externallink` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `mitretacticid` | `mitretacticid` | `computed` |  |
| `mitretacticname` | `mitretacticname` | `computed` |  |
| `mitretechniqueid` | `mitretechniqueid` | `computed` |  |
| `mitretechniquename` | `mitretechniquename` | `computed` |  |
| `agent_hostname` | `agent_hostname` | `computed` |  |
| `agent_id` | `agent_id` | `computed` |  |
| `agent_device_domain` | `agent_device_domain` | `computed` |  |
| `actor_effective_username` | `actor_effective_username` | `computed` |  |
| `action_file_name` | `action_file_name` | `computed` |  |
| `action_file_path` | `action_file_path` | `computed` |  |
| `action_file_sha256` | `action_file_sha256` | `computed` |  |
| `user_principal` | `user_principal` | `computed` |  |
| `userid` | `user_principal` | `computed` |  |
| `usersid` | `evidence_user_sid` | `computed` |  |
| `samaccountname` | `evidence_user_sam` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `causality_actor_causality_id` | `causality_synth` | `computed` |  |
| `xdmsourceprocesscausalityid` | `causality_synth` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `agentid` | `agent_id` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filepath` | `action_file_path` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `socfwidentityuserdisplayname` | `idr_display_name` | `cie` |  |
| `emailmessageid` | `emailmessageid` | `computed` |  |
| `fw_email_recipient` | `fw_email_recipient` | `computed` |  |
| `fw_email_sender` | `fw_email_sender` | `computed` |  |
| `fw_email_subject` | `fw_email_subject` | `computed` |  |
| `emailsource` | `fw_email_sender` | `computed` |  |
| `socfwemaildeliveryaction` | `socfwemaildeliveryaction` | `computed` |  |
| `dlp_alert_policy_id` | `dlp_alert_policy_id` | `computed` |  |
| `dlp_incident_id` | `dlp_incident_id` | `computed` |  |
| `dlp_first_activity` | `dlp_first_activity` | `computed` |  |
| `dlp_last_activity` | `dlp_last_activity` | `computed` |  |
| `dlp_app_name` | `dlp_app_name` | `computed` |  |
| `dlp_app_instance` | `dlp_app_instance` | `computed` |  |
| `dlp_app_id` | `dlp_app_id` | `computed` |  |
| `dlp_file_size` | `dlp_file_size` | `computed` |  |
| `dlp_file_action` | `dlp_file_action` | `computed` |  |
| `dlp_recipient` | `dlp_recipient` | `computed` |  |
| `dlp_attachments` | `dlp_attachments` | `computed` |  |
| `tags` | `alert_tags` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Microsoft", product_name = productName

// ---- Scope: Purview DLP alerts only (partition with MDE / MDO rules)
| filter serviceSource = "dataLossPrevention"
| filter status != "resolved"

// Tactic alias — drives user_defined_category
| alter tactic = category

// Severity: Graph severities are lowercase
| alter severity = if(
        lowercase(severity) = "high",   "High",
        lowercase(severity) = "medium", "Medium",
        lowercase(severity) = "low",    "Low",
        lowercase(severity) = "informational", "Informational",
        "Low"
    )

// MITRE — same derivation as the Defender contracts
| alter cat_norm = replace(replace(replace(replace(lowercase(category), " ", ""), "-", ""), "_", ""), ".", "")
| alter
    mitre_tactic          = category,
    mitre_tactic_id       = if(
        cat_norm contains "exfiltration",        "TA0010",
        cat_norm contains "collection",          "TA0009",
        cat_norm contains "initialaccess",       "TA0001",
        cat_norm contains "impact",              "TA0040",
        ""),
    mitre_technique_first = arrayindex(mitreTechniques -> [], 0),
    mitre_technique_str   = arraystring(mitreTechniques -> [], ",")

// ---- Evidence: first element of each type
| alter
    userEvidence    = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "userEvidence"), 0),
    fileEvidence    = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "fileEvidence"), 0),
    messageEvidence = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "analyzedMessageEvidence"), 0),
    appEvidence     = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "cloudApplicationEvidence"), 0),
    deviceEvidence  = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "deviceEvidence"), 0)

| alter
    evidence_user_upn     = userEvidence -> userAccount.userPrincipalName,
    evidence_user_sid     = userEvidence -> userAccount.userSid,
    evidence_user_display = userEvidence -> userAccount.displayName,
    evidence_user_domain  = userEvidence -> userAccount.domainName,
    evidence_user_sam     = userEvidence -> userAccount.accountName

| alter
    dlp_file_name     = fileEvidence -> fileDetails.fileName,
    dlp_file_path     = fileEvidence -> fileDetails.filePath,
    dlp_file_sha256   = fileEvidence -> fileDetails.sha256,
    dlp_file_size     = fileEvidence -> fileDetails.fileSize,
    dlp_file_device   = fileEvidence -> mdeDeviceId,
    dlp_file_action   = fileEvidence -> detectionStatus

| alter
    dlp_recipient     = messageEvidence -> recipientEmailAddress,
    dlp_sender        = messageEvidence -> p1Sender.emailAddress,
    dlp_subject       = messageEvidence -> subject,
    dlp_internet_msg  = messageEvidence -> internetMessageId,
    dlp_network_msg   = messageEvidence -> networkMessageId,
    dlp_delivery      = messageEvidence -> deliveryAction,
    dlp_attachments   = messageEvidence -> attachmentsCount

| alter
    dlp_app_name      = appEvidence -> displayName,
    dlp_app_instance  = appEvidence -> instanceName,
    dlp_app_id        = appEvidence -> saasAppId,
    dlp_device_host   = deviceEvidence -> hostName,
    dlp_device_id     = deviceEvidence -> mdeDeviceId

// ---- Identity: the acting user, email-first. For email DLP the sender
//      (an internal user) is the actor; the recipient is the destination.
| alter acting_user = lowercase(coalesce(evidence_user_upn, dlp_sender))
| alter user_principal = acting_user
| alter user_name      = coalesce(acting_user, evidence_user_sam)
| alter display_name   = evidence_user_display
| alter actor_effective_username = acting_user

// Cross-rule grouping: same synthetic causality as MDE / MDO365
| alter causality_synth = if(incidentId != null, concat("msgraph-incident-", to_string(incidentId)), null)

// Title: [DLP] {user} - {tactic}: {policy alert title}
| alter alert_name = concat(
        "[DLP] ",
        coalesce(acting_user, "Unknown User"),
        " - ",
        coalesce(category, "Policy Match"),
        ": ",
        coalesce(title, "Purview DLP alert")
    )

| alter alert_description = concat(
        coalesce(description, "Microsoft Purview DLP policy alert"),
        " | User: ",      coalesce(acting_user, "Unknown"),
        " | App: ",       coalesce(dlp_app_name, dlp_app_instance, "-"),
        " | File: ",      coalesce(dlp_file_name, "-"),
        " | Recipient: ", coalesce(dlp_recipient, "-"),
        " | Subject: ",   coalesce(dlp_subject, ""),
        " | Severity: ",  coalesce(severity, "Unknown")
    )

// ============================================================
// CANONICAL CORE NORMALIZATION
// ============================================================
| alter
        vendor                               = vendor_name,
        product                              = product_name,
        originalalertid                      = providerAlertId,
        originalalertname                    = alert_name,
        originalalertsource                  = productName,
        externallink                         = alertWebUrl,
        severity                             = severity,
        mitretacticid                        = mitre_tactic_id,
        mitretacticname                      = mitre_tactic,
        mitretechniqueid                     = mitre_technique_first,
        mitretechniquename                   = mitre_technique_str,
        agent_hostname                       = dlp_device_host,
        agent_id                             = coalesce(dlp_device_id, dlp_file_device),
        agent_device_domain                  = evidence_user_domain,
        actor_process_image_name             = null,
        actor_process_image_path             = null,
        actor_process_image_sha256           = null,
        actor_process_command_line           = null,
        actor_process_os_pid                 = null,
        causality_actor_process_image_name   = null,
        causality_actor_process_image_path   = null,
        causality_actor_process_image_sha256 = null,
        action_file_name                     = dlp_file_name,
        action_file_path                     = dlp_file_path,
        action_file_sha256                   = dlp_file_sha256,
        action_local_ip                      = null,
        action_remote_ip                     = null

// ---- DLP surface + email parity fields
| alter
        dlp_alert_policy_id        = alertPolicyId,
        dlp_incident_id            = to_string(incidentId),
        dlp_first_activity         = firstActivityDateTime,
        dlp_last_activity          = lastActivityDateTime,
        emailmessageid             = dlp_internet_msg,
        fw_email_recipient         = dlp_recipient,
        fw_email_sender            = dlp_sender,
        fw_email_subject           = dlp_subject,
        socfwemaildeliveryaction   = dlp_delivery

// Tag injection — DS:Microsoft/Data Loss Prevention → ds_microsoft_data_loss_prevention
| alter alert_tags = arraycreate("DS:Microsoft/Data Loss Prevention", "DOM:Security")
```
