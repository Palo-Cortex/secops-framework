# Microsoft Defender for Office 365 (microsoft-defender-office365) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/microsoft-defender-office365/microsoft-defender-office365.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/microsoft-defender-office365/microsoft-defender-office365.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `microsoft-defender-office365` |
| product | `Microsoft Defender for Office 365` |
| data_source | `msft_graph_security_alerts_raw` |
| category | `Email` |

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
| `mitreTechniques` | `json` | ✓ | declared |  |
| `evidence` | `json` | ✓ | declared | @odata.type, recipientEmailAddress, p1Sender, p2Sender, subject, networkMessa... |

## Correlation Rules

### SOC MDO365 - Email Threat Detected

| Field | Value |
|---|---|
| global_rule_id | `SOC MDO365 - Email Threat Detected` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for each Microsoft Defender for Office 365 email threat from the Microsoft Graph Security alerts feed. Parses the Graph evidence array for the analyzed message (recipient, sender, message ids, delivery action, threats, URLs, attachment hash) and the recipient mailbox, canonicalizes the recipient email-first as the grouping pivot, and groups with Defender for Endpoint alerts of the same Defender incident via the synthetic causality id.

**Tags:** `SOCFramework`, `Passthrough`, `Email`, `MicrosoftDefenderForOffice365`, `InitialAccess`, `LateralMovement`, `T1566`, `T1566.001`, `T1566.002`, `T1534`

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
| duration | `24 hours` |
| fields | `emailmessageid` |

Preserved from the shipped rule: emailmessageid = providerAlertId
(Graph's per-alert unique id), 24h window. The real message ids are
additive fields (fw_email_internet_message_id / fw_email_network_message_id).

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
| `actor_process_image_name` | `actor_process_image_name` | `computed` |  |
| `actor_process_image_path` | `actor_process_image_path` | `computed` |  |
| `actor_process_image_sha256` | `actor_process_image_sha256` | `computed` |  |
| `actor_process_command_line` | `actor_process_command_line` | `computed` |  |
| `actor_process_os_pid` | `actor_process_os_pid` | `computed` |  |
| `causality_actor_process_image_name` | `causality_actor_process_image_name` | `computed` |  |
| `causality_actor_process_image_path` | `causality_actor_process_image_path` | `computed` |  |
| `causality_actor_process_image_sha256` | `causality_actor_process_image_sha256` | `computed` |  |
| `action_file_name` | `action_file_name` | `computed` |  |
| `action_file_path` | `action_file_path` | `computed` |  |
| `action_file_sha256` | `action_file_sha256` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `action_remote_ip` | `action_remote_ip` | `computed` |  |
| `dns_query_name` | `dns_query_name` | `computed` |  |
| `user_principal` | `user_principal` | `computed` |  |
| `causality_actor_causality_id` | `causality_synth` | `computed` |  |
| `xdmsourceprocesscausalityid` | `causality_synth` | `computed` |  |
| `userid` | `user_principal` | `computed` |  |
| `usersid` | `mailbox_sid` | `computed` |  |
| `socfwidentityuserdisplayname` | `idr_display_name` | `cie` |  |
| `emailmessageid` | `emailmessageid` | `computed` |  |
| `emailsenderip` | `email_sender_ipv4` | `computed` |  |
| `emailsource` | `email_sender` | `computed` |  |
| `fw_email_recipient` | `fw_email_recipient` | `computed` |  |
| `fw_email_internet_message_id` | `fw_email_internet_message_id` | `computed` |  |
| `fw_email_network_message_id` | `fw_email_network_message_id` | `computed` |  |
| `fw_email_sender` | `fw_email_sender` | `computed` |  |
| `fw_email_subject` | `fw_email_subject` | `computed` |  |
| `clickedurls` | `socfwemailthreaturl` | `computed` |  |
| `filehash` | `attachment_sha256` | `computed` |  |
| `socfwemaildeliveryaction` | `socfwemaildeliveryaction` | `computed` |  |
| `socfwemaildirection` | `socfwemaildirection` | `computed` |  |
| `socfwemailthreaturl` | `socfwemailthreaturl` | `computed` |  |
| `socfwemailthreattype` | `socfwemailthreattype` | `computed` |  |
| `socfwemailcampaignid` | `socfwemailcampaignid` | `computed` |  |
| `fw_email_alert_id` | `fw_email_alert_id` | `computed` |  |
| `fw_email_incident_id` | `fw_email_incident_id` | `computed` |  |
| `fw_email_threat_severity` | `fw_email_threat_severity` | `computed` |  |
| `fw_email_category` | `fw_email_category` | `computed` |  |
| `fw_email_tactic_id` | `fw_email_tactic_id` | `computed` |  |
| `fw_email_mitre_techniques` | `fw_email_mitre_techniques` | `computed` |  |
| `fw_email_detection_source` | `fw_email_detection_source` | `computed` |  |
| `fw_email_service_source` | `fw_email_service_source` | `computed` |  |
| `fw_email_alert_url` | `fw_email_alert_url` | `computed` |  |
| `fw_email_tenant_id` | `fw_email_tenant_id` | `computed` |  |
| `fw_email_description` | `fw_email_description` | `computed` |  |
| `fw_email_first_activity` | `fw_email_first_activity` | `computed` |  |
| `fw_email_last_activity` | `fw_email_last_activity` | `computed` |  |
| `socfwemailthreat_type` | `socfwemailthreat_type` | `computed` |  |
| `socfwemailthreat_status` | `socfwemailthreat_status` | `computed` |  |
| `socfwemailthreat_source` | `socfwemailthreat_source` | `computed` |  |
| `socfwemailthreat_detection` | `socfwemailthreat_detection` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Microsoft", product_name = productName

// ---- Scope: Defender for Office 365 only. Partition with the MDE rule
//      (productName in MDE/XDR). Preserved from the shipped rule.
| filter serviceSource = "microsoftDefenderForOffice365"
| filter severity in ("high", "medium")
| filter status in ("new", "inProgress", "queued", "running", "partiallyRemediated")
| filter category in ("InitialAccess", "LateralMovement")

// Tactic alias — drives user_defined_category
| alter tactic = category

// MITRE — same derivation as the MDE contract so both rules agree
| alter
    cat_norm  = replace(replace(replace(replace(lowercase(category), " ", ""), "-", ""), "_", ""), ".", "")
| alter
    mitre_tactic          = category,
    mitre_tactic_id       = if(
        cat_norm contains "initialaccess",       "TA0001",
        cat_norm contains "execution",           "TA0002",
        cat_norm contains "persistence",         "TA0003",
        cat_norm contains "privilegeescalation", "TA0004",
        cat_norm contains "defenseevasion",      "TA0005",
        cat_norm contains "credentialaccess",    "TA0006",
        cat_norm contains "discovery",           "TA0007",
        cat_norm contains "lateralmovement",     "TA0008",
        cat_norm contains "collection",          "TA0009",
        cat_norm contains "commandandcontrol",   "TA0011",
        cat_norm contains "exfiltration",        "TA0010",
        cat_norm contains "impact",              "TA0040",
        ""),
    mitre_technique_first = arrayindex(mitreTechniques -> [], 0),
    mitre_technique_str   = arraystring(mitreTechniques -> [], ",")

// ---- Evidence: first element of each type we care about
| alter
    messageEvidence = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "analyzedMessageEvidence"), 0),
    mailboxEvidence = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "mailboxEvidence"), 0),
    userEvidence    = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "userEvidence"), 0),
    urlEvidence     = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "urlEvidence"), 0),
    fileEvidence    = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "fileEvidence"), 0),
    clusterEvidence = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "mailClusterEvidence"), 0)

// Analyzed message
| alter
    email_recipient       = messageEvidence -> recipientEmailAddress,
    email_sender          = messageEvidence -> p1Sender.emailAddress,
    email_sender_header   = messageEvidence -> p2Sender.emailAddress,
    email_sender_domain   = messageEvidence -> p1Sender.domainName,
    email_subject         = messageEvidence -> subject,
    email_network_msg_id  = messageEvidence -> networkMessageId,
    email_internet_msg_id = messageEvidence -> internetMessageId,
    email_urls            = messageEvidence -> urls,
    email_url_count       = messageEvidence -> urlCount,
    email_delivery_action = messageEvidence -> deliveryAction,
    email_delivery_loc    = messageEvidence -> deliveryLocation,
    email_threats         = messageEvidence -> threats,
    email_attachment_cnt  = messageEvidence -> attachmentsCount,
    email_sender_ip       = messageEvidence -> senderIp,
    email_direction       = messageEvidence -> antiSpamDirection,
    email_received        = messageEvidence -> receivedDateTime

// Recipient mailbox / user
| alter
    mailbox_address   = mailboxEvidence -> primaryAddress,
    mailbox_upn       = mailboxEvidence -> userAccount.userPrincipalName,
    mailbox_sid       = mailboxEvidence -> userAccount.userSid,
    mailbox_display   = mailboxEvidence -> displayName,
    evidence_user_upn = userEvidence -> userAccount.userPrincipalName

// URL / attachment / cluster
| alter
    url_first         = urlEvidence -> url,
    attachment_name   = fileEvidence -> fileDetails.fileName,
    attachment_sha256 = fileEvidence -> fileDetails.sha256,
    cluster_by        = clusterEvidence -> clusterBy,
    cluster_value     = clusterEvidence -> clusterByValue,
    cluster_count     = clusterEvidence -> emailCount

// Sender IP as IPv4 only (canonical action_remote_ip is IPv4)
| alter email_sender_ipv4 = if(email_sender_ip ~= "(?:\\d{1,3}\\.){3}\\d{1,3}", email_sender_ip, null)

// ---- Identity: recipient, email-first. The recipient is who the
//      lifecycle acts on (the mailbox that got the phish), matching the
//      Proofpoint rule. user_principal / user_name feed the shared seed
//      + finalization (identity: true) → actor_effective_username.
| alter recipient_first = lowercase(coalesce(mailbox_upn, mailbox_address, email_recipient, evidence_user_upn))
| alter user_principal  = recipient_first
| alter user_name       = recipient_first
| alter display_name    = mailbox_display
| alter actor_effective_username = recipient_first

// Cross-rule grouping: same synthetic causality as the MDE contract, so
// an MDO phish and the MDE detonation from one Defender incident land in
// one XSIAM case. Never collides with process causality GUIDs.
| alter causality_synth = if(incidentId != null, concat("msgraph-incident-", to_string(incidentId)), null)

// Title: [Email] {recipient} - {tactic}: {vendor title}
| alter alert_name = concat(
        "[Email] ",
        coalesce(recipient_first, "Unknown Recipient"),
        " - ",
        coalesce(category, "Detection"),
        ": ",
        coalesce(title, "Defender for Office 365 alert")
    )

| alter alert_description = concat(
        coalesce(description, "Microsoft Defender for Office 365 alert"),
        " | Recipient: ",  coalesce(recipient_first, "Unknown"),
        " | Sender: ",     coalesce(email_sender, "Unknown"),
        " | Subject: ",    coalesce(email_subject, ""),
        " | Delivery: ",   coalesce(email_delivery_action, "Unknown"),
        " | Threats: ",    coalesce(to_string(email_threats), ""),
        " | Severity: ",   coalesce(severity, "Unknown")
    )

// ============================================================
// CANONICAL CORE NORMALIZATION
// Endpoint / process columns stay null for email alerts.
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
        mitretechniqueid                     = mitre_technique_str,
        mitretechniquename                   = mitre_technique_str,
        agent_hostname                       = null,
        agent_id                             = null,
        agent_device_domain                  = null,
        actor_process_image_name             = null,
        actor_process_image_path             = null,
        actor_process_image_sha256           = null,
        actor_process_command_line           = null,
        actor_process_os_pid                 = null,
        causality_actor_process_image_name   = null,
        causality_actor_process_image_path   = null,
        causality_actor_process_image_sha256 = null,
        action_file_name                     = attachment_name,
        action_file_path                     = null,
        action_file_sha256                   = attachment_sha256,
        action_local_ip                      = null,
        action_remote_ip                     = email_sender_ipv4,
        dns_query_name                       = email_sender_domain

// ---- Email surface preserved from the shipped rule (fw_email_* /
//      socfwemailthreat*), plus the Proofpoint-aligned issue fields
//      Foundation_-_Normalize_Email_V3 reads.
| alter
        fw_email_alert_id          = id,
        fw_email_incident_id       = to_string(incidentId),
        fw_email_subject           = coalesce(email_subject, title),
        fw_email_threat_severity   = severity,
        fw_email_category          = category,
        fw_email_tactic_id         = mitre_tactic_id,
        fw_email_mitre_techniques  = mitre_technique_str,
        fw_email_detection_source  = detectionSource,
        fw_email_service_source    = serviceSource,
        fw_email_alert_url         = alertWebUrl,
        fw_email_tenant_id         = tenantId,
        fw_email_description       = description,
        fw_email_first_activity    = firstActivityDateTime,
        fw_email_last_activity     = lastActivityDateTime,
        fw_email_recipient         = recipient_first,
        fw_email_sender            = email_sender,
        emailmessageid             = providerAlertId,
        fw_email_internet_message_id = email_internet_msg_id,
        fw_email_network_message_id  = email_network_msg_id,
        socfwemailthreat_type      = category,
        socfwemailthreat_status    = status,
        socfwemailthreat_source    = serviceSource,
        socfwemailthreat_detection = detectionSource,
        socfwemailthreattype       = to_string(email_threats),
        socfwemaildeliveryaction   = email_delivery_action,
        socfwemaildirection        = email_direction,
        socfwemailthreaturl        = coalesce(url_first, to_string(email_urls)),
        socfwemailcampaignid       = if(cluster_by != null, concat(cluster_by, "=", coalesce(cluster_value, "")), null)
```
