# Email Protection (abnormal-security) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/abnormal/abnormal-email.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/abnormal/abnormal-email.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `abnormal-security` |
| product | `Email Protection` |
| data_source | `abnormal_security_email_protection_raw` |
| category | `Email` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `abxMessageId` | `string` |  | declared |  |
| `abxMessageIdStr` | `string` |  | declared |  |
| `threatId` | `string` |  | declared |  |
| `internetMessageId` | `string` |  | declared |  |
| `fromAddress` | `string` |  | declared |  |
| `fromName` | `string` |  | declared |  |
| `senderDomain` | `string` |  | declared |  |
| `senderIpAddress` | `string` |  | declared |  |
| `returnPath` | `string` |  | declared |  |
| `replyToEmails` | `string` |  | declared |  |
| `recipientAddress` | `string` |  | declared |  |
| `toAddresses` | `string` |  | declared |  |
| `ccEmails` | `string` |  | declared |  |
| `subject` | `string` |  | declared |  |
| `urls` | `string` |  | declared |  |
| `links` | `string` |  | declared |  |
| `urlCount` | `int` |  | declared |  |
| `attachmentCount` | `int` |  | declared |  |
| `attachmentNames` | `string` |  | declared |  |
| `summaryInsights` | `string` |  | declared |  |
| `attackType` | `string` |  | declared |  |
| `attackVector` | `string` |  | declared |  |
| `attackStrategy` | `string` |  | declared |  |
| `attackedParty` | `string` |  | declared |  |
| `impersonatedParty` | `string` |  | declared |  |
| `remediationStatus` | `string` |  | declared |  |
| `remediationTimestamp` | `datetime` |  | declared |  |
| `autoRemediated` | `string` |  | declared |  |
| `postRemediated` | `string` |  | declared |  |
| `abxPortalUrl` | `string` |  | declared |  |
| `receivedTime` | `datetime` |  | declared |  |
| `sentTime` | `datetime` |  | declared |  |

## Correlation Rules

### SOC Abnormal Security - Threat Detected All Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC Abnormal Security - Threat Detected All Alerts` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Unified Abnormal Security inbound-email detection rule. Fires on any Abnormal attack verdict (attackType populated). Suppression is per abxMessageId to preserve full blast-radius visibility across recipients. Email-only vendor: host/process fields are null. Cross-rule grouping pivots against endpoint/identity sources: actor_effective_username (lowercase recipient email/UPN), user_principal (parallel), and the URL registered domain via fw_url_domain / dns_query_name (matches the endpoint's DNS/C2 domain artifact). Abnormal's threat log carries no attachment hashes, so action_file_sha256 is null by design. Username normalization: lowercase, email-first. Lowercase is mandatory -- exact-equality grouping makes casing a silent pivot-killer.

**Tags:** `SOCFramework`, `Detection`, `Email`, `AbnormalSecurity`, `T1566`

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
| duration | `24 hours` |
| fields | `abxMessageId` |

abxMessageId is unique per delivered message per recipient. A campaign
to N recipients generates N distinct ids, so suppression scopes to a
single message only -- zero effect on any other recipient's alert.

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
| `user_principal` | `user_principal` | `computed` |  |
| `dns_query_name` | `dns_name` | `computed` |  |
| `fw_url_domain` | `domain` | `computed` |  |
| `emailmessageid` | `internetMessageId` | `raw` |  |
| `emailsenderip` | `senderIpAddress` | `raw` |  |
| `emailsource` | `fromAddress` | `raw` |  |
| `fw_email_recipient` | `recipientAddress` | `raw` |  |
| `fw_email_sender` | `fromAddress` | `raw` |  |
| `fw_email_subject` | `subject` | `raw` |  |
| `clickedurls` | `cleaned_url` | `computed` | Cleaned URL for downstream proxy/firewall correlation |
| `socfwemaildeliveryaction` | `delivery_action` | `computed` |  |
| `socfwemaildirection` | `direction` | `computed` |  |
| `socfwemailthreaturl` | `cleaned_url` | `computed` |  |
| `socfwemailthreattype` | `threat_type` | `computed` |  |
| `socfwemailthreatstatus` | `remediationStatus` | `raw` |  |
| `socfwemailthreatid` | `threatId` | `raw` |  |
| `socfwemailclassification` | `threat_classification` | `computed` |  |
| `abnormalsecurityattacktype` | `attackType` | `raw` |  |
| `abnormalsecurityattackvector` | `attackVector` | `raw` |  |
| `abnormalsecurityattackstrategy` | `attackStrategy` | `raw` |  |
| `abnormalsecurityattackedparty` | `attackedParty` | `raw` |  |
| `abnormalsecurityimpersonatedparty` | `impersonatedParty` | `raw` |  |
| `abnormalsecuritysenderdomain` | `senderDomain` | `raw` |  |
| `abnormalsecuritysenderip` | `senderIpAddress` | `raw` |  |
| `abnormalsecurityfromname` | `fromName` | `raw` |  |
| `abnormalsecuritymessageid` | `abxMessageIdStr` | `raw` |  |
| `abnormalsecurityremediationstatus` | `remediationStatus` | `raw` |  |
| `abnormalsecurityremediationtimestamp` | `remediationTimestamp` | `raw` |  |
| `abnormalsecurityurlcount` | `urlCount` | `raw` |  |
| `abnormalsecurityattachmentcount` | `attachmentCount` | `raw` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `emailrecipient` | `recipientAddress` | `raw` |  |
| `emailsender` | `fromAddress` | `raw` |  |
| `emailsubject` | `subject` | `raw` |  |
| `dnsqueryname` | `dns_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product drive SOCProductCategoryMap routing downstream.
| alter vendor_name = "Abnormal Security", product_name = "Email Protection"

// Fire only on a real Abnormal verdict. Blank attackType = no threat.
| filter attackType != null and attackType != ""

// Recipient: Abnormal ships a scalar recipientAddress plus a toAddresses
// JSON array. Prefer the scalar, fall back to the first array address.
| alter recipient_first = coalesce(
        recipientAddress,
        arrayindex(regextract(to_string(toAddresses), "([\w.%+-]+@[\w.-]+)"), 0))
| alter recipient_local = lowercase(arrayindex(regextract(coalesce(recipient_first, ""), "([\w.%+-]+)@"), 0))
| alter recipient_email = lowercase(recipient_first)

// urls is a JSON array of URL strings. Pull the first and derive its
// registered domain -- this is the cross-product grouping artifact that
// matches the endpoint source's DNS/C2 domain. Empty array => null domain.
| alter urls_str  = to_string(urls)
| alter first_url = coalesce(
        arrayindex(json_extract_array(urls_str, "$."), 0),
        arrayindex(regextract(urls_str, "(https?://[^\"\s\]]+)"), 0))
| alter url_domain = extract_url_registered_domain(first_url)
| alter domain   = url_domain,
        dns_name = url_domain
| alter cleaned_url = ltrim(replex(coalesce(first_url, ""), "^https?://", ""), "www.")

// Delivery / remediation posture. Abnormal auto-remediates; a remediated
// message was still delivered to the mailbox before pull-back.
| alter delivery_action = if(
        remediationStatus in ("Remediated", "Auto-Remediated", "Manually Remediated"),
        "remediated", "delivered")
| alter direction = "inbound"

// Abnormal attack taxonomy surfaced for the analyst.
| alter threat_type           = coalesce(attackVector, ""),
        threat_classification = coalesce(attackType, ""),
        threat_strategy       = coalesce(attackStrategy, "")

// MITRE technique derived from delivery vector. Inbound email is
// categorically Initial Access (TA0001); the sub-technique varies by how
// the threat is delivered.
| alter email_technique_id = if(
        lowercase(coalesce(attackVector, "")) = "link", "T1566.002",
        lowercase(coalesce(attackVector, "")) = "attachment", "T1566.001",
        "T1566"),
        email_technique_name = if(
        lowercase(coalesce(attackVector, "")) = "link", "Phishing: Spearphishing Link",
        lowercase(coalesce(attackVector, "")) = "attachment", "Phishing: Spearphishing Attachment",
        "Phishing")

| alter alert_severity = if(
        lowercase(coalesce(attackType, "")) in ("malware", "phishing", "credential phishing", "extortion", "bec", "invoice/payment fraud", "social engineering (bec)"),
        "SEV_040_HIGH",
        lowercase(coalesce(attackType, "")) in ("spam", "graymail", "reconnaissance", "promotion"),
        "SEV_020_LOW",
        "SEV_030_MEDIUM")
| alter alert_category = "Email Security"
| alter alert_name = concat("[Email] ", coalesce(recipient_first, "Unknown"), " - Initial Access: ", coalesce(attackType, "Threat"), " Email Detected")
| alter alert_type = concat("Abnormal Security - ", coalesce(attackType, "Threat"))

// Attachment names only -- Abnormal's threat log carries no file hashes.
| alter action_filenames = arraystring(json_extract_array(to_string(attachmentNames), "$."), ", ")

// Identity from the recipient alone (email-first). The CIE block above
// overwrites these from socfw_identity_map when enabled; with it commented
// the rule still resolves an email-first actor.
| alter idr_email            = recipient_email,
        idr_upn              = null,
        idr_netbios          = null,
        idr_display_name     = null,
        idr_sid              = null,
        idr_on_prem_sid      = null,
        idr_domain_name      = null,
        idr_sam_account_name = recipient_local

| alter actor_effective_username = lowercase(coalesce(idr_email, idr_upn, idr_netbios, recipient_first))
| alter display_name = coalesce(idr_display_name, recipient_first)

| alter description = concat("Abnormal Security detection: ", coalesce(attackType, ""), " / ", coalesce(attackVector, ""), " | Recipient: ", coalesce(recipient_first, "Unknown"), " | Sender: ", coalesce(fromAddress, ""), " | URL Domain: ", coalesce(url_domain, ""), " | Strategy: ", coalesce(attackStrategy, ""), " | Remediation: ", coalesce(remediationStatus, ""), " -- MsgId: ", coalesce(abxMessageIdStr, abxMessageId))

// The 29 canonical core columns. Email-only: host/process null.
// agent_device_domain is null on purpose -- it is the AD machine domain;
// the URL registered domain rides fw_url_domain instead.
| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = coalesce(threatId, abxMessageIdStr, abxMessageId),
        originalalertname                   = alert_name,
        originalalertsource                 = "Abnormal Security",
        externallink                        = abxPortalUrl,
        alert_description                   = description,
        severity                            = alert_severity,
        mitretacticid                       = "TA0001",
        mitretacticname                     = "Initial Access",
        mitretechniqueid                    = email_technique_id,
        mitretechniquename                  = email_technique_name,
        agent_hostname                      = null,
        agent_id                            = null,
        agent_device_domain                 = null,
        actor_process_image_name            = null,
        actor_process_image_path            = null,
        actor_process_image_sha256          = null,
        actor_process_command_line          = null,
        actor_process_os_pid                = null,
        causality_actor_process_image_name  = null,
        causality_actor_process_image_path  = null,
        causality_actor_process_image_sha256 = null,
        action_file_name                    = action_filenames,
        action_file_path                    = null,
        action_file_sha256                  = null,
        action_local_ip                     = null,
        action_remote_ip                    = null

// user_principal carries the recipient as a parallel grouping pivot.
| alter user_principal = coalesce(idr_upn, recipient_first)
| alter user_name      = actor_effective_username
```
