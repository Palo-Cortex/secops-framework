# Darktrace Email (darktrace-email) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/darktrace-email/darktrace-email.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/darktrace-email/darktrace-email.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `darktrace-email` |
| product | `Darktrace Email` |
| data_source | `darktraceemail_generic_alert_raw` |
| category | `Email` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `uuid` | `string` |  | declared |  |
| `time` | `int` |  | declared |  |
| `timestamp` | `float` |  | declared |  |
| `score` | `float` |  | declared |  |
| `darktrace_url` | `string` |  | declared |  |
| `sender` | `string` |  | declared |  |
| `recipient` | `string` |  | declared |  |
| `subject` | `string` |  | declared |  |
| `summary` | `string` |  | declared |  |
| `direction` | `string` |  | declared |  |
| `tags` | `string` |  | declared |  |
| `tags_critical` | `string` |  | declared |  |
| `tags_warning` | `string` |  | declared |  |
| `tags_informational` | `string` |  | declared |  |
| `receipt_status` | `string` |  | declared |  |
| `action_status` | `string` |  | declared |  |
| `actions` | `string` |  | declared |  |
| `read_status` | `string` |  | declared |  |
| `release_requested` | `boolean` |  | declared |  |
| `attachments` | `float` |  | declared |  |
| `links` | `float` |  | declared |  |

## Correlation Rules

### SOC Darktrace Email - Threat Detected

| Field | Value |
|---|---|
| global_rule_id | `SOC Darktrace Email - Threat Detected` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Darktrace EMAIL threat detection for the SOC Framework Email category. Fires on a critical-tier Darktrace verdict that names an actual threat, scoring 70 or above, excluding outbound. Suppression is per uuid, which is one id per analysed message per recipient, so a campaign to N recipients still produces N alerts and blast radius stays visible. Email-only vendor: host and process fields are null. Cross-rule grouping pivots against other email and identity sources: actor_effective_username (lowercase recipient), user_principal (parallel), and fw_email_sender, which is what collapses one campaign across many mailboxes into a single case. Darktrace EMAIL exposes link COUNTS rather than URLs, so fw_url_domain and dns_query_name are null and the URL-based Email-to-Endpoint bridge is unavailable from this source. SCOPE is measured on a reference tenant over 30 days -- see pre_alter.

**Tags:** `SOCFramework`, `Detection`, `Email`, `Darktrace`, `T1566`

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
| fields | `uuid` |

uuid is unique per analysed message per recipient and is a real
top-level column, so suppression resolves against the dataset rather
than against an alter. A campaign to N recipients yields N distinct
uuids, so this suppresses only a re-report of the SAME message and has
zero effect on any other recipient's alert. Verified 1:1 over 30 days:
count() and count_distinct(uuid) agree on every bucket, so unlike the
NDR collector this source does not re-poll.

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
| `socfwidentityuserdisplayname` | `idr_display_name` | `cie` |  |
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
| `causality_actor_causality_id` | `causality_actor_causality_id` | `computed` |  |
| `dns_query_name` | `dns_name` | `computed` |  |
| `fw_url_domain` | `domain` | `computed` |  |
| `emailmessageid` | `uuid` | `raw` | Darktrace message uuid, not an RFC 5322 Message-ID. It is the handle Darktrace hold / release acts on, so it is the actionable id for containment through Darktrace itself. A purge through M365 needs the internet message id, which this source does not expose. |
| `emailsource` | `sender` | `raw` |  |
| `fw_email_recipient` | `recipient` | `raw` |  |
| `fw_email_sender` | `sender` | `raw` |  |
| `fw_email_subject` | `subject` | `raw` |  |
| `socfwemaildeliveryaction` | `delivery_action` | `computed` |  |
| `socfwemaildirection` | `email_direction` | `computed` |  |
| `socfwemailthreattype` | `dt_all_tags` | `computed` |  |
| `socfwemailthreatstatus` | `threat_status` | `computed` |  |
| `socfwemailthreatid` | `uuid` | `raw` |  |
| `socfwemailclassification` | `dt_primary_tag` | `computed` |  |
| `darktraceemailscore` | `score` | `raw` |  |
| `darktraceemailtags` | `dt_all_tags` | `computed` |  |
| `darktraceemailreceiptstatus` | `receipt_status` | `raw` |  |
| `darktraceemailactions` | `actions` | `raw` |  |
| `darktraceemailsenderdomain` | `sender_domain` | `computed` |  |
| `darktraceemaillinkcount` | `links` | `raw` |  |
| `darktraceemailattachmentcount` | `attachments` | `raw` |  |
| `darktraceemailsummary` | `summary` | `raw` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `emailrecipient` | `recipient` | `raw` |  |
| `emailsender` | `sender` | `raw` |  |
| `emailsubject` | `subject` | `raw` |  |
| `dnsqueryname` | `dns_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product drive SOCProductCategoryMap routing downstream.
| alter vendor_name = "Darktrace", product_name = "Darktrace Email"

// ========================================================================
// DETECTION SCOPE — measured on a reference tenant, 30 days, DISTINCT uuid
//
// Three cuts, each earning its place:
//
//   1. A CRITICAL-TIER TAG must be present.
//      tags_warning (Graymail, Cold Call, Wide Distribution) and
//      tags_informational (Freemail, Mailer, VIP) are mail-hygiene
//      signals, not detections. 96% of messages carry an informational
//      tag; they are the corpus, not the threat.
//
//   2. score >= 70.
//      Below that the critical tier is almost entirely Spam (183 msgs in
//      the 40-69 band, all Spam).
//
//   3. The critical tag set must name an ACTUAL THREAT.
//      This is the cut that matters. Darktrace files Spam and
//      Solicitation in the same critical tier as Credential Harvesting.
//      At score >= 70 inbound they are 303 of 348 messages — 87% — and
//      an issue per spam message is exactly the noise that makes a SOC
//      stop reading the queue.
//
//      critical + score>=70 + inbound, 30d        msgs   senders  recips
//        nuisance-only (Spam, Solicitation)        303      205      80
//        threat-tagged                              45       33      29
//
//      45 msgs / 30d = ~1.5/day, every one a phish, BEC or account
//      takeover. 33 senders across 45 messages is why fw_email_sender is
//      a grouping pivot: the multi-recipient campaigns are real.
//
//   4. Outbound excluded. No outbound message carried a critical tag in
//      30 days. Outbound detections mean a COMPROMISED INTERNAL ACCOUNT
//      and are a different investigation from inbound phishing — when
//      this source starts producing them they want their own rule, not
//      a wider filter on this one.
//
// Tag tiers are STRINGS holding JSON array text, not XSIAM arrays.
// arraystring() is rejected on them ("Expected array but received
// string"); matching is by regex on to_string().
// ========================================================================
| alter dt_crit = to_string(tags_critical)
| filter dt_crit != null and dt_crit != "" and dt_crit != "[]"
| filter to_integer(score) >= 70
| filter direction != "Outbound"
| filter dt_crit ~= "Phishing|Credential|Takeover|Impersonation|Multistage|Payload|Extortion|Payment|Forged|Fake Account|Document Anomalies"

// ---- Participants. Lowercase is mandatory: grouping is exact-equality,
// so casing is a silent pivot-killer. ----
| alter recipient_first = recipient
| alter recipient_email = lowercase(recipient),
        sender_email    = lowercase(sender)
| alter recipient_local = lowercase(arrayindex(regextract(coalesce(recipient, ""), "([\w.%+-]+)@"), 0))
| alter sender_domain   = lowercase(arrayindex(regextract(coalesce(sender, ""), "@([\w.-]+)"), 0))

// ---- Primary threat tag: the first threat-bearing tag in the critical
// set, used for the analyst-facing title and the classification field.
// Evaluated in descending severity, not in Darktrace's array order. ----
| alter dt_primary_tag = if(
        dt_crit ~= "Email Account Takeover",  "Email Account Takeover",
        dt_crit ~= "Credential Harvesting",   "Credential Harvesting",
        dt_crit ~= "Multistage Payload",      "Multistage Payload",
        dt_crit ~= "Phishing Link",           "Phishing Link",
        dt_crit ~= "VIP Impersonation",       "VIP Impersonation",
        dt_crit ~= "Extortion",               "Extortion",
        dt_crit ~= "Payment Scare",           "Payment Scare",
        dt_crit ~= "Fake Account Alert",      "Fake Account Alert",
        dt_crit ~= "Forged Address",          "Forged Address",
        dt_crit ~= "Document Anomalies",      "Document Anomalies",
        "Threat")

// Full critical tag set, readable: ["Phishing Link","Email Account
// Takeover"] -> Phishing Link, Email Account Takeover
| alter dt_all_tags = replex(replex(replex(dt_crit, "[\[\]\"]", ""), ",", ", "), "\s+", " ")

// ---- Severity: score 0..100 onto the XSIAM ladder. Same thresholds as
// the Darktrace NDR pack so the two read consistently. The scope filter
// is score >= 70, so in practice this yields HIGH and CRITICAL only. ----
| alter alert_severity = if(
        to_integer(score) >= 85, "SEV_050_CRITICAL",
        to_integer(score) >= 70, "SEV_040_HIGH",
        to_integer(score) >= 40, "SEV_030_MEDIUM",
        to_integer(score) >= 20, "SEV_020_LOW",
        "SEV_010_INFO")

// ---- Disposition. receipt_status is what happened to the message;
// action_status / actions are what Darktrace did about it. ----
| alter delivery_action = if(
        receipt_status = "Delivered", "delivered",
        receipt_status = "Held",      "blocked",
        receipt_status = "Junk",      "junked",
        receipt_status = "Invalid",   "invalid",
        lowercase(coalesce(receipt_status, "unknown")))
| alter threat_status = if(
        coalesce(actions, "") != "", concat("Darktrace: ", actions),
        action_status = "True",      "Darktrace action taken",
        "No action taken")
| alter email_direction = lowercase(coalesce(direction, "inbound"))

// ---- MITRE. Inbound email threat is categorically Initial Access
// (TA0001); the sub-technique follows the delivery vector. Darktrace
// gives link and attachment COUNTS, which is enough to choose. ----
| alter email_technique_id = if(
        dt_crit ~= "Phishing Link|Credential Harvesting", "T1566.002",
        to_integer(coalesce(attachments, 0)) > 0,         "T1566.001",
        to_integer(coalesce(links, 0)) > 0,               "T1566.002",
        "T1566"),
        email_technique_name = if(
        dt_crit ~= "Phishing Link|Credential Harvesting", "Phishing: Spearphishing Link",
        to_integer(coalesce(attachments, 0)) > 0,         "Phishing: Spearphishing Attachment",
        to_integer(coalesce(links, 0)) > 0,               "Phishing: Spearphishing Link",
        "Phishing")

| alter alert_category = "Email Security"

// ---- Analyst-facing title: [Email] <recipient> - Initial Access: <tag> ----
| alter alert_name = concat("[Email] ", coalesce(recipient, "Unknown"),
                            " - Initial Access: ", dt_primary_tag,
                            " Email Detected")
| alter alert_type = concat("Darktrace Email - ", dt_primary_tag)

| alter description = concat(
      "Darktrace EMAIL detection: ", dt_all_tags,
      " | Recipient: ", coalesce(recipient, "Unknown"),
      " | Sender: ", coalesce(sender, "Unknown"),
      " | Subject: ", coalesce(subject, ""),
      " | Score: ", to_string(score),
      " | Direction: ", coalesce(direction, ""),
      " | Disposition: ", delivery_action,
      " | ", threat_status,
      " | Links: ", to_string(coalesce(links, 0)),
      " | Attachments: ", to_string(coalesce(attachments, 0)),
      " -- MsgId: ", coalesce(uuid, ""))

// ---- Identity from the recipient alone (email-first). The CIE block
// above overwrites these from socfw_identity_map when enabled; with it
// commented the rule still resolves an email-first actor. ----
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

// ---- The canonical core columns. Email-only: host/process null.
// agent_device_domain stays null -- it is the AD machine domain, not the
// sender's mail domain, which rides its own vendor field instead. ----
| alter
        vendor                               = vendor_name,
        product                              = product_name,
        originalalertid                      = uuid,
        originalalertname                    = alert_name,
        originalalertsource                  = "Darktrace Email",
        externallink                         = darktrace_url,
        alert_description                    = description,
        severity                             = alert_severity,
        mitretacticid                        = "TA0001",
        mitretacticname                      = "Initial Access",
        mitretechniqueid                     = email_technique_id,
        mitretechniquename                   = email_technique_name,
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
        action_file_name                     = null,
        action_file_path                     = null,
        action_file_sha256                   = null,
        action_local_ip                      = null,
        action_remote_ip                     = null

// Darktrace EMAIL exposes link and attachment COUNTS, never the URLs or
// filenames. The URL-domain bridge to endpoint DNS/C2 artifacts that
// Abnormal and Proofpoint carry is therefore unavailable from this
// source. Null rather than absent, so the field reads as "checked,
// nothing found" rather than "not yet populated".
| alter dns_name = null, domain = null, cleaned_url = null

// causality_actor_causality_id is the per-message uuid, NOT the XSOAR
// collector's event id. The collector id changes on re-ingest and would
// split one message across cases.
| alter causality_actor_causality_id = uuid

// user_principal carries the recipient as a parallel grouping pivot.
| alter user_principal = coalesce(idr_upn, recipient_first)
| alter user_name      = actor_effective_username
```
