# TAP (proofpoint-tap) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/proofpoint-tap/proofpoint-tap-threats.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/proofpoint-tap/proofpoint-tap-threats.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `proofpoint-tap` |
| product | `TAP` |
| data_source | `proofpoint_tap_v2_generic_alert_raw` |
| category | `Email` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `ccAddresses` | `string` |  | declared |  |
| `fromAddress` | `string` |  | declared |  |
| `GUID` | `string` |  | declared |  |
| `messageID` | `string` |  | declared |  |
| `messageParts` | `string` |  | declared | filename, md5, sha256 |
| `messageTime` | `datetime` |  | declared |  |
| `recipient` | `string` |  | declared |  |
| `sender` | `string` |  | declared |  |
| `senderIP` | `string` |  | declared |  |
| `subject` | `string` |  | declared |  |
| `threatsInfoMap` | `string` |  | declared | threatID, classification, threatType, threatStatus, threatUrl, threatURL, threat |
| `clickIP` | `string` |  | declared |  |
| `clickTime` | `datetime` |  | declared |  |
| `type` | `string` |  | confirmed |  |
| `threatStatus` | `string` |  | confirmed |  |
| `url` | `string` |  | confirmed |  |
| `campaignId` | `string` |  | inferred_from_correlation |  |
| `phishScore` | `int` |  | inferred_from_correlation |  |
| `malwareScore` | `int` |  | inferred_from_correlation |  |
| `spamScore` | `int` |  | inferred_from_correlation |  |
| `impostorScore` | `int` |  | inferred_from_correlation |  |
| `threatTime` | `datetime` |  | inferred_from_correlation |  |
| `headerFrom` | `string` |  | inferred_from_correlation |  |
| `headerReplyTo` | `string` |  | inferred_from_correlation |  |
| `replyToAddress` | `string` |  | inferred_from_correlation |  |
| `messageSize` | `int` |  | inferred_from_correlation |  |
| `xmailer` | `string` |  | inferred_from_correlation |  |
| `id` | `string` |  | inferred_from_correlation |  |
| `_alert_data` | `json` |  | inferred_from_correlation | severity, alert_category, linkedCount |

## Modeling Rule — ProofpointTAP Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `ProofpointTAP_modeling_rule` |
| modeling_rule_name | `ProofpointTAP Modeling Rule` |
| directory_name | `ProofpointTAPModelingRules` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.source.ipv4` | `senderIP` | `senderIP` | `emailsenderip` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Email.Sender`
- `Email.Recipients`
- `Email.CC`
- `Email.Subject`
- `Email.MessageID`
- `Email.DeliveryTimestamp`
- `Email.ReturnPath`
- `Email.Attachment.Filename`
- `Email.Attachment.MD5`
- `Email.Attachment.SHA256`
- `Network.SenderIP`

## Correlation Rules

### SOC Proofpoint TAP - Threat Detected All Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC Proofpoint TAP - Threat Detected All Alerts` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Unified Proofpoint TAP alert rule covering messages delivered and clicks permitted. Fires on active or malicious threat status only. Suppression is per GUID to preserve full blast-radius visibility for lateral risk detection. Replaces 1.0.4 two-rule/two-instance split. Volume controlled by threat status filter. Supports both V3 SOC Framework playbooks (via socfw* fields) and legacy soc-phishing-investigation-1.0.5 playbooks and layouts (via proofpointtap* fields). Legacy fields marked for removal when old phishing pack is decommissioned. Cross-rule grouping pivots (with CrowdStrike Falcon and other endpoint sources): actor_effective_username (lowercase full principal -- UPN when the vendor has it), user_principal (raw-case UPN, parallel pivot), action_local_ip (clickIP → endpoint local_ip), and action_file_sha256 (attachment hash). Username normalization: lowercase, DOMAIN\-prefix-stripped, full principal. UPN when the vendor delivers one; bare SAM only when it genuinely doesn't. Lowercase is mandatory -- exact-equality grouping makes casing a silent pivot-killer.

**Tags:** `SOCFramework`, `Detection`, `Email`, `ProofpointTAP`, `T1566`, `T1114`

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
| fields | `GUID, type` |

GUID + type: a click event reuses its delivered message's GUID, so
GUID-only suppression swallowed the click alert whenever the user
clicked within 24h of delivery -- exactly the escalation signal an
analyst needs. Keying on type as well lets delivered and clicked
suppress independently; the GUID dedup itself is correct and loses
nothing.
GUID is assigned per individual email delivery event in Proofpoint TAP.
A mass email to N recipients generates N distinct GUIDs. Suppressing on
GUID scopes deduplication to a single delivery event only — zero effect
on any other recipient's alert. 24-hour window covers the full TAP
replay window (TAP delivers events in batches and can replay the same
event across multiple cycles).

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
| `action_file_md5` | `proofpointmd5` | `computed` |  |
| `filehash` | `proofpointsha256` | `computed` |  |
| `dns_query_name` | `dns_name` | `computed` |  |
| `fw_url_domain` | `domain` | `computed` |  |
| `emailmessageid` | `messageID` | `raw` |  |
| `emailsenderip` | `senderIP` | `raw` |  |
| `emailsource` | `sender` | `raw` |  |
| `fw_email_recipient` | `recipient` | `raw` |  |
| `fw_email_sender` | `sender` | `raw` |  |
| `fw_email_subject` | `subject` | `raw` |  |
| `clickedurls` | `cleaned_url` | `computed` | Cleaned URL for downstream proxy/firewall correlation |
| `linkedcount` | `linkedCount` | `computed` | Outbound-compromise scoring signal in Email_Analysis_V3 |
| `socfwemaildeliveryaction` | `delivery_action` | `computed` |  |
| `socfwemaildirection` | `direction` | `computed` |  |
| `socfwemailthreaturl` | `threat_urls` | `computed` |  |
| `socfwemailthreattype` | `threat_types` | `computed` |  |
| `socfwemailthreatstatus` | `threat_statuses` | `computed` |  |
| `socfwemailthreatid` | `threat_ids` | `computed` |  |
| `socfwemailclassification` | `classification_all` | `computed` |  |
| `socfwemailphishscore` | `phishScore` | `raw` |  |
| `socfwemailmalwarescore` | `malwareScore` | `raw` |  |
| `socfwemailcampaignid` | `campaignId` | `raw` |  |
| `socfwemailclickip` | `clickIP` | `raw` |  |
| `socfwemailclicktime` | `clickTime` | `raw` |  |
| `proofpointtapcampaignid` | `campaignId` | `raw` |  |
| `proofpointtapclickip` | `clickIP` | `raw` |  |
| `proofpointtapclicktime` | `clickTime` | `raw` |  |
| `proofpointtapguid` | `GUID` | `raw` |  |
| `proofpointtapheadersfrom` | `headerFrom` | `raw` |  |
| `proofpointtapheadersreplyto` | `headerReplyTo` | `raw` |  |
| `proofpointtapid` | `id` | `raw` |  |
| `proofpointtapimposterscore` | `impostorScore` | `raw` |  |
| `proofpointtapmalwarescore` | `malwareScore` | `raw` |  |
| `proofpointtapmessageid` | `messageID` | `raw` |  |
| `proofpointtapmessageparts` | `messageParts` | `raw` |  |
| `proofpointtapmessagesize` | `messageSize` | `raw` |  |
| `proofpointtapphishingscore` | `phishScore` | `raw` |  |
| `proofpointtapreplytoaddress` | `replyToAddress` | `raw` |  |
| `proofpointtapsenderip` | `senderIP` | `raw` |  |
| `proofpointtapsmtpsender` | `sender` | `raw` |  |
| `proofpointtapspamscore` | `spamScore` | `raw` |  |
| `proofpointtapsubject` | `subject` | `raw` |  |
| `proofpointtapthreatstatus` | `threatStatus` | `raw` |  |
| `proofpointtapthreattime` | `threatTime` | `raw` |  |
| `proofpointtaptype` | `type` | `raw` |  |
| `proofpointtapxmailer` | `xmailer` | `raw` |  |
| `proofpointtapthreatid` | `bc_threatid` | `computed` |  |
| `proofpointtapclassification` | `bc_classification` | `computed` |  |
| `proofpointtapsuspiciousurl` | `bc_threaturl` | `computed` |  |
| `proofpointtapthreaturl` | `bc_threaturl` | `computed` |  |
| `proofpointtapthreatinfomap` | `bc_threatinfomap` | `computed` |  |
| `agentid` | `agent_id` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `initiatedby` | `actor_process_image_name` | `computed` |  |
| `initiatorpath` | `actor_process_image_path` | `computed` |  |
| `initiatorsha256` | `actor_process_image_sha256` | `computed` |  |
| `initiatorcmd` | `actor_process_command_line` | `computed` |  |
| `initiatorpid` | `actor_process_os_pid` | `computed` |  |
| `cgosha256` | `causality_actor_process_image_sha256` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filepath` | `action_file_path` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `emailrecipient` | `recipient` | `raw` |  |
| `emailsender` | `sender` | `raw` |  |
| `emailsubject` | `subject` | `raw` |  |
| `filemd5` | `proofpointmd5` | `computed` |  |
| `dnsqueryname` | `dns_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product drive SOCProductCategoryMap routing downstream.
| alter vendor_name = "Proofpoint", product_name = "TAP"

// Only delivered mail and permitted clicks are actionable. Blocked events are
// Proofpoint doing its job and carry no response work.
| filter type in ("messages delivered", "clicks permitted")

// Drop threats Proofpoint has already cleared or marked false positive.
// Click events carry threatStatus at the top level and have no threatsInfoMap.
| alter threatsInfoMap_str = threatsInfoMap
| alter first_threat_status = json_extract_scalar(threatsInfoMap_str, "$[0].threatStatus")
| filter (
    first_threat_status in ("active", "malicious")
    or threatStatus in ("active", "malicious")
)

// recipient arrives as a JSON array string; pull the first address out.
| alter recipient_first = arrayindex(regextract(to_string(recipient), "([\w.%+-]+@[\w.-]+)"), 0)

| alter
    alert_severity    = coalesce(_alert_data -> severity, "SEV_030_MEDIUM"),
    alert_category    = coalesce(_alert_data -> alert_category, "Email Security"),
    alert_name = if(
        type = "clicks permitted",
        concat("[Email] ", coalesce(recipient_first, "Unknown"), " - Initial Access: Malicious Link Clicked"),
        concat("[Email] ", coalesce(recipient_first, "Unknown"), " - Initial Access: Threat Email Delivered")
    ),
    alert_type = if(
        type = "clicks permitted",
        "Proofpoint TAP - Click Permitted",
        "Proofpoint TAP - Message Delivered"
    )

| alter delivery_action = if(
    type = "messages delivered", "delivered",
    type = "clicks permitted",   "click_permitted",
    type = "messages blocked",   "blocked",
    type = "clicks blocked",     "click_blocked",
    type
)
| alter direction = "inbound"

// Every threat on the message, flattened for the analyst. Parallel lists --
// position N in each describes the same threat.
| alter
    threat_ids         = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threatID")), ", "),
    classification_all = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.classification")), ", "),
    threat_types       = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threatType")), ", "),
    threat_statuses    = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threatStatus")), ", "),
    threat_urls        = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threat")), ", ")

// Attachment hashes and names across all message parts.
| alter
    proofpointsha256   = arraystring(arraymap(json_extract_array(messageParts, "$."), json_extract_scalar("@element", "$.sha256")), ", "),
    proofpointmd5      = arraystring(arraymap(json_extract_array(messageParts, "$."), json_extract_scalar("@element", "$.md5")), ", "),
    proofpointfilename = arraystring(arraymap(json_extract_array(messageParts, "$."), json_extract_scalar("@element", "$.filename")), ", ")

// $.threat is the malicious URL. $.threatUrl is a link to the Proofpoint
// console, not the threat itself.
| alter first_threat_type = json_extract_scalar(threatsInfoMap_str, "$[0].threatType")
| alter first_threat_url  = if(
        first_threat_type = "url",
        json_extract_scalar(threatsInfoMap_str, "$[0].threat"),
        null
    )

// Feeds fw_url_domain and dns_query_name, which XSIAM turns into grouping
// artifacts. Both take the same value so a single alert cannot contribute two
// competing domains. Null on attachment-only threats.
| alter url_domain = extract_url_registered_domain(first_threat_url)
| alter domain     = url_domain,
        dns_name   = url_domain

// URL in the form proxies and firewalls log it, for cross-product correlation
// (Zscaler ZPA, NGFW). Click events have no threatsInfoMap and fall back to
// the top-level url.
| alter cleaned_url = ltrim(replex(coalesce(first_threat_url, url), "^https?://", ""), "www.")

// Link count feeds outbound-compromise scoring in Email_Analysis_V3. The rule
// fires neutrally; direction filtering happens in Issue Exclusions.
| alter linkedCount = to_integer(_alert_data -> linkedCount)

// First-element extractions consumed by soc-phishing-investigation-1.0.5
// playbooks and layouts. bc_threatinfomap uses json_extract, not
// json_extract_scalar, so those playbooks can reach .threat and .threatType as
// sub-keys. Remove this block when that pack is decommissioned everywhere.
| alter
    bc_threatid       = json_extract_scalar(threatsInfoMap_str, "$[0].threatID"),
    bc_classification = json_extract_scalar(threatsInfoMap_str, "$[0].classification"),
    bc_threaturl      = coalesce(
        json_extract_scalar(threatsInfoMap_str, "$[0].threatUrl"),
        json_extract_scalar(threatsInfoMap_str, "$[0].threatURL")
    ),
    bc_threatinfomap  = json_extract(threatsInfoMap_str, "$[0]")

// Grouping pivots. recipient_local matches CrowdStrike's bare-SAM fallback;
// recipient_email matches its resolved lowercase UPN. Lowercasing at the
// canonical alter avoids the casing pitfall -- grouping is exact-equality.
| alter recipient_local = lowercase(arrayindex(regextract(coalesce(recipient_first, ""), "([\w.%+-]+)@"), 0))
| alter recipient_email = lowercase(recipient_first)

// Identity from the recipient alone. The CIE block below overwrites these from
// socfw_identity_map when enabled; with it commented the rule still resolves an
// email-first actor.
| alter idr_email            = recipient_email,
        idr_upn              = null,
        idr_netbios          = null,
        idr_display_name     = null,
        idr_sid              = null,
        idr_on_prem_sid      = null,
        idr_domain_name      = null,
        idr_sam_account_name = recipient_local

// Email-first canonicalization, falling back through UPN and netbios to the
// raw recipient. Matches the other vendor rules.
| alter actor_effective_username = lowercase(coalesce(idr_email, idr_upn, idr_netbios, recipient_first))
| alter display_name = coalesce(idr_display_name, recipient_first)

| alter description = concat("Proofpoint TAP threat detected: ", type," | Recipient: ", coalesce(recipient_first, "Unknown")," | User: ", coalesce(actor_effective_username, "")," | Display Name: ", coalesce(display_name, "")," | Email: ", coalesce(idr_email, "")," | UPN: ", coalesce(idr_upn, "")," | Domain: ", coalesce(idr_domain_name, "")," | SAM: ", coalesce(idr_sam_account_name, "")," | SID: ", coalesce(idr_sid, "")," | On-Prem SID: ", coalesce(idr_on_prem_sid, "")," | NetBIOS: ", coalesce(idr_netbios, "")," -- GUID: ", GUID)

// The 29 canonical core columns every vendor pack exposes. Column names match
// the issue field names in alert_fields; Foundation, Universal Command and the
// dashboards all read this surface.
//
// TAP is email-only, so host/process fields are null. agent_device_domain is
// null on purpose: it is the AD machine domain, and mapping the URL registered
// domain there false-grouped a threat URL domain against an AD domain. The URL
// registered domain rides fw_url_domain instead.
//
// MITRE is hardcoded: both event types are phishing.
| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = GUID,
        originalalertname                   = alert_name,
        originalalertsource                 = "Proofpoint TAP",
        externallink                        = null,
        alert_description                   = description,
        severity                            = alert_severity,
        mitretacticid                       = "TA0001",
        mitretacticname                     = "Initial Access",
        mitretechniqueid                    = "T1566",
        mitretechniquename                  = "Phishing",
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
        action_file_name                    = proofpointfilename,
        action_file_path                    = null,
        action_file_sha256                  = proofpointsha256,
        action_local_ip                     = clickIP,
        action_remote_ip                    = null

// user_principal carries the full UPN as a parallel grouping pivot against
// CrowdStrike's user_principal.
| alter user_principal = coalesce(idr_upn, recipient_first)
| alter user_name      = actor_effective_username

| alter tmp_severity = if(proofpointfilename in ("*.jpeg", "*.jpg",
"*.png", "*.html", "text.txt"), "SEV_030_LOW", alert_severity)
```
