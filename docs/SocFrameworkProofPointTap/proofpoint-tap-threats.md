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
| `ccaddresses` | `string` | ✓ | declared |  |
| `fromaddress` | `string` | ✓ | declared |  |
| `guid` | `string` |  | declared |  |
| `messageid` | `string` |  | declared |  |
| `messageparts` | `string` | ✓ | declared | filename, md5, sha256 |
| `messagetime` | `datetime` |  | declared |  |
| `recipient` | `string` | ✓ | declared |  |
| `sender` | `string` |  | declared |  |
| `senderip` | `string` |  | declared |  |
| `subject` | `string` |  | declared |  |
| `threatsinfomap` | `string` | ✓ | declared | threatID, classification, threatType, threatStatus, threatUrl, threatURL, threat |
| `clickip` | `string` |  | declared |  |
| `clicktime` | `datetime` |  | declared |  |
| `type` | `string` |  | inferred_from_correlation |  |
| `threatstatus` | `string` |  | inferred_from_correlation |  |
| `url` | `string` |  | inferred_from_correlation |  |
| `campaignid` | `string` |  | inferred_from_correlation |  |
| `phishscore` | `int` |  | inferred_from_correlation |  |
| `malwarescore` | `int` |  | inferred_from_correlation |  |
| `spamscore` | `int` |  | inferred_from_correlation |  |
| `impostorscore` | `int` |  | inferred_from_correlation |  |
| `threattime` | `datetime` |  | inferred_from_correlation |  |
| `headerfrom` | `string` |  | inferred_from_correlation |  |
| `headerreplyto` | `string` |  | inferred_from_correlation |  |
| `replytoaddress` | `string` |  | inferred_from_correlation |  |
| `messagesize` | `int` |  | inferred_from_correlation |  |
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
| `xdm.email.cc` | `json_extract_array(ccaddresses, "$.")` | `ccaddresses` | `emailcc` |  |
| `xdm.email.recipients` | `json_extract_array(recipient, "$.")` | `recipient` | `emailrecipients` |  |
| `xdm.email.sender` | `arrayindex(json_extract_array(fromaddress, "$."), 0)` | `fromaddress` | `emailsender` | fromaddress is array-typed in the raw dataset. xdm.email.sender is scalar — first element only. Other addresses preserved in xdm.email.cc / xdm.email.recipients. |
| `xdm.email.return_path` | `sender` | `sender` | `emailreturnpath` |  |
| `xdm.email.subject` | `subject` | `subject` | `emailsubject` |  |
| `xdm.email.message_id` | `messageid` | `messageid` | `emailmessageid` |  |
| `xdm.email.delivery_timestamp` | `parse_timestamp("%Y-%m-%dT%H:%M:%E*SZ", messagetime)` | `messagetime` | `emaildeliverytimestamp` | TAP's messageTime is ISO 8601 string. XDM.email.delivery_timestamp is typed `date`. Use parse_timestamp() — to_timestamp() only accepts numeric epochs. Format string %E*S matches seconds with optional fractional component, final Z is literal. Without this cast install fails: "Field xdm.email.delivery_timestamp for model xdm is invalid. Expected date but received string." |
| `xdm.email.attachment.filename` | `json_extract_scalar(messageparts, "$[0].filename")` | `messageparts` | `emailattachmentfilename` | xdm.email.attachment.filename is scalar; only the first message part is mapped here. All parts are surfaced via the correlation rule's proofpointfilename / proofpointsha256 / proofpointmd5 alert_fields (comma-joined arraystrings). |
| `xdm.email.attachment.md5` | `json_extract_scalar(messageparts, "$[0].md5")` | `messageparts` | `emailattachmentmd5` |  |
| `xdm.email.attachment.sha256` | `json_extract_scalar(messageparts, "$[0].sha256")` | `messageparts` | `emailattachmentsha256` |  |
| `xdm.source.ipv4` | `senderip` | `senderip` | `emailsenderip` |  |

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

### SOC Proofpoint TAP - Threat Detected

| Field | Value |
|---|---|
| global_rule_id | `SOC Proofpoint TAP - Threat Detected` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Unified Proofpoint TAP alert rule covering messages delivered and clicks permitted. Fires on active or malicious threat status only. Suppression is per GUID to preserve full blast-radius visibility for lateral risk detection. Replaces 1.0.4 two-rule/two-instance split. Volume controlled by threat status filter. Supports both V3 SOC Framework playbooks (via socfw* fields) and legacy soc-phishing-investigation-1.0.5 playbooks and layouts (via proofpointtap* fields). Legacy fields marked for removal when old phishing pack is decommissioned. Cross-rule grouping pivots (with CrowdStrike Falcon and other endpoint sources): actor_effective_username (UPN format, e.g. "Gunter@SKT.LOCAL", matches CrowdStrike's user_name field byte-for-byte), user_principal (full UPN, parallel pivot), action_local_ip (clickip → endpoint local_ip), and action_file_sha256 (attachment hash). The username contract across all framework vendor rules is full UPN -- vendors that emit bare SAM or DOMAIN\user must normalize to UPN in their own pre_alter block.

**Tags:** `SOCFramework`, `Detection`, `Email`, `ProofpointTAP`, `T1566`, `T1114`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `REAL_TIME` |
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
| fields | `GUID` |

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
| `emailmessageid` | `messageid` | `raw` |  |
| `emailsenderip` | `senderip` | `raw` |  |
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
| `socfwemailphishscore` | `phishscore` | `raw` |  |
| `socfwemailmalwarescore` | `malwarescore` | `raw` |  |
| `socfwemailcampaignid` | `campaignid` | `raw` |  |
| `socfwemailclickip` | `clickip` | `raw` |  |
| `socfwemailclicktime` | `clicktime` | `raw` |  |
| `proofpointtapcampaignid` | `campaignid` | `raw` |  |
| `proofpointtapclickip` | `clickip` | `raw` |  |
| `proofpointtapclicktime` | `clicktime` | `raw` |  |
| `proofpointtapguid` | `guid` | `raw` |  |
| `proofpointtapheadersfrom` | `headerfrom` | `raw` |  |
| `proofpointtapheadersreplyto` | `headerreplyto` | `raw` |  |
| `proofpointtapid` | `id` | `raw` |  |
| `proofpointtapimposterscore` | `impostorscore` | `raw` |  |
| `proofpointtapmalwarescore` | `malwarescore` | `raw` |  |
| `proofpointtapmessageid` | `messageid` | `raw` |  |
| `proofpointtapmessageparts` | `messageparts` | `raw` |  |
| `proofpointtapmessagesize` | `messagesize` | `raw` |  |
| `proofpointtapphishingscore` | `phishscore` | `raw` |  |
| `proofpointtapreplytoaddress` | `replytoaddress` | `raw` |  |
| `proofpointtapsenderip` | `senderip` | `raw` |  |
| `proofpointtapsmtpsender` | `sender` | `raw` |  |
| `proofpointtapspamscore` | `spamscore` | `raw` |  |
| `proofpointtapsubject` | `subject` | `raw` |  |
| `proofpointtapthreatstatus` | `threatstatus` | `raw` |  |
| `proofpointtapthreattime` | `threattime` | `raw` |  |
| `proofpointtaptype` | `type` | `raw` |  |
| `proofpointtapxmailer` | `xmailer` | `raw` |  |
| `proofpointtapthreatid` | `bc_threatid` | `computed` |  |
| `proofpointtapclassification` | `bc_classification` | `computed` |  |
| `proofpointtapsuspiciousurl` | `bc_threaturl` | `computed` |  |
| `proofpointtapthreaturl` | `bc_threaturl` | `computed` |  |
| `proofpointtapthreatinfomap` | `bc_threatinfomap` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Proofpoint", product_name = "TAP"

// Gate 1: event type
| filter type in ("messages delivered", "clicks permitted")

// Gate 2: actionable threats only
| alter threatsInfoMap_str = threatsinfomap
| alter first_threat_status = json_extract_scalar(threatsInfoMap_str, "$[0].threatStatus")
| filter (
    first_threat_status in ("active", "malicious")
    or threatstatus in ("active", "malicious")
)

// Alert identity and naming
| alter
    alert_severity    = if(_alert_data -> severity != null and _alert_data -> severity != "",
                           _alert_data -> severity,
                           "SEV_030_MEDIUM"),
    alert_category    = if(_alert_data -> alert_category != null and _alert_data -> alert_category != "",
                           _alert_data -> alert_category,
                           "Email Security"),
    alert_name = if(
        type = "clicks permitted",
        concat("[Email] ", coalesce(to_string(recipient), "Unknown"), " - Initial Access: Malicious Link Clicked"),
        concat("[Email] ", coalesce(to_string(recipient), "Unknown"), " - Initial Access: Threat Email Delivered")
    ),
    alert_type = if(
        type = "clicks permitted",
        "Proofpoint TAP - Click Permitted",
        "Proofpoint TAP - Message Delivered"
    )

// SOC Framework: delivery action and direction
| alter delivery_action = if(
    type = "messages delivered", "delivered",
    type = "clicks permitted",   "click_permitted",
    type = "messages blocked",   "blocked",
    type = "clicks blocked",     "click_blocked",
    type
)
| alter direction = "inbound"

// SOC Framework: all threats as multi-value comma-separated strings
| alter
    threat_ids         = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threatID")), ", "),
    classification_all = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.classification")), ", "),
    threat_types       = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threatType")), ", "),
    threat_statuses    = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threatStatus")), ", "),
    threat_urls        = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), coalesce(json_extract_scalar("@element", "$.threatUrl"), json_extract_scalar("@element", "$.threatURL"))), ", "),
    threat_indicators  = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."), json_extract_scalar("@element", "$.threat")), ", ")

// Attachment fields (all parts)
| alter
    proofpointsha256   = arraystring(arraymap(json_extract_array(messageparts, "$."), json_extract_scalar("@element", "$.sha256")), ", "),
    proofpointmd5      = arraystring(arraymap(json_extract_array(messageparts, "$."), json_extract_scalar("@element", "$.md5")), ", "),
    proofpointfilename = arraystring(arraymap(json_extract_array(messageparts, "$."), json_extract_scalar("@element", "$.filename")), ", ")

// Domain extraction
| alter
    domain   = if(threat_types ~= "url", coalesce(extract_url_registered_domain(threat_indicators), extract_url_registered_domain(sender)), ""),
    dns_name = if(threat_types ~= "url", extract_url_registered_domain(threat_indicators), "")

| alter cleaned_url = ltrim(replex(coalesce(threat_indicators, url), "^https?://", ""), "www.")

| alter linkedCount = to_integer(_alert_data -> linkedCount)

// Backwards-compat alters (first-element extractions for legacy fields)
| alter
    bc_threatid       = json_extract_scalar(threatsInfoMap_str, "$[0].threatID"),
    bc_classification = json_extract_scalar(threatsInfoMap_str, "$[0].classification"),
    bc_threaturl      = coalesce(
        json_extract_scalar(threatsInfoMap_str, "$[0].threatUrl"),
        json_extract_scalar(threatsInfoMap_str, "$[0].threatURL")
    ),
    bc_threatinfomap  = json_extract(threatsInfoMap_str, "$[0]")

| alter description = concat("Proofpoint TAP threat detected: ", type, " -- GUID: ", guid)

// Cross-rule username contract: emit full UPN to match CrowdStrike's
// user_name (which Falcon delivers as e.g. "Gunter@SKT.LOCAL"). The
// earlier "recipient_local" trick stripped the @domain to bare SAM,
// which broke pivot grouping with CrowdStrike on the Turla scenario.
// recipient is array-typed in raw_schema; to_string coerces to scalar.
// See investigation in tools/correlation_rule_grouping_check notes.

// ============================================================
// CANONICAL CORE NORMALIZATION
// Produces the 29 canonical core columns every vendor pack must
// expose. Column names match issue field names in alert_fields.
// Foundation, Universal Command, and SOC Framework dashboards
// all read from this normalized surface.
//
// TAP is email-only — host/process/network-host fields are null.
// MITRE is hardcoded: TAP fires on phishing detections (messages
// delivered with active/malicious threat status, clicks permitted).
// Both event types map to T1566 Phishing under TA0001 Initial Access.
// ============================================================
| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = guid,
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
        agent_device_domain                 = domain,
        actor_effective_username            = to_string(recipient),
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
        action_local_ip                     = clickip,
        action_remote_ip                    = null

// Vendor-specific pivots beyond canonical core.
// user_principal carries full UPN as a parallel grouping pivot against
// CrowdStrike's user_principal. With actor_effective_username also now
// carrying UPN, both fields match CrowdStrike for grouping; keeping
// user_principal explicit avoids regressions if the canonical-core
// username field's semantics change.
| alter
        user_principal                      = recipient
```
