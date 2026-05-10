# Microsoft Defender for Endpoint (microsoft-defender) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/microsoft-defender/microsoft-defender-alerts.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/microsoft-defender/microsoft-defender-alerts.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `microsoft-defender` |
| product | `Microsoft Defender for Endpoint` |
| data_source | `msft_graph_security_alerts_raw` |
| category | `Endpoint` |

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
| `productName` | `string` |  | declared |  |
| `providerAlertId` | `string` |  | declared |  |
| `alertWebUrl` | `string` |  | declared |  |
| `incidentId` | `string` |  | declared |  |
| `mitreTechniques` | `json` | ✓ | declared |  |
| `evidence` | `json` | ✓ | declared | @odata.type, imageFile, processCommandLine, processCreationDateTime, detectio... |
| `detectorId` | `string` |  | inferred_from_correlation |  |

## Modeling Rule — Microsoft Graph Defender EP Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `Microsoft_Graph_MDE_ModelingRule` |
| modeling_rule_name | `Microsoft Graph Defender EP Modeling Rule` |
| directory_name | `MSGraphMDE_ModelingRule` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.event.id` | `id` | `id` | `eventid` |  |
| `xdm.event.description` | `coalesce(description, title)` | `description, title` | `eventdescription` | Falls back to title when description is empty. |
| `xdm.event.original_event_type` | `category` | `category` | `original_event_type` |  |
| `xdm.alert.name` | `title` | `title` | `alertname` |  |
| `xdm.alert.category` | `category` | `category` | `alertcategory` |  |
| `xdm.alert.original_alert_id` | `providerAlertId` | `providerAlertId` | `originalalertid` |  |
| `xdm.alert.severity` | `severity` | `severity` | `severity` | Microsoft Graph severity is a string ("low"/"medium"/"high"/"informational"). XDM severity accepts string values; no coercion needed. |
| `xdm.observer.product` | `productName` | `productName` | `observerproduct` |  |
| `xdm.observer.vendor` | `"Microsoft"` |  | `observervendor` | Literal — vendor is constant for this rule. |
| `xdm.network.http.url` | `alertWebUrl` | `alertWebUrl` | `alerturl` | Direct link back to the Microsoft Defender portal for the alert. |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Endpoint.AlertID`
- `Endpoint.AlertName`
- `Endpoint.AlertCategory`
- `Endpoint.AlertSeverity`
- `Endpoint.OriginalAlertID`
- `Endpoint.AlertURL`
- `Vendor`
- `Product`

## Correlation Rules

### SOC Microsoft Graph Defender EndPoint

| Field | Value |
|---|---|
| global_rule_id | `SOC Microsoft Graph Defender EndPoint` |
| subtype | `passthrough` |
| fromversion | `8.0.0` |

Creates an XSIAM alert for each Microsoft Graph Endpoint Detection Event.

**Tags:** `SOCFramework`, `Passthrough`, `Endpoint`, `MicrosoftDefenderForEndpoint`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `REAL_TIME` |
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

providerAlertId is Microsoft Graph's per-alert unique identifier.
Suppressing on it scopes dedup to a single alert — different alerts
on the same device fire independently. 1-hour window prevents
back-to-back ingestion polls from re-creating the same alert.

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
| `samaccountname` | `evidence_user_upn` | `computed` |  |
| `usersid` | `evidence_user_userSid` | `computed` |  |
| `actor_process_signature_vendor` | `evidence_process_signer` | `computed` |  |
| `processid` | `evidence_process_pid` | `computed` |  |
| `processcreationtime` | `evidence_process_starttime` | `computed` |  |
| `causality_actor_process_signature_vendor` | `evidence_parent_process_signer` | `computed` |  |
| `parentprocessid` | `evidence_parent_process_pid` | `computed` |  |
| `parentprocessname` | `evidence_parent_process_name` | `computed` |  |
| `parentprocesspath` | `evidence_parent_process_path` | `computed` |  |
| `parentprocesssha256` | `evidence_parent_process_sha256` | `computed` |  |
| `deviceexternalips` | `evidence_device_externalip` | `computed` |  |
| `deviceosname` | `evidence_device_os` | `computed` |  |
| `action_remote_ip_v6` | `evidence_remote_ipv6` | `computed` |  |
| `alertaction` | `evidence_process_action` | `computed` |  |
| `detectionid` | `detectorId` | `raw` |  |
| `alert_name` | `alert_name` | `computed` |  |
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

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Microsoft", product_name = productName

// Focus on Defender endpoint / XDR alerts
| filter productName in ("Microsoft Defender for Endpoint", "Microsoft Defender XDR")

// Exclude resolved alerts
| filter status != "resolved"

// Tactic alias — drives user_defined_category
| alter tactic = category

// MITRE helpers
| alter
    cat_norm  = replace(replace(replace(replace(lowercase(category), " ", ""), "-", ""), "_", ""), ".", ""),
    mitre_str = lowercase(coalesce(mitreTechniques, ""))

// XSIAM MITRE Normalization
| alter
    mitre_tactic       = category,
    mitre_tactic_id    = if(
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
    mitre_technique       = mitreTechniques,
    mitre_technique_id    = mitreTechniques,
    mitre_technique_first = arrayindex(mitreTechniques -> [], 0),
    mitre_technique_str   = arraystring(mitreTechniques -> [], ", ")

// First element of each evidence type (lightweight extraction)
| alter
    processEvidence = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "processEvidence"), 0),
    fileEvidence    = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "fileEvidence"), 0),
    deviceEvidence  = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "deviceEvidence"), 0),
    userEvidence    = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "userEvidence"), 0),
    ipEvidence      = arrayindex(arrayfilter(evidence -> [], "@element" -> ["@odata.type"] contains "ipEvidence"), 0)

// Process evidence (initiator / target process)
| alter
    evidence_process_name          = processEvidence -> imageFile.fileName,
    evidence_process_path          = processEvidence -> imageFile.filePath,
    evidence_process_command_line  = processEvidence -> processCommandLine,
    evidence_process_signer        = processEvidence -> imageFile.filePublisher,
    evidence_process_sha256        = processEvidence -> imageFile.sha256,
    evidence_process_pid           = processEvidence -> processId,
    evidence_process_starttime     = processEvidence -> processCreationDateTime,
    evidence_process_action        = processEvidence -> detectionStatus,
    evidence_parent_process_signer = processEvidence -> parentProcessImageFile.filePublisher,
    evidence_parent_process_name   = coalesce(processEvidence -> parentProcessImageFile.fileName, null),
    evidence_parent_process_path   = coalesce(processEvidence -> parentProcessImageFile.filePath, null),
    evidence_parent_process_sha256 = coalesce(processEvidence -> parentProcessImageFile.sha256, null),
    evidence_parent_process_pid    = processEvidence -> parentProcessId

// File evidence (target file)
| alter
    evidence_file_name   = fileEvidence -> fileDetails.fileName,
    evidence_file_sha256 = fileEvidence -> fileDetails.sha256

// Device evidence
| alter
    evidence_device_hostname   = deviceEvidence -> hostName,
    evidence_device_ntdomain   = deviceEvidence -> ntDomain,
    evidence_device_os         = deviceEvidence -> osPlatform,
    evidence_device_agentid    = deviceEvidence -> mdeDeviceId,
    evidence_device_externalip = deviceEvidence -> lastExternalIpAddress,
    evidence_local_ipv4        = deviceEvidence -> lastIpAddress,
    evidence_device_dnsdomain  = deviceEvidence -> deviceDnsName

// User evidence
| alter
    evidence_user_upn      = userEvidence -> userAccount.userPrincipalName,
    evidence_user_domain   = userEvidence -> userAccount.domainName,
    evidence_user_userSid  = userEvidence -> userAccount.userSid,
    evidence_loggedon_user = userEvidence -> userAccount.accountName

// IP evidence — discriminate IPv4 vs IPv6 by regex
| alter
    evidence_remote_ipv4 = if(ipEvidence -> ipAddress ~= "(?:\\d{1,3}\\.){3}\\d{1,3}",
                              ipEvidence -> ipAddress, null),
    evidence_remote_ipv6 = if(ipEvidence -> ipAddress ~= "^[0-9a-f:]+$",
                              ipEvidence -> ipAddress, null)

// Unified source_user + SOC Framework grouping keys
| alter
    source_user           = coalesce(evidence_loggedon_user, evidence_user_upn),
    cid                   = incidentId,
    initiator_sha256      = evidence_process_sha256,
    cgo_sha256            = evidence_parent_process_sha256,
    target_process_sha256 = evidence_process_sha256,
    file_sha256           = evidence_file_sha256,
    remote_ip             = evidence_remote_ipv4

// Final description and alert_name
| alter
    description = coalesce(description,
                           concat("Microsoft Defender for Endpoint alert: ", title)),
    alert_name  = concat(
        "[Endpoint] ",
        coalesce(evidence_device_hostname, "Unknown Host"),
        " | ",
        coalesce(category, "Detection"),
        " | ",
        coalesce(arrayindex(mitreTechniques -> [], 0), arraystring(mitreTechniques -> [], ","), title)
    )

// ============================================================
// CANONICAL CORE NORMALIZATION
// Produces the 29 canonical core columns every vendor pack must
// expose. Column names match issue field names in alert_fields.
// Foundation, Universal Command, and SOC Framework dashboards
// all read from this normalized surface.
//
// Defender ships MITRE per-alert via mitreTechniques + the category
// field. mitre_tactic_id is computed earlier from category via
// an if-chain. mitre_technique_first is the array's first element.
// ============================================================
| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = providerAlertId,
        originalalertname                   = alert_name,
        originalalertsource                 = productName,
        externallink                        = alertWebUrl,
        alert_description                   = description,
        severity                            = severity,
        mitretacticid                       = mitre_tactic_id,
        mitretacticname                     = mitre_tactic,
        mitretechniqueid                    = mitre_technique_first,
        mitretechniquename                  = mitre_technique_str,
        agent_hostname                      = evidence_device_hostname,
        agent_id                            = evidence_device_agentid,
        agent_device_domain                 = evidence_device_ntdomain,
        actor_effective_username            = source_user,
        actor_process_image_name            = evidence_process_name,
        actor_process_image_path            = evidence_process_path,
        actor_process_image_sha256          = evidence_process_sha256,
        actor_process_command_line          = evidence_process_command_line,
        actor_process_os_pid                = evidence_process_pid,
        causality_actor_process_image_name  = evidence_parent_process_name,
        causality_actor_process_image_path  = evidence_parent_process_path,
        causality_actor_process_image_sha256 = evidence_parent_process_sha256,
        action_file_name                    = evidence_file_name,
        action_file_path                    = null,
        action_file_sha256                  = evidence_file_sha256,
        action_local_ip                     = evidence_local_ipv4,
        action_remote_ip                    = evidence_remote_ipv4
```
