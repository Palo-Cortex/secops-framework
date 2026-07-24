SOC Framework Dataset Writer posts SOC Framework execution events to an XSIAM HTTP Collector.

Credentials live on the integration instance rather than in pack content, so no
keys are stored in the repository, in playbooks, or in automation scripts. This
integration replaces the System XQL HTTP Collector integration.

Dataset routing is determined by the HTTP Collector, not by this integration.
The collector's configured vendor and product decide which dataset receives the
events. To write different lifecycles to different datasets, create one HTTP
Collector per dataset and one integration instance per collector, then address
them by instance name using the `using` argument.

## Prerequisites

Create the HTTP Collector before configuring this integration.

1. Navigate to **Settings** > **Data Sources** > **Add Data Source**.
2. Select **Custom - HTTP Collector**.
3. Set **Vendor** and **Product**. For SOC Framework execution metrics, use
   vendor `XSIAM` and product `socfw_ir_execution`, which creates the
   `xsiam_socfw_ir_execution_raw` dataset.
4. Open **Connection Details** and copy the API URL and API key.

## Configure SOC Framework Dataset Writer on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for **SOC Framework Dataset Writer**.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Instance name | Callers address this instance by name through the `using` argument, so it must match what the calling content expects. For execution metrics, use `socfw_ir_execution_writer`. | True |
    | HTTP Collector URL | The API URL from the collector's Connection Details. | True |
    | API Key | The API key from the collector's Connection Details. | True |
    | Trust any certificate (not secure) | Skip TLS verification. | False |
    | Use system proxy settings | Route requests through the configured proxy. | False |

4. Click **Test** to validate the URL and API key. The test posts a single probe
   event, so a passing test confirms the full write path.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a
playbook.

### socfw-post-to-dataset

***
Posts events to the configured HTTP Collector as NDJSON.

#### Base Command

`socfw-post-to-dataset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| JSON | Events to post. Accepts a JSON array of objects, a single JSON object, or NDJSON text. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```
!socfw-post-to-dataset using="socfw_ir_execution_writer" JSON=`[{"timestamp":"1","lifecycle":"AUTO_TRIAGE","incident_id":"12345","action_status":"success"}]`
```

#### Human Readable Output

>Posted 1 event(s) to the HTTP Collector.

## Troubleshooting

**Events do not appear in the dataset.** Allow a short delay for ingestion, then
confirm the collector's vendor and product match the dataset you are querying.
A collector configured with vendor `XSIAM` and product `socfw_ir_execution`
writes to `xsiam_socfw_ir_execution_raw`.

**HTTP 401 or 403 from the collector.** The API key is wrong or has been
rotated. Copy it again from the collector's Connection Details.

**Command not found.** Confirm the pack is installed and an instance of this
integration is configured and enabled.
