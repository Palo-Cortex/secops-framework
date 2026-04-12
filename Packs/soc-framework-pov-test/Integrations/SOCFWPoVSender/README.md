# SOCFWPoVSender

Sends PoV attack scenario event data from XSIAM lists to an XSIAM HTTP Collector endpoint.

Configure one instance per data source. Run `!socfw-pov-send-data` from any case war room or the playground.

## Commands

### socfw-pov-send-data

Reads scenario events from an XSIAM list, rebases timestamps to now, normalizes source-specific fields, rotates suppression IDs, and POSTs to the configured HTTP Collector.

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `list_name` | Yes | XSIAM list containing scenario event data (JSON array) |
| `global_min` | No | ISO timestamp of earliest event across all sources in this scenario |
| `global_max` | No | ISO timestamp of latest event across all sources in this scenario |
| `compress_window` | No | Override compress window (e.g. `2h`, `30m`). Default: instance setting |

**Example:**

```
!socfw-pov-send-data list_name=SOCFWPoVData_CrowdStrike_TurlaCarbon_V1
  global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  using=socfw_pov_crowdstrike_sender
```
