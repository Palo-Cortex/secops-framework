## SOC Framework Pack Manager — Integration Setup

This integration stores the XSIAM API credentials used by the `SOCFWPackManager` script to install custom packs. All pack installation commands run through this credential store — credentials are never passed as command arguments.

### Prerequisites

- An XSIAM tenant with an active API key
- Instance Administrator or content-management role sufficient to upload packs

### Configuration Steps

1. Go to **Settings → Configurations → API Keys**
2. Click **+ New Key** → select **Standard** → choose a role with content management permissions
3. Copy the generated **API Key** and note the **Key ID** from the ID column
4. Click **Copy API URL** at the top of the API Keys page — this is your Server URL
5. In XSIAM, go to **Settings → Configurations → Integrations** → search for **SOC Framework Pack Manager** → click **Add Instance**
6. Enter:
   - **Server URL** — the API URL from step 4 (format: `https://api-<tenant>.xdr.us.paloaltonetworks.com`)
   - **API Key ID** — the numeric ID from step 3
   - **API Key** — the key from step 3
7. Click **Test** to validate connectivity, then **Save**

### Verifying the Connection

The test button hits the XSIAM datasets endpoint with the provided credentials. A green checkmark confirms the integration can reach the tenant and authenticate.

### Usage

This integration is called automatically by the `SOCFWPackManager` script. Run commands from the XSIAM Playground:

```
!SOCFWPackManager action=list
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=sync-tags
```

> Do not call `socfw-install-pack` directly — it is an internal command used by the script.
