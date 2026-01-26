# SOC Framework Manager — Pre-Install Requirements

Before installing or using the **SOC Framework Manager** content pack, ensure the following prerequisites are met.  
These are required for the pack to function correctly and are **not** created automatically.

---

## Required Prerequisites

### 1. Cortex REST API Integration Installed
Ensure the **Cortex REST API** integration is installed from the Marketplace and has **one enabled instance**.

- Integration name: **Cortex REST API**
- Instance should be enabled and available to all playbooks/scripts.

---

### 2. Generate a Standard XSIAM API Key

Generate an API key with sufficient permissions for content and configuration operations.

- Role required: **Instance Administrator**
- Copy both:
    - **API Key**
    - **API URL**

You will need these in the next step.

---

### 3. Create a Credential Named `Standard XSIAM API Key`

Create a credential object using the API key you generated.

**Path:**  
`Settings → Configuration → Integrations → Credentials`

**Credential requirements:**
- **Name:** `Standard XSIAM API Key` *(must match exactly)*
- **Type:** API Key
- **API Key:** Paste the generated key
- **ID / Username:** Use the API Key ID (or appropriate identifier per your tenant)

This credential is referenced by SOC Framework Manager for authenticated Core API operations.

---

## Summary Checklist

Before install, confirm:
- ✅ Cortex REST API integration is installed and enabled
- ✅ An API Key exists with the *Instance Administrator* role
- ✅ A Credential named **Standard XSIAM API Key** exists and is correctly populated

Once these are complete, proceed with installing the **SOC Framework Manager** content pack.

---

### ✔ Ready to Continue

Once all pre-install requirements above are complete, continue the installation by running:

`!SOCFWPackManager action=apply pack_id=soc-framework-manager pre_config_done=true`

This confirms that pre-configuration is complete and allows the installer to proceed.
