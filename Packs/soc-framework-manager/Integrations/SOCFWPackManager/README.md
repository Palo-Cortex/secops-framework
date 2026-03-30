# SOC Framework Pack Manager Integration

Credential store and pack installer for the SOC Framework. Exposes `socfw-install-pack`, which posts directly to the XSIAM content bundle endpoint — no `core-api-*` commands required. Credentials are stored masked in the integration instance params and are never passed as command arguments.

## Configure SOC Framework Pack Manager in XSIAM

| Parameter | Description | Required |
| --- | --- | --- |
| Server URL | API URL for your XSIAM tenant. Format: `https://api-<tenant>.xdr.us.paloaltonetworks.com`. Found at **Settings → API Keys → Copy API URL**. | True |
| API Key ID | Numeric ID of the XSIAM API key. Found in the ID column of the API Keys table. | True |
| API Key | XSIAM API key. Created at **Settings → API Keys → New Key**. | True |
| Trust any certificate (not secure) | Skip TLS verification. Enable only in lab environments. | False |
| Use system proxy settings | Route requests through the system proxy. | False |

## Commands

You can execute these commands from the XSIAM Playground, in a playbook, or using the REST API. After a successful command, a DBot message appears in the War Room with the command details.

### socfw-install-pack

Download and install a custom pack ZIP via the XSIAM content bundle endpoint.

> This command is called automatically by the `SOCFWPackManager` script. Do not invoke it directly — use `!SOCFWPackManager action=apply pack_id=<id>` instead.

#### Base Command

`socfw-install-pack`

#### Input

| Argument Name | Description | Required |
| --- | --- | --- |
| url | GitHub Releases URL of the pack ZIP to install. | Required |
| filename | Asset filename including the `.zip` extension. Derived from the URL if omitted. | Optional |

#### Context Output

| Path | Type | Description |
| --- | --- | --- |
| SOCFramework.PackInstall.filename | String | Installed pack filename. |
| SOCFramework.PackInstall.status | String | Install status (`success`). |

#### Command Example

```
!socfw-install-pack url=https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-unified-v3.5.0/soc-optimization-unified-v3.5.0.zip filename=soc-optimization-unified-v3.5.0.zip
```

#### Context Example

```json
{
    "SOCFramework": {
        "PackInstall": {
            "filename": "soc-optimization-unified-v3.5.0.zip",
            "url": "https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-unified-v3.5.0/soc-optimization-unified-v3.5.0.zip",
            "status": "success"
        }
    }
}
```

#### Human Readable Output

`Pack soc-optimization-unified-v3.5.0.zip installed successfully.`
