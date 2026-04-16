# SOC Framework — Microsoft Entra ID

Correlation rules for Microsoft Entra ID (formerly Azure AD) sign-in events.

## Dataset

`msft_azure_ad_raw` — populated via **Office 365 data source** with Microsoft Graph API sign-in log checkboxes enabled. The dataset retains the legacy "Azure AD" naming despite Microsoft's rebrand to Entra ID.

## Prerequisite

The `msft_azure_ad_raw` dataset must exist and have a populated schema before this pack is installed. On PoV tenants without real Entra ID data, use the SOC Framework PoV Test Pack seed:

```
!SOCFWPoVSend list_name=SOCFWPoVData_Identity_TurlaCarbon_V1 source_name=identity seed=true
```

Wait 60 seconds, then install this pack.

On production tenants with the Office 365 data source configured, the dataset already exists.

## Native Detection Overlap

XSIAM has native behavioral identity analytics (UEBA, Identity Threat Detection) that will also fire on real Entra ID data after baseline learning. This rule fires immediately on field values without requiring a behavioral baseline — designed for PoV demonstration with synthetic data. Document the overlap during PS handoff and consider disabling this rule once native detections are confirmed active.

## Correlation Rules

| Rule | MITRE | Fires On |
|------|-------|----------|
| SOC Identity - Entra ID Suspicious Sign-In | TA0001 / T1078 | Failed auth, elevated risk level, risky sign-in state |

## Dependencies

- `soc-optimization-unified` (Foundation, Universal Command)
- `soc-framework-nist-ir` (NIST IR lifecycle)
