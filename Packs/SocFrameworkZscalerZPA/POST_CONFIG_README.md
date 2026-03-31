# SocFrameworkZscalerZPA — Post-Configuration Steps

Complete these steps **after** installing the pack.

## 1. Enable the Correlation Rule

The correlation rule ships with `is_enabled: false` for side-by-side
testing. Once validated against your `zscaler_zpa_raw` data source,
set `is_enabled: true` and redeploy.

## 2. Verify Case Grouping

Confirm ZPA alerts group into the same XSIAM case as CrowdStrike Falcon
endpoint alerts and Proofpoint TAP email alerts via shared fields:
- `agent_hostname` (ZPA: `identHostName`, CrowdStrike: `hostname`)
- `actor_effective_username` (ZPA: `usrName`, Proofpoint: `recipient`)

## 3. Shadow Mode Verification

Run `SOCFWHealthCheck` to confirm `soc-terminate-zpa-session` is logging
to `xsiam_socfw_ir_execution_raw` with `execution_mode: shadow` before
flipping to production.

## 4. Production Handoff

To go live: set `"shadow_mode": false` for `soc-terminate-zpa-session`
in `SOCFrameworkActions_V3`. No playbook edits required.
