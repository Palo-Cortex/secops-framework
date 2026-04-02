# SOC Framework NIST IR (800-61) — Post-Installation Steps

---

## Step 1 — Create the Automation Rule

**Navigation:** Left sidebar → **Investigation & Response** → **Automation** → **Automation Rules** → **+ Add**

| Field | Value |
|---|---|
| Rule Name | `SOC Framework NIST IR` |
| Condition | `severity` = `High`, `Medium`, `Critical` **AND** `name` doesn't contain `POV` |
| Automation | `EP_IR_NIST (800-61)_V3` |

> The `name doesn't contain POV` condition excludes POV Starter Configuration issues from entering the NIST IR lifecycle. Adjust if your tenant uses a different naming convention for non-live issues.

XSIAM executes automation rules in order — only the first matching rule fires per issue. Confirm this rule is positioned correctly relative to any other automation rules in the tenant.

---

## Step 2 — Create the Layout Rule

**Navigation:** Left sidebar → **Settings** → **Customization** → **Layout Rules** → **+ New Rule**

| Field | Value |
|---|---|
| Rule Name | `NIST IR` |
| Layout To Display | `SOCFramework NIST IR Layout` |
| Condition 1 | `Severity` = `Medium`, `High`, `Critical` |
| Condition 2 | `Issue Domain` = `Security` |
| Condition 3 | `Name` not contains `POV` |

> Create this rule **after** the pack is fully installed. The layout must exist in the tenant before it can be selected in the dropdown.

---

## Step 3 — Verify Shadow Mode

1. Navigate to **Settings → Advanced → Lists**
2. Open `SOCFrameworkActions_V3`
3. Confirm every action has `"shadow_mode": true`

With Shadow Mode on, all containment, eradication, and recovery commands log their intent to the war room and to `xsiam_socfw_ir_execution_raw` without executing the vendor action.

---

## Step 4 — Run Health Check

From the XSIAM Playground war room:

```
!SOCFWHealthCheck
```

Resolve any failures before routing live traffic.

---

## Troubleshooting: Layout Rule Shows Blank Layout

**Symptom:** The Layout To Display column is empty in the Layout Rules list. Cases open with the default layout instead of the NIST IR phase view.

**Cause:** The layout binding stores an internal content ID reference. When the pack is reinstalled, the layout content item is replaced and the old reference goes stale.

**Fix:**

1. Navigate to **Settings → Customization → Layout Rules**
2. Open the affected rule
3. Re-select **`SOCFramework NIST IR Layout`** from the **Layout To Display** dropdown
4. Save

Re-bind after every reinstall of `soc-framework-nist-ir` that includes the Layouts directory.

If both a `NIST IR` and `NIST IR Layout` rule exist, delete the duplicate. Keep the rule with all three conditions (Severity + Issue Domain + Name not contains POV).
