# 🏷️ `setValueTags` Script Usage

`setValueTags` views and sets the value of each SOC Framework action: the analyst minutes the
action saves and its category. `SOCCommandWrapper` writes both onto every row in
`xsiam_socfw_ir_execution_raw`, and the value dashboards add those rows up.

Where a value comes from, in order:

1. **This tenant** — `SOCFWTenantConfig` → `value` → `<action>`, written by `setValueTags`.
2. **The pack** — `SOCActionTimeMap_V3`, shipped with `soc-optimization-unified`.

**An action in neither records 0 minutes.** `SOCActionTimeMap_V3` is a pack list the platform does not
let a script change, so `setValueTags` only writes the tenant value. Tenant values survive pack upgrades.

> Replaces the `value_tags` lookup table and `setValueTags_V3`. Nothing needs syncing.

---

## 📋 Parameters

| Parameter | Used by | Description |
|---|---|---|
| `action` | all | `list_all`, `list_by_type`, `list_by_tag_or_name`, `add`, `update`, `delete` |
| `tag` | add, update, delete, list_by_tag_or_name | The action name, e.g. `soc-star-case` (or part of one, to search) |
| `time` | add, update | Analyst minutes the action saves, a whole number |
| `category` | add, list_by_type; optional on update | `comms`, `containment`, `enrichment`, `eradication`, `recovery`, `triage` |
| `output_format` | lists | `markdown` (default), `table` or `json` |

---

## 🧠 Usage Examples

```bash
# Every action's value and where it comes from (tenant or shipped), and the actions with none
!setValueTags action=list_all

# Only containment actions
!setValueTags action=list_by_type category=containment

# Find by name
!setValueTags action=list_by_tag_or_name tag=email

# Give an action with no value one
!setValueTags action=add tag=soc-star-case time=5 category=triage

# Set this tenant's minutes, category or both (works on shipped actions too)
!setValueTags action=update tag=soc-isolate-endpoint time=20

# Remove this tenant's value and go back to the shipped one
!setValueTags action=delete tag=soc-isolate-endpoint

# Stop a shipped action counting
!setValueTags action=update tag=soc-enrich-user time=0
```

---

## ⚠️ Rules

- `add` refuses an action that already has a value (use `update`), and needs both `time` and `category`.
- `update` refuses an action that has no value (use `add`).
- `delete` removes only this tenant's value; a shipped value cannot be removed — set `time=0` instead.
- `time` must be a whole number of minutes, 0 or more.
- The lookup-era arguments (`playbook_name`, `playbookid`, `scriptid`, `product`, `vendor`, `type`) are refused: value is per action now.
- An unreadable `SOCFWTenantConfig` is never written over; creating it the first time needs the Core REST API integration.
