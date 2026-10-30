# Value Metrics and Industry-Centric CIA Usage

This guide outlines how to use Value Metrics to support **CIA-focused measurement** tailored to industry-specific priorities. By mapping automation outcomes to Confidentiality, Integrity, and Availability concerns, organizations can demonstrate security alignment with their operational mission — not just with alert volume.

---

## 🔐 What Is CIA in This Context?

- **Confidentiality**: Preventing unauthorized access to sensitive data
- **Integrity**: Ensuring systems and data are accurate and trustworthy
- **Availability**: Keeping systems and services operational under stress

Different industries emphasize these pillars differently — for example:

| Industry             | CIA Priority Order         |
|----------------------|----------------------------|
| Healthcare           | Confidentiality → Integrity → Availability |
| Manufacturing        | Availability → Integrity → Confidentiality |
| Financial Services   | Integrity → Confidentiality → Availability |
| Government           | Confidentiality → Availability → Integrity |

---

## 🧭 Why Map CIA to Value Metrics?

Standard metrics like time saved or playbook execution are valuable — but when framed through the **CIA lens**, they reveal *business-aligned impact*:

- How does automation **reduce data leakage risk**? *(Confidentiality)*
- Does it **prevent manual error or manipulation**? *(Integrity)*
- Is automation **keeping systems running at scale**? *(Availability)*

---

## 🧩 CIA Mapping to Value Metric Categories

Use the table below to align each value metric type to CIA pillars depending on how the task affects outcomes:

| Value Metric Category      | CIA Mapping Explanation |
|---------------------------|--------------------------|
| **Time Saved by Task**     | Tasks like decryption, malware analysis, and URL detonation often preserve **Confidentiality** by catching data leaks early. |
| **Time Saved by Category** | Tasks in *triage* and *investigation* protect **Integrity** by identifying and flagging compromised users or systems. |
| **Vendor/Product Usage**   | Monitoring endpoint or cloud security tool usage supports **Confidentiality** and **Integrity** based on function. |
| **Scripts vs Playbooks**   | Playbooks increase **Integrity** (repeatable, validated logic); high scripting usage may reduce consistency. |
| **Use Case Execution**     | Use cases like ransomware or phishing contribute to all three CIA areas depending on response type. |

---

## 🧪 Sample CIA Use Case Breakdown

### 🚑 Healthcare Example: Phishing Investigation

| Value Metric                | CIA Alignment      | Explanation |
|-----------------------------|--------------------|-------------|
| Time Saved: Email Triage    | Confidentiality     | Prevents unauthorized access to PHI via credential harvesting |
| Playbook Execution Rate     | Integrity           | Ensures repeatable, audited steps for incident response |
| Auto-resolved Incidents     | Availability        | Reduces alert backlog, ensuring systems remain available to care teams |

---

## 🧠 How to Tag for CIA Visibility

The `value_tags` lookup is retired; value is per action in `SOCActionTimeMap_V3` (see [setValueTags](setValueTags.md)). The idea below still applies if you keep your own tagging: add a `cia_focus` field (optional, internal use):

```json
{
  "category": "triage",
  "tag": "Credential Dump Analysis",
  "minutes": 8,
  "script_id": "AnalyzeDumps",
  "product": "CrowdStrike",
  "vendor": "CrowdStrike",
  "cia_focus": "Confidentiality"
}
```