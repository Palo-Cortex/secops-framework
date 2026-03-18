def preflight_correlation_rules(sdk_errors_path: str) -> int:
    """
    Validate all correlation rule YAML files found under Packs/**/CorrelationRules/.

    Correct schema (verified against working tenant upload):
      fromversion: 6.10.0
      rule_id: 0
      global_rule_id: <name>   ← SDK pydantic reads identity from here
      name: <name>
      NO top-level id: or ruleid: keys — these cause "Parsed CorrelationRule:None"
      and 101704 server rejection on upload.

    Returns the number of issues found.
    """
    import glob, re

    BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║  MANUAL FIX REQUIRED — Correlation rule schema violation        ║
╚══════════════════════════════════════════════════════════════════╝"""

    issues = 0

    for path in glob.glob("Packs/**/CorrelationRules/*.yml", recursive=True):
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception:
            continue

        file_issues = []

        # Must have global_rule_id
        if not re.search(r'^global_rule_id\s*:', text, flags=re.M):
            file_issues.append("Missing 'global_rule_id' — SDK reads rule identity from this field")

        # Must NOT have top-level id: or ruleid:
        if re.search(r'^id\s*:', text, flags=re.M):
            file_issues.append("Has top-level 'id:' key — remove it (causes Parsed CorrelationRule:None)")
        if re.search(r'^ruleid\s*:', text, flags=re.M):
            file_issues.append("Has top-level 'ruleid:' key — remove it (causes Parsed CorrelationRule:None)")

        # Must have rule_id: 0
        if not re.search(r'^rule_id\s*:\s*0\s*$', text, flags=re.M):
            file_issues.append("Missing or wrong 'rule_id: 0'")

        # Must have fromversion: 6.10.0
        fv = re.search(r'^fromversion\s*:\s*(.+)$', text, flags=re.M)
        if not fv:
            file_issues.append("Missing 'fromversion: 6.10.0'")
        elif fv.group(1).strip() != "6.10.0":
            file_issues.append(f"Wrong fromversion: {fv.group(1).strip()!r} — must be 6.10.0")

        if file_issues:
            issues += len(file_issues)
            print(BANNER)
            print(f"  File: {path}")
            for issue in file_issues:
                print(f"  ✗ {issue}")
            print("""
  Required schema:
    fromversion: 6.10.0
    rule_id: 0
    global_rule_id: YourRuleName
    name: YourRuleName
    (NO top-level id: or ruleid: fields)

  Run: python3 tools/normalize_ruleid_adopted.py --root <PackDir> --fix
  to auto-correct these issues.
""")

    return issues
