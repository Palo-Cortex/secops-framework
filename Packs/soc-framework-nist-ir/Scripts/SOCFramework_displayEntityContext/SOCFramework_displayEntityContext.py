import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa

# Entity context panel: Identity + Device.
# Reads normalized context, coalescing live-enrichment (Analysis.*) OVER
# directory/CIE (SOCFramework.Artifacts.*). Never reads raw vendor keys.
# Fail-open: any missing key just renders "-".

IDENTITY_ROWS = [
    ("Display Name", "Identity.User.DisplayName", "Identity.User.DisplayName"),
    ("UPN", "Identity.User.UPN", "Identity.User.UPN"),
    ("Username", "Identity.User.Name", "Identity.User.Name"),
    ("SAM Account", "Identity.User.SAM", "Identity.User.SAM"),
    ("User ID", "Identity.User.ID", "Identity.User.ID"),
    ("Email", "Identity.User.Email", "Identity.User.Email"),
    ("Job Title", "Identity.User.JobTitle", "Identity.User.JobTitle"),
    ("Department", "Identity.User.Department", "Identity.User.Department"),
    ("Manager", "Identity.User.Manager", "Identity.User.Manager"),
    ("City", "Identity.User.City", "Identity.User.City"),
    ("Office", "Identity.User.OfficeLocation", "Identity.User.OfficeLocation"),
    ("Employee ID", "Identity.User.EmployeeID", "Identity.User.EmployeeID"),
    ("Account Status", "Identity.User.AccountEnabled", "Identity.User.AccountEnabled"),
    ("Employment Status", "Identity.User.EmploymentStatus", "Identity.User.EmploymentStatus"),
]
DEVICE_ROWS = [
    ("Tags", "Endpoint.Tags", "Endpoint.Tags"),
    ("Most Logon", "Endpoint.MostLogonUser", "Endpoint.MostLogonUser"),
    ("Newest Logon", "Endpoint.NewestLogonUser", "Endpoint.NewestLogonUser"),
]


def _get(ctx, path):
    v = demisto.dt(ctx, path)
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v if x not in (None, "")) or None
    return v if v not in (None, "", [], {}, "null") else None


def _resolve(ctx, analysis_suffix, artifacts_suffix):
    # live enrichment first (Analysis.* — try top-level and SOCFramework-rooted)
    for base in ("Analysis." + analysis_suffix, "SOCFramework.Analysis." + analysis_suffix):
        v = _get(ctx, base)
        if v is not None:
            return v, "live"
    # directory baseline (CIE-surfaced, SOCFramework.Artifacts.*)
    v = _get(ctx, "SOCFramework.Artifacts." + artifacts_suffix)
    if v is not None:
        return v, "directory"
    return None, None


def _section(ctx, title, rows):
    body = []
    any_val = False
    for label, a_suf, art_suf in rows:
        val, src = _resolve(ctx, a_suf, art_suf)
        if val is None:
            body.append("| {} | - |".format(label))
        else:
            any_val = True
            tag = " *(directory)*" if src == "directory" else ""
            body.append("| {} | {}{} |".format(label, val, tag))
    header = "### {}\n| Field | Value |\n| --- | --- |".format(title)
    note = "" if any_val else "\n_No context available yet._"
    return header + "\n" + "\n".join(body) + note


def main():
    ctx = demisto.context() or {}
    md = _section(ctx, "Identity", IDENTITY_ROWS) + "\n\n" + _section(ctx, "Device", DEVICE_ROWS)
    return_results(CommandResults(readable_output=md))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
