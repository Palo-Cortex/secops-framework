import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
import json

# Entity context panel: Identity + Device.
#
# Fields the framework decides and acts on are normalized into the contract and
# copied to Analysis, so they are read from there. Display-only profile and
# device detail is resolved here from the vendor output the enrichment left in
# context, ordered by SOCFrameworkProfileMap_NIST_IR — per-tenant variance is a
# list edit, not a content change.

PROFILE_LIST = "SOCFrameworkProfileMap_NIST_IR"

IDENTITY_ROWS = [
    ("Display Name", "Identity.User.DisplayName"),
    ("UPN", "Identity.User.UPN"),
    ("Username", "Identity.User.Name"),
    ("SAM Account", "Identity.User.SAM"),
    ("User ID", "Identity.User.ID"),
    ("Email", "Identity.User.Email"),
    ("Job Title", "Identity.User.JobTitle"),
    ("Department", "Identity.User.Department"),
    ("Manager", "Identity.User.Manager"),
    ("City", "Identity.User.City"),
    ("Office", "Identity.User.OfficeLocation"),
    ("Employee ID", "Identity.User.EmployeeID"),
    ("Employment Status", "Identity.User.EmploymentStatus"),
]
DEVICE_ROWS = [
    ("Hostname", "Endpoint.Hostname"),
    ("FQDN", "Endpoint.FQDN"),
    ("Domain", "Endpoint.Domain"),
    ("Agent ID", "Endpoint.AgentID"),
    ("OS", "Endpoint.OS"),
    ("OS Version", "Endpoint.OSVersion"),
    ("MAC Address", "Endpoint.MACAddress"),
    ("IP Address", "Endpoint.IPAddress"),
    ("Tags", "Endpoint.Tags"),
    ("Most Logon", "Endpoint.MostLogonUser"),
    ("Newest Logon", "Endpoint.NewestLogonUser"),
]


def load_profile_map():
    """Vendor source paths per field. Missing list just means no vendor fallback."""
    try:
        res = demisto.executeCommand("getList", {"listName": PROFILE_LIST})
        data = res[0]["Contents"] if res else None
        if isinstance(data, str):
            data = json.loads(data)
        return (data or {}).get("fields") or {}
    except Exception:
        return {}


def _get(ctx, path):
    v = demisto.dt(ctx, path)
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v if x not in (None, "")) or None
    return v if v not in (None, "", [], {}, "null") else None


def _resolve(ctx, suffix, profile):
    # what the framework normalized, then what the vendor published
    for base in ("Analysis." + suffix, "SOCFramework.Artifacts." + suffix):
        v = _get(ctx, base)
        if v is not None:
            return v, "contract"
    for src in (profile.get(suffix) or []):
        v = _get(ctx, src)
        if v is not None:
            return v, src.split(".")[0]
    return None, None


def _section(ctx, title, rows, profile):
    body = []
    for label, suffix in rows:
        val, src = _resolve(ctx, suffix, profile)
        if val is None:
            continue
        tag = "" if src == "contract" else " *({})*".format(src)
        body.append("| {} | {}{} |".format(label, val, tag))
    if not body:
        return "### {}\n_Nothing resolved yet._".format(title)
    return "### {}\n| Field | Value |\n| --- | --- |\n".format(title) + "\n".join(body)


def main():
    ctx = demisto.context() or {}
    profile = load_profile_map()
    md = (_section(ctx, "Identity", IDENTITY_ROWS, profile) + "\n\n"
          + _section(ctx, "Device", DEVICE_ROWS, profile))
    return_results(CommandResults(readable_output=md))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
