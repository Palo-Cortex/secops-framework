"""Render who and where, from the normalized contract.

Reads SOCFramework.Artifacts.* and SOCFramework.Primary.* directly, for the same
reason as the alert detail script: the NIST IR equivalent resolves through
Analysis.* first, which the AI lifecycle does not populate.

Identity and endpoint are drawn as separate blocks so an alert carrying only one
of them renders cleanly rather than showing an empty half.
"""
import json

import demistomock as demisto
from CommonServerPython import *

_DOT = (
    "<span style='color:{color};font-size:13px;line-height:1;'>&#9679;</span>"
    "<span style='color:{color};margin-left:5px;'>{label}</span>"
)

_STATES = {
    "contained": ("#e53935", "ISOLATED"),
    "containment_pending": ("#ffa000", "ISOLATION PENDING"),
    "normal": ("#43a047", "NORMAL"),
    "unknown": ("#9e9e9e", "STATUS UNKNOWN"),
}

_VENDOR_MAP = {
    "contained": "contained",
    "isolated": "contained",
    "containment_requested": "containment_pending",
    "containment_pending": "containment_pending",
    "isolation_requested": "containment_pending",
    "pending isolation": "containment_pending",
    "lift_containment_approved": "containment_pending",
    "normal": "normal",
    "not isolated": "normal",
}


PROFILE_LIST = "SOCFrameworkProfileMap_NIST_IR"


def load_profile_map():
    """Vendor source paths per contract field, in preference order.

    Upon Trigger enrichment leaves vendor output in context under its own
    namespace (MSGraphUser.*, MicrosoftATP.MachineUser.*), not on the contract.
    This list is what maps one to the other, and per-tenant variance is a list
    edit rather than a content change. A missing list just means no fallback.
    """
    try:
        res = demisto.executeCommand("getList", {"listName": PROFILE_LIST})
        data = res[0].get("Contents") if res else None
        if isinstance(data, str):
            data = json.loads(data)
        return (data or {}).get("fields") or {}
    except Exception as e:
        demisto.debug(f"SOCFWDisplayIdentityDevice: profile map unavailable - {e}")
        return {}


def _v(ctx, path):
    # Contract paths are plain dotted keys, so demisto.get resolves them locally.
    # Only the profile map's vendor paths need bracket indexing, and those go to
    # demisto.dt, which evaluates server-side and returns HTTP 400 when the path
    # does not fit the data — a [0] index against a map, for instance. Profile
    # paths are vendor-shaped guesses by design, so a miss is the normal case and
    # must not take the panel down with it.
    if "[" in path:
        try:
            val = demisto.dt(ctx, path)
        except Exception as e:
            demisto.debug(f"SOCFWDisplayIdentityDevice: dt failed on {path} - {e}")
            return None
    else:
        val = demisto.get(ctx, path)

    if isinstance(val, list):
        val = ", ".join(str(v) for v in val if v not in (None, "")) or None
    return val if val not in (None, "", [], {}, "null") else None


def _rows(ctx, pairs, prefix, profile=None):
    """Contract first, then vendor output resolved through the profile map.

    A vendor-sourced value is labelled with its namespace so an analyst can tell
    what the framework normalized from what a live lookup returned.
    """
    profile = profile or {}
    out = []
    for label, suffix in pairs:
        v = _v(ctx, prefix + suffix)
        tag = ""
        if v is None:
            for src in (profile.get(suffix) or []):
                v = _v(ctx, src)
                if v is not None:
                    tag = (f" <span style='color:#666;font-size:10px;'>"
                           f"{src.split('.')[0]}</span>")
                    break
        if v is not None:
            out.append(
                f"<div style='margin:2px 0;'><span style='color:#888;'>{label}</span> "
                f"<span style='color:#ddd;'>{v}</span>{tag}</div>"
            )
    return "".join(out)


def _block(title, body, color="#0288d1"):
    if not body:
        return ""
    return (
        f"<div style='margin-bottom:12px;border-left:3px solid {color};padding-left:10px;'>"
        f"<div style='font-size:10px;color:#888;text-transform:uppercase;letter-spacing:1px;"
        f"margin-bottom:4px;'>{title}</div>"
        f"<div style='font-size:12px;line-height:1.5;'>{body}</div></div>"
    )


def _dot(state):
    color, label = _STATES[state]
    return _DOT.format(color=color, label=label)


def _endpoint_status(ctx):
    """Current containment state, read live through the Universal Command.

    The rest of this panel is contract data frozen at playbook time. Containment
    state is the one field that changes after the alert and that an analyst
    reads to decide what to do next, so it is fetched at render instead.

    Action_Actor 'layout' keeps the render out of the execution dataset. Nothing
    is written back to context: a render must not move what C/E/R reads.
    """
    if not (_v(ctx, "SOCFramework.Primary.Endpoint")
            or _v(ctx, "SOCFramework.Artifacts.EndPointID")):
        return ""

    raw = ""
    try:
        result = demisto.executeCommand("SOCCommandWrapper", {
            "action": "soc-enrich-endpoint",
            "Action_Actor": "layout",
            "Phase": "StatusCheck",
            "tags": "Status Check",
        })
        if is_error(result):
            return _dot("unknown")

        for entry in (result or []):
            contents = entry.get("Contents") or {}
            if isinstance(contents, str):
                try:
                    contents = json.loads(contents)
                except ValueError:
                    continue
            if isinstance(contents, dict):
                raw = (demisto.get(contents, "status")
                       or demisto.get(contents, "containment_status")
                       or demisto.get(contents, "device_status")
                       or "")
                if raw:
                    break
    except Exception as e:
        demisto.debug(f"SOCFWDisplayIdentityDevice: status lookup failed - {e}")
        return _dot("unknown")

    # An unrecognized or absent status means the EDR did not report one, which
    # is not the same as the endpoint being healthy.
    return _dot(_VENDOR_MAP.get(str(raw).lower().strip(), "unknown"))


def main():
    ctx = demisto.context()
    ART = "SOCFramework.Artifacts."
    profile = load_profile_map()
    html = ""

    # The primary entity is what the framework resolved as the subject of the
    # issue, which is not always the same as the identity fields on the alert.
    html += _block("Primary entity", _rows(ctx, [
        ("User", "User"), ("Email", "Email"), ("SAM", "SamAccountName"),
    ], "SOCFramework.Primary."), "#4a148c")

    html += _block("User", _rows(ctx, [
        ("Name", "Identity.User.Name"), ("Display name", "Identity.User.DisplayName"),
        ("Email", "Identity.User.Email"), ("UPN", "Identity.User.UPN"),
        ("SAM", "Identity.User.SAM"), ("ID", "Identity.User.ID"),
        ("Job title", "Identity.User.JobTitle"),
        ("Department", "Identity.User.Department"), ("City", "Identity.User.City"),
        ("Office", "Identity.User.OfficeLocation"),
        ("Employee ID", "Identity.User.EmployeeID"),
        ("Employment status", "Identity.User.EmploymentStatus"),
        ("Manager", "Identity.User.Manager"),
    ], ART, profile), "#0277bd")

    html += _block("Sign-in source", _rows(ctx, [
        ("IP", "Identity.Source.IP"), ("Hostname", "Identity.Source.Hostname"),
        ("Country", "Identity.Source.Country"), ("User agent", "Identity.Source.UserAgent"),
        ("Event", "Identity.Provider.EventType"),
    ], ART), "#1a237e")

    status = _endpoint_status(ctx)
    html += _block(f"Endpoint&nbsp;&nbsp;{status}" if status else "Endpoint", _rows(ctx, [
        ("Hostname", "Endpoint.Hostname"), ("FQDN", "Endpoint.FQDN"),
        ("IP", "Endpoint.IPAddress"), ("MAC", "Endpoint.MACAddress"),
        ("Domain", "Endpoint.Domain"), ("OS", "Endpoint.OS"),
        ("OS version", "Endpoint.OSVersion"), ("Agent ID", "Endpoint.AgentID"),
        ("Most logon", "Endpoint.MostLogonUser"),
        ("Newest logon", "Endpoint.NewestLogonUser"),
        ("Tags", "Endpoint.Tags"),
    ], ART, profile), "#00695c")

    html += _block("Scope", _rows(ctx, [
        ("Risk score", "RiskScore"), ("Linked issues", "LinkedCount"),
        ("Hosts", "HostCount"), ("Users", "UserCount"),
    ], "SOCFramework.Investigation."), "#37474f")

    if not html:
        html = ("<div style='color:#888;font-style:italic;padding:8px;'>"
                "No identity or device context resolved for this alert.</div>")

    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"],
                     "Contents": f"<div style='padding:4px;'>{html}</div>"})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
