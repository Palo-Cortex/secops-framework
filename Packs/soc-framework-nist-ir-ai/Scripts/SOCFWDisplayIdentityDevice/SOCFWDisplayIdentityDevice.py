"""Render who and where, from the normalized contract.

Reads SOCFramework.Artifacts.* and SOCFramework.Primary.* directly, for the same
reason as the alert detail script: the NIST IR equivalent resolves through
Analysis.* first, which the AI lifecycle does not populate.

Identity and endpoint are drawn as separate blocks so an alert carrying only one
of them renders cleanly rather than showing an empty half.
"""
import demistomock as demisto
from CommonServerPython import *


def _v(ctx, path):
    val = demisto.get(ctx, path)
    if isinstance(val, list):
        val = ", ".join(str(v) for v in val if v) or None
    return val if val not in (None, "", [], {}) else None


def _rows(ctx, pairs, prefix):
    out = []
    for label, suffix in pairs:
        v = _v(ctx, prefix + suffix)
        if v:
            out.append(
                f"<div style='margin:2px 0;'><span style='color:#888;'>{label}</span> "
                f"<span style='color:#ddd;'>{v}</span></div>"
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


def main():
    ctx = demisto.context()
    ART = "SOCFramework.Artifacts."
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
        ("Department", "Identity.User.Department"), ("City", "Identity.User.City"),
        ("Manager", "Identity.User.Manager"),
    ], ART), "#0277bd")

    html += _block("Sign-in source", _rows(ctx, [
        ("IP", "Identity.Source.IP"), ("Hostname", "Identity.Source.Hostname"),
        ("Country", "Identity.Source.Country"), ("User agent", "Identity.Source.UserAgent"),
        ("Event", "Identity.Provider.EventType"),
    ], ART), "#1a237e")

    html += _block("Endpoint", _rows(ctx, [
        ("Hostname", "Endpoint.Hostname"), ("FQDN", "Endpoint.FQDN"),
        ("IP", "Endpoint.IPAddress"), ("MAC", "Endpoint.MACAddress"),
        ("Domain", "Endpoint.Domain"), ("OS", "Endpoint.OS"),
        ("OS version", "Endpoint.OSVersion"), ("Agent ID", "Endpoint.AgentID"),
        ("Tags", "Endpoint.Tags"),
    ], ART), "#00695c")

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
