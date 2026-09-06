"""Render what fired, from the normalized contract.

Reads SOCFramework.Artifacts.* directly. The NIST IR equivalents resolve through
Analysis.* first, which the AI lifecycle never populates — it writes Assessment.*
— so they render empty here regardless of how complete the contract is.

Only groups with data are drawn, so an endpoint alert shows process detail and a
network alert shows flow detail without either carrying empty headings.
"""
import demistomock as demisto
from CommonServerPython import *

ART = "SOCFramework.Artifacts."


def _v(ctx, suffix):
    val = demisto.get(ctx, ART + suffix)
    if isinstance(val, list):
        val = ", ".join(str(v) for v in val if v) or None
    return val if val not in (None, "", [], {}) else None


def _rows(ctx, pairs):
    """Label/value rows for whichever paths resolved."""
    out = []
    for label, suffix in pairs:
        v = _v(ctx, suffix)
        if v:
            out.append(
                f"<div style='margin:2px 0;'><span style='color:#888;'>{label}</span> "
                f"<span style='color:#ddd;'>{v}</span></div>"
            )
    return out


def _mono(ctx, label, suffix):
    v = _v(ctx, suffix)
    if not v:
        return ""
    return (
        f"<div style='margin:3px 0;'><span style='color:#888;font-size:10px;'>{label}</span>"
        f"<div style='font-family:monospace;font-size:11px;color:#80cbc4;"
        f"word-break:break-all;'>{v}</div></div>"
    )


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
    html = ""

    html += _block("Detection", "".join(
        _rows(ctx, [("Action", "Source.Action"), ("Domain", "Source.AlertDomain"),
                    ("Module", "Source.Module")])
    ) + _mono(ctx, "DETAIL", "Source.Details"), "#0277bd")

    html += _block("MITRE", "".join(
        _rows(ctx, [("Tactic", "MITRE.Tactic"), ("Technique", "MITRE.Technique"),
                    ("Technique ID", "MITRE.TechniqueID"), ("Category", "MITRE.Category")])
    ), "#4a148c")

    proc = "".join(
        _rows(ctx, [("Process", "Process.Name"), ("PID", "Process.PID"),
                    ("Signature", "Process.Signature"),
                    ("Parent", "Process.Parent.Name"), ("Parent PID", "Process.Parent.PID"),
                    ("Parent signature", "Process.Parent.Signature")])
    ) + _mono(ctx, "COMMAND LINE", "Process.CommandLine") \
      + _mono(ctx, "PATH", "Process.Path") \
      + _mono(ctx, "SHA256", "Process.SHA256") \
      + _mono(ctx, "PARENT SHA256", "Process.Parent.SHA256")
    html += _block("Process", proc, "#00695c")

    tgt = "".join(_rows(ctx, [("File", "Target.File"), ("Verdict", "Target.Verdict"),
                              ("Signature", "Target.SignatureStatus")])) \
        + _mono(ctx, "PATH", "Target.Path") + _mono(ctx, "SHA256", "Target.SHA256")
    html += _block("Target file", tgt, "#00695c")

    net = "".join(_rows(ctx, [
        ("Action", "Network.Flow.Action"), ("Application", "Network.Flow.Application"),
        ("Event", "Network.Flow.EventType"),
        ("Destination", "Network.Destination.IP"), ("Dest host", "Network.Destination.Hostname"),
        ("Dest port", "Network.Destination.Port"), ("Dest country", "Network.Destination.Country"),
        ("Source", "Network.Source.IP"), ("Source country", "Network.Source.Country"),
        ("DNS query", "Network.DNS.Query"),
        ("Device", "Network.Device.Name"), ("Rule", "Network.Device.RuleName")]))
    html += _block("Network", net, "#1a237e")

    mail = "".join(_rows(ctx, [("From", "Email.From"), ("To", "Email.To"),
                               ("Subject", "Email.Subject"), ("Threat type", "Email.ThreatType")])) \
        + _mono(ctx, "THREAT URL", "Email.ThreatURL")
    html += _block("Email", mail, "#e65100")

    if not html:
        html = ("<div style='color:#888;font-style:italic;padding:8px;'>"
                "No normalized contract for this alert. If this persists, check the alert's "
                "source has a category in SOCProductCategoryMap_V3 — an uncategorised source "
                "falls through to generic and populates no artifacts.</div>")

    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"],
                     "Contents": f"<div style='padding:4px;'>{html}</div>"})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
