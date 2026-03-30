import demistomock as demisto
from CommonServerPython import *


PENDING = "<div style='color:#888;font-style:italic;padding:8px;'>Analysis phase running...</div>"


def _get(ctx, path):
    val = demisto.get(ctx, path)
    if isinstance(val, list):
        val = val[0] if val else None
    return val if val not in (None, "", [], {}) else None


def _badge(label, color):
    return (
        f"<span style='background:{color};color:#fff;padding:2px 8px;"
        f"border-radius:3px;font-size:11px;font-weight:bold;'>{label}</span>"
    )


def _verdict_badge(verdict):
    colors = {
        "malicious": "#c62828", "true_positive": "#c62828",
        "benign": "#2e7d32", "false_positive": "#2e7d32",
        "suspicious": "#e65100",
    }
    v = str(verdict).lower().replace(" ", "_")
    color = colors.get(v, "#555")
    return _badge(str(verdict).upper(), color)


def _section(title, content, border_color="#0288d1"):
    return (
        f"<div style='margin-bottom:12px;border-left:3px solid {border_color};"
        f"padding-left:10px;'>"
        f"<div style='font-size:10px;color:#888;text-transform:uppercase;"
        f"letter-spacing:1px;margin-bottom:4px;'>{title}</div>"
        f"<div style='color:#ddd;font-size:12px;line-height:1.5;'>{content}</div>"
        f"</div>"
    )


def _ioc_list(items, ioc_type):
    if not items:
        return ""
    if isinstance(items, str):
        items = [i.strip() for i in items.split(",") if i.strip()]
    if isinstance(items, list):
        links = "".join(
            f"<div style='font-family:monospace;font-size:11px;color:#80cbc4;"
            f"margin:1px 0;'>{i}</div>" for i in items if i
        )
        return links
    return str(items)


def main():
    ctx = demisto.context()

    story = _get(ctx, "Analysis.story")
    verdict = _get(ctx, "Analysis.verdict") or _get(ctx, "Analysis.Email.verdict")
    confidence = _get(ctx, "Analysis.confidence") or _get(ctx, "Analysis.Email.confidence")
    spread = _get(ctx, "Analysis.spread_level")
    score = _get(ctx, "Analysis.case_score")
    primary_user = _get(ctx, "SOCFramework.Primary.User")
    primary_host = _get(ctx, "SOCFramework.Primary.Endpoint")
    affected_users = _get(ctx, "Analysis.AffectedUsers")
    affected_hosts = _get(ctx, "Analysis.AffectedEndpoints")
    hashes = _get(ctx, "SOCFramework.Artifacts.Hash")
    ips = _get(ctx, "SOCFramework.Artifacts.IP")
    domains = _get(ctx, "SOCFramework.Artifacts.Domain")
    url = _get(ctx, "SOCFramework.Artifacts.URL")
    rec = _get(ctx, "Analysis.Email.response_recommended") or _get(ctx, "Analysis.response_recommendation")

    if not story and not verdict:
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": PENDING})
        return

    html = "<div style='padding:4px;'>"

    # Header: verdict + score
    if verdict or score:
        header = ""
        if verdict:
            header += _verdict_badge(verdict) + "&nbsp;"
        if confidence:
            header += _badge(f"Confidence: {confidence}", "#37474f") + "&nbsp;"
        if score:
            header += _badge(f"Risk Score: {score}", "#4a148c") + "&nbsp;"
        if spread:
            header += _badge(f"Spread: {spread}", "#1a237e")
        html += f"<div style='margin-bottom:12px;'>{header}</div>"

    # Narrative
    if story:
        story_html = str(story).replace("\n", "<br>")
        html += _section("Attack Narrative", story_html)

    # Victim scope
    scope_parts = []
    if primary_user:
        scope_parts.append(f"<b>User:</b> {primary_user}")
    if primary_host:
        scope_parts.append(f"<b>Host:</b> {primary_host}")
    if affected_users and str(affected_users) not in ("0", ""):
        scope_parts.append(f"<b>Total Users Affected:</b> {affected_users}")
    if affected_hosts and str(affected_hosts) not in ("0", ""):
        scope_parts.append(f"<b>Total Hosts Affected:</b> {affected_hosts}")
    if scope_parts:
        html += _section("Victim Scope", "<br>".join(scope_parts), "#0277bd")

    # IOCs
    ioc_html = ""
    if url:
        ioc_html += f"<div style='margin-bottom:4px;'><span style='color:#888;font-size:10px;'>THREAT URL</span><br>{_ioc_list(url, 'url')}</div>"
    if hashes:
        ioc_html += f"<div style='margin-bottom:4px;'><span style='color:#888;font-size:10px;'>FILE HASHES</span><br>{_ioc_list(hashes, 'hash')}</div>"
    if ips:
        ioc_html += f"<div style='margin-bottom:4px;'><span style='color:#888;font-size:10px;'>C2 / REMOTE IPs</span><br>{_ioc_list(ips, 'ip')}</div>"
    if domains:
        ioc_html += f"<div style='margin-bottom:4px;'><span style='color:#888;font-size:10px;'>DOMAINS</span><br>{_ioc_list(domains, 'domain')}</div>"
    if ioc_html:
        html += _section("Indicators of Compromise", ioc_html, "#00695c")

    # Recommendation
    if rec and rec != "no_action":
        html += _section("Recommended Action", f"<b style='color:#ffb74d;'>{rec}</b>", "#e65100")

    html += "</div>"

    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
