import demistomock as demisto
from CommonServerPython import *

# Generic alert-narrative renderer. One section on every category layout;
# the resolved SOCFramework.Product.category decides which renderer runs.
# Add a category by writing a render_<category>(f) function and registering it.


def _fields():
    inc = demisto.incident() or {}
    cf = inc.get("CustomFields") or {}
    merged = {k: v for k, v in inc.items() if k != "CustomFields"}
    merged.update(cf)
    return merged


def _one(v):
    if isinstance(v, list):
        v = v[0] if v else None
    return v if v not in (None, "", [], {}) else None


def _coalesce(f, *names):
    for n in names:
        v = _one(f.get(n))
        if v is not None:
            return v
    return None


def _badge(label, color):
    return (f"<span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:3px;font-size:12px;font-weight:bold;'>{label}</span>")


def _sev_color(sev):
    return {"critical": "#c62828", "high": "#e65100", "medium": "#f9a825",
            "low": "#2e7d32"}.get(str(sev).lower(), "#555")


def _section(title, content, border="#0288d1"):
    return (f"<div style='margin-bottom:12px;border-left:3px solid {border};padding-left:10px;'>"
            f"<div style='font-size:11px;color:#888;text-transform:uppercase;"
            f"letter-spacing:1px;margin-bottom:4px;'>{title}</div>"
            f"<div style='color:#ddd;font-size:14px;line-height:1.55;'>{content}</div></div>")


def _mono(v):
    return f"<span style='font-family:monospace;font-size:13px;color:#80cbc4;'>{v}</span>"


def render_endpoint(f):
    headline = _coalesce(f, "originalalertname", "alert_name")
    host = _coalesce(f, "hostname", "agent_hostname", "xdmsourcehosthostname")
    if not headline:
        return None
    tactic = _coalesce(f, "mitretacticname")
    technique = _coalesce(f, "mitretechniquename")
    meaning = _coalesce(f, "alert_description", "originaldescription")
    proc = _coalesce(f, "initiatedby", "actor_process_image_name")
    cmd = _coalesce(f, "initiatorcmd", "actor_process_command_line")
    parent = _coalesce(f, "parentprocessname")
    root = _coalesce(f, "causality_actor_process_image_name")
    grandparent = _coalesce(f, "grandparentprocessname")
    user = _coalesce(f, "username", "user_principal", "actor_effective_username")
    ip = _coalesce(f, "localip")
    file_name = _coalesce(f, "action_file_name", "filename")
    file_hash = _coalesce(f, "action_file_sha256", "filesha256")
    remote_ip = _coalesce(f, "action_remote_ip", "remoteip")
    action_taken = _coalesce(f, "alertaction", "pattern_disposition_details")
    vendor = _coalesce(f, "product", "vendor")
    sev = _one(f.get("severity"))
    link = _coalesce(f, "externallink", "external_pivot_url")

    html = "<div style='padding:4px;'>"
    band = ""
    kc = " &rsaquo; ".join([x for x in (tactic, technique) if x])
    if kc:
        band += _badge(kc, "#4a148c") + "&nbsp;"
    if sev:
        band += _badge(str(sev).upper(), _sev_color(sev)) + "&nbsp;"
    if vendor:
        band += _badge(str(vendor), "#37474f")
    if band:
        html += f"<div style='margin-bottom:10px;'>{band}</div>"
    bits = []
    if host:
        bits.append("On " + f"<b>{host}</b>" + (f" ({ip})" if ip else ""))
    if proc:
        bits.append(_mono(proc) + (f" running as <b>{user}</b>" if user else ""))
    sentence = ", ".join(bits)
    if headline:
        sentence = (sentence + " &mdash; " if sentence else "") + f"<b>{headline}</b>"
    if sentence:
        html += _section("What happened", sentence, "#0277bd")
    if meaning:
        html += _section("Why it matters", str(meaning))
    chain = [x for x in (grandparent, parent, proc) if x]
    if root and root not in chain:
        chain = [root] + chain
    if len(chain) > 1:
        html += _section("Process lineage", " &rarr; ".join(_mono(c) for c in chain), "#00695c")
    if cmd:
        html += _section("Command line", _mono(cmd), "#00695c")
    art = ""
    if file_name or file_hash:
        art += ("<div><span style='color:#888;font-size:10px;'>FILE</span><br>"
                + _mono(file_name or "") + (f"<br>{_mono(file_hash)}" if file_hash else "") + "</div>")
    if remote_ip:
        art += (f"<div style='margin-top:4px;'><span style='color:#888;font-size:10px;'>"
                f"REMOTE / C2 IP</span><br>{_mono(remote_ip)}</div>")
    if art:
        html += _section("Artifacts", art, "#00695c")
    if action_taken:
        html += _section("EDR action taken", f"<b style='color:#ffb74d;'>{action_taken}</b>", "#e65100")
    if link:
        html += _section("Pivot", f"<a href='{link}' target='_blank' style='color:#4fc3f7;'>"
                                  f"Open in {vendor or 'source console'}</a>", "#555")
    html += "</div>"
    return html


def render_email(f):
    headline = _coalesce(f, "originalalertname", "alert_name")
    sender = _coalesce(f, "emailsource", "emailsender")
    recipient = _coalesce(f, "emailrecipient")
    if not headline:
        return None
    tactic = _coalesce(f, "mitretacticname")
    technique = _coalesce(f, "mitretechniquename")
    subject = _coalesce(f, "emailsubject")
    sender_ip = _coalesce(f, "emailsenderip")
    msgid = _coalesce(f, "emailmessageid")
    delivery = _coalesce(f, "socfwemaildeliveryaction")
    direction = _coalesce(f, "socfwemaildirection")
    phish = _coalesce(f, "socfwemailphishscore")
    malware = _coalesce(f, "socfwemailmalwarescore")
    campaign = _coalesce(f, "socfwemailcampaignid")
    click_ip = _coalesce(f, "socfwemailclickip")
    click_time = _coalesce(f, "socfwemailclicktime")
    url = _coalesce(f, "socfwemailthreaturl", "clickedurls", "url")
    sev = _one(f.get("severity"))
    vendor = _coalesce(f, "product", "vendor")

    html = "<div style='padding:4px;'>"
    band = ""
    kc = " &rsaquo; ".join([x for x in (tactic, technique) if x])
    if kc:
        band += _badge(kc, "#4a148c") + "&nbsp;"
    if sev:
        band += _badge(str(sev).upper(), "#e65100") + "&nbsp;"
    if vendor:
        band += _badge(str(vendor), "#37474f")
    if band:
        html += f"<div style='margin-bottom:10px;'>{band}</div>"
    bits = []
    if sender:
        bits.append(f"A message from {_mono(sender)}" + (f" ({sender_ip})" if sender_ip else ""))
    if recipient:
        bits.append(f"reached <b>{recipient}</b>")
    sentence = " ".join(bits)
    if headline:
        sentence = (sentence + " &mdash; " if sentence else "") + f"<b>{headline}</b>"
    if sentence:
        html += _section("What happened", sentence, "#0277bd")
    if subject:
        html += _section("Subject", f"<i>{subject}</i>")
    vb = []
    if delivery:
        vb.append(f"<b>Delivery:</b> {delivery}")
    if direction:
        vb.append(f"<b>Direction:</b> {direction}")
    if phish:
        vb.append(f"<b>Phish score:</b> {phish}")
    if malware:
        vb.append(f"<b>Malware score:</b> {malware}")
    if vb:
        html += _section("Assessment", "<br>".join(vb), "#00695c")
    if url:
        defanged = str(url).replace("http", "hxxp").replace(".", "[.]")
        html += _section("Malicious URL", _mono(defanged), "#e65100")
    if click_ip or (delivery and "click" in str(delivery).lower()):
        ce = "User <b style='color:#ff8a65;'>clicked</b> the link"
        if click_ip:
            ce += f" from {_mono(click_ip)}"
        if click_time:
            ce += f" at {click_time}"
        html += _section("Click evidence", ce, "#c62828")
    meta = []
    if campaign:
        meta.append(f"<b>Campaign:</b> {_mono(campaign)}")
    if msgid:
        meta.append(f"<b>Message-ID:</b> {_mono(msgid)}")
    if meta:
        html += _section("Campaign", "<br>".join(meta), "#555")
    html += "</div>"
    return html


RENDERERS = {
    "endpoint": render_endpoint,
    "email": render_email,
}


def _detect_category(f, ctx):
    cat = _one(demisto.get(ctx, "SOCFramework.Product.category") or "")
    if cat:
        return str(cat).strip().lower()
    if _coalesce(f, "emailsource", "email_sender", "fw_email_recipient"):
        return "email"
    if _coalesce(f, "hostname", "agent_hostname") and _coalesce(f, "initiatorcmd", "actor_process_command_line", "initiatedby"):
        return "endpoint"
    return ""


def main():
    f = _fields()
    ctx = demisto.context()
    cat = _detect_category(f, ctx)
    renderer = RENDERERS.get(cat)
    html = renderer(f) if renderer else None
    if not html:
        html = ("<div style='color:#888;font-style:italic;padding:8px;'>"
                "No category-specific detail available for this alert.</div>")
    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
