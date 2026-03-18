#!/usr/bin/env python3
"""
Build 6 realistic Proofpoint TAP TSV test scenario files.

Each scenario drives a specific playbook path in the SOC Email framework:

  Path 1 — escalate_IR       : messages delivered + malware + VIP recipient
  Path 2 — search_and_purge  : clicks permitted + phish + multi_user + lateral risk
  Path 3 — retract_message   : messages delivered + phish + single user + no click
  Path 4 — quarantine        : messages blocked (SEG quarantine, not inbox delivered)
  Path 5 — no_action         : messages delivered + benign verdict
  Path 6 — false_positive    : clicks permitted + malware → analyst marks benign → unblock

Output: one TSV per scenario in ./proofpoint-test-scenarios/
"""

import csv
import json
import uuid
import os
from datetime import datetime, timezone
from copy import deepcopy

OUT_DIR = "/home/claude/proofpoint-test-scenarios"
os.makedirs(OUT_DIR, exist_ok=True)

# ── Field order matches real Proofpoint TAP XQL export exactly ──────────────
HEADERS = [
    "_time", "GUID", "QID", "_alert_data", "_collector_name", "_id",
    "_insert_time", "_product", "_vendor", "cluster", "completelyRewritten",
    "fromAddress", "headerFrom", "id", "impostorScore", "malwareScore",
    "messageID", "messageParts", "messageSize", "messageTime", "modulesRun",
    "phishScore", "policyRoutes", "recipient", "sender", "senderIP", "spamScore",
    "subject", "threatsInfoMap", "toAddresses", "type", "ccAddresses",
    "headerReplyTo", "replyToAddress", "xmailer", "_collector_type", "_device_id",
    "_final_reporting_device_ip", "_raw_json", "_raw_log", "_reporting_device_ip",
    "_tag", "campaignId", "classification", "clickIP", "clickTime",
    "quarantineFolder", "quarantineRule", "threatID", "threatStatus",
    "threatTime", "threatURL", "url", "userAgent",
]

TS        = "Nov 17 2025 14:22:03"
TS_ISO    = "2025-11-17T14:22:03Z"
TS_THREAT = "2025-11-17T14:18:45.000Z"
CLUSTER   = "socfw_hosted"
TENANT_ID = "58540bd2-e4ec-86c3-084a-eb31d24be8b6"


def guid():
    return str(uuid.uuid4()).replace("-", "")[:34]


def mid():
    return str(uuid.uuid4())


def alert_data_template(event_type: str, g: str, severity: str = "SEV_020_HIGH") -> dict:
    """Minimal _alert_data that XSIAM needs to process the alert."""
    is_click = "click" in event_type.lower()
    return {
        "activated": "0001-01-01T00:00:00Z",
        "agent_os_type": "AGENT_OS_ANDROID",
        "alert_action_status": "DETECTED",
        "alert_domain": "DOMAIN_HEALTH",
        "alert_name": f"Proofpoint - {'Click Permitted' if is_click else 'Message Delivered'} - {g}",
        "alert_source": "Proofpoint TAP v2",
        "alert_sub_type": "XDR",
        "alert_type": f"Proofpoint TAP - {'Click Permitted' if is_click else 'Message Delivered'}",
        "alertsearchresults": [{}, {}, {}],
        "allRead": False,
        "allReadWrite": False,
        "asmalertsummary": [{}, {}, {}],
        "asmcloud": [{}, {}, {}],
        "asmdatacollection": [{}, {}, {}],
        "asmenrichmentstatus": [{"columnheader1": "", "columnheader2": "", "columnheader3": ""}, {}, {}],
        "asmnotification": [{}, {}, {}],
        "asmplaybookstage": [],
        "asmprivateip": [{}, {}, {}],
        "asmrelated": [{}, {}, {}],
        "asmremediation": [{}, {}, {}],
        "asmremediationobjectives": [{}, {}, {}],
        "asmremediationpathrule": [{}],
        "asmservicedetection": [{}],
        "asmserviceowner": [{}, {}, {}],
        "asmserviceownerunrankedraw": [{}, {}, {}],
        "asmsystemids": [{}, {}, {}],
        "asmtags": [{}, {}, {}],
        "attachment": None,
        "canvases": None,
        "category": "",
        "closeReason": "",
        "closed": "0001-01-01T00:00:00Z",
        "closingUserId": "",
        "containmentsla": {"runStatus": "idle", "slaStatus": -1, "accumulatedPause": 0,
                           "startDate": "0001-01-01T00:00:00Z", "dueDate": "0001-01-01T00:00:00Z",
                           "sla": 30, "endDate": "0001-01-01T00:00:00Z", "totalDuration": 0,
                           "lastPauseDate": "0001-01-01T00:00:00Z", "breachTriggered": False},
        "detectionsla": {"runStatus": "idle", "slaStatus": -1, "accumulatedPause": 0,
                         "startDate": "0001-01-01T00:00:00Z", "dueDate": "0001-01-01T00:00:00Z",
                         "sla": 30, "endDate": "0001-01-01T00:00:00Z", "totalDuration": 0,
                         "lastPauseDate": "0001-01-01T00:00:00Z", "breachTriggered": False},
        "emaildeletefrombrand": "Unspecified",
        "emaildeletetype": "soft",
        "forensics_artifact_type": "AMCACHE",
        "isactive": True,
        "labels": [
            {"value": "Proofpoint TAP v2", "type": "Brand"},
            {"value": f"Proofpoint TAP v2_{'Clicks_Permitted' if is_click else 'Messages_Delivered'}", "type": "Instance"},
        ],
        "occurred": TS_ISO,
        "resolution_status": "STATUS_010_NEW",
        "servicenowbusinessimpact": "1 - Critical",
        "servicenowimpact": "1 - High",
        "servicenownotify": "Send Email",
        "servicenowpriority": "1 - Critical",
        "servicenowseverity": "1 - High",
        "servicenowsircategory": "Confidential personal identity data exposure",
        "servicenowsirstate": "New",
        "servicenowstate": "1 - New",
        "servicenowurgency": "1 - High",
        "severity": severity,
        "similarincidentsdbot": [{}],
        "source_insert_ts": 1763035807670,
        "sourceInstance": f"Proofpoint TAP v2_{'Clicks_Permitted' if is_click else 'Messages_Delivered'}",
    }


def make_raw_json(threats: list, subject: str, from_addr: list,
                  to_addrs: list, cc: list = None,
                  parts: list = None, qfolder: str = None) -> str:
    return json.dumps({
        "spamScore": 0,
        "phishScore": 100 if any(t.get("classification") == "phish" for t in threats) else 0,
        "malwareScore": 100 if any(t.get("classification") == "malware" for t in threats) else 0,
        "threatsInfoMap": threats,
        "messageTime": TS_ISO,
        "impostorScore": 0.0,
        "cluster": CLUSTER,
        "subject": subject,
        "quarantineFolder": qfolder,
        "quarantineRule": "socfw-malware-quarantine" if qfolder else None,
        "policyRoutes": ["O365Inbound", "default_inbound"],
        "modulesRun": ["access", "av", "dkimv", "spf", "sandbox", "spam", "dmarc", "urldefense"],
        "messageSize": 245760,
        "headerFrom": from_addr[0] if from_addr else "",
        "fromAddress": from_addr,
        "toAddresses": to_addrs,
        "ccAddresses": cc or [],
        "replyToAddress": [],
        "messageParts": parts or [],
    })


def write_tsv(filename: str, rows: list):
    path = os.path.join(OUT_DIR, filename)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Serialize any dict/list fields back to JSON strings for TSV
            out = {}
            for h in HEADERS:
                v = row.get(h, "")
                if isinstance(v, (dict, list)):
                    out[h] = json.dumps(v)
                elif v is None:
                    out[h] = ""
                else:
                    out[h] = v
            writer.writerow(out)
    print(f"  ✅ {filename}  ({len(rows)} row{'s' if len(rows) != 1 else ''})")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# PATH 1 — escalate_IR
# messages delivered + malware + VIP recipient + threatStatus=malicious
# Drives: verdict=malicious + HighValueUserInvolved=True → escalate_IR
# ══════════════════════════════════════════════════════════════════════════════
def scenario_escalate_ir():
    g  = guid()
    i  = mid()
    threat_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    campaign_id = "4a1c29ab-3a4b-4d95-bf46-db9ab2e4e193"
    sender_email = "cfo-urgent@malicious-wire.net"
    # VIP user — must be in the SOCFramework VIP Users list on the tenant
    recipient_email = "cfo@socframework.local"

    threats = [{
        "threatID": threat_id,
        "threatStatus": "malicious",
        "classification": "malware",
        "detectionType": "EMERGING_THREAT",
        "threatUrl": f"https://threatinsight.proofpoint.com/{TENANT_ID}/threat/email/{threat_id}",
        "threatTime": TS_THREAT,
        "threat": "https://evilpayload-cdn.ru/stage2/loader.exe",
        "campaignID": campaign_id,
        "actors": [{"id": "TA505", "name": "TA505"}],
        "threatType": "attachment",
    }]

    parts = [{
        "disposition": "attached",
        "sha256": "3c9ab2f847c1e5b2d4e9f0a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "filename": "Invoice_Q4_URGENT.exe",
        "sandboxStatus": "THREAT",
        "oContentType": "application/octet-stream",
        "contentType": "application/octet-stream",
    }]

    ad = alert_data_template("messages delivered", g, severity="SEV_010_CRITICAL")
    ad["raw_json"] = make_raw_json(
        threats=threats,
        subject="URGENT: Wire Transfer Authorization Required — CFO Action Needed",
        from_addr=[sender_email],
        to_addrs=[recipient_email],
        parts=parts,
    )
    # Inject proofpoint-specific fields XSIAM maps to alert.proofpointtapthreatinfomap
    ad["proofpointtapthreatinfomap"] = [{}]

    row = {
        "_time": TS, "GUID": g, "QID": f"5{g[:12].upper()}",
        "_alert_data": ad,
        "_collector_name": "XSIAM", "_id": f"{g}:0:15773:15978",
        "_insert_time": TS, "_product": "generic_alert", "_vendor": "Proofpoint TAP v2",
        "cluster": CLUSTER, "completelyRewritten": "false",
        "fromAddress": json.dumps([sender_email]),
        "headerFrom": f"Wire Transfer <{sender_email}>",
        "id": i, "impostorScore": 95, "malwareScore": 100,
        "messageID": f"<{guid()}@evilpayload-cdn.ru>",
        "messageParts": json.dumps(parts),
        "messageSize": 312880, "messageTime": TS,
        "modulesRun": json.dumps(["access", "av", "sandbox", "urldefense"]),
        "phishScore": 95,
        "policyRoutes": json.dumps(["O365Inbound", "default_inbound"]),
        "recipient": json.dumps([recipient_email]),
        "sender": sender_email, "senderIP": "91.243.80.41", "spamScore": 0,
        "subject": "URGENT: Wire Transfer Authorization Required — CFO Action Needed",
        "threatsInfoMap": json.dumps(threats),
        "toAddresses": json.dumps([recipient_email]),
        "type": "messages delivered",
        "ccAddresses": json.dumps([]), "headerReplyTo": "", "replyToAddress": json.dumps([]),
        "campaignId": campaign_id, "classification": "malware",
        "threatID": threat_id, "threatStatus": "malicious",
        "threatTime": TS, "threatURL": threats[0]["threatUrl"],
    }
    write_tsv("scenario_01_escalate_ir.tsv", [row])


# ══════════════════════════════════════════════════════════════════════════════
# PATH 2 — search_and_purge + internal_lateral_risk=true
# clicks permitted + phish + multi_user (5 recipients clicked)
# Drives: ClickCount>0 + verdict=malicious + NOT VIP → search_and_purge
#         category=phish + clicked + multi_user → internal_lateral_risk=true
# ══════════════════════════════════════════════════════════════════════════════
def scenario_search_and_purge():
    campaign_id = "7f3b19cc-2a5d-4e81-bf47-ac9bc3e5e291"
    threat_id = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
    sender_email = "payroll-update@hr-portal-secure.net"
    phish_url = "https://login-o365-secure.hr-portal-fake.net/auth/reset"

    threats = [{
        "threatID": threat_id,
        "threatStatus": "malicious",
        "classification": "phish",
        "detectionType": "URL",
        "threatUrl": f"https://threatinsight.proofpoint.com/{TENANT_ID}/threat/email/{threat_id}",
        "threatTime": TS_THREAT,
        "threat": phish_url,
        "campaignID": campaign_id,
        "actors": [],
        "threatType": "url",
    }]

    # 5 recipients — drives multi_user scope (2–10 range)
    recipients = [
        "j.martinez@socframework.local",
        "k.chen@socframework.local",
        "a.okonkwo@socframework.local",
        "p.brennan@socframework.local",
        "t.lindqvist@socframework.local",
    ]

    rows = []
    for recip in recipients:
        g = guid()
        i = mid()
        ad = alert_data_template("clicks permitted", g)
        ad["raw_json"] = make_raw_json(
            threats=threats,
            subject="Action Required: Verify Your Payroll Direct Deposit Details",
            from_addr=[sender_email],
            to_addrs=recipients,
        )
        ad["proofpointtapthreatinfomap"] = [{}]

        row = {
            "_time": TS, "GUID": g, "QID": "",
            "_alert_data": ad,
            "_collector_name": "XSIAM", "_id": f"{g}:0:15773:15978",
            "_insert_time": TS, "_product": "generic_alert", "_vendor": "Proofpoint TAP v2",
            "cluster": CLUSTER, "completelyRewritten": "true",
            "fromAddress": json.dumps([sender_email]),
            "headerFrom": f"HR Portal <{sender_email}>",
            "id": i, "impostorScore": 0, "malwareScore": 0,
            "messageID": f"<{guid()}@hr-portal-secure.net>",
            "messageParts": json.dumps([]),
            "messageSize": 18432, "messageTime": TS,
            "modulesRun": json.dumps(["access", "urldefense", "spam"]),
            "phishScore": 100,
            "policyRoutes": json.dumps(["O365Inbound", "default_inbound"]),
            "recipient": recip,   # clicks permitted uses scalar, not array
            "sender": sender_email, "senderIP": "185.220.101.47", "spamScore": 10,
            "subject": "Action Required: Verify Your Payroll Direct Deposit Details",
            "threatsInfoMap": json.dumps(threats),
            "toAddresses": json.dumps(recipients),
            "type": "clicks permitted",
            "ccAddresses": json.dumps([]), "headerReplyTo": "", "replyToAddress": json.dumps([]),
            "campaignId": campaign_id, "classification": "phish",
            "clickIP": "192.168.10.{}".format(50 + recipients.index(recip)),
            "clickTime": TS,
            "threatID": threat_id, "threatStatus": "malicious",
            "threatTime": TS, "threatURL": threats[0]["threatUrl"],
            "url": phish_url,
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        }
        rows.append(row)

    write_tsv("scenario_02_search_and_purge.tsv", rows)


# ══════════════════════════════════════════════════════════════════════════════
# PATH 3 — retract_message
# messages delivered + phish + single user + no click
# Drives: DeliveredCount>0 + ClickCount=0 + verdict=malicious → retract_message
# ══════════════════════════════════════════════════════════════════════════════
def scenario_retract_message():
    g = guid()
    i = mid()
    threat_id = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    campaign_id = "9d1f4ba3-7c2e-4a61-be93-12de5f8a7c04"
    sender_email = "docusign-notification@sign-verify-secure.com"
    recipient_email = "r.patel@socframework.local"
    phish_url = "https://docusign-verify.sign-verify-secure.com/envelope/review?id=TX992841"

    threats = [{
        "threatID": threat_id,
        "threatStatus": "malicious",
        "classification": "phish",
        "detectionType": "URL",
        "threatUrl": f"https://threatinsight.proofpoint.com/{TENANT_ID}/threat/email/{threat_id}",
        "threatTime": TS_THREAT,
        "threat": phish_url,
        "campaignID": campaign_id,
        "actors": [],
        "threatType": "url",
    }]

    ad = alert_data_template("messages delivered", g)
    ad["raw_json"] = make_raw_json(
        threats=threats,
        subject="Please DocuSign: NDA Agreement — Signature Required",
        from_addr=[sender_email],
        to_addrs=[recipient_email],
    )
    ad["proofpointtapthreatinfomap"] = [{}]

    row = {
        "_time": TS, "GUID": g, "QID": f"5{g[:12].upper()}",
        "_alert_data": ad,
        "_collector_name": "XSIAM", "_id": f"{g}:0:15773:15978",
        "_insert_time": TS, "_product": "generic_alert", "_vendor": "Proofpoint TAP v2",
        "cluster": CLUSTER, "completelyRewritten": "true",
        "fromAddress": json.dumps([sender_email]),
        "headerFrom": f"DocuSign <{sender_email}>",
        "id": i, "impostorScore": 0, "malwareScore": 0,
        "messageID": f"<{guid()}@sign-verify-secure.com>",
        "messageParts": json.dumps([]),
        "messageSize": 22528, "messageTime": TS,
        "modulesRun": json.dumps(["access", "urldefense", "spam", "dmarc"]),
        "phishScore": 100,
        "policyRoutes": json.dumps(["O365Inbound", "default_inbound"]),
        "recipient": json.dumps([recipient_email]),
        "sender": sender_email, "senderIP": "103.76.228.15", "spamScore": 0,
        "subject": "Please DocuSign: NDA Agreement — Signature Required",
        "threatsInfoMap": json.dumps(threats),
        "toAddresses": json.dumps([recipient_email]),
        "type": "messages delivered",
        "ccAddresses": json.dumps([]), "headerReplyTo": "", "replyToAddress": json.dumps([]),
        "campaignId": campaign_id, "classification": "phish",
        "threatID": threat_id, "threatStatus": "malicious",
        "threatTime": TS, "threatURL": threats[0]["threatUrl"],
        "url": phish_url,
    }
    write_tsv("scenario_03_retract_message.tsv", [row])


# ══════════════════════════════════════════════════════════════════════════════
# PATH 4 — quarantine
# Message blocked at SEG — quarantineFolder set, not delivered to inbox
# Drives: DeliveredCount=0 + verdict=malicious → quarantine
# ══════════════════════════════════════════════════════════════════════════════
def scenario_quarantine():
    g = guid()
    i = mid()
    threat_id = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
    sender_email = "remittance@swift-payment-notify.biz"
    recipient_email = "accounts.payable@socframework.local"
    threat_url = "https://swift-payment-notify.biz/dl/remittance_advice_2024.zip"

    threats = [{
        "threatID": threat_id,
        "threatStatus": "malicious",
        "classification": "malware",
        "detectionType": "COMPROMISED_WEBSITE",
        "threatUrl": f"https://threatinsight.proofpoint.com/{TENANT_ID}/threat/email/{threat_id}",
        "threatTime": TS_THREAT,
        "threat": threat_url,
        "campaignID": None,
        "actors": [],
        "threatType": "url",
    }]

    parts = [{
        "disposition": "attached",
        "sha256": "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
        "md5": "098f6bcd4621d373cade4e832627b4f6",
        "filename": "remittance_advice_2024.zip",
        "sandboxStatus": "THREAT",
        "oContentType": "application/zip",
        "contentType": "application/zip",
    }]

    ad = alert_data_template("messages delivered", g, severity="SEV_020_HIGH")
    ad["raw_json"] = make_raw_json(
        threats=threats,
        subject="Remittance Advice — Payment Ref: INV-20241117-8841",
        from_addr=[sender_email],
        to_addrs=[recipient_email],
        parts=parts,
        qfolder="Malware",
    )
    ad["proofpointtapthreatinfomap"] = [{}]

    row = {
        "_time": TS, "GUID": g, "QID": f"5{g[:12].upper()}",
        "_alert_data": ad,
        "_collector_name": "XSIAM", "_id": f"{g}:0:15773:15978",
        "_insert_time": TS, "_product": "generic_alert", "_vendor": "Proofpoint TAP v2",
        "cluster": CLUSTER, "completelyRewritten": "false",
        "fromAddress": json.dumps([sender_email]),
        "headerFrom": f"Remittance <{sender_email}>",
        "id": i, "impostorScore": 0, "malwareScore": 100,
        "messageID": f"<{guid()}@swift-payment-notify.biz>",
        "messageParts": json.dumps(parts),
        "messageSize": 198456, "messageTime": TS,
        "modulesRun": json.dumps(["access", "av", "sandbox", "urldefense"]),
        "phishScore": 0,
        "policyRoutes": json.dumps(["O365Inbound", "default_inbound", "malware_quarantine"]),
        "recipient": json.dumps([recipient_email]),
        "sender": sender_email, "senderIP": "196.202.156.31", "spamScore": 0,
        "subject": "Remittance Advice — Payment Ref: INV-20241117-8841",
        "threatsInfoMap": json.dumps(threats),
        "toAddresses": json.dumps([recipient_email]),
        "type": "messages delivered",
        "ccAddresses": json.dumps([]), "headerReplyTo": "", "replyToAddress": json.dumps([]),
        "campaignId": "", "classification": "malware",
        "quarantineFolder": "Malware",
        "quarantineRule": "socfw-malware-quarantine",
        "threatID": threat_id, "threatStatus": "malicious",
        "threatTime": TS, "threatURL": threats[0]["threatUrl"],
    }
    write_tsv("scenario_04_quarantine.tsv", [row])


# ══════════════════════════════════════════════════════════════════════════════
# PATH 5 — no_action (benign verdict)
# messages delivered + threatStatus=benign → no_action, no containment
# Validates: Containment skip path writes contract correctly
# ══════════════════════════════════════════════════════════════════════════════
def scenario_no_action():
    g = guid()
    i = mid()
    threat_id = "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
    sender_email = "newsletter@legitimate-vendor.com"
    recipient_email = "m.thornton@socframework.local"
    url = "https://legitimate-vendor.com/blog/q4-2024-update"

    threats = [{
        "threatID": threat_id,
        "threatStatus": "benign",
        "classification": "phish",        # was initially flagged, re-classified benign
        "detectionType": "URL",
        "threatUrl": f"https://threatinsight.proofpoint.com/{TENANT_ID}/threat/email/{threat_id}",
        "threatTime": TS_THREAT,
        "threat": url,
        "campaignID": None,
        "actors": [],
        "threatType": "url",
    }]

    ad = alert_data_template("messages delivered", g, severity="SEV_040_LOW")
    ad["raw_json"] = make_raw_json(
        threats=threats,
        subject="Q4 2024 Product Update — What's New This Quarter",
        from_addr=[sender_email],
        to_addrs=[recipient_email],
    )
    ad["proofpointtapthreatinfomap"] = [{}]

    row = {
        "_time": TS, "GUID": g, "QID": f"5{g[:12].upper()}",
        "_alert_data": ad,
        "_collector_name": "XSIAM", "_id": f"{g}:0:15773:15978",
        "_insert_time": TS, "_product": "generic_alert", "_vendor": "Proofpoint TAP v2",
        "cluster": CLUSTER, "completelyRewritten": "true",
        "fromAddress": json.dumps([sender_email]),
        "headerFrom": f"Vendor News <{sender_email}>",
        "id": i, "impostorScore": 0, "malwareScore": 0,
        "messageID": f"<{guid()}@legitimate-vendor.com>",
        "messageParts": json.dumps([]),
        "messageSize": 14336, "messageTime": TS,
        "modulesRun": json.dumps(["access", "urldefense", "spam", "dmarc"]),
        "phishScore": 5,
        "policyRoutes": json.dumps(["O365Inbound", "default_inbound"]),
        "recipient": json.dumps([recipient_email]),
        "sender": sender_email, "senderIP": "209.85.220.41", "spamScore": 2,
        "subject": "Q4 2024 Product Update — What's New This Quarter",
        "threatsInfoMap": json.dumps(threats),
        "toAddresses": json.dumps([recipient_email]),
        "type": "messages delivered",
        "ccAddresses": json.dumps([]), "headerReplyTo": "", "replyToAddress": json.dumps([]),
        "campaignId": "", "classification": "",
        "threatID": threat_id, "threatStatus": "benign",
        "threatTime": TS, "threatURL": threats[0]["threatUrl"],
    }
    write_tsv("scenario_05_no_action.tsv", [row])


# ══════════════════════════════════════════════════════════════════════════════
# PATH 6 — false_positive → Recovery unblock_sender
# clicks permitted + malware, analyst marks benign during investigation
# → verdict flips to benign → Recovery fires soc-unblock-sender
# Note: the TSV fires the initial alert; analyst decision drives Recovery path.
#       Subject line and sender domain chosen to look borderline — realistic FP.
# ══════════════════════════════════════════════════════════════════════════════
def scenario_false_positive():
    g = guid()
    i = mid()
    threat_id = "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"
    sender_email = "updates@internal-sharepoint-notify.socframework.local"
    recipient_email = "b.okafor@socframework.local"
    url = "https://internal-sharepoint-notify.socframework.local/sites/it/Shared%20Documents/VPN_Guide_2025.pdf"

    # Proofpoint flagged this as malware but it's an internal SharePoint link
    # that matched a generic signature — analyst will mark benign
    threats = [{
        "threatID": threat_id,
        "threatStatus": "active",          # active = not yet re-evaluated by Proofpoint
        "classification": "malware",
        "detectionType": "URL",
        "threatUrl": f"https://threatinsight.proofpoint.com/{TENANT_ID}/threat/email/{threat_id}",
        "threatTime": TS_THREAT,
        "threat": url,
        "campaignID": None,
        "actors": [],
        "threatType": "url",
    }]

    ad = alert_data_template("clicks permitted", g, severity="SEV_030_MEDIUM")
    ad["raw_json"] = make_raw_json(
        threats=threats,
        subject="IT Notice: Updated VPN Configuration Guide Available on SharePoint",
        from_addr=[sender_email],
        to_addrs=[recipient_email],
    )
    ad["proofpointtapthreatinfomap"] = [{}]

    row = {
        "_time": TS, "GUID": g, "QID": "",
        "_alert_data": ad,
        "_collector_name": "XSIAM", "_id": f"{g}:0:15773:15978",
        "_insert_time": TS, "_product": "generic_alert", "_vendor": "Proofpoint TAP v2",
        "cluster": CLUSTER, "completelyRewritten": "false",
        "fromAddress": json.dumps([sender_email]),
        "headerFrom": f"IT SharePoint <{sender_email}>",
        "id": i, "impostorScore": 0, "malwareScore": 0,
        "messageID": f"<{guid()}@internal-sharepoint-notify.socframework.local>",
        "messageParts": json.dumps([]),
        "messageSize": 9216, "messageTime": TS,
        "modulesRun": json.dumps(["access", "urldefense", "spam"]),
        "phishScore": 0,
        "policyRoutes": json.dumps(["O365Inbound", "default_inbound"]),
        "recipient": recipient_email,
        "sender": sender_email, "senderIP": "10.0.1.50", "spamScore": 0,
        "subject": "IT Notice: Updated VPN Configuration Guide Available on SharePoint",
        "threatsInfoMap": json.dumps(threats),
        "toAddresses": json.dumps([recipient_email]),
        "type": "clicks permitted",
        "ccAddresses": json.dumps([]), "headerReplyTo": "", "replyToAddress": json.dumps([]),
        "campaignId": "", "classification": "malware",
        "clickIP": "10.0.1.142",
        "clickTime": TS,
        "threatID": threat_id, "threatStatus": "active",
        "threatTime": TS, "threatURL": threats[0]["threatUrl"],
        "url": url,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    }
    write_tsv("scenario_06_false_positive.tsv", [row])


# ── Run all ──
print(f"\nBuilding Proofpoint TAP test scenarios → {OUT_DIR}/\n")
scenario_escalate_ir()
scenario_search_and_purge()
scenario_retract_message()
scenario_quarantine()
scenario_no_action()
scenario_false_positive()

print("""
Done. Send any scenario:

  # 1. Convert TSV → JSON
  python3 tools/tsv_to_json_proofpoint.py \\
    --input proofpoint-test-scenarios/scenario_01_escalate_ir.tsv \\
    --output /tmp/test.json

  # 2. Send to tenant
  python3 tools/send_test_events.py \\
    --file /tmp/test.json \\
    --env .env-brumxdr-proofpoint \\
    --time-field _time

Playbook paths covered:
  scenario_01_escalate_ir.tsv       → verdict=malicious + VIP → escalate_IR
  scenario_02_search_and_purge.tsv  → 5 clicks permitted + phish + multi_user → search_and_purge + lateral_risk=true
  scenario_03_retract_message.tsv   → delivered + phish + no click + single_user → retract_message
  scenario_04_quarantine.tsv        → delivered to quarantine folder → quarantine
  scenario_05_no_action.tsv         → threatStatus=benign → no_action (validates Containment skip path contract)
  scenario_06_false_positive.tsv    → internal SharePoint URL flagged → analyst marks benign → Recovery unblock_sender
""")
EOF
