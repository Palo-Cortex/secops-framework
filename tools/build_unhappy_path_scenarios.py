#!/usr/bin/env python3
"""Build the unhappy-path TSVs for the close/leave branches.

Every adversary-emulation scenario is a true positive, so the assessment always
escalates and soc-close-issue is never reached. That means the close path, the
leave path and the thin-evidence path have no test data at all — which is why a
30-day window on deathstar shows 1,847 close decisions and 8 closes.

These three fill that gap. All derive from MS-Defender-Benign-Blocked.tsv so
they land on the same collector, the same correlation rule and the same
normalize band as a case we already know routes end to end.

The source TSVs under input_tsv/ are gitignored, so this script is the recipe.
Prefer it to a comment describing how to hand-edit a row.

    python3 tools/build_unhappy_path_scenarios.py

  U1 fp_endpoint_admin_tool     benign, but it EXECUTED. The common real FP.
  U2 ambiguous_endpoint         evidence that does not settle -> leave
  U3 thin_endpoint_no_evidence  contract mostly empty -> evidence_unavailable
  U4 malicious_contained        true positive, stopped cold -> the A2 input
"""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(HERE, "input_tsv", "MS-Defender-Benign-Blocked.tsv")
OUT = os.path.join(HERE, "input_tsv")


def load_template():
    with open(SRC, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    if not rows:
        sys.exit(f"no rows in {SRC}")
    return rows[0]


def device_evidence(hostname, user, ip, remediation="none", detail=""):
    return {
        "@odata.type": "#microsoft.graph.security.deviceEvidence",
        "createdDateTime": "2025-12-02T19:17:28.000Z",
        "verdict": "unknown",
        "remediationStatus": remediation,
        "remediationStatusDetails": detail,
        "roles": ["PrimaryDevice"], "detailedRoles": ["PrimaryDevice"], "tags": [],
        "firstSeenDateTime": "2025-11-17T15:16:44Z",
        "mdeDeviceId": "8c41aa73de2f4b1290ee5c7761de0a44cc330001",
        "azureAdDeviceId": None,
        "deviceDnsName": f"{hostname}.skt.local", "hostName": hostname,
        "ntDomain": "SKT", "dnsDomain": "skt.local",
        "osPlatform": "Windows10", "osBuild": 19045, "version": "22H2",
        "healthStatus": "active", "riskScore": "low",
        "rbacGroupId": 1, "rbacGroupName": "Default",
        "onboardingStatus": "onboarded", "defenderAvStatus": "updated",
        "lastIpAddress": ip, "lastExternalIpAddress": "20.124.230.220",
        "ipInterfaces": [ip, "127.0.0.1"], "vmMetadata": None,
        "loggedOnUsers": [{"accountName": user, "domainName": "SKT"}],
    }


def process_evidence(cmdline, fname, fpath, sha256, publisher, signer,
                     detection_status, remediation="none", detail="", user="greta"):
    return {
        "@odata.type": "#microsoft.graph.security.processEvidence",
        "createdDateTime": "2025-12-02T19:17:28.000Z",
        "verdict": "unknown",
        "remediationStatus": remediation, "remediationStatusDetails": detail,
        "roles": [], "detailedRoles": [], "tags": [],
        "parentProcessId": 4180,
        "processCommandLine": cmdline,
        "processCreationDateTime": "2025-12-02T19:17:28.000Z",
        "parentProcessCreationDateTime": "2025-12-02T19:12:28.000Z",
        "detectionStatus": detection_status,
        "mdeDeviceId": "8c41aa73de2f4b1290ee5c7761de0a44cc330001",
        "imageFile": {"sha1": None, "sha256": sha256, "md5": None, "sha256Ac": None,
                      "fileName": fname, "filePath": fpath, "fileSize": None,
                      "filePublisher": publisher, "signer": signer,
                      "issuer": "DigiCert", "fileType": "exe"},
        "parentProcessImageFile": {
            "sha1": None,
            "sha256": "9f2a17c4e8b6d035a1c94e7f2b830d6154e9a7c8b21f0e34d59a86b7c4e13f02",
            "md5": None, "sha256Ac": None, "fileName": "explorer.exe",
            "filePath": "C:\\Windows", "fileSize": None,
            "filePublisher": "Microsoft Windows Publisher",
            "signer": "Microsoft Windows Publisher", "issuer": None},
        "userAccount": {"accountName": user, "domainName": "SKT",
                        "userSid": "S-1-5-21-4168186624-547105363-3065826963-2204"},
        "riskScore": None,
    }


# ── U1 ── legitimate admin tooling that actually ran ─────────────────────────
# The hard false positive: exposure is "executed" and nothing was contained, so
# every shortcut the matrix offers is unavailable. The only route to benign is
# the evidence — signed Microsoft binary, IT admin account, admin workstation,
# a scheduled maintenance window. If the model escalates this, the prompt is
# leaning on containment rather than reading evidence.
U1 = {
    "file": "MS-Defender-FP-Admin-Tool.tsv",
    "id": "fpAdminTool_0007",
    "title": "Remote execution tool launched on managed endpoint",
    "category": "SuspiciousActivity",
    "severity": "medium",
    "description": (
        "PsExec was launched from an IT administration workstation against a managed "
        "endpoint during the Tuesday 19:00-21:00 patch window. The binary is the "
        "Microsoft-signed Sysinternals release. The initiating account is a member of "
        "Helpdesk-Admins and has run the same command on 41 endpoints in the last 30 "
        "days. No credential access, no lateral movement beyond the maintenance scope, "
        "and no follow-on process was created."),
    "recommendedActions": "Confirm the change record for the patch window.",
    "evidence": [
        device_evidence("it-adm-02", "svc_patching", "10.20.10.12"),
        process_evidence(
            cmdline='"C:\\Program Files\\Sysinternals\\PsExec64.exe" \\\\greta-lt-04 -s cmd /c wuauclt /detectnow',
            fname="PsExec64.exe", fpath="C:\\Program Files\\Sysinternals",
            sha256="57492d33b7c0755bb411b22d2dfdfdf088cbbfcd010e30dd8d425d5fe66adff4",
            publisher="Microsoft Corporation", signer="Microsoft Corporation",
            detection_status="detected", user="svc_patching"),
    ],
}

# ── U2 ── genuinely unsettled ────────────────────────────────────────────────
# Dual-use, unsigned, no reputation either way, one weak signal. The correct
# answer is neither close nor escalate: nothing is owed and nothing is proven.
# This is the only scenario that exercises the `leave` disposition, and it is
# the one that shows whether `inconclusive` is being used as a verdict or as a
# shrug.
U2 = {
    "file": "MS-Defender-Ambiguous-Unsigned.tsv",
    "id": "ambiguous_0008",
    "title": "Unsigned archiving utility executed from user profile",
    "category": "SuspiciousActivity",
    "severity": "medium",
    "description": (
        "An unsigned 7-Zip-derived archiver executed from the user profile and wrote a "
        "password-protected archive to a local temp path. Archiving before exfiltration "
        "uses this pattern; so does an ordinary user compressing files. No network "
        "egress followed within the observation window, the hash has no reputation "
        "either way, and the user has no prior detections."),
    "recommendedActions": "Confirm with the user whether the archive was expected.",
    "evidence": [
        device_evidence("greta-lt-04", "greta", "10.20.40.61"),
        process_evidence(
            cmdline='"C:\\Users\\greta\\AppData\\Local\\Temp\\7zx.exe" a -p -mhe=on archive.7z .\\Documents',
            fname="7zx.exe", fpath="C:\\Users\\greta\\AppData\\Local\\Temp",
            sha256="b83a1f0e5d7c92a4681fbb3e0d5c47a9e21f6c8d3b0a94e7f215c6d8093ab4e1",
            publisher="", signer="", detection_status="detected"),
    ],
}

# ── U3 ── the contract is mostly empty ───────────────────────────────────────
# The Check Point shape, reproduced on a source we know routes, so a thin result
# cannot be blamed on the product map. Device evidence only: no process, no
# hash, no command line, no user. The assessment should say what is missing
# rather than inventing a verdict, and this is the fixture the required-set gate
# and the evidence_unavailable blocker class get tested against.
U3 = {
    "file": "MS-Defender-Thin-No-Evidence.tsv",
    "id": "thinEvidence_0009",
    "title": "Anomalous outbound connection observed",
    "category": "SuspiciousActivity",
    "severity": "medium",
    "description": "Anomalous outbound connection observed from managed endpoint.",
    "recommendedActions": "",
    "evidence": [device_evidence("greta-lt-04", "", "10.20.40.61")],
}



# ── U4 ── contained malicious ────────────────────────────────────────────────
# The only input the A2 matrix change actually depends on, and the one no
# scenario produces today. All 735 rows blocked by "a true-positive verdict is
# never auto-closed" are malicious; suspicious already closes, because the code
# guard only names malicious. So A2 is untestable without this.
#
# Real technique, unambiguously malicious, and stopped cold: Mimikatz written to
# disk, blocked at write time, quarantined, never executed. Nothing is owed —
# which is exactly the case the blanket malicious guard refuses to close.
U4 = {
    "file": "MS-Defender-Malicious-Contained.tsv",
    "id": "maliciousContained_0010",
    "title": "Credential dumping tool blocked and quarantined",
    "category": "CredentialAccess",
    "severity": "medium",
    "description": (
        "A known credential-dumping utility was written to disk and blocked at write "
        "time by Defender, then quarantined and removed. No process was created, no "
        "LSASS access attempt was observed, and no network activity followed. The "
        "detection is correct and the remediation completed automatically."),
    "recommendedActions": "None. The file was blocked and quarantined automatically.",
    "evidence": [
        device_evidence("greta-lt-04", "greta", "10.20.40.61",
                        remediation="remediated",
                        detail="Blocked and quarantined before execution."),
        process_evidence(
            cmdline='"C:\\Users\\greta\\Downloads\\mimi.exe" sekurlsa::logonpasswords',
            fname="mimi.exe", fpath="C:\\Users\\greta\\Downloads",
            sha256="f1a2b3c4d5e6970819283746555adf0e1c2b3a495867d1e2f3a4b5c6d7e8f901",
            publisher="", signer="",
            detection_status="blocked", remediation="remediated",
            detail="Blocked and quarantined before execution."),
    ],
}

def build(template, spec):
    row = dict(template)
    row["id"] = spec["id"]
    row["providerAlertId"] = spec["id"]
    row["alertWebUrl"] = f"https://security.microsoft.com/alerts/{spec['id']}"
    row["title"] = spec["title"]
    row["category"] = spec["category"]
    row["severity"] = spec["severity"]
    row["description"] = spec["description"]
    row["recommendedActions"] = spec["recommendedActions"]
    row["evidence"] = json.dumps(spec["evidence"])
    # "resolved" is filtered out by the rule, and "remediated" would hand the
    # assessment a containment signal these three deliberately do not have.
    row["status"] = "new"
    row["investigationState"] = "unknown"
    row["mitreTechniques"] = "[]"
    row["incidentId"] = str(999000 + int(spec["id"].split("_")[-1]))
    dest = os.path.join(OUT, spec["file"])
    with open(dest, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(template.keys()), delimiter="\t")
        w.writeheader()
        w.writerow(row)
    return dest


def main():
    template = load_template()
    for spec in (U1, U2, U3, U4):
        print("wrote", build(template, spec))


if __name__ == "__main__":
    main()
