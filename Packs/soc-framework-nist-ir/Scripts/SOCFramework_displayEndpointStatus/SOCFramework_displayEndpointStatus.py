import demistomock as demisto
from CommonServerPython import *
import json

_CARD = (
    "<div style='background:{bg};border:1px solid {bd};border-radius:6px;"
    "padding:10px 14px;display:flex;align-items:center;gap:10px;'>"
    "<span style='font-size:18px;'>{icon}</span>"
    "<div><strong style='color:{tc};'>{label}</strong>"
    "<div style='font-size:11px;color:#666;margin-top:2px;font-family:monospace;'>"
    "{meta}</div></div></div>"
)

STATES = {
    "contained": dict(
        bg="#FDECEA", bd="#E53935", tc="#B71C1C",
        icon="&#128274;", label="ISOLATED",
        meta="containment_status = Contained"
    ),
    "containment_pending": dict(
        bg="#FFF8E1", bd="#FFA000", tc="#E65100",
        icon="&#9203;", label="ISOLATION PENDING",
        meta="containment_status = containment_pending"
    ),
    "normal": dict(
        bg="#E8F5E9", bd="#388E3C", tc="#1B5E20",
        icon="&#10003;", label="NORMAL",
        meta="containment_status = Normal"
    ),
}

UNKNOWN_HTML = (
    "<div style='background:#F5F5F5;border:1px solid #BDBDBD;border-radius:6px;"
    "padding:10px 14px;color:#757575;'>"
    "Status unavailable — EDR unreachable or endpoint not found.</div>"
)

_VENDOR_MAP = {
    "contained":                 "contained",
    "containment_requested":     "containment_pending",
    "containment_pending":       "containment_pending",
    "lift_containment_approved": "containment_pending",
    "normal":                    "normal",
    "isolated":                  "contained",
    "not isolated":              "normal",
    "pending isolation":         "containment_pending",
    "isolation_requested":       "containment_pending",
}


def _render(key):
    params = STATES.get(key)
    return _CARD.format(**params) if params else UNKNOWN_HTML


def main():
    ctx = demisto.context()
    endpoint_id = (
        demisto.get(ctx, "SOCFramework.Primary.Endpoint")
        or demisto.get(ctx, "SOCFramework.Artifacts.EndPointID")
        or ""
    )

    if not endpoint_id:
        demisto.results({
            "ContentsFormat": formats["html"],
            "Type": entryTypes["note"],
            "Contents": UNKNOWN_HTML
        })
        return

    result = demisto.executeCommand(
        "SOCCommandWrapper",
        {
            "action": "soc-enrich-endpoint",
            "Action_Actor": "layout",
            "Phase": "StatusCheck",
            "tags": "Status Check",
        },
    )

    if is_error(result):
        demisto.results({
            "ContentsFormat": formats["html"],
            "Type": entryTypes["note"],
            "Contents": UNKNOWN_HTML
        })
        return

    raw_status = ""
    try:
        for entry in (result or []):
            contents = entry.get("Contents") or {}
            if isinstance(contents, str):
                try:
                    contents = json.loads(contents)
                except Exception:
                    pass
            if isinstance(contents, dict):
                raw_status = (
                    demisto.get(contents, "status")
                    or demisto.get(contents, "containment_status")
                    or demisto.get(contents, "device_status")
                    or ""
                )
                if raw_status:
                    break
    except Exception as e:
        demisto.debug(f"displayEndpointStatus: parse error {e}")

    canonical = _VENDOR_MAP.get(raw_status.lower().strip(), "normal")

    demisto.setContext(
        "SOCFramework.Endpoint.containment_status",
        canonical.replace("_", " ").title()
    )

    demisto.results({
        "ContentsFormat": formats["html"],
        "Type": entryTypes["note"],
        "Contents": _render(canonical)
    })


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
