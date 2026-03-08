register_module_line('SOCCommandWrapper', 'start', __line__())
CONSTANT_PACK_VERSION = '3.1.5'
demisto.debug('pack id = soc-optimization-unified, pack version = 3.1.5')

import json
import re
from datetime import datetime

CTX_REF_RE = re.compile(r"^\$\{(.+?)\}$")


def warroom_log(title, payload, tags=None):
    try:
        entry = {
            "Type": EntryType.NOTE,
            "ContentsFormat": "json",
            "Contents": payload,
            "HumanReadable": f"### {title}\n```json\n{json.dumps(payload, indent=2)}\n```"
        }

        if tags:
            entry["Tags"] = tags

        demisto.results(entry)

    except Exception as e:
        demisto.debug(f"warroom_log failed: {str(e)}")


def _try_json_loads(s):
    try:
        return json.loads(s)
    except Exception:
        return None


def _resolve_ctx_string(s, ctx):

    if not isinstance(s, str):
        return s

    s = s.strip()

    m = CTX_REF_RE.match(s)
    if m:
        return demisto.get(ctx, m.group(1))

    if s.startswith("SOCFramework.") or s.startswith("incident.") or s.startswith("alert."):
        return demisto.get(ctx, s)

    return s


def _resolve_templates(obj, ctx):

    if isinstance(obj, dict):
        return {k: _resolve_templates(v, ctx) for k, v in obj.items()}

    if isinstance(obj, list):
        return [_resolve_templates(x, ctx) for x in obj]

    if isinstance(obj, str):
        return _resolve_ctx_string(obj, ctx)

    return obj


def append_context(key, record):

    ctx = demisto.context()
    existing = demisto.get(ctx, key)

    if not existing:
        demisto.setContext(key, [record])
        return

    if not isinstance(existing, list):
        existing = [existing]

    existing.append(record)

    demisto.setContext(key, existing)


def integration_failed(result):

    if not result:
        return True, "Empty result"

    entry = result[0]

    if entry.get("Type") == entryTypes["error"]:
        return True, entry.get("Contents")

    contents = entry.get("Contents")

    if isinstance(contents, str) and "error" in contents.lower():
        return True, contents

    return False, None


def parse_tags(raw_tags):

    if not raw_tags:
        return []

    if isinstance(raw_tags, list):
        return [str(t).strip() for t in raw_tags if str(t).strip()]

    if isinstance(raw_tags, str):
        s = raw_tags.strip()

        if not s:
            return []

        # Support JSON arrays
        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(t).strip() for t in parsed if str(t).strip()]
            except Exception:
                pass

        return [t.strip() for t in s.split(",") if t.strip()]

    return [str(raw_tags).strip()]


def main():

    args = demisto.args()
    ctx = demisto.context()

    demisto.debug(f"RAW TAGS: {args.get('tags')} | TYPE: {type(args.get('tags'))}")

    action = args.get("action")
    shadow_mode = str(args.get("shadow_mode", "false")).lower() == "true"
    list_name = args.get("list_name")
    output_key = args.get("output_key")

    raw_tags = args.get("tags")
    tags = parse_tags(raw_tags)

    if not action:
        return_error("Missing action")

    if not list_name:
        return_error("Missing list_name")

    list_data = demisto.executeCommand("getList", {"listName": list_name})

    if not list_data or "Contents" not in list_data[0]:
        return_error("Failed to load action list")

    action_map = _try_json_loads(list_data[0]["Contents"])

    if not action_map:
        return_error("Invalid JSON in action list")

    action_entry = action_map.get(action)

    if not action_entry:
        return_error(f"Action not found: {action}")

    responses = action_entry.get("responses", {})

    vendor = None
    vendor_data = None

    for k, v in responses.items():
        vendor = k
        vendor_data = v
        break

    if not vendor_data:
        return_error("No vendor response defined")

    command = vendor_data.get("command")
    inline_args = vendor_data.get("inline_args", {})

    inline_args = _resolve_templates(inline_args, ctx)

    warroom_log(
        "SOC Framework - Universal Command Resolved",
        {
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": shadow_mode,
            "raw_tags": raw_tags,
            "raw_tags_type": str(type(raw_tags)),
            "tags": tags
        },
        tags
    )

    timestamp = datetime.utcnow().isoformat() + "Z"

    # SHADOW MODE
    if shadow_mode:

        record = {
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": True,
            "success": False,
            "tags": tags,
            "timestamp": timestamp
        }

        if output_key:
            append_context(output_key, record)

        warroom_log(
            "SOC Framework - SHADOW MODE (Command Not Executed)",
            record,
            tags
        )

        return_results("Shadow Mode: command not executed")
        return

    try:

        warroom_log(
            "SOC Framework - Executing Command",
            {
                "command": command,
                "args": inline_args
            },
            tags
        )

        result = demisto.executeCommand(command, inline_args)

        failed, error_msg = integration_failed(result)

        if failed:

            record = {
                "action": action,
                "vendor": vendor,
                "command": command,
                "args": inline_args,
                "shadow_mode": False,
                "success": False,
                "error": error_msg,
                "tags": tags,
                "timestamp": timestamp
            }

            if output_key:
                append_context(output_key, record)

            warroom_log(
                "SOC Framework - Command Failure",
                record,
                tags
            )

            return_error(error_msg)

        else:

            record = {
                "action": action,
                "vendor": vendor,
                "command": command,
                "args": inline_args,
                "shadow_mode": False,
                "success": True,
                "tags": tags,
                "timestamp": timestamp
            }

            if output_key:
                append_context(output_key, record)

            warroom_log(
                "SOC Framework - Command Success",
                record,
                tags
            )

            return_results(result)

    except Exception as e:

        record = {
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": False,
            "success": False,
            "error": str(e),
            "tags": tags,
            "timestamp": timestamp
        }

        if output_key:
            append_context(output_key, record)

        warroom_log(
            "SOC Framework - Command Execution Error",
            record,
            tags
        )

        raise


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
