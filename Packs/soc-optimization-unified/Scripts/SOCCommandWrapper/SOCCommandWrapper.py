import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re

CTX_REF_RE = re.compile(r"^\$\{(.+?)\}$")

def _try_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None

def _as_dict(v):
    if v is None:
        return {}
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return {}
        parsed = _try_json_loads(s)
        return parsed if isinstance(parsed, dict) else {}
    return {}

def _coerce_scalar(v):
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        if len(v) == 0:
            return None
        if len(v) == 1:
            return _coerce_scalar(v[0])
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        # If it is a stringified JSON list/dict, parse it
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            parsed = _try_json_loads(s)
            if parsed is not None:
                return _coerce_scalar(parsed)
        return s
    return v

def _looks_like_ctx_path(s: str) -> bool:
    s = s.strip()
    return s.startswith("SOCFramework.") or s.startswith("incident.") or s.startswith("alert.")

def _resolve_ctx_string(s: str, ctx: dict):
    """
    Resolve either:
      - "${SOCFramework.Artifacts.EndPointID}"
      - "SOCFramework.Artifacts.EndPointID"
    """
    s = s.strip()
    m = CTX_REF_RE.match(s)
    if m:
        path = m.group(1).strip()
        return demisto.get(ctx, path)

    if _looks_like_ctx_path(s):
        return demisto.get(ctx, s)

    return s  # literal string

def _resolve_templates(obj, ctx: dict):
    """
    Recursively resolve templates/paths in dict/list/str.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k: _resolve_templates(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_templates(x, ctx) for x in obj]
    if isinstance(obj, str):
        return _resolve_ctx_string(obj, ctx)
    return obj

def _should_be_list(arg_name: str) -> bool:
    """
    Heuristic:
      keep list for plural-y args like:
        *_ids, *_id_list, *_list, identifiers, endpoints, machines, hashes, paths
    """
    n = (arg_name or "").lower()
    return (
        n.endswith("s") or
        "list" in n or
        "identifiers" in n or
        n.endswith("_ids") or
        n.endswith("ids") or
        "hash" in n or
        "paths" in n
    )

def _normalize_arg_value(arg_name: str, value):
    """
    - Resolve singletons: ["id"] -> "id" for scalar args
    - Keep list for list-y args
    """
    v = _coerce_scalar(value)
    if _should_be_list(arg_name):
        # ensure list if scalar provided for list arg
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]
    else:
        # scalar arg: unwrap singleton lists
        if isinstance(v, list):
            return v[0] if v else None
        return v

def main():
    args = demisto.args()
    ctx = demisto.context()

    command = args.get("command")
    if not command:
        return demisto.results({"success": False, "error": "Missing required argument: command"})

    artifacts_path_or_dict = args.get("artifacts")
    artifacts = _as_dict(artifacts_path_or_dict)
    if not artifacts and isinstance(artifacts_path_or_dict, str) and artifacts_path_or_dict.strip():
        maybe = demisto.get(ctx, artifacts_path_or_dict.strip())
        artifacts = maybe if isinstance(maybe, dict) else {}
    if not artifacts:
        artifacts = demisto.get(ctx, "SOCFramework.Artifacts") or {}
    if not isinstance(artifacts, dict):
        artifacts = {}

    inline_args_raw = args.get("inline_args")
    inline_args = _as_dict(inline_args_raw)

    # ✅ Resolve context refs INSIDE inline_args (the key fix)
    inline_args = _resolve_templates(inline_args, ctx)

    # Build exec args with normalization
    exec_args = {}
    for k, v in inline_args.items():
        exec_args[k] = _normalize_arg_value(k, v)

    using = args.get("using") or demisto.get(ctx, "SOCFramework.Product.using")

    try:
        if using:
            result = demisto.executeCommand(command, exec_args, using=using)
        else:
            result = demisto.executeCommand(command, exec_args)
    except TypeError:
        # runtime fallback
        if using:
            exec_args2 = dict(exec_args)
            exec_args2["using"] = using
            result = demisto.executeCommand(command, exec_args2)
        else:
            result = demisto.executeCommand(command, exec_args)

    demisto.setContext("SOCFramework.ActionOutput", result)

    demisto.results({
        "success": True,
        "command_executed": command,
        "using": using,
        "args_used": exec_args,
        "raw_result": result
    })

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
