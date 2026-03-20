"""
playbook_simulator.py
─────────────────────
Static execution engine for XSIAM SOC Framework playbooks.
"""

from __future__ import annotations
import yaml, json, re, os
from dataclasses import dataclass, field
from typing import Any
from copy import deepcopy


# ── Context ───────────────────────────────────────────────────────────────────

class Context:
    def __init__(self, initial: dict | None = None):
        self._data: dict = {}
        if initial:
            for k, v in initial.items():
                self.set(k, v)

    def set(self, key: str, value: Any, append: bool = False):
        if append and key in self._data:
            existing = self._data[key]
            self._data[key] = (existing if isinstance(existing, list) else [existing]) + \
                              (value if isinstance(value, list) else [value])
        else:
            self._data[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def get_by_path(self, path: str) -> Any:
        """Look up a dotted key path in context. Returns the value or None."""
        return self._data.get(path)

    def resolve_string(self, expr: str) -> Any:
        """Resolve ${Key.path} references within a string. Returns raw value for pure references."""
        pattern = re.compile(r'\$\{([^}]+)\}')
        matches = list(pattern.finditer(expr))
        if not matches:
            return expr
        if len(matches) == 1 and matches[0].group(0) == expr.strip():
            return self.get(matches[0].group(1))
        result = expr
        for m in reversed(matches):
            val = self.get(m.group(1))
            result = result[:m.start()] + str(val or '') + result[m.end():]
        return result

    def snapshot(self) -> dict:
        return deepcopy(self._data)


# ── Transformers ─────────────────────────────────────────────────────────────

def apply_transformers(value: Any, transformers: list) -> Any:
    for t in transformers:
        op   = t.get('operator')
        args = t.get('args', {})
        if op == 'join':
            sep = args.get('separator', {})
            if isinstance(sep, dict): sep = sep.get('value', {})
            if isinstance(sep, dict): sep = sep.get('simple', ',')
            value = sep.join(str(v) for v in value) if isinstance(value, list) else (str(value) if value is not None else '')
        elif op == 'count':
            value = len(value) if isinstance(value, list) else (1 if value is not None else 0)
        elif op == 'uniq':
            if isinstance(value, list):
                seen, out = set(), []
                for v in value:
                    k = str(v)
                    if k not in seen: seen.add(k); out.append(v)
                value = out
        elif op == 'getField':
            field = args.get('field', {})
            if isinstance(field, dict): field = field.get('value', {}).get('simple', '')
            if isinstance(value, dict) and field:
                value = value.get(field)
            elif isinstance(value, list) and field:
                value = [item.get(field) for item in value if isinstance(item, dict)]
        elif op == 'toLowerCase':
            value = str(value).lower() if value is not None else ''
        elif op == 'toUpperCase':
            value = str(value).upper() if value is not None else ''
        elif op == 'substringFrom':
            from_val = args.get('from', {})
            if isinstance(from_val, dict): from_val = from_val.get('value', {})
            if isinstance(from_val, dict): from_val = from_val.get('simple', '@')
            if isinstance(value, str) and from_val in value:
                value = value[value.index(from_val) + len(from_val):]
        elif op == 'MapRangeValues':
            mf = args.get('map_from', {}); mt = args.get('map_to', {})
            if isinstance(mf, dict): mf = mf.get('value', {}).get('simple', '')
            if isinstance(mt, dict): mt = mt.get('value', {}).get('simple', '')
            try:
                score = int(value)
                for r, label in zip(mf.split(','), mt.split(',')):
                    lo, hi = (int(x) for x in r.split('-'))
                    if lo <= score <= hi: value = label; break
            except Exception: pass
        elif op == 'if-then-else':
            cond     = args.get('condition', {})
            then_val = args.get('thenValue', {})
            else_val = args.get('elseValue', {})
            if isinstance(cond, dict):     cond     = cond.get('value', {}).get('simple', '')
            if isinstance(then_val, dict): then_val = then_val.get('value', {}).get('simple', '')
            if isinstance(else_val, dict): else_val = else_val.get('value', {}).get('simple', '')
            if cond.startswith('lte,'):
                try:
                    value = then_val if (isinstance(value, (int,float)) and value <= int(cond.split(',',1)[1])) else else_val
                except Exception: value = else_val
            elif cond.startswith('gte,'):
                try:
                    value = then_val if (isinstance(value, (int,float)) and value >= int(cond.split(',',1)[1])) else else_val
                except Exception: value = else_val
    return value


def resolve_value_spec(spec: Any, ctx: Context, iscontext: bool = False) -> Any:
    """
    Resolve a playbook value specification against context.
    iscontext=True means the 'simple' value is a context key path, not a literal.
    """
    if spec is None:
        return None
    if isinstance(spec, dict):
        if 'simple' in spec:
            raw = spec['simple']
            # If iscontext flag is on the parent condition operand, or the value
            # contains ${...}, resolve as context reference
            if iscontext and isinstance(raw, str) and not raw.startswith('${'):
                # Treat as context key path directly
                return ctx.get_by_path(raw)
            return ctx.resolve_string(raw) if isinstance(raw, str) else raw
        if 'complex' in spec:
            c          = spec['complex']
            root       = c.get('root', '')
            accessor   = c.get('accessor')
            transformers = c.get('transformers', [])
            value = ctx.get_by_path(root) if root else None
            if value is None and root:
                value = ctx.resolve_string(f'${{{root}}}')
            if accessor:
                if isinstance(value, dict):
                    val = value.get(accessor)
                    if val is None:
                        # Fallback: try flat dotted key root.accessor
                        val = ctx.get_by_path(f'{root}.{accessor}')
                    value = val
                elif isinstance(value, list):
                    value = [item.get(accessor) for item in value if isinstance(item, dict)]
                elif value is None:
                    # root not in context — try flat dotted key
                    value = ctx.get_by_path(f'{root}.{accessor}')
            value = apply_transformers(value, transformers)
            return value
    return ctx.resolve_string(str(spec)) if spec is not None else None


def _resolve_cond_operand(operand: dict, ctx: Context) -> Any:
    """Resolve a condition left/right operand respecting iscontext."""
    val_spec   = operand.get('value', {})
    iscontext  = operand.get('iscontext', False)
    return resolve_value_spec(val_spec, ctx, iscontext=iscontext)


# ── Condition evaluation ──────────────────────────────────────────────────────

def _truthy(v) -> bool:
    if v is None: return False
    if isinstance(v, bool): return v
    if isinstance(v, (int, float)): return v != 0
    if isinstance(v, str): return v.lower() not in ('', 'false', 'none', '0')
    if isinstance(v, list): return len(v) > 0
    return bool(v)


def evaluate_single_condition(cond: dict, ctx: Context) -> bool:
    op    = cond.get('operator', '')
    left  = _resolve_cond_operand(cond.get('left', {}), ctx)
    right = _resolve_cond_operand(cond.get('right', {}), ctx)
    icase = cond.get('ignorecase', False)

    if icase:
        if isinstance(left,  str): left  = left.lower()
        if isinstance(right, str): right = right.lower()

    if op == 'isNotEmpty':       return _truthy(left)
    if op == 'isEmpty':          return not _truthy(left)
    if op == 'isTrue':           return left is True or str(left).lower() == 'true'
    if op == 'isFalse':          return not _truthy(left)
    if op == 'isExists':         return left is not None
    if op == 'isEqualString':    return str(left or '').strip() == str(right or '').strip()
    if op == 'isEqualNumber':
        try: return float(left or 0) == float(right or 0)
        except Exception: return str(left or '') == str(right or '')
    if op == 'isNotEqualString': return str(left or '') != str(right or '')
    if op in ('containsGeneral', 'contains', 'containsString'):
        return str(right or '') in str(left or '')
    if op == 'inList':
        lst = right if isinstance(right, list) else str(right or '').split(',')
        return str(left or '') in [str(x).strip() for x in lst]
    if op == 'match':
        import re as _re
        try: return bool(_re.search(str(right or ''), str(left or '')))
        except Exception: return False
    if op == 'in':
        # XSIAM 'in': checks if left value exists within right (list or comma-separated string)
        if isinstance(right, list):
            return str(left or '') in [str(r) for r in right]
        return str(left or '') in str(right or '')
    if op == 'notIn':
        if isinstance(right, list):
            return str(left or '') not in [str(r) for r in right]
        return str(left or '') not in str(right or '')
    if op == 'greaterThan':
        try: return float(left or 0) > float(right or 0)
        except Exception: return False
    if op == 'greaterThanOrEqual':
        try: return float(left or 0) >= float(right or 0)
        except Exception: return False
    if op == 'lessThanOrEqual':
        try: return float(left or 0) <= float(right or 0)
        except Exception: return False
    if op == 'lessThan':
        try: return float(left or 0) < float(right or 0)
        except Exception: return False
    return False


def evaluate_condition_label(label_conditions: list, ctx: Context) -> bool:
    """
    XSIAM condition evaluation:
      outer list (label_conditions) = AND — all groups must pass
      inner list (and_group) = OR — any condition in the group passes the group
    This models the XSIAM condition builder where multiple rows in one group are OR'd,
    and multiple groups are AND'd together.
    """
    for and_group in label_conditions:
        if not any(evaluate_single_condition(c, ctx) for c in and_group):
            return False
    return True


# ── Script mocks ──────────────────────────────────────────────────────────────

def _resolve_arg(args: dict, key: str, ctx: Context) -> Any:
    spec = args.get(key, {})
    if isinstance(spec, dict) and 'simple' in spec:
        return ctx.resolve_string(spec['simple'])
    return resolve_value_spec(spec, ctx)


def mock_set_and_handle_empty(args: dict, ctx: Context):
    key    = _resolve_arg(args, 'key', ctx)
    value  = resolve_value_spec(args.get('value'), ctx)
    append = str(_resolve_arg(args, 'append', ctx) or 'false').lower() == 'true'
    if key and value is not None and value != '':
        ctx.set(key, value, append=append)


def mock_add_dbot_score(args: dict, ctx: Context):
    indicator = resolve_value_spec(args.get('indicator'), ctx)
    score     = resolve_value_spec(args.get('score'), ctx)
    vendor    = _resolve_arg(args, 'vendor', ctx) or 'Unknown'
    ind_type  = _resolve_arg(args, 'indicatorType', ctx) or 'Unknown'
    if indicator:
        ctx.set('DBotScore', {
            'Indicator': indicator, 'Score': int(score or 0),
            'Type': ind_type, 'Vendor': vendor,
        })



def mock_set_multiple_values(args: dict, ctx: Context):
    """
    SetMultipleValues: writes multiple keys at once.
    args: keys (csv), values (csv), parent (optional namespace prefix)
    e.g. parent=Analysis keys=Email.verdict,Email.confidence values=malicious,high
    → sets Analysis.Email.verdict=malicious, Analysis.Email.confidence=high
    """
    keys_raw   = _resolve_arg(args, 'keys', ctx) or ''
    values_raw = _resolve_arg(args, 'values', ctx) or ''
    parent     = _resolve_arg(args, 'parent', ctx) or ''
    keys   = [k.strip() for k in keys_raw.split(',') if k.strip()]
    values = [v.strip() for v in values_raw.split(',') if v.strip()]
    prefix = f"{parent}." if parent else ""
    for key, val in zip(keys, values):
        ctx.set(f"{prefix}{key}", val)

SCRIPT_MOCKS = {
    'SetAndHandleEmpty':              mock_set_and_handle_empty,
    'SetMultipleValues':              mock_set_multiple_values,
    'SetField':                       mock_set_and_handle_empty,
    'AddDBotScoreToContext':          mock_add_dbot_score,
    'GetIndicatorDBotScoreFromCache': lambda a, c: None,
}


# ── Execution result ──────────────────────────────────────────────────────────

@dataclass
class ExecutionResult:
    playbook_name: str
    executed_tasks: list[str] = field(default_factory=list)
    branch_taken:   dict      = field(default_factory=dict)
    context_before: dict      = field(default_factory=dict)
    context_after:  dict      = field(default_factory=dict)
    warnings:       list[str] = field(default_factory=list)
    errors:         list[str] = field(default_factory=list)


# ── Simulator ─────────────────────────────────────────────────────────────────

class PlaybookSimulator:
    def __init__(self, playbook_dir: str):
        self.playbook_dir = playbook_dir
        self._cache: dict[str, dict] = {}

    def _load(self, name: str) -> dict:
        if name in self._cache:
            return self._cache[name]
        candidates = [
            os.path.join(self.playbook_dir, name + '.yml'),
            os.path.join(self.playbook_dir, name.replace(' ', '_') + '.yml'),
        ]
        for path in candidates:
            if os.path.exists(path):
                with open(path) as f:
                    d = yaml.safe_load(f)
                self._cache[name] = d
                return d
        raise FileNotFoundError(f"Playbook not found: {name!r}")

    def _prepopulate_inputs(self, pb: dict, ctx: Context):
        """
        Pre-populate inputs.* keys from playbook input definitions.
        In XSIAM, conditions that read 'inputs.Foo' (iscontext=true) resolve
        against the playbook's input namespace, which in turn resolves its
        default expression against the outer context.
        """
        for inp in pb.get('inputs', []):
            key = inp.get('key', '')
            if not key:
                continue
            input_key = f'inputs.{key}'
            # If already injected by test, leave it
            if ctx.get_by_path(input_key) is not None:
                continue
            # Resolve the default value from context
            val_spec = inp.get('value', {})
            value = resolve_value_spec(val_spec, ctx)
            if value is not None:
                ctx.set(input_key, value)

    def run(
        self,
        playbook_name: str,
        context: Context,
        uc_mocks: dict | None = None,
        sub_mocks: dict | None = None,
        max_steps: int = 200,
    ) -> ExecutionResult:

        result = ExecutionResult(
            playbook_name=playbook_name,
            context_before=context.snapshot()
        )
        uc_mocks  = uc_mocks  or {}
        sub_mocks = sub_mocks or {}

        try:
            pb = self._load(playbook_name)
        except FileNotFoundError as e:
            result.errors.append(str(e))
            return result

        self._prepopulate_inputs(pb, context)

        tasks    = pb.get('tasks', {})
        start    = str(pb.get('starttaskid', '0'))
        queue    = [start]
        visited  = set()
        steps    = 0

        while queue and steps < max_steps:
            tid = queue.pop(0)
            if tid in visited:
                continue
            visited.add(tid)
            steps += 1

            task = tasks.get(tid)
            if task is None:
                result.warnings.append(f"Task {tid!r} not found")
                continue

            result.executed_tasks.append(tid)
            task_type = task.get('type', 'regular')
            task_def  = task.get('task', {})
            nexttasks = task.get('nexttasks', {})

            if task_type in ('start', 'title'):
                for targets in nexttasks.values():
                    queue.extend(targets)

            elif task_type == 'condition':
                matched = None
                for entry in task.get('conditions', []):
                    if evaluate_condition_label(entry.get('condition', []), context):
                        matched = entry.get('label')
                        break
                result.branch_taken[tid] = matched if matched is not None else '#default#'
                # YAML bool labels (True/False) need to map to string nexttask keys
                lookup = matched
                if matched is True:  lookup = 'true'
                if matched is False: lookup = 'false'
                targets = nexttasks.get(lookup, nexttasks.get('#default#', []))
                queue.extend(targets)

            elif task_type == 'regular':
                script_name = (task_def.get('scriptName') or
                               task_def.get('script', '').split('|||')[-1])
                script_args = task.get('scriptarguments', {})

                if script_name == 'SOCCommandWrapper':
                    action = resolve_value_spec(script_args.get('action', {}).get('simple'), context)
                    if action in uc_mocks:
                        for k, v in uc_mocks[action].items():
                            context.set(k, v)
                    else:
                        result.warnings.append(f"No UC mock for action={action!r} (task {tid})")
                elif script_name in SCRIPT_MOCKS:
                    SCRIPT_MOCKS[script_name](script_args, context)
                elif script_name:
                    result.warnings.append(f"Unmocked script {script_name!r} at task {tid} — skipped")

                for targets in nexttasks.values():
                    queue.extend(targets)

            elif task_type == 'playbook':
                sub_name = task_def.get('playbookName', '')
                if sub_name in sub_mocks:
                    for k, v in sub_mocks[sub_name].items():
                        context.set(k, v)
                else:
                    sub_result = self.run(sub_name, context, uc_mocks, sub_mocks, max_steps)
                    result.warnings.extend([f"[sub:{sub_name}] {w}" for w in sub_result.warnings])
                    result.errors.extend([f"[sub:{sub_name}] {e}" for e in sub_result.errors])

                for targets in nexttasks.values():
                    queue.extend(targets)

            else:
                result.warnings.append(f"Unknown task type {task_type!r} at task {tid}")
                for targets in nexttasks.values():
                    queue.extend(targets)

        if steps >= max_steps:
            result.errors.append(f"Max steps ({max_steps}) reached — possible loop")

        result.context_after = context.snapshot()
        return result
