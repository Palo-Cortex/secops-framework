"""
test_playbooks.py
─────────────────
Test runner for SOC Framework playbooks.

Usage:
    python3 tools/test_playbooks.py [--category email|endpoint|identity|all]
                                    [--suite unit|e2e|all]
                                    [--playbook SOC_Email_Signal_Characterization_V3]
                                    [--pb-dir Packs/soc-framework-nist-ir/Playbooks]
                                    [--fixtures tools/fixtures]
                                    [--verbose]

Exit code 0 = all pass. Exit code 1 = failures present.
"""

from __future__ import annotations
import argparse, json, os, sys, textwrap, time
from dataclasses import dataclass, field
from typing import Any
from playbook_simulator import PlaybookSimulator, Context, ExecutionResult


# ──────────────────────────────────────────────────────────────────────────────
# Test case schema
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Assertion:
    """A single assertion on the output context or execution path."""
    type: str           # context_key_equals | context_key_exists | context_key_absent
    # branch_taken | task_executed | task_not_executed
    target: str         # key name, task id, etc.
    expected: Any = None
    description: str = ''


@dataclass
class TestCase:
    name: str
    playbook: str
    category: str                       # email | endpoint | identity
    suite: str                          # unit | e2e
    context_inputs: dict = field(default_factory=dict)
    uc_mocks: dict       = field(default_factory=dict)   # action → {key: val}
    sub_mocks: dict      = field(default_factory=dict)   # pb_name → {key: val}
    assertions: list[Assertion] = field(default_factory=list)
    tags: list[str]      = field(default_factory=list)   # happy_path | non_happy | edge_case


@dataclass
class TestResult:
    test_case: TestCase
    passed: bool
    failures: list[str]
    warnings: list[str]
    errors: list[str]
    duration_ms: float
    execution: ExecutionResult | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Assertion evaluator
# ──────────────────────────────────────────────────────────────────────────────

def evaluate_assertions(tc: TestCase, exec_result: ExecutionResult) -> list[str]:
    failures = []
    ctx = exec_result.context_after

    for a in tc.assertions:
        if a.type == 'context_key_equals':
            actual = ctx.get(a.target)
            # Normalize bool vs string: playbooks write "true"/"false" as strings
            def _normalize(v):
                if isinstance(v, bool): return v
                if isinstance(v, str) and v.lower() == 'true': return True
                if isinstance(v, str) and v.lower() == 'false': return False
                return v
            if _normalize(actual) != _normalize(a.expected):
                failures.append(
                    f"[{a.target}] expected={a.expected!r} actual={actual!r}"
                    + (f" — {a.description}" if a.description else '')
                )
        elif a.type == 'context_key_exists':
            if a.target not in ctx:
                failures.append(
                    f"[{a.target}] expected to exist but was absent"
                    + (f" — {a.description}" if a.description else '')
                )
        elif a.type == 'context_key_absent':
            if a.target in ctx:
                failures.append(
                    f"[{a.target}] expected absent but was {ctx[a.target]!r}"
                    + (f" — {a.description}" if a.description else '')
                )
        elif a.type == 'context_key_not_equals':
            actual = ctx.get(a.target)
            if actual == a.expected:
                failures.append(
                    f"[{a.target}] expected != {a.expected!r} but got same value"
                    + (f" — {a.description}" if a.description else '')
                )
        elif a.type == 'branch_taken':
            # target is task id, expected is label string
            actual = exec_result.branch_taken.get(a.target)
            if actual != a.expected:
                failures.append(
                    f"task {a.target} branch: expected={a.expected!r} actual={actual!r}"
                    + (f" — {a.description}" if a.description else '')
                )
        elif a.type == 'task_executed':
            if a.target not in exec_result.executed_tasks:
                failures.append(f"task {a.target} expected to execute but did not")
        elif a.type == 'task_not_executed':
            if a.target in exec_result.executed_tasks:
                failures.append(f"task {a.target} expected NOT to execute but did")
        else:
            failures.append(f"Unknown assertion type: {a.type!r}")

    return failures


# ──────────────────────────────────────────────────────────────────────────────
# Test runner
# ──────────────────────────────────────────────────────────────────────────────

class TestRunner:
    def __init__(self, pb_dir: str, verbose: bool = False):
        self.simulator = PlaybookSimulator(pb_dir)
        self.verbose = verbose

    def run_test(self, tc: TestCase) -> TestResult:
        ctx = Context(tc.context_inputs)
        t0 = time.monotonic()
        exec_result = self.simulator.run(
            tc.playbook, ctx,
            uc_mocks=tc.uc_mocks,
            sub_mocks=tc.sub_mocks,
        )
        duration_ms = (time.monotonic() - t0) * 1000

        failures = evaluate_assertions(tc, exec_result)
        if exec_result.errors:
            failures.extend([f"[SIM ERROR] {e}" for e in exec_result.errors])

        return TestResult(
            test_case=tc,
            passed=len(failures) == 0,
            failures=failures,
            warnings=exec_result.warnings,
            errors=exec_result.errors,
            duration_ms=duration_ms,
            execution=exec_result,
        )

    def run_suite(self, test_cases: list[TestCase]) -> list[TestResult]:
        return [self.run_test(tc) for tc in test_cases]


# ──────────────────────────────────────────────────────────────────────────────
# Reporter
# ──────────────────────────────────────────────────────────────────────────────

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
WARN = "\033[33m⚠\033[0m"

def report(results: list[TestResult], verbose: bool = False) -> bool:
    """Print report, return True if all passed."""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    # Group by category + suite
    from itertools import groupby
    grouped: dict[tuple, list[TestResult]] = {}
    for r in results:
        key = (r.test_case.category, r.test_case.suite)
        grouped.setdefault(key, []).append(r)

    print()
    print("═" * 70)
    print("  SOC Framework Playbook Test Results")
    print("═" * 70)

    for (category, suite), group in sorted(grouped.items()):
        group_pass = sum(1 for r in group if r.passed)
        print(f"\n  [{category.upper()} / {suite}]  {group_pass}/{len(group)} passed")
        print("  " + "─" * 60)

        for r in group:
            icon = PASS if r.passed else FAIL
            tag_str = ' '.join(f"[{t}]" for t in r.test_case.tags)
            print(f"  {icon}  {r.test_case.name:<50} {r.duration_ms:5.1f}ms  {tag_str}")

            if not r.passed:
                for f in r.failures:
                    print(f"       {FAIL} {f}")

            if verbose and r.warnings:
                for w in r.warnings:
                    print(f"       {WARN} {w}")

            if verbose and r.passed:
                ctx = r.execution.context_after if r.execution else {}
                relevant = {k: v for k, v in ctx.items()
                            if any(k.startswith(p) for p in
                                   ('Analysis.', 'Containment.', 'Eradication.',
                                    'Recovery.', 'Email.', 'DBotScore'))}
                if relevant:
                    print(f"       Context: {json.dumps(relevant, default=str)}")

    print()
    print("═" * 70)
    status = "\033[32mALL PASS\033[0m" if failed == 0 else f"\033[31m{failed} FAILED\033[0m"
    print(f"  {passed}/{total} passed  —  {status}")
    print("═" * 70)
    print()
    return failed == 0


# ──────────────────────────────────────────────────────────────────────────────
# Fixture loader
# ──────────────────────────────────────────────────────────────────────────────

def _assertion_from_dict(d: dict) -> Assertion:
    return Assertion(
        type=d['type'],
        target=d['target'],
        expected=d.get('expected'),
        description=d.get('description', ''),
    )


def load_fixtures(fixture_path: str) -> list[TestCase]:
    with open(fixture_path) as f:
        raw = json.load(f)
    # Support both flat list [ {...}, ... ] and scenario-dict { "scenarios": [...] }
    if isinstance(raw, dict):
        raw = raw.get('scenarios', [])
    cases = []
    for tc in raw:
        # Skip smoke-test scenarios that don't define a playbook to simulate
        if 'playbook' not in tc:
            continue
        cases.append(TestCase(
            name=tc['name'],
            playbook=tc['playbook'],
            category=tc.get('category', 'unknown'),
            suite=tc.get('suite', 'unit'),
            context_inputs=tc.get('context_inputs', {}),
            uc_mocks=tc.get('uc_mocks', {}),
            sub_mocks=tc.get('sub_mocks', {}),
            assertions=[_assertion_from_dict(a) for a in tc.get('assertions', [])],
            tags=tc.get('tags', []),
        ))
    return cases


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='SOC Framework Playbook Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 tools/test_playbooks.py --category email --suite unit
              python3 tools/test_playbooks.py --category email --suite e2e --verbose
              python3 tools/test_playbooks.py --category all --suite all
              python3 tools/test_playbooks.py --playbook SOC_Email_Signal_Characterization_V3
        """)
    )
    parser.add_argument('--category',  default='all',
                        choices=['email','endpoint','identity','foundation','all'])
    parser.add_argument('--suite',     default='all',
                        choices=['unit','e2e','all'])
    parser.add_argument('--playbook',  default=None,
                        help='Run only tests for this specific playbook')
    parser.add_argument('--pb-dir',    default='Packs/soc-framework-nist-ir/Playbooks',
                        help='Path to playbooks directory')
    parser.add_argument('--fixtures',  default='tools/fixtures',
                        help='Path to fixtures directory')
    parser.add_argument('--verbose',   action='store_true',
                        help='Show warnings and context after each test')

    args = parser.parse_args()

    # Discover fixture files
    fixture_dir = args.fixtures
    if not os.path.isdir(fixture_dir):
        print(f"Fixtures directory not found: {fixture_dir}")
        sys.exit(1)

    all_cases: list[TestCase] = []
    for fname in sorted(os.listdir(fixture_dir)):
        if not fname.endswith('.json'):
            continue
        # filename pattern: {category}_{suite}.json  e.g. email_unit.json
        try:
            cat, suite_name = fname.replace('.json', '').rsplit('_', 1)
        except ValueError:
            cat, suite_name = fname.replace('.json', ''), 'unit'

        cases = load_fixtures(os.path.join(fixture_dir, fname))
        # Tag with category/suite from filename if not set in fixture
        for c in cases:
            if c.category == 'unknown': c.category = cat
            if c.suite == 'unit' and suite_name == 'e2e': c.suite = 'e2e'
        all_cases.extend(cases)

    # Filter
    filtered = all_cases
    if args.category == 'all':
        filtered = [c for c in filtered if c.category != 'foundation']
    else:
        filtered = [c for c in filtered if c.category == args.category]
    if args.suite != 'all':
        filtered = [c for c in filtered if c.suite == args.suite]
    if args.playbook:
        filtered = [c for c in filtered if c.playbook == args.playbook]

    if not filtered:
        print(f"No test cases matched filters "
              f"(category={args.category}, suite={args.suite}, playbook={args.playbook})")
        sys.exit(0)

    print(f"\nRunning {len(filtered)} test(s) from {args.pb_dir}")

    runner = TestRunner(args.pb_dir, verbose=args.verbose)
    results = runner.run_suite(filtered)
    all_passed = report(results, verbose=args.verbose)
    sys.exit(0 if all_passed else 1)


if __name__ == '__main__':
    main()
