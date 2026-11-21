# Self-documenting code

How to write Python in this repo so a reader can tell what each name holds and what each function does from the code itself, without asking the person who wrote it. The framework runs actions on customer systems; code a reviewer has to decode is code they approve on trust.

## Where the rules come from

| Practice | Origin | What we take from it |
|---|---|---|
| Self-documenting code | Steve McConnell, *Code Complete* (2nd ed., 2004), "The Power of Variable Names" and "Self-Documenting Code" | The code is the main documentation. Good names and clear structure carry most of the meaning; comments add what the code can't say |
| Meaningful names, small functions | Robert C. Martin, *Clean Code* (2008), "Meaningful Names", "Functions", "Comments" | Names reveal intent. A function does one thing, at one level of abstraction. Explain yourself in code before reaching for a comment |
| Intention-revealing names | Kent Beck, *Smalltalk Best Practice Patterns* (1997) | Name a function for what it achieves, not how it works |
| Comments for what isn't obvious | John Ousterhout, *A Philosophy of Software Design* (2018) | Interface comments say what a function does and promises, so callers never read its body. Comments record what the code can't: why, units, limits, platform behaviour |
| Refactorings that name things | Martin Fowler, [*Refactoring*](https://martinfowler.com/books/refactoring.html) (2nd ed., 2018) | When you feel the need to comment a block, extract it and let the name say it (Extract Function, Extract Variable, Rename Variable, Replace Magic Literal). A comment that explains confusing code is a smell, not a fix |
| Names sized to their scope | Brian Kernighan and Rob Pike, *The Practice of Programming* (1999), "Style" | Descriptive names for things used widely, short names for things used in a few lines. Be consistent |
| Python conventions | [PEP 8](https://peps.python.org/pep-0008/) naming, [PEP 257](https://peps.python.org/pep-0257/) docstrings, [PEP 484](https://peps.python.org/pep-0484/) type hints, the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html) (docstrings and naming) | The shapes a Python reader already expects |

## The platform's guidelines come first

Pack content runs on XSIAM, and Palo Alto Networks publishes how it should be written: the
[code conventions](https://xsoar.pan.dev/docs/integrations/code-conventions) and the
[linting guide](https://cortex-docs.paloaltonetworks.com/cortex-xsiam-developer-guide/cortex-xsiam-development-guide/testing/linting)
for XSOAR and XSIAM content. When a rule on this page and the platform's guideline disagree,
the guideline wins, unless the table below names the difference and why.

| Platform guideline | What it means here |
|---|---|
| Functions and variables in `snake_case`; commands lowercase with hyphens; constants in `UPPER_SNAKE_CASE` after the imports; no global variables | The same as PEP 8 naming, which ruff checks (N) |
| A command function returns `CommandResults`; `main()` calls `return_results` and `return_error`, and catches the exceptions the functions raise | Command functions stay unit-testable. Some older framework scripts, `SOCCommandWrapper` among them, report from inside their functions; they move to this shape as they are refactored, never in the same pull request as a behaviour change |
| No `sleep()`; retries through `BaseClient` | Already a framework rule |
| No `print`; log with `demisto.debug`, `demisto.info`, `demisto.error`; never log sensitive data | The same, for War Room output and dataset rows too |
| Docstrings document parameters and return values: `Args:` and `Returns:` sections in command functions, `:type:` fields in client classes | Google sections, as the rules below say; `:type:` fields are fine in a client class |
| Every command has a unit test in `<Name>_test.py`, and each test's docstring says Given / When / Then | Pack tests need a docstring in that form; tests of `tools/` don't |
| Content is linted with ruff, mypy, pylint, the XSOAR linter and Bandit (`demisto-sdk pre-commit`). An inline suppression names its rule: `# noqa: E501`, `# type: ignore[<error>]`, never a bare one | This repo runs ruff in the PR gate. Bandit's rules and mypy are planned |

### Where the framework differs on purpose

| Difference | Why |
|---|---|
| Pack scripts have no `import demistomock as demisto` or `from CommonServerPython import *` line | The platform loads both into every script, and the pack is installed from its source as it is. Tests inject the same names instead (`load_script` in `SOCCommandWrapper_test.py`) |

## The rules

| Rule | In practice |
|---|---|
| A name says what a thing holds or does | `isolate_endpoint`, `pending_issue_ids`, `is_shadow_mode`. Functions are verbs, booleans read as yes-or-no questions (`is_`, `has_`, `should_`), collections are plural. Not `data`, `res`, `tmp`, `obj2`, `flag` |
| A name's length fits its scope | `i` in a three-line loop is fine. A module-level name or a function argument is spelled out. No abbreviation a newcomer can't expand, except the domain terms below |
| One name per idea, across the repo | Use the platform's words: *issue* and *case* (not alert and incident in new code), *actor*, *action*, *Shadow Mode*. A second word for the same thing makes a reader wonder whether it's a different thing |
| A function does one thing, and its name says what | If a function needs "and" in its name, or a comment to mark its sections, split it. Each extracted function is named for what it achieves |
| Name the condition, not just the code | `if is_contained and not has_open_blockers:` beats a three-line boolean with a comment above it (Extract Variable) |
| Numbers and strings that mean something have names | `MAX_ISOLATE_RETRIES = 3`, not a bare `3`. Ruff flags magic numbers (PLR2004) |
| Every argument and return value has a type hint | `def close_issue(issue_id: str, reason: str) -> bool:`. A type is documentation the interpreter and the linter can check |
| Every public function, class and module has a docstring | One line saying what it does, in the imperative or as a statement. Add `Args`, `Returns` and `Raises` sections (Google style) only when the names and types don't already say it |
| Comments say why, never what | The code says what. A comment records why a non-obvious choice was made, a unit, a limit, or a platform behaviour a reader couldn't guess. No change history or version notes: that is git's job |
| Platform behaviour is always commented | XSIAM quirks look like mistakes to a reader who doesn't know them: why `execute_command` and not `demisto.executeCommand`, why a field is read from the parent case, why a sleep is not allowed. Say so where the code depends on it |
| Delete code instead of commenting it out | Git keeps it. Commented-out code is a question nobody can answer |

### Domain terms that need no expansion

EDR, IOC, XQL, XDM, SOAR, SIEM, MITRE, TTP, C2, IR, NIST, MTTD, MTTR, PoV, UC (universal command), PS. Anything else is spelled out in a name, or explained in the docstring.

### Names the platform fixes

Script names, command names, argument names and context paths are set by XSIAM and by the packs' contracts (`CamelCase` scripts, `soc-` commands, `SOCFramework.*` keys). Keep them as they are; the PEP 8 naming rules apply to the Python inside.

## Fix it as you go

Old code on `main` doesn't meet these rules yet. It gets there as it is worked on:

- **A function you change leaves with a docstring and type hints.** If any line of a function is added or changed in your pull request, its docstring and type-hint findings must be gone. Untouched functions keep theirs.
- **Renaming a local name, adding a docstring or a type hint is not a behaviour change**, so it can ride along with a fix in the function you're already changing. Restructuring (extracting functions, moving code) is a refactor and goes in its own pull request ([refactoring](refactoring.md)).
- **Don't sweep a whole file** to fix names and docstrings while making an unrelated change. The reviewer can't find your change in it.

## What a tool checks, and what a person checks

| Rule | Checked by |
|---|---|
| Docstrings on public modules, classes and functions (D1) | `ruff check`; for functions you touch, the PR gate (`check_ruff_no_new.py`) |
| Type hints on arguments and return values (ANN001, ANN201) | Same |
| Ambiguous single letters `l`, `O`, `I` (E741), PEP 8 naming (N) | `ruff check`; a changed file may not gain findings |
| Magic numbers (PLR2004), function size and complexity (C901, PLR09xx) | Same |
| Whether a name actually says what it holds | Review ([checklist](https://github.com/Palo-Cortex/secops-framework/blob/main/.github/review-checklist.md)): no linter can tell `pending_ids` from `x` |
| Whether a comment says why rather than what | Review |
| One name per idea | Review |

Pack tests need a docstring in Given / When / Then form, as the platform's guideline asks; type hints stay optional in tests, where pytest fixtures are typed by use. Tests of `tools/` need neither.

## Verify

Run the gate's check against `main` on your branch:

```
python tools/check_ruff_no_new.py
```

**Expected:** `OK    no changed file gained ruff findings; every touched function is documented`. Otherwise it lists each `file:line: rule` to fix.
