# Writing documentation

How pages on this site and the pack READMEs are written, so a reader who has never seen the framework can find a capability, turn it on and check it works, from the page alone.

## The practices, and where they come from

| Practice | Source | What we take from it |
|---|---|---|
| [Diátaxis](https://diataxis.fr/) | Daniele Procida | Four kinds of page: tutorial, how-to, reference, explanation. One kind per page, never mixed |
| Minimalism | John Carroll, *The Nurnberg Funnel* | Start from real tasks, cut the preamble, help people recover from errors |
| Every Page Is Page One | Mark Baker | Readers arrive by search. Every page says what it covers in its first sentence and stands on its own |
| [Docs as Code](https://www.writethedocs.org/guide/docs-as-code/) | Write the Docs | Docs live in the repo, go through pull requests and gates, and change with the code they describe |
| Information Mapping | Robert Horn | Labelled blocks in the same order on every page of a kind; a table for anything with two or more attributes |
| Scanning and progressive disclosure | Nielsen Norman Group | Answer first, one idea per block, descriptive headings, detail behind a toggle |
| [Page structure](https://developers.google.com/style) | Google developer documentation style guide | One-sentence lead, prerequisites before steps, numbered steps with one action each, the expected result after the steps, commands you can copy |
| Organise by task | GOV.UK content design | Sections are named for what the reader is doing, not for who they are |
| Refactoring discipline | Martin Fowler | Small changes; a wrong page is corrected in place, never annotated with its history. Git is the changelog |

## Page shapes

| Kind of page | Blocks, in this order |
|---|---|
| Capability | One sentence on what it does and the outcome · **Where the switch lives** (Where, Key, Shipped default) · **Turn it on** (numbered steps) · **Verify** (one query or War Room check, then **Expected:**) · **What it feeds** · a footer naming the pack version it was checked against |
| Install | One-sentence lead · **Before you start** (a checklist) · numbered steps · a verify step with **Expected:** · three links to what comes next |
| Support | The symptom, in the lead · where to look, in order · a table of causes seen and the fix for each |

Anything longer than its template goes behind a `details` toggle, not into a longer page.

## Writing rules

- Every name on a page (list, key, command, dataset, field, script, dashboard) is read from the file that defines it. A value you couldn't find is written `UNVERIFIED`, never guessed.
- Defaults, list keys and version numbers come from the generated pages or are quoted from the source file, never typed from memory.
- No figure without a source. "Read it from the widget" beats a typical range.
- Name playbook tasks by their name, not their number; numbers change on re-export.
- XQL that starts with `config timeframe` continues on the next line with `| dataset =`.
- Never imply XSIAM lacks something it does natively. The framework adds to the platform.
- Pages say what the reader is doing, not their job title.
- No customer or tenant names anywhere, including command examples and API URLs: write `<tenant>`.
- No change history in a page. A correction replaces the wrong text.
- Prompt bodies and their input bindings never go in this repo. `check_private_content.py` fails the gate if they do.

## Where things live

| Content | Source of truth |
|---|---|
| A pack's capabilities | Its README (between the `capabilities` markers) and `docs/capabilities.yml` |
| List defaults | Each list's `_data.json`, rendered on the pack's overview page |
| The tools reference | Each tool's docstring, rendered into [Tools reference](tools.md) |
| The site map | `docs/nav.yml`. Never edit `mkdocs.yml`'s `nav:` by hand |

Pages carrying a generated banner are changed by editing what they are generated from.

## Ship a docs change

1. Regenerate and build:
   ```
   make docs
   ```
2. Check nothing generated is stale:
   ```
   make docs-check
   ```
3. Open a pull request with `[skip release]` in the merge subject.

**Expected:** `make docs` finishes with no warnings (the build runs `--strict`, so a dead link or a page missing from `nav.yml` fails it), and `make docs-check` reports no drift.
