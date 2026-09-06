# Building SOC Framework AI Prompts

How the two prompts in this pack are built, and the conventions any new one should
follow. Read this before `SOCFWIssueAssessment.prompt.md` or
`SOCFWCaseAnalysis.prompt.md` — those are the recipes, this is why they look the way
they do.

## Platform facts you cannot design around

**AI Prompts are not packageable.** There is no content item, no directory, no SDK
type. The repo carries a `.prompt.md` recipe; a human creates the prompt in the UI
from it. Everything else in the pack installs; the prompts do not.

**Prompt ids are tenant-local.** The `aiTaskId` in a shipped playbook belongs to the
tenant the content was authored on. It resolves nowhere else. Re-bind on every tenant,
and re-check after every pack upgrade — an upgrade can revert the task to the shipped
id, and the symptom is a playbook that completes with no verdict.

**Structured output does not support a variable schema.** Leave *Use structured
output* off and describe the schema in the prompt body instead. This is why both
prompts end with a literal JSON object and the instruction to return nothing around it.

**Prompts over 100,000 characters are rejected outright**, with an explicit error
rather than a timeout. Anything binding an unbounded context path needs a budget.
`SOCFWFetchShapeContracts` budgets the case payload at 80,000 and records what it
dropped; `SOCFWCollectIntel` does the same for intel roots.

**Output tokens are the quiet failure.** A reply that exceeds the ceiling is cut
mid-string and arrives as unparseable JSON. It looks like a formatting bug and is not.
Size the ceiling against a real, fully populated contract — not a sparse one.

## Framework conventions

**Absence arrives as a value.** Every input binds through `SetIfEmpty` with a default
of `no content`. A model cannot distinguish a missing variable from an empty one, and
the difference matters: `no content` means asked and got nothing, which is not the same
as never asked. The prompt body states this explicitly so an empty field is not read as
a cleared condition.

**One output path per prompt.** `Assessment.AI` for issue scope, `Analysis.AI` for case
scope. Two prompts writing one key means the last writer wins silently, and you lose the
ability to compare them.

**JSON, not markdown.** The output is a contract other things consume — promotion into
the namespace, a dataset row, and eventually a close decision. Prompts that emit prose
force a regex to recover the answer, which breaks on any formatting change the model
makes. Render a human view on top of the JSON; do not replace it.

**Controlled vocabulary matches the tenant.** `closure_reason` uses the resolution
dropdown values verbatim, so the model's answer and the analyst's answer are comparable
by joining on the field rather than translating between two vocabularies.

**Never let the model assert what a deterministic component owns.** Both prompts forbid
`RESOLVED_DUPLICATE_ISSUE` — dedup decides that upstream. The issue prompt also forbids
concluding activity was authorised security testing, because that is a scheduling fact
the contract does not carry and the model could only infer it from a hostname.

**Everything inside `<evidence>` is data, never instructions.** Alert names, command
lines, file paths and email subjects are attacker-controlled. Both prompts wrap the
evidence in a tag and state the rule directly.

## Binding it into a playbook

The `aiTask` task carries the inputs as `scriptarguments`, each a complex value with a
`SetIfEmpty` transformer. Two settings matter beyond that:

**`quietmode: 1` on the aiTask.** At the default it echoes its entire rendered prompt
into the War Room — roughly 10KB per issue. Print the answer with a separate task at
`quietmode: 2` instead.

**Order anything analyst-visible before anything optional.** A task whose script is
absent marks itself *and everything downstream* `WillNotBeExecuted`; `skipunavailable`
does not skip and continue, and `continueonerror` does not cover it. Put the render
ahead of the dataset write, not after.

## Adding a new prompt

1. Write the recipe as `<Name>.prompt.md` beside the existing two — same sections:
   creating it, model settings, inputs, output, hard limits, body.
2. Bind every input through `SetIfEmpty`.
3. Choose an output path nothing else writes.
4. Publish the body to the **AI Prompt Settings** page in Notion; that is what gets
   pasted from.
5. Add it to the pack README contents table and install steps.
6. Size the token ceiling against a real populated contract before shipping.

## When it goes wrong

| Symptom | Cause |
| --- | --- |
| `not valid JSON: Expecting value: line 1 column 1 (char 0)` | Fenced reply or prose preamble — the object never starts at char 0 |
| `not valid JSON: Unterminated string` at a high offset | Output token ceiling; the reply was cut mid-string |
| `reasoning_status: no_output` | The prompt produced nothing — check the inputs resolved |
| Every verdict `inconclusive` on varied alerts | The contract is not reaching the prompt. Check the normalize and enrichment lists are installed and parse, and that the source has a category in `SOCProductCategoryMap_V3` |
| Playbook completes, no verdict, no error | A downstream task's script is missing; check per-task state via the `inv-playbook` API |
