# Read the result surfaces before building a diagnostic

**11–12 Sep 2026 · ~3 hours lost · AI Analysis JOB returning no verdict**

## The cause, for the record

`SOCFWCaseAnalysis` had **max output tokens at 8192**. A case `story` spanning
multiple hosts does not fit, and the model returned an **empty completion** rather
than truncating. Raised to 65536 and both cases produced verdicts immediately —
including the 73,409-byte payload that three separate theories had blamed on size.

Everything else concluded on the way there was wrong.

## The surfaces, in the order they should be read

The framework writes to four places. The least informative one was read first, and
three hours went into reconstructing what the other three already held.

**1. The JOB War Room — the aiTask entry.** The authoritative surface, and the one
never opened. It carries the full rendered prompt *and the model's response*, so it
answers "what did the model get, and what did it say" in a single read. It also
carries XQL cost, per-task arguments, and payload size at each stage.

JOB investigations are not returned by `incidents/search`. Get the id from the job:

```
POST /xsoar/public/v1/jobs/search        {"page":0,"size":30}
  -> job["currentIncidentId"]            e.g. job-8ca53d4f8da3453293207ed2cc82f3ce
POST /xsoar/public/v1/investigation/<currentIncidentId>   {"pageSize":250}
```

Filter entries on `entryTask.taskName`. The aiTask entry begins `AI Task Name:`.

**2. The execution dataset** — `reasoning_status`, `ai_error`, `prompt_input_bytes`,
`story_steps`, plus run-level counters.

> **The dataset under-reports success.** Runs that produced a real verdict were
> absent from `xsiam_socfw_ir_execution_raw`, or landed as `no_output` while the
> War Room held full reasoning. Read alone it looks like nothing ever works. It is
> a starting point, never a conclusion, until that is fixed.

**3. Case context** — one call, and it exposes a real bug on the way past:

```
POST /xsoar/public/v1/investigation/INCIDENT-<case_id>/context
     {"query": "${SOCFramework}"}
```

`Analysis.AI` accumulates as an **array of JSON strings, one element per run**.
`setParentIncidentContext` appends at a leaf path rather than overwriting, so
anything reading `Analysis.AI.<field>` resolves element 0 — the oldest.

**4. The War Room verdict entry — last.** It is a rendering, not a result.
"model returned nothing" is a rendering of an empty object and says nothing about why.

## Wrong conclusions, and the rule each one earns

**"The AI gateway is down tenant-wide."** Hand-invoking prompts from the API gave
`AI Gateway ... 400 Bad Request`, including on Palo Alto's own `system: True`
prompts, and a support case was drafted. The JOB's own invocation never produced a
400 — an aiTask invoked as a plain command is malformed, and the 400 was self-inflicted.

> **A test is not evidence until the test itself is validated.** A control proved
> the command *dispatch* was real; that was mistaken for proving the *request* was
> well-formed.

**"The sibling fetch window is 2 hours."** Derived from a local experiment.
`CaseWindowHours = 72`, one config read away.

> **Read the config before inferring it from behaviour.**

**"It's payload size."** 73,409 bytes against an 80,000 budget looked obvious, so
`max_payload_chars` was changed to 5000 and shipped — while a 7KB case was already
failing identically in data already on screen.

> **Do not act on a theory before testing it.** Reverted, no information gained.

**"It's quota."** Compute units read 0% and LLM consumption is informational only.
Then a 30-day consumption chart was argued from, with no baseline for a successful run.

> **A number you cannot calibrate is not evidence.**

## Two engineering rules from the same night

**A diagnostic must never be able to suppress the thing it reports on.** An
`AttributeError` in `recent_ai_error` sat outside its `try`, so failing to read the
error killed the entire verdict entry. The case silently stopped being reported at
all — strictly worse than the ambiguity the diagnostic was added to remove.

**Match markers narrowly.** `Error from Scripts` matched any script failure in the
investigation and reported an unrelated stale traceback as the model's error.

## Payload composition, measured

From the JOB War Room, case 49056:

```
Build case payloads       5,866 bytes   (12 shapes)
Attach shape contracts   73,409 bytes
```

**Per-shape contracts are ~92% of the payload**, roughly 5.6KB each. If trimming is
ever needed, trim `CONTRACT_KEEP` / the `Intel` roots — dropping shapes discards
whole techniques to save bytes that are not where the bytes are.

## Still open

- Successful runs do not reach the execution dataset; likely the `Analysis.AI`
  array accumulation above. Blocks metrics and the watermark.
- `prompt_output_bytes` reads `2` on runs that rendered a verdict, so the
  watermark's `analyses` never increments and `CaseMaxAnalyses: 2` never caps.
- Sibling annotation is detected (`sibling_groups: 4`) but does not reach the
  verdict report. Cause unknown; the window explanation was wrong.
- `shape_key` is null for any source whose alert names do not use the endpoint
  `" | "` convention — observed on Abnormal email and PANW NGFW.
- Verdict instability: 49057 returned SUSPICIOUS then MALICIOUS on identical
  evidence at temperature 0.
