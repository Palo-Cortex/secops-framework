---
title: "A job ran but produced no verdict"
---

# A job ran but produced no verdict

The case analysis job finished, the case shows no verdict or a "model returned nothing" entry, and nothing errored. Read the four surfaces in the order below before changing anything; the first one usually answers it.

## Where to look, in order

**1. The job's War Room, at the aiTask entry.** This is the authoritative surface. It carries the full rendered prompt and the model's response, so it answers "what did the model get, and what did it say" in one read, plus the XQL cost, the per-task arguments and the payload size at each stage.

Job investigations are not returned by `incidents/search`. Get the id from the job, then read the investigation:

```
POST /xsoar/public/v1/jobs/search          {"page": 0, "size": 30}
  -> job["currentIncidentId"]
POST /xsoar/public/v1/investigation/<currentIncidentId>   {"pageSize": 250}
```

Filter entries on `entryTask.taskName`; the aiTask entry begins `AI Task Name:`.

**2. The execution dataset.** `reasoning_status`, `ai_error`, `prompt_input_bytes`, `story_steps`, and the run-level counters.

```
config timeframe = 24h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "ai_reasoning"
| fields _time, incident_id, reasoning_status, ai_error, prompt_input_bytes, story_steps
| sort desc _time
```

A run that rendered a verdict in the War Room but has no row here, or a `no_output` row, is a recording gap, not a model failure. Treat the dataset as the place to start, and the War Room as the place to conclude.

**3. The case context.** One call:

```
POST /xsoar/public/v1/investigation/INCIDENT-<case_id>/context   {"query": "${SOCFramework}"}
```

`Analysis.AI` accumulates one element per run, because `setParentIncidentContext` appends at a leaf path rather than overwriting. Anything that reads `Analysis.AI.<field>` resolves element 0, the oldest run.

**4. The verdict entry on the case, last.** It is a rendering, not a result. "Model returned nothing" is how an empty object renders and says nothing about why it was empty.

## Causes seen, and the fix

| What the War Room shows | Cause | Fix |
|---|---|---|
| The prompt rendered in full; the response is an empty completion, not a truncated one | The prompt's maximum output tokens is below what a long case `story` needs. The model returns nothing rather than cutting off. | Set the prompt's max output tokens and timeout to the values on its master page in the AI Prompt Settings (the recipe shipped in the pack mirrors them). See [Install NIST IR AI](../evaluate/install-nist-ir-ai.md). |
| `AI Gateway ... 400 Bad Request` only when the prompt is invoked by hand from the API | An aiTask invoked as a plain command is malformed. The job's own invocation is fine. | Nothing to fix on the tenant. Test prompts from the job or from the AI Prompts page, not from a raw command. |
| A stale traceback reported as the model's error | A diagnostic that matched any script failure in the investigation, not the aiTask's. | Check the entry's task name against the aiTask before reading its error as the model's. |

## Before you change a setting

- Read the configuration before inferring it from behaviour: windows, thresholds and batch sizes are one `!SOCFWConfig command=status` away.
- A test is not evidence until the test itself is validated: prove the request is well-formed before concluding the gateway is down.
- A number you cannot calibrate is not evidence: a consumption chart with no baseline for a successful run tells you nothing.
