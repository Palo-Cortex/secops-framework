# Refactoring and keeping the framework lean

How to change the framework's structure without changing what it does on a tenant, and how to decide whether a new script, list or setting should exist at all. The refactoring rules follow Martin Fowler, [*Refactoring*](https://martinfowler.com/books/refactoring.html) (2nd edition); the framework runs actions in production SOCs, so a refactor that changes behaviour by accident is an incident, not rework.

## Before you build anything

| Question | Rule |
|---|---|
| Does this already exist? | Search the packs first. Extend an existing script, list or action before adding a new one |
| Which pack does it belong in? | If you can describe what it does without naming a lifecycle (NIST IR, posture), it is framework machinery and goes in `soc-optimization-unified`. Otherwise it goes in the lifecycle pack. Decide now: moving an item between packs later collides on item ids, and the second install is silently discarded |
| Who asked for it? | Every new capability, flag, argument, output or mode names who uses it and the request that needs it. Anything else goes under *Not built* in the pull request |
| Is this the third real case? | Abstract on the third real use, not the first (Fowler's rule of three). A general mechanism with one caller is speculative generality |
| Is the name agreed? | Propose new names, keys, actors and lists before building them. New components use the `SOCFW` prefix and no `_V3` suffix |

## Settings are a cost

| Rule | Why |
|---|---|
| A setting is a decision to defend, not a feature | Every setting each tenant sets differently is a support conversation and a source of drift |
| Ship a correct default; put exceptions in named profiles (`SOCFWConfig command=mode`) | Going live should mean changing a handful of settings, not dozens |
| Read every setting with a code-side default that is the safe value: `policy.get("require_no_blockers", True)` | A missing key that reads as "allowed" turns an upgrade into a silent change of authority. Absent means conservative |
| Anything that can change something on a customer's systems fails closed to Shadow Mode | The one default that must never need configuring |
| Customer values go in `SOCFWTenantConfig` through `SOCFWConfig`, never in a hand-edited pack list | Pack lists are overwritten on install and can't be changed by a script |
| One question, one surface: a new setting doesn't add a second place that answers a question another setting already answers | Two surfaces that both decide whether an action runs can't both be right |

## The refactoring rules

| Rule | In practice |
|---|---|
| **Two hats.** A refactor changes structure and keeps behaviour; a feature or fix changes behaviour. Never both in one pull request | First the restructure, proven unchanged. Then the small behaviour change on top |
| **Make the change easy, then make the easy change** | When a requested change is awkward, first ship a preparatory refactor that makes it simple, on its own |
| **Characterisation test before the first edit** | Capture what the code does today. For configuration code that is an effective-configuration snapshot (for each action and caller: live or shadow, which vendor, which arguments); the refactor must leave it identical |
| **Small steps, each shippable** | One move per commit, each green on its own. If a step needs two sentences to describe, it is two steps. No long-lived refactor branches |
| **Parallel change for anything a tenant holds** | Lists, list shapes, script names and actor names: expand (add the new form; readers accept both), migrate (move writers and docs), contract (remove the old form, as its own change, only when nothing reads it) |
| **Refactor when it makes the next real change cheaper** | Not for tidiness and not ahead of need. Before proposing one, state the change it enables, the steps, the test for each step and what stays untouched |

## Smells to look for

| Smell | What it looks like here | Refactoring |
|---|---|---|
| Duplicated code that drifts apart | Two places pick a vendor by different rules, so a button offers an action the universal command then skips | One resolver; the second place asks the first |
| Shotgun surgery | One customer fact restated in many map entries | One default the entries fall back to |
| Speculative generality | A catalog, ordered list or extra field proposed with no real case | Don't build it until the third real case |
| Dead code | A check or argument nothing reads | Delete it |
| Mixed concerns | Customer values inside shipped rows | Move them to the tenant settings; the shipped row stays blank |
