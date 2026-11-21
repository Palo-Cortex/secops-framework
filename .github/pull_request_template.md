## What
<!-- One sentence: what changes and why. -->

## Evidence
<!-- Gate output, test output, and the tenant run. For a fix or a change in behaviour: the test failing on main, then passing here. -->

## Not built
<!-- Ideas you had along the way and left out. "None" if there were none. -->

## Checklist
- [ ] One concern, and only what was asked.
- [ ] A fix or a change in behaviour has a test that fails on `main` and passes here.
- [ ] `ruff check` on the changed files adds no findings.
- [ ] Test data uses reserved domains and IP ranges only. No customer or tenant names, case or issue ids, keys or collector URLs.
- [ ] Touches a high-risk path (see `docs/contributing/engineering-practices.md`): a person has read every line. <!-- who -->
