# Review checklist

What the automated reviewer checks on every pull request. It sees only the diff and this file. Each item is a question a rule can't answer yet; when a tool starts checking an item, the item is removed from this list. Background: `docs/contributing/engineering-practices.md`.

## Every pull request

- [ ] Does the change do only what the pull request says? Anything extra belongs under *Not built*.
- [ ] Could someone who didn't write it explain each function? Flag clever one-liners, unclear names, and non-obvious choices with no comment saying why.
- [ ] Does a test exercise the changed behaviour, and would it fail without the change?
- [ ] Are the unhappy paths tested: empty input, a missing field, a vendor error, a list that can't be read?
- [ ] Do the fixtures match what the vendor really sends, rather than what the code expects?
- [ ] Is any `${...}` left unresolved in a playbook or list?
- [ ] Does any name, id, URL or address in code, tests, fixtures, the commit message or the pull request point at a real customer or tenant?
- [ ] Is there code nothing calls, or an option nobody asked for, that could be deleted?

## High-risk paths

A person reads every line of these as well; see the high-risk paths in the guide.

- [ ] Does any action that changes something (isolate, revoke, block, retract, close, star, assign) ship in Shadow Mode for every actor?
- [ ] Does a correlation rule write into an issue field the platform owns?
- [ ] Can the close path close an issue when its policy is missing, empty or unreadable?
