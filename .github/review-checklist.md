# Review checklist

What the author checks before opening a pull request. Each item is a question a rule can't answer yet; when a tool starts checking an item, the item is removed from this list. Background: `docs/contributing/engineering-practices.md`.

## Every pull request

- [ ] Does the change do only what the pull request says? Anything extra belongs under *Not built*.
- [ ] Could someone who didn't write it explain each function? Flag clever one-liners, unclear names, and non-obvious choices with no comment saying why.
- [ ] Can a reader tell what each name holds without reading the code that fills it? `data`, `res`, `tmp` and `x` outside a few lines fail this.
- [ ] Does a test exercise the changed behaviour, and would it fail without the change?
- [ ] Are the unhappy paths tested: empty input, a missing field, a vendor error, a list that can't be read?
- [ ] Do the fixtures match what the vendor really sends, rather than what the code expects?
- [ ] Is any `${...}` left unresolved in a playbook or list?
- [ ] Does any name, id, URL or address in code, tests, fixtures, the commit message or the pull request point at a real customer or tenant?
- [ ] Is there code nothing calls, or an option nobody asked for, that could be deleted?

## Security

What a tool can't see. Background: the [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/).

- [ ] Is every value from an alert, an issue field or a vendor treated as untrusted? XQL, a command argument, a URL or a file path built from one is checked or escaped first.
- [ ] Can a key, token or password reach the War Room, a dataset row, a log line or an error message?
- [ ] Does each integration or API key get only the permissions the action needs?
- [ ] When a check can't be completed (a list unreadable, a lookup timed out), does the code stop or refuse, rather than carry on as if it passed?
- [ ] Does a workflow that runs with a write token act only for trusted people, and only on code from `main`?

## High-risk paths

A person reads every line of these as well; see the high-risk paths in the guide.

- [ ] Does any action that changes something (isolate, revoke, block, retract, close, star, assign) ship in Shadow Mode for every actor?
- [ ] Does a correlation rule write into an issue field the platform owns?
- [ ] Can the close path close an issue when its policy is missing, empty or unreadable?
