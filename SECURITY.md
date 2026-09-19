# Security

## Tenant deploy form — removed

This repository previously shipped a browser-based tenant deploy form
(`docs/deploy/index.html`) and a workflow that consumed it
(`.github/workflows/deploy-to-tenant.yml`). Customer tenant credentials were
entered in the browser, RSA-OAEP + AES-GCM encrypted against an embedded public
key, and decrypted inside a workflow run using the `PAYLOAD_PRIVATE_KEY` secret.

That mechanism was a leftover from an earlier testing tenant and is removed. The
form, the workflow, and the `Integrity Check` workflow that SHA-pinned them are
all deleted. The trust boundary this file used to describe no longer exists,
because tenant credentials no longer enter this repository's CI by that path at
all.

Packs reach a tenant through the SOC Framework Pack Manager
(`!SOCFWPackManager action=apply`), which reads release assets and runs with
credentials held on the tenant, not in this repo.

### Leftovers to clear in repository settings

Removing the code does not remove the secrets it used. These are now unused and
should be deleted through **Settings**, since an unused private key is a
liability rather than a dormant convenience:

- secret `PAYLOAD_PRIVATE_KEY`
- variable `DEPLOY_FORM_SHA256`
- variable `DEPLOY_WORKFLOW_SHA256`

## Still in force

- **Signed commits required on `main`.** Commits must carry a valid SSH or GPG
  signature.
- **GitHub Actions pinned to commit SHAs**, not mutable tags, across all
  workflows.
- **`Scan — no customer data`** runs on every PR and blocks customer
  identifiers from entering the repository.

## Reporting a vulnerability

Raise an issue in this repository, or contact the maintainers directly for
anything that should not be disclosed publicly.
