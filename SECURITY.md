# Security model: tenant deploy form

## Threat model

The form at `docs/deploy/index.html` and the workflow at
`.github/workflows/deploy-to-tenant.yml` constitute a trust boundary. Customer
tenant credentials enter via the form, get RSA-OAEP + AES-GCM encrypted in the
browser against the embedded public key, and are decrypted only inside a
workflow run using `PAYLOAD_PRIVATE_KEY`.

The realistic compromise scenarios for this single-maintainer repo:

1. Pushed code on `main` is altered (compromised GitHub account, compromised laptop,
   or sophisticated supply-chain attack against tooling).
2. The `PAYLOAD_PRIVATE_KEY` secret is exfiltrated via a modified workflow.

Mitigations layered against these:

- **Hash pinning via `Integrity Check` workflow.** Any change to
  `docs/deploy/index.html` or `deploy-to-tenant.yml` fails CI unless the
  corresponding repository variable (`DEPLOY_FORM_SHA256`,
  `DEPLOY_WORKFLOW_SHA256`) is updated through the GitHub Settings UI. The
  Settings UI is a separate access path from `git push`. For a solo maintainer
  this is detection rather than prevention: the check fails after the push,
  raising a visible red status and a failure notification, but the push has
  already landed on `main`. The maintainer must push a fix or revert.
- **Signed commits required on `main`.** Commits must carry a valid SSH or GPG
  signature. Hardware-backed signing keys (Touch ID or YubiKey) cannot be
  exercised by remote attackers or laptop malware without physical presence.
- **Browser-side payload encryption.** Even with full repo read access, an
  attacker cannot decrypt past dispatched payloads. Decryption requires
  `PAYLOAD_PRIVATE_KEY`, which is only readable inside a workflow run.
- **Replay window.** Encrypted payloads carry a nonce and ISO8601 timestamp; the
  workflow rejects payloads older than 5 minutes.

## Keypair rotation procedure

Rotate quarterly, or immediately on suspected compromise.

1. Generate new keypair outside the repo:
   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /tmp/deploy_private.pem
   openssl rsa -in /tmp/deploy_private.pem -pubout -out /tmp/deploy_public.pem
   ```
2. Update the `PUBLIC_KEY_PEM` block in `docs/deploy/index.html` to the new
   public key.
3. Compute new form hash:
   ```bash
   sha256sum docs/deploy/index.html
   ```
4. Commit the HTML change on a branch. Push. Integrity check will fail on
   `DEPLOY_FORM_SHA256` mismatch — this is expected. Note the new hash from the
   failed run's logs.
5. Settings → Variables → update `DEPLOY_FORM_SHA256` to the new hash. CI
   re-runs and passes.
6. Upload new private key:
   ```bash
   gh secret set PAYLOAD_PRIVATE_KEY --repo Palo-Cortex/secops-framework < /tmp/deploy_private.pem
   ```
7. Destroy local copy:
   ```bash
   shred -u /tmp/deploy_private.pem 2>/dev/null || rm -f /tmp/deploy_private.pem
   rm -f /tmp/deploy_public.pem
   ```
8. Merge into `main`.

After rotation, payloads that were dispatched against the old public key but not
yet processed will fail to decrypt. In practice this is a non-issue because
workflow queue depth is near-zero.

## Audit cadence

Quarterly, review the GitHub organization audit log (Settings → Security log at
the `Palo-Cortex` org level) for:

- Unexpected pushes to `main`.
- Secret access events on `PAYLOAD_PRIVATE_KEY`.
- Variable update events on `DEPLOY_FORM_SHA256` / `DEPLOY_WORKFLOW_SHA256`.
- New CODEOWNERS or branch protection rule changes.
- Failed `Integrity Check` runs (these are the canaries for unauthorized
  changes to the trust-boundary files).

## Future state

When a second technical contributor joins the team, enable enforced
`CODEOWNERS` review on `docs/deploy/index.html` and `.github/workflows/**` and
add `Require a pull request before merging` with `Require status checks to
pass` selecting `Integrity Check / verify`. This upgrades the trust-boundary
files from detection-only to prevention by requiring a second reviewer and
blocking merges until the integrity check passes.
