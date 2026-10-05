# Automatic Chocolatey publishing

**Goal:** Publish the existing `cmtraceopen` Chocolatey package when a stable GitHub release is published. Reuse the existing `release` environment and its `CHOCOLATEY_API_KEY`; change no environment protections or credentials.

The checked-in package preserves the existing 1.5.0 installer behavior with the verified 1.6.2 version/hash update. The workflow renders a temporary copy from the selected release's version and x64 MSI digest, so future stable versions require no package-source edit. It never executes the installer or modifies the GitHub release, assets, or tag.

## Trigger and trust boundary

- Normal trigger: `release: published` only. Drafts, prereleases, non-three-part tags, and other repositories are rejected. Editing a release does not trigger another upload.
- Backfill: `workflow_dispatch` on `main`, restricted to `v1.6.2`, because this release predates the workflow. First run with `publish=false` verifies native Windows packing; the coordinator can then run with `publish=true` through the same jobs. This is a one-time bootstrap, not a manual publishing requirement for future releases.
- Read-only GitHub token, immutable action pins, no publishing secret in preparation. The package job validates release ID (for release events), tag, state, exact product MSI URL, SHA256 digest, size, and downloaded bytes.
- AST validation permits only the existing five installer statements and nine arguments. It rejects later mutations, extra architecture URLs, or changed installer behavior without executing PowerShell package code.
- The publish job uses the existing `release` environment and a same-run artifact download. It has no repository checkout. Only the final `choco push` step receives `CHOCOLATEY_API_KEY`, and it verifies the package hash again before uploading to `https://push.chocolatey.org/`.
- A public lookup checks the exact existing package version. Identical package bytes skip upload; different bytes fail without overwriting. Only HTTP 404 permits a new submission; access/network/server failures stop. No force or overwrite switch is used. ZIP metadata can differ on a repack, so a rerun can stop with a mismatch even when installer content agrees. Resolve that explicitly, never overwrite automatically. A pending/unlisted package not visible through the download endpoint may still make the server reject a duplicate submission.

GitHub suppresses most events created with `GITHUB_TOKEN`. Future release publication must produce a `release.published` event (for example, owner publication of the existing draft); this workflow does not alter release producers or add credentials to bypass that rule. It also expects the MSI to be present when the release is published. [GitHub trigger behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

## Existing access and owner action

Adam confirmed entering the key. Metadata-only verification found `CHOCOLATEY_API_KEY` in `adamgell/cmtraceopen` environment `release`, created and updated `2026-10-05T20:29:57Z`. Existing environment metadata showed no protection rules or deployment branch policy; this change does not add or remove either. Secret presence does not prove the account key's validity or publishing authority. The public package lists `adamgell` and `Kipjr` as maintainers. The inherited nuspec owner field remains unchanged.

The key stays in GitHub's existing environment secret; no agent reads, generates, rotates, or copies its value. Chocolatey documents an account publishing credential, not a guaranteed per-package scope. [Chocolatey API keys](https://docs.chocolatey.org/en-us/create/commands/api-key/), [Chocolatey push](https://docs.chocolatey.org/en-us/create/commands/push/).

## Validation and rollout

- [x] Package validation and future-version rendering tests, including malformed/mismatched tags and the two independent-review regressions.
- [x] Existing-version guard tests for absent, identical, different, denied, rate-limited, server-error, and network-error responses.
- [x] `actionlint .github/workflows/chocolatey-publish.yml` and validation against the downloaded public 1.6.2 MSI plus release JSON.
- [ ] Fresh independent internal review, signed draft PR, coordinator merge.
- [ ] Coordinator-authorized Windows backfill with `publish=false`; confirm `choco pack` and artifact output without executing the MSI.
- [ ] Coordinator-authorized backfill with `publish=true`; confirm submission, moderation, and public availability separately.

Local commands: `pwsh -NoProfile -File scripts/chocolatey-package.test.ps1` and `pwsh -NoProfile -File scripts/chocolatey-publish.test.ps1`. Windows installation/upgrade/uninstallation and Chocolatey moderation remain unverified. A successful push is not public approval.

## Existing prepared artifact

The separately reviewed `cmtraceopen.1.6.2.nupkg`, with its icon URL corrected to return PNG bytes, is 4,570 bytes, SHA256 `0b1d3f007522ea503675c562978668b765426ac8a45162b6c2c32e0dae166f95`. It replaces the existing Library file without creating a duplicate. Native `choco pack` can change ZIP/core metadata and its package hash; the MSI digest remains `12166bd88a2e4f4c2faa216dcce950e1b4eedc33f64aed48e171d11e63bc32d2`. This workflow does not replace that Library artifact.
