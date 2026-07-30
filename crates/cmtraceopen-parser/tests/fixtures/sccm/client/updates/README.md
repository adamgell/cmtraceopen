# Synthetic SCCM client software-update corpus

This directory is the issue #323 preparation corpus for the client-side
software-update workflow. It contains synthetic evidence contracts only. It
does not implement an update reducer, native source discovery, server SUP
health analysis, or cross-side correlation.

Every scenario contains:

- `manifest.json`: additive SCCM proposal metadata for every expected physical
  source and coverage-only source;
- `evidence/`: only the bounded files referenced by captured/capped manifest
  entries; and
- `expected.json`: proposed behavior labels for the future #318/#319-backed
  reducer.

`contractState: proposedPending318` means the expected-output field names are
review labels rather than a speculative public API. The future reducer must be
independently callable and consume normalized update evidence directly. It may
not require policy, deployment, health, correlation, or server reducer output.

## Synthetic-data boundary

All evidence is generated for this repository. Allowed identity material is
limited to `LAB-CLIENT-01`, site code `LAB`, RFC-style test UUIDs, opaque
`CI-UPDATE-*`/`CONTENT-UPDATE-*`/`JOB-UPDATE-*` labels, `safe:` correlation
handles, and `SYNTHETIC://` provenance. No customer hostname, path, user, SID,
tenant, token, certificate, serial, deployment name, or copied production log
text is permitted.

Complete `ccmLog` evidence uses the existing CCM grammar. The two
`rotation-boundary` fragments and the exact 128-byte `capped` prefix are
deliberately incomplete and cannot produce a key, phase, or terminal result.
The `supplemental-conflict` CBS file remains a separately typed supplemental
source; it is not converted into SCCM/CCM grammar.

## Coverage and confidence boundary

The matrix explicitly exercises `captured`, `absent`, `accessDenied`, `capped`,
`skipped`, `unsupported`, `parseFailed`, and incomplete physical-fragment
states. Every state other than complete captured evidence is coverage or
capability information, never proof of success/failure.

Future counterpart-ready facts are emitted only when the synthetic
`updates-client-5.00.test-v1` profile directly supplies exact update/CI/content
and safe client/site/SUP handles. Their timestamp provenance must equal the
normalized cited CCM record; an unavailable SUP handle remains `null`. They
remain client facts for future #330/#333 work. Time alone is never eligible,
topology is not evaluated here, and no server cause is claimed.

Expected coverage and artifact provenance are exact, one-to-one projections of
the manifest. Absent/skipped sources do not claim physical-fragment
completeness, and profile families are validated only from compatible captured
evidence.

## Replay

From the repository root:

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_updates_fixture_contract
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
```

The focused contract validates the exact 17-scenario directory set, 51
manifest artifacts, 43 physical files, capture-state rules, safe paths,
manifest byte counts, no orphans, physical evidence line references, CCM
framing, exact rollover paths, the capped payload, exact corpus hashes and
record totals, stable outcome labels, independent-reducer boundary, and
correlation-safe facts.
