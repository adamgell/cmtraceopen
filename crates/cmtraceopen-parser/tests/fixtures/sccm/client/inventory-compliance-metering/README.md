# SCCM client inventory, compliance, and metering preparation corpus

This issue-#325 corpus is synthetic, sanitized, deterministic, and
`proposedPending318And319`. The exported production analyzer exercises every
admissible scenario through sealed intake. Its explicit test adapter maps only
the reviewed `5.00.TEST.325` fixture version to the experimental production
profile and records the fixture-to-admitted artifact identity map used by exact
assertions. Unknown profiles and invalid timestamps are rejected rather than
rewritten as coverage. No fixture claims live Windows acceptance.

The three top-level directories are independent workflow families:

- `inventory`: Collect -> Provider -> Serialize -> Queue -> Report
- `compliance`: Evaluate -> Remediate -> Report
- `metering`: Collect -> Aggregate -> Report

Every scenario contains:

- `manifest.json`: additive SCCM-specific artifact, coverage, rotation, cap,
  source-version, and provenance design;
- `expected.json`: proposed exact-key transaction or source-local coverage
  outcomes with cited evidence, closed non-causal schemas, evidence-backed phase
  state, and canonical output ordering;
- optional `evidence/`: raw CCM transport records or deliberately incomplete
  synthetic input.

The preparation validator treats each `(captureHost, sanitizedSourcePath,
rotation)` tuple as one source identity in every scenario. Synthetic root
labels must agree across the sanitized path, fingerprint, and relative evidence
path; retained-byte fields are exact for the declared capture state. Cited CCM
fields and source-to-phase ownership are closed, evidence line ranges cannot
overlap, and filesystem separators are normalized before manifest comparison.
Artifact, transaction, and observation identities are bounded canonical
lowercase tokens scoped to their active family (and scenario for artifacts).
Source versions must be canonical tokens before profile-prefix selection, and
one `(observation kind, artifact)` membership can appear only once. A
`rotationSplit` observation additionally requires one common synthetic root,
canonical basename, source version, and exact family key across its `current`
and `.lo` fragments.

Do not add real tenant, device, user, domain, path, package, baseline, or rule
identifiers. Do not use these fixtures to admit production catalog sources
until #318/#319 contracts and the relevant extraction profile have been
reviewed.

Validation:

```bash
cargo test --locked -p cmtraceopen-parser \
  --test sccm_client_inventory_compliance_metering_fixture_contract
cargo test --locked -p cmtraceopen-parser \
  --test sccm_client_inventory
```
