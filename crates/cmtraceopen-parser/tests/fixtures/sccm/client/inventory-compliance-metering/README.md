# SCCM client inventory, compliance, and metering preparation corpus

This issue-#325 corpus is synthetic, sanitized, deterministic, and
`proposedPending318And319`. It is test preparation only: no fixture claims live
Windows acceptance or production source-profile support.

The three top-level directories are independent workflow families:

- `inventory`: Collect -> Provider -> Serialize -> Queue -> Report
- `compliance`: Evaluate -> Remediate -> Report
- `metering`: Collect -> Aggregate -> Report

Every scenario contains:

- `manifest.json`: additive SCCM-specific artifact, coverage, rotation, cap,
  source-version, and provenance design;
- `expected.json`: proposed exact-key transaction or source-local coverage
  outcomes with cited evidence;
- optional `evidence/`: raw CCM transport records or deliberately incomplete
  synthetic input.

Do not add real tenant, device, user, domain, path, package, baseline, or rule
identifiers. Do not use these fixtures to admit production catalog sources
until #318/#319 contracts and the relevant extraction profile have been
reviewed.

Validation:

```bash
cargo test --locked -p cmtraceopen-parser \
  --test sccm_client_inventory_compliance_metering_fixture_contract
```
