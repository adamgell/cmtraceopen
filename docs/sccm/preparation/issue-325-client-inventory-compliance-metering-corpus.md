# Issue #325 preparation: inventory, compliance, and metering

Status: `proposedPending318And319`

This slice prepares the source, manifest, fixture, and reducer-test contract for
issue #325. It intentionally does not add production catalog entries, native
capture, fact extractors, reducers, findings, or public model changes.
Production work remains dependent on reviewed, stable contracts from #318 and
#319.

The fixtures are synthetic and sanitized. They prove only that this proposed
contract is deterministic and adversarially guarded. They are not evidence of
live Windows acceptance, ConfigMgr-version support, or observed production
message grammar.

## Three independent workflow contracts

| Workflow | Proposed logical group | Candidate sources | State chain | Exact proposed key |
| --- | --- | --- | --- | --- |
| Inventory | `client-inventory` | `InventoryAgent.log`, `InventoryProvider.log`, and `InventoryAgentProvider.log` when observed | Collect -> Provider -> Serialize -> Queue -> Report | inventory cycle ID + resource handle + report ID |
| Compliance | `client-compliance` | `CIAgent.log`, `CITaskMgr.log`, `DCMAgent.log`, `DCMReporting.log`, and `StateMessage.log` when observed | Evaluate -> Remediate -> Report | CI ID + baseline ID + state ID + resource handle |
| Metering | `client-metering` | `SWMTRReportGen.log`; additional names require separately observed evidence | Collect -> Aggregate -> Report | metering cycle ID + rule ID + report ID + resource handle |

The names above are preparation candidates, not production admission. A later
catalog change must be table-driven and backed by sanitized source evidence plus
a reviewed extraction profile. Generic message keyword scanning is prohibited.

Each proposed exact key is accepted only when every field co-occurs in one
complete cited CCM logical record. A field borrowed from another line, artifact,
root, rotation, or workflow cannot complete a key. The profile identifiers in
this corpus are deliberately test-only:

- `sccm-client-inventory-5.00.test-v1`
- `sccm-client-compliance-5.00.test-v1`
- `sccm-client-metering-5.00.test-v1`

An unknown source version has no fallback profile. It remains a source-local,
low-confidence observation and a coverage/profile gap.

## Fixture matrix

The fixture root is
`crates/cmtraceopen-parser/tests/fixtures/sccm/client/inventory-compliance-metering`.
It contains 20 scenarios, 54 manifest artifacts, and 42 physical evidence files
(16,479 bytes). The deterministic fixture digest is `6eef3efbb0c531ba`.

| Family | Scenarios | Contract coverage |
| --- | --- | --- |
| Inventory | `success`, `terminal-failures`, `recovery-contradictory`, `coverage-states`, `rotation-boundary`, `same-minute-collision` | all five phases; exact-key recovery; contradictory terminal records; missing/access-denied/capped/skipped/unsupported/malformed/partial sources; split rotations; two same-minute cross-root records |
| Compliance | `success`, `noncompliant-result`, `remediation-success`, `terminal-failures`, `recovery-contradictory`, `coverage-states`, `malformed-unknown-profile-invalid-offset`, `same-minute-collision` | compliant and noncompliant evaluation results; remediation; all three terminal phases; recovery and contradiction; every coverage state; unknown profile; unusable offset; same-minute records with different exact keys |
| Metering | `success`, `terminal-failures`, `recovery-contradictory`, `coverage-states`, `rotation-boundary`, `same-minute-collision` | collect/aggregate/report; exact-key recovery; contradiction; every coverage state; split rotations; two same-minute cross-root records |

`noncompliant-result` is an evaluation result, not a confirmed failure.
Compliance evaluation, remediation, and report are separate phases. Inventory
queue/report failures never become compliance failures, and metering facts never
borrow CI/baseline/state identifiers.

## Proposed additive manifest contract

Every scenario has a `manifest.json` and `expected.json`.

The manifest is SCCM-specific preparation data and does not overload generic
`ArtifactStatus` semantics. It preserves:

- a synthetic bundle ID, client role, sanitized capture host, and site code;
- exact physical artifact identity and logical workflow membership;
- original basename, sanitized attempted source path, and path fingerprint;
- current or `.lo` rotation identity and fragment completeness;
- explicit `captured`, `absent`, `accessDenied`, `capped`, `skipped`,
  `unsupported`, or `parseFailed` capture state;
- source version, UTF-8 encoding, byte cap state, copied byte count, and safe
  relative evidence path.

`captured` plus `fragmentComplete: false` projects to `partial` coverage.
Nonphysical states have no evidence path and zero copied bytes. An absent source
does not invent path, fingerprint, or version identity. Duplicate basenames from
different roots remain separate when their sanitized paths, fingerprints, and
relative paths are distinct.

The expected contract keeps output deterministic and preparation-only:

- every coverage row is an exact artifact-level projection of the manifest;
- every transaction is bound to one workflow and one versioned exact-key
  profile;
- every evidence reference names a manifest artifact and valid line range;
- transaction citations contain complete raw CCM records;
- `findings` remains empty until production reducers are authorized;
- source-local observations have a low confidence ceiling and are not
  correlation eligible;
- next-artifact requests name one admitted logical group and basename, never an
  arbitrary path, drive, volume, wildcard, or recursive scan.

## Conservative reducer expectations

Future implementation may promote a preparation fact only after #318/#319
review and an issue-scoped failing production test:

- high-confidence success requires a complete, terminal phase record, an exact
  family key, a selected source-version profile, and usable timestamp offset;
- confirmed failure requires an explicit terminal failure in the cited phase;
- recovery requires later terminal success with the same exact key and usable
  ordering provenance;
- contradictory terminal evidence remains low confidence;
- missing, access-denied, capped, skipped, unsupported, malformed, partial, or
  unknown-profile evidence remains coverage, not a workflow outcome;
- time proximity alone never joins transactions;
- client evidence alone never asserts a server-side cause.

## Dynamic adversarial guards

The fixture contract mutates valid scenarios at test time and requires rejection
of:

- client-to-server role swaps and workflow/log-family source injection;
- unsafe relative paths, incorrect byte counts, and cross-root fingerprint
  aliasing;
- cross-family key fields, uncited key values, and phase borrowing from another
  record;
- high-confidence output from an unknown source profile or invalid timestamp
  offset;
- promotion of missing coverage to captured evidence;
- promotion of noncompliance to confirmed failure;
- same-minute key borrowing between distinct root artifacts;
- merging same-minute inventory and compliance terminal failures;
- unbounded next-artifact requests.

This mutation layer is independent of the positive fixture assertions, so an
internally consistent edit to both a manifest and its expected file cannot
silently weaken the safety contract.

## Promotion gates and remaining blockers

Production code must not be added from this branch. Promotion requires:

1. #318 API review to publish stable evidence, coverage, signal, key,
   redaction, and conservative finding contracts.
2. #319 API review to publish stable client manifest, collision, rotation,
   access, cap, and native adapter contracts.
3. A source-evidence review for every basename and versioned grammar admitted
   to the production catalog.
4. Focused RED then GREEN production tests for three separate fact extractors
   and three separate reducers.
5. Parser, SCCM-spine, client-intake, wasm32, strict Clippy, formatting, and
   `git diff --check` gates.
6. Native Windows capture/acceptance evidence before any live-support claim.

The SCCM Server lab is a future native validation source and is not a blocker
for this pure-Rust preparation slice.
