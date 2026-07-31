# Issue #326 client-management corpus preparation

## Scope and dependency boundary

This slice prepares the source, ownership, evidence, coverage, and adversarial
contracts for co-management, scripts, client notification, and observational
Software Center diagnostics. It intentionally owns only:

- this preparation document;
- `sccm_client_management_fixture_contract.rs`; and
- the synthetic corpus under `fixtures/sccm/client/management/`.

It does **not** add a production reducer, shared SCCM model, source catalog,
native capture adapter, server fact, cross-side rule, UI, or Windows acceptance
claim. Every manifest and expected contract is
`proposedPending318And319`. Production implementation remains blocked on the
reviewed public contracts from #318 and #319. This branch must also be
restacked and revalidated after the currently active #318 shared-contract PR
lands.

## Capability and ownership gate

The proposed ownership result is resolved before an operational transaction:

```text
SccmOwned | IntuneOwned | SharedOrTransitioning | UnknownOwnership
```

- `SccmOwned` and `IntuneOwned` require complete, profile-recognized,
  explicit-offset `CoManagementHandler` evidence.
- `IntuneOwned` is an evidenced terminal handoff, never an Intune diagnosis.
- `SharedOrTransitioning` is medium-confidence and cannot emit an operational
  failure.
- `UnknownOwnership` is low-confidence and either cites contradictory evidence
  or names the bounded co-management coverage gap.
- Only `SccmOwned` permits a script or client-notification transaction in this
  proposed corpus.

Software Center remains an observational capability gate. The sanitized
`SCClient_SYNTHETIC_*.log` and `SCNotify_SYNTHETIC_*.log` names are test-only
placeholders for a redacted filename class. They are always
`candidateUnsupported` and `parserEligible: false`. Capturing such a candidate
does not admit its grammar or establish UI state, user intent, server
availability, or an action outcome.

## Design-only source contract

| Logical artifact | Exact synthetic basename | Preparation status | Semantic boundary |
| --- | --- | --- | --- |
| `client-co-management` | `CoManagementHandler.log` | admitted only by `sccm-client-co-management-5.00.test-v1` | workload ownership/handoff |
| `client-scripts` | `Scripts.log`, canonical `Scripts.lo_` rotation | admitted only by `sccm-client-scripts-5.00.test-v1` | Receive → Execute → Report |
| `client-notification` | `CcmNotificationAgent.log` | admitted only by `sccm-client-notification-5.00.test-v1` | Receive → DeferOrDispatch → Acknowledge |
| `client-software-center` | sanitized `SCClient_SYNTHETIC_1.log`, `SCClient_SYNTHETIC_2.log`, `SCNotify_SYNTHETIC_1.log` | candidate/unsupported; never parser eligible | physical capability/coverage observation only |

No BGB or server log is admitted. A source alias, case-folded basename, broad
`*.log` match, or module-name resemblance does not enter the catalog.

## Versioned keys and timestamp provenance

The scripts proposal requires all three exact fields in every cited complete
logical record:

```text
ScriptId + ExecutionId + ResourceHandle
```

The notification proposal likewise requires:

```text
NotificationId + ChannelId + ResourceHandle
```

All values are bound to the named synthetic extraction profile. Handles use a
`safe:` representation. Filename, component, same-minute timing, physical
root, signal, display text, and ingestion order cannot create or merge a key.
A terminal record is high-confidence only when the exact key is co-located,
the source version matches the canonical `5.00.TEST.` plus four-decimal test
profile grammar, the CCM record is complete, and its additive SCCM timestamp
envelope has normalized UTC provenance. Signless
legacy offsets retain their SCCM interpretation; seven-digit fractional tails
remain offset-missing. Unknown profiles and unusable offsets stay source-local
and noncorrelatable. Every artifact has a canonical `capturedUtc`, and no cited
normalized record may postdate its capture.

Structured fields are parsed as exact, unique, record-local names under the
workflow source contract. Substring lookalikes, conflicting duplicate fields,
nested CCM envelopes, and fields borrowed from another record cannot satisfy a
key, phase, ownership, disposition, or terminal assertion.

Raw command arguments and user context are not present. The corpus uses only
`CommandContextHandle` and `UserContextHandle` values under the `safe:`
boundary.

## Coverage and physical provenance

The preparation manifest is additive and does not reuse generic
`ArtifactStatus` semantics. Each artifact preserves:

- exact client role and logical source group;
- exact source/capability admission state;
- canonical capture-attempt time;
- sanitized source path bound to the exact scenario, client role, logical
  source group, and closed fixture layout, plus a lowercase opaque
  `safe:path:326:` fingerprint when a candidate path was observed;
- case-normalized physical source identity uniqueness enforced independently
  of self-declared fingerprints;
- unique bundle-relative path for physical bytes;
- explicit current versus `.lo_` rotation and fragment completeness;
- collection-cap provenance for capped bytes;
- source version for captured bytes; and
- `captured`, `partial`, `capped`, `absent`, `accessDenied`, `malformed`, or
  `unsupported` effective coverage.

Raw `captureState: parseFailed` maps only to effective `malformed` coverage; it
never becomes `captured`.

Every non-complete artifact is surfaced by a low-confidence source-local
observation. It cannot prove success, failure, ownership, delivery, or
nonexistence.

## Scenario matrix

| Scenario | Workflow | Contract outcome |
| --- | --- | --- |
| `co-management-intune-owned` | co-management | exact terminal Intune handoff; no SCCM/Intune failure |
| `co-management-sccm-owned` | co-management | exact terminal SCCM ownership |
| `co-management-transitioning` | co-management | explicit transitioning state; medium confidence |
| `co-management-unknown` | co-management | absent evidence becomes an ownership coverage gap |
| `script-success` | scripts | Receive → Execute → terminal Report for one exact key |
| `script-failure` | scripts | terminal Execute failure after cited Receive success |
| `script-incomplete` | scripts | capped current plus incomplete `.lo_` fragments stay separate |
| `script-intune-handoff` | scripts | unkeyed SCCM error remains local after exact Intune handoff |
| `notification-received` | notification | Receive → terminal Acknowledge for one exact key |
| `notification-deferred` | notification | explicit defer is not failure and requests one bounded continuation |
| `notification-failure` | notification | terminal Acknowledge failure after cited Receive success |
| `software-center-observed` | Software Center | captured candidate remains unsupported/parser-ineligible |
| `software-center-insufficient` | Software Center | absent, malformed, unsupported, and unknown-ownership gaps |
| `mixed-unrelated` | mixed adversarial | same-time roots, conflicting ownership, access denial, unknown profile, and invalid offsets remain unlinked |

The corpus is pinned at 14 scenarios, 30 artifacts, and 25 physical evidence
files totaling 8,648 bytes. Raw capture-state inventory is 23 captured, three
absent, one capped, one access-denied, one parse-failed, and one unsupported.
The FNV-1a-64 digest over sorted
`scenario NUL artifactId NUL relativePath NUL hex(evidence bytes) LF` rows is:

```text
409619f730304018
```

The digest binds physical identity, path, and exact synthetic bytes. It is not
a cryptographic authenticity claim.

## Adversarial contract

The focused Rust target dynamically proves that the validator rejects:

- client artifacts relabeled as server role;
- case-folded or invented source aliases;
- raw Windows paths, cross-workflow evidence roots, server-shaped sanitized
  paths, identity-bearing synthetic paths/fingerprints, duplicate sanitized
  physical identities, and aliased cross-root path fingerprints;
- borrowed exact transaction keys;
- substring field lookalikes, conflicting duplicate fields, and nested CCM
  envelopes;
- contradictory ownership and ownership borrowed across workflows;
- unversioned profile aliases, malformed in-prefix versions, and unknown-version
  promotion;
- capped coverage relabeled captured;
- invalid/signless/missing-offset evidence promoted to high confidence and
  capture times earlier than cited evidence;
- parse-failed evidence relabeled as a generic coverage gap;
- terminal phases moved before receipt, ownership observed after an operational
  transaction, distinct phases assigned the same ambiguous timestamp, and
  required intermediate script phases omitted;
- missing scenario transactions, duplicate exact transaction keys, and
  out-of-order transactions;
- unknown ownership/transaction semantic fields and unsupported causal phrasing
  using `because`, `resulted in`, or `responsible for`;
- a coherent attempt to mark Software Center candidates admitted and parser
  eligible;
- a server-causal claim in client-only source-local output; and
- a fabricated SCCM operational transaction after an exact Intune handoff.

The checked-in `mixed-unrelated` case additionally proves that two
same-basename `Scripts.log` artifacts from different roots retain distinct
paths and fingerprints. Their same-minute, unkeyed success/error records do
not combine. Exact-looking notification evidence with an invalid offset also
cannot become a high-confidence transaction.

## TDD record

The first focused run was intentionally red:

```text
cargo test --locked -p cmtraceopen-parser --test sccm_client_management_fixture_contract
1 failed: management fixture corpus did not exist
```

After the smallest corpus/validator was green, the dynamic adversarial target
was added. That second red run reported 7 passed / 2 failed and exposed six
accepted fabrications: server role alias, source alias, raw path, fingerprint
collision, coherent unsupported-source promotion, and server-causal text.
The validator was then hardened at those exact boundaries.

CodeRabbit review exposed a third red boundary: reversed terminal phases, late
ownership evidence, and equal timestamps for distinct phases were all
accepted. The evidence envelope now retains parsed UTC milliseconds, phase
progression must be strictly chronological, and cited SCCM ownership must
strictly precede the first operational event.

Independent exact-head review of PR #373 exposed a fourth red boundary. The
permanent Rust 1.88 run executed 17 tests: the 11 prior tests passed while six
new adversarial groups failed with all 19 reviewed mutations accepted. The
correction now consumes #318 `normalize_ccm_artifact` timestamp provenance,
closes record/JSON field sets, binds paths and ownership to workflow source
groups, requires exact scenario transaction cardinality and unique keys, and
preserves malformed coverage semantics. The same focused target is green at
17/17 only after those structural corrections.

A subsequent independent review exposed four more physical-provenance
bypasses: a malformed in-prefix source version, identity-bearing material
inside a synthetic source path or fingerprint, and duplicate sanitized source
identities hidden behind different fingerprints. The permanent contract now
rejects all four while retaining the bounded synthetic corpus.

## Replay and acceptance limits

Run the preparation target:

```bash
cargo +1.88.0 test --locked -p cmtraceopen-parser --test sccm_client_management_fixture_contract
```

Before review, also run:

```bash
cargo +1.88.0 test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo +1.88.0 test --locked -p cmtraceopen-parser --test sccm_client_intake_fixture_contract
cargo +1.88.0 test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo +1.88.0 check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
npx tsc --noEmit
rustfmt +1.88.0 --edition 2021 --check crates/cmtraceopen-parser/tests/sccm_client_management_fixture_contract.rs
git diff --check
```

This command set checks the deterministic pure-Rust fixture contracts, the
package-wide parser suite, strict linting, TypeScript type checking,
formatting/whitespace, and wasm32 compilation. It does not exercise native
candidate discovery, permissions, Windows layout, ConfigMgr version, Software
Center filename classes, notification transport, Intune behavior, or live SCCM
acceptance. Passing this preparation corpus is not an issue-closure condition.
