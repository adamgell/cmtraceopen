# Issue #323 client software-update corpus preparation

## Purpose and dependency boundary

This document and the synthetic fixture corpus prepare Task 7 of the SCCM
Client intake/core plan. The slice defines evidence-first client
software-update behavior without implementing `analyze_client_updates`, a
production reducer, native collection, or a private replacement for #318's
shared contracts.

Production implementation remains dependent on the reviewed #318 artifact,
logical-record, evidence, timestamp, signal, key, redaction, and finding
contracts plus #319's final client manifest/intake surface. Every expected file
therefore declares `contractState: proposedPending318`: the labels are the
behavior future code must preserve, not proposed final public field names.

The updates reducer must remain independently callable. It consumes normalized
update evidence directly and declares its own gaps. It never consumes policy,
deployment, health, server, or correlation reducer output as a shortcut. A
missing policy artifact may be a coverage fact when update reporting requires
`StateMessage.log`; it is not permission to call the policy reducer or inherit
its result.

## Client update state contract

```text
Scan -> Evaluate -> LocateSup -> Download -> MaintenanceWindow
     -> Install -> Reboot -> Report
```

- `Scan` requires a profile-recognized client scan outcome.
- `Evaluate` requires metadata/compliance applicability evidence for the same
  exact update key.
- `LocateSup` is a client observation that a specific safe SUP/location handle
  was selected/used. It does not prove the SUP server is healthy.
- `Download` is client content-transfer evidence with a validated
  update/content/job key. It does not prove a DP or SUP root cause.
- `MaintenanceWindow` preserves an explicit wait/defer state separately from
  failure.
- `Install` requires source-specific install disposition; a generic error code
  alone is only a signal.
- `Reboot` preserves pending/deferred separately from install failure.
- `Report` requires exact client report/state evidence.

The last successful phase is the latest coherently evidenced phase for one
exact key. Existence of a file, filename order, bundle artifact order, display
time, or an error-looking token cannot advance/fail the state machine.

## Design-only source groups

| Preparation group | Basenames exercised | Responsibility |
| --- | --- | --- |
| `client-updates` | `ScanAgent.log`, `WUAHandler.log`, `UpdatesDeployment.log`, `UpdatesHandler.log`, `UpdatesStore.log` | scan, evaluate, update disposition, install |
| `client-location-services-shared` | `LocationServices.log` | client-observed SUP/location selection |
| `client-content` | `DataTransferService.log`, `ContentTransferManager.log` | download/content state |
| `client-maintenance-window` | `ServiceWindowManager.log` | maintenance-window disposition/context |
| `client-reboot` | `RebootCoordinator.log` | reboot pending/completion |
| `client-policy-state` | `StateMessage.log` | update report/state output only; no policy-reducer dependency |
| `client-windows-update-supplemental` | separately typed `CBS.log` plus skipped/unsupported `ReportingEvents.log`/CBS candidates | optional corroboration/capability only |

These are preparation labels. Shared catalog admission belongs to #319/#318 API
review. No entry in this corpus adds a raw parser or broad unsupported source
family.

## Version-profiled key and evidence contract

The only selected preparation profile is
`updates-client-5.00.test-v1`, scoped to synthetic source versions beginning
`5.00.TEST.` and the declared update artifacts. It makes no claim about a
production ConfigMgr build.

The shared `sccm-keys-5.00.9128-experimental-v1` profile remains Low confidence.
This corpus cannot promote its keys to an exact/terminal transaction or emit a
correlation-eligible counterpart fact from them.

A transaction or counterpart-ready fact requires profile-validated exact
values:

- `updateId`;
- `ciId`;
- `contentId`;
- `updateJobId`;
- `clientHandle`;
- three-character `siteCode`; and
- `supHostHandle` when a complete client `LocateSup`/equivalent record directly
  supplies it.

Keys are not filled from `LAB-CLIENT-01`, filenames, component names, display
names, time proximity, bundle capture host, or another reducer. Malformed,
unknown-version, rotation-split, capped, or invalid-offset evidence retains a
source-local/limited observation with a low confidence ceiling where
appropriate. It cannot later become exact through proximity.

All required transaction fields must co-occur in one cited complete CCM record;
fields from adjacent/same-minute records cannot form a key. A High success or
confirmed failure additionally requires a compatible source record containing
the exact key plus the claimed phase disposition/terminal marker.

Every evidence reference names a physical artifact and inclusive physical line
range. Complete logical CCM records are one or more physical lines only when
the manifest proves a complete fragment; the partial rotation/capped inputs
cannot yield an entry/key/terminal fact.

Correlation-ready facts bind their normalized UTC instant, numeric offset, and
ordering state to the cited complete CCM record. An unavailable SUP handle is
represented as `null`; it is never inferred from the capture host, another
transaction, or a timestamp. These remain counterpart-ready client facts, but
`correlationEligible` stays false while
`topologyCompatibilityEvaluated` is false. A fact may not self-attest
`topologyCompatible`, including an incompatible, null, or malformed value;
issue #333 must evaluate topology before correlation can become eligible.

## Supplemental servicing boundary

CBS, DISM, Windows Update, and ReportingEvents evidence remains separately
typed with explicit provenance. The `supplemental-conflict` case proves that an
unkeyed CBS error at the same instant as exact client install success remains a
low-confidence supplemental symptom. It cannot override the client phase,
merge by time, or create an SCCM/SUP server cause.

A future reducer may attach supplemental evidence only after compatible
source/profile provenance and an exact update/KB/CI match. Missing optional
supplemental evidence does not prevent a complete client result when the
client sources themselves prove it.

## Scenario matrix

| Scenario | Required outcome | Last successful phase | Coverage/request boundary |
| --- | --- | --- | --- |
| `success` | Succeeds through Report; optional ReportingEvents is skipped without degrading the client result. | Report | No request |
| `no-sup` | Insufficient client location/SUP evidence; no server health claim. | Evaluate | `client-location-services-shared` |
| `scan-failure` | Profile-recognized terminal client Scan failure. | None | No inferred downstream cause |
| `evaluation-failure` | Terminal client Evaluate failure after Scan success. | Scan | No SUP/content claim |
| `content-failure` | Terminal client Download failure with exact content/job evidence. | LocateSup | No DP/SUP cause |
| `maintenance-window` | Blocked/deferred because next-window context is unavailable. | Download | `client-maintenance-window` |
| `reboot-pending` | Blocked/deferred, explicitly not install failure. | Install | `client-reboot` continuation |
| `install-failure` | Terminal Install failure under the exact update key. | MaintenanceWindow | No server claim |
| `reporting-failure` | Terminal Report failure after evidenced Reboot completion. | Reboot | No policy-reducer dependency |
| `supplemental-conflict` | Client install success plus unkeyed conflicting CBS symptom; no override/merge. | Install | Keyed supplemental evidence only |
| `incomplete` | Stops after Download because MW/reboot/report artifacts are absent coverage. | Download | `client-maintenance-window` |
| `rotation-boundary` | Two partial `ScanAgent` fragments produce no key/transaction/cause. | None | Bounded complete `client-updates` recapture |
| `capped` | Exact 128-byte incomplete content prefix cannot establish Download failure. | LocateSup | `client-content` |
| `access-denied` | Scan evidence plus inaccessible update-handler source remains insufficient. | Scan | `client-updates` |
| `malformed` | Unknown-version malformed key plus parse-failed/unsupported coverage stays keyless/low. | None | `client-updates` |
| `invalid-offset` | Same-key cross-artifact ordering is non-comparable and capped low. | Scan | Comparable `client-updates` evidence |
| `same-minute-separate` | Two exact update keys at the same instant remain two transactions. | Per transaction | Never time-merge |

`BlockedOrDeferred`, `InsufficientEvidence`, and low-confidence symptoms are
not terminal failures. `Absent`, `AccessDenied`, `Capped`, `Skipped`,
`Unsupported`, `ParseFailed`, malformed, and partial sources are coverage or
capability states.

## Future #330/#333 handoff

The corpus exposes only exact, profile-qualified client facts. For a proven
client SUP interaction, a counterpart-ready fact may retain update/CI/content
and job IDs plus safe client/site/SUP handles, client phase, ordering
provenance, and exact evidence reference.

The handoff explicitly records:

- #330 is the server SUP prerequisite;
- #333 owns any future pairwise correlation;
- time alone is never eligible;
- topology compatibility is not evaluated here;
- no topology compatibility value or correlation eligibility is claimed before
  #333 evaluates topology;
- bundle capture host is not SUP evidence;
- no server cause is claimed; and
- missing/unvalidated client source evidence emits no counterpart-ready fact.

Software-update/SUP correlation must not begin until #323 and #330 each publish
stable, reviewed source facts and #333 defines the pairwise contract.

## Determinism, privacy, and corpus identity

All 17 scenarios use role `client`, capture host `LAB-CLIENT-01`, exact site
code `LAB`, `SYNTHETIC://` provenance, deterministic artifact IDs, sorted
artifact/coverage/transaction arrays, and stable synthetic keys/handles.
Expected coverage and artifact provenance are exact, one-to-one projections of
the manifest. Absent/skipped sources omit physical-fragment completeness, and
validated profile families are derived only from compatible captured evidence.
Client role, catalog entry, logical group, basename, rotation, and evidence path
must remain coherent. Relative paths and path fingerprints cannot alias another
artifact. Every captured or capped physical artifact must also carry a
non-empty path fingerprint; missing, null, empty, and whitespace-only values
are invalid provenance rather than collision-safe identity.

The corpus contains:

- 51 manifest artifacts;
- 42 captured, 1 capped, 4 absent, 1 access-denied, 1 parse-failed,
  1 unsupported, and 1 skipped state;
- 43 physical evidence files totaling 23,142 bytes;
- 61 physical evidence lines;
- 57 complete CCM logical records;
- 2 deliberately partial rotation files and 1 deliberately capped physical
  prefix; and
- no orphan evidence files.

The exact capped 128-byte prefix has SHA-256
`a0afd1fa4e1204c6d085886ed62b07f6b1d4af119f747c181f6e206194db9f7f`.
The path-qualified corpus SHA-256 is
`b7670821f385f90eb0178528480307f617c508c28abacf21e927d30ed3bdffef`,
computed by sorting evidence paths relative to the updates root and hashing
each UTF-8 path, one NUL byte, then its committed bytes in sequence. The
focused Rust contract also pins a path-qualified FNV-1a value
`0x1ff672e51adbeb52`.

No evidence contains customer paths, hostnames, users, SIDs, tenants, tokens,
certificates, serials, production deployment names, or copied live log text.

## Replay and acceptance gates

Before implementation, map these preparation labels to the final #318/#319
types. Then load through the public reader and run the independent update
reducer with original/reversed/shuffled input. Compare normalized serialized
output and validate key/profile confidence, line ranges, redaction, coverage,
offset comparability, stable ordering, and the no-server-cause boundary.

Current preparation replay:

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_updates_fixture_contract
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
npx tsc --noEmit
```

Native Windows source discovery/capture is not exercised by this slice. Issue
`#323` must remain open for production implementation, shared-interface review,
and eventual authorized development-client validation.
