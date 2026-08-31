# Intune Parser Family Closeout Design

## Status

The repository owner authorized ownership of the complete issue #356 program on
2026-08-29 and approved this design plus ADR-004 Revision 2 as the implementation
contract on 2026-08-30. This document refreshes the 2026-07-29 parser-family
design against current `main` and defines the work required before the epic can
truthfully close.

This document supersedes the Intune compatibility, skeleton, and completion
sections of `2026-07-29-parser-family-architecture-design.md`. It does not
change that document's SCCM architecture.

Its redaction implementation is governed by the accepted
`ADR-004-redaction-scope-revision-2.md`, which supersedes Revision 1's deferred
algorithm, derivation, secret-source, local-preserving API, IPC, and migration
questions.

Approval was reverified against `origin/main` at
`2f8b5cf3339df95b0798bdeb376b37c58cec91d3`. The only intervening main commit
after the audited baseline was release/CI work from PR #587; it changed no
Intune parser-family contract or child-issue state.

Baseline audited for this design:

```text
origin/main 59679c06b5dd1f5d59849a14d527f4b262b30a1c
cargo test --locked -p cmtraceopen-parser  PASS
npx tsc --noEmit                           PASS
git diff --check                           PASS
cargo fmt --check --all                    FAIL (pre-existing formatting drift)
```

## Goal

Close issue #356 only after CMTrace Open has a discoverable workload-first
Intune parser family whose implemented leaves have real source contracts,
deterministic and privacy-safe pure analysis, the required native acquisition
or import boundary, and exact native-platform acceptance evidence.

Closing GitHub issues, compiling a placeholder module, or passing authored
fixtures is not completion.

## Governing decisions

### Current instructions replace the old compatibility window

The repository now explicitly forbids backward-compatibility layers. When an
Intune API moves to its canonical workload path, every repository consumer is
updated in the same slice and the obsolete path is deleted. No deprecated
facade, dual reader, dual writer, fallback parser, or migration shim is added.

Wire changes use a new explicit schema version. Producers and consumers move
together; old and new wire shapes are not accepted in parallel.

This rule is scoped to paths changed by this program. It does not authorize an
unrelated whole-crate API rewrite.

### Workload paths represent support only when implemented

The canonical family remains:

```text
intune
├── apps
├── enrollment
├── device
└── portal
```

An empty module, reserved namespace, or documentation-only leaf does not count
as support. A leaf becomes public only with its source classifier, versioned
input contract, typed result, conservative coverage behavior, privacy-safe
projection, sanitized corpus, and required native boundary.

The current implementation-pending leaves for #361, #365, #369, and #371 stay
truthfully unsupported until their contracts land. They must not remain empty
placeholders when the epic closes.

### Pure analysis and native acquisition remain separate

`cmtraceopen-parser` receives bytes, decoded records, and explicit provenance.
It performs no filesystem discovery, archive extraction, registry access,
event-log access, unified-log queries, device access, or platform command
execution.

`src-tauri` owns those native operations and converts their output into the
versioned pure-parser inputs. Native failures become typed coverage states;
they do not become empty successful captures.

### Evidence is admitted before it is interpreted

Every workload follows the same direction:

```text
native or imported artifact
  -> bounded acquisition/import result
  -> source and version admission
  -> normalized evidence with provenance
  -> workload reducer
  -> cited findings and explicit gaps
  -> redacted deterministic export
```

Missing, denied, capped, skipped, unsupported, malformed, partial, and
unknown-version evidence remain distinct. None proves success or absence.

## Approaches considered

### Close only the five open child issues

Rejected. It would leave stale tracker state, duplicate script/remediation
rules, missing native handoffs behind already-closed issues, absent docs.rs
navigation, and unenforced wasm/format/diff gates.

### Revive the preserved recovery branches

Rejected. The preserved #361, #365, #369, and #371 recovery heads are stale,
unreviewed donor evidence and are ineligible for wholesale integration. A plan
may cite an exact donor SHA for a small idea, but implementation starts from
current `main`, reproduces the need with a failing test, and rewrites the
smallest correct change under the current contracts. No recovery payload is
merged or cherry-picked wholesale.

### Current-main issue-scoped closeout

Selected. Shared foundations land first. Each child then uses a fresh worktree
from the exact integrated `main`, starts with a focused failing contract test,
and delivers one independently reviewable vertical slice. Source-contract
acquisition proceeds in parallel without advertising unsupported formats.

## Current-state reconciliation

The issue #356 checklist shows 10 of 17 children complete, while live issue
state reports 12 closed and 5 open. #357 and #363 are stale unchecked entries.
Issue state is not used as acceptance evidence.

| Area | Current state | Required closeout |
| --- | --- | --- |
| #354 Device Inventory | Parser, detector, known source, association, and tail hardening are on `main`; issue remains open | Add RED tests for raw timestamp retention, offset/naive-time semantics and ordering parity, Harvester/Adaptor formatting parity, secondary context including `[Registry]`, bracketed-syslog and arbitrary-JSON collision rejection, camelCase serialization, CRLF/aggregate behavior, structured ACL denial, and fixture provenance for Harvester, Adaptor, and RotationFailure; then run discovery, hermetic `.log_` registration/detection/launch/restoration, aggregate, tail, and access-denied acceptance on Windows |
| #357 Win32 | Pure supplied-log contract is on `main`; no typed Tauri/frontend route calls it | Admit or narrow every claimed IME, AppWorkload, AppActionProcessor, AgentExecutor, and InstallerOutput source; add a corpus-level `capped`/`accessDenied`/`parseFailed` case, a complete true negative, and per-record timestamp-trust assertions; land desktop supplied-log selection/dispatch through the typed analyzer and projected export; then correct the epic tracker |
| #358 Store | Pure normalized-event analyzer is on `main` | Correct the truncated fixture's `fragmentComplete` contract, broaden offset evidence, admit or narrow IME, AppWorkload, StoreAgent, AppX, package-fact, Assignments, and InstallerOutcomes sources, and land one Store-owned AppX/package-fact adapter-to-analyzer slice |
| #359 scripts | Pure analyzer is on `main` | Move the native command and TypeScript consumer atomically to the typed script analysis, delete AgentExecutor classification/status/wire behavior from `event_tracker`, and prove the command path on Windows |
| #360 remediations | Pure analyzer is on `main` | Admit or narrow HealthScripts, AgentExecutor, and IME evidence; move the native command and TypeScript consumer atomically to the typed remediation analysis, delete duplicate remediation classification/status/wire behavior from `event_tracker`, and prove the command path on Windows |
| #361 macOS packages/scripts | Public paths are placeholders | Admit observed, sanitized Intune daemon and per-user agent logs; implement one package vertical slice before adding a separate script reducer over only the raw admission proven common; validate both roots, rotations, order, and denial on macOS |
| #362 Autopilot | Pure analyzer is on `main` | Admit source anchors and land an Autopilot-owned event/diagnostics-report adapter-to-analyzer slice with Windows acceptance |
| #363 configuration | Pure analyzer is on `main` | Admit, inherit exactly, or narrow Registry, DiagnosticReport, IME, CCM, Agent, PlainText, UnifiedLog, and Graph/SuppliedFact authority inputs; land configuration-owned native/import envelopes with Windows acceptance and no service query |
| #364 compliance | Pure analyzer is on `main` | Admit source anchors and land a compliance-owned event/report adapter-to-analyzer slice with Windows acceptance |
| #365 WUfB | Public path is a placeholder | Admit each claimed registry, Windows Update event, update-log, and supplied-policy source; implement leaf-owned envelopes and a fresh reducer whose unknown/incomplete evidence cannot produce a verdict; validate each source on Windows |
| #366 Windows portal logs | Parser, dispatcher, collector path, and tail integration are on `main`, but only one grammar profile is admitted | Admit a second real-version capture or narrow the supported profile, then reproduce LocalState discovery, aggregate load, denial, and tail acceptance at the exact candidate SHA |
| #367 package state | Canonical JSON and an experimental legacy text reader coexist | Delete `import_legacy_format_list`, `LegacyFormatList`, its findings branch, module, callers, fixtures, and tests; leave canonical JSON only and reprove the native AppX command-to-analyzer path |
| #368 macOS portal logs | Pure parser and known-source discovery are on `main`; its corpus is synthetic | Replace self-referential version claims with observed sanitized anchors or narrow them, route native opens through the canonical parser, and record macOS acceptance |
| #369 macOS saved reports | Public path is a placeholder | Admit a real sanitized report schema and implement an atomic bounded native importer against that format, reusing proven ESP archive primitives where compatible, with actual #368 handoff |
| #370 macOS unified log | Pure normalized contract has a synthetic corpus; a parallel older native DTO exists | Admit a real capture or narrow the subsystem/version claims; make native collection feed versioned bytes into the pure parser, delete the older DTO, and preserve denied/malformed/capped coverage |
| #371 Android diagnostics | Public path is a placeholder | Admit real sanitized artifacts and implement only their import and container contracts; no ADB/device assumption and no generic ZIP/logcat support |
| #372 iOS Console import | Pure imported-artifact contract has a synthetic corpus | Admit an observed sanitized Console export, remove or mark unproven aliases such as German labels experimental, and prove desktop import through dispatch, analysis, and redacted export; device automation remains a non-goal |

## Program architecture

### Canonical IME and ESP ownership

CCM framing remains in the shared CCM layer because it is consumed by both IME
and SCCM. Cross-workload Intune identity helpers such as GUID parsing live in a
lower, private `intune::common` layer. Only app-owned IME semantic analysis is
exposed under `intune::apps::windows::ime`. ESP and Device Preparation move
under `intune::enrollment::windows::esp`. This keeps core framing and enrollment
from depending upward on an app workload.

The program owns one deletion ledger, but removes each surface in the smallest
vertical slice that can migrate all of its consumers atomically:

- the canonical-path slice moves every consumer and deletes flat IME and
  crate-root ESP public paths, `ParsedEspEventBatch`, the manifest-missing ESP
  bundle fallback, and the ESP-only compatibility relaunch command/wire
  (`restart_esp_as_administrator`, `EspRelaunchReason`, `EspRelaunchResult`, and
  `EspRelaunchError`) from Rust registration and TypeScript;
- the ESP redaction slice deletes raw `EspDiagnosticsSnapshot` command responses
  and raw `EspSessionUpdate` event payloads, plus the public no-context
  `esp::redacted_export_projection`, after the projected command/event/frontend
  contract lands. It also replaces capture export/replay atomically with the
  single V2 native boundary and deletes the frontend `parseEspSessionCapture`
  parser, `EspSessionCapture` TypeScript DTO/guard, V1 envelope reader,
  bare-`EspDiagnosticsSnapshot` reader, permissive version handling, and their
  tests and wires;
- #354 keeps `parser_selection` as the one parse-selection wire, moves tailing
  and every consumer to it, and deletes `compatibility_format` and the parallel
  `ParseResult.format_detected` field;
- #359 deletes only script classification, status, and wire variants from
  `event_tracker` when the typed script consumer lands;
- #360 separately deletes only remediation classification, status, and wire
  variants from `event_tracker` when the typed remediation consumer lands;
- #367 deletes its `legacy` module, `import_legacy_format_list`,
  `LegacyFormatList`, findings branch, callers, fixtures, and tests;
- #370 deletes the native `MacosUnifiedLogResult` DTO when the pure capture path
  lands;
- the redaction foundation moves the shared Windows masking grammar out of the
  public app-owned `intune::apps::windows::common::redaction` path and deletes
  that obsolete helper path after all imports move;
- #366 deletes `parse_log_document_preserving_local_values`, the public
  no-context log projection, and its `redacted` wire flag;
- #363 deletes `ConfigurationInput.analysis_scope`,
  `ConfigurationSnapshot.analysis_scope`, `ConfigurationSnapshot.redacted`, the
  timestamp fallback, and `redacted_configuration_snapshot`;
- each lane's redaction slice deletes its public no-context projection API. The
  known inventory is the Win32, scripts, remediations, Store, compliance, and
  Autopilot `redacted_export_projection` functions; package-state
  `redacted_package_state_export`; macOS unified-log
  `redacted_capture_projection` and `redacted_export_projection`; macOS direct
  log and iOS Console `redacted_export_projection`; and their public re-exports,
  serializers, flags, tests, and call sites;
- those same slices make workload grammars private and delete all public old
  minter/token surfaces: Store, Autopilot, and macOS unified-log `redact_text`;
  Win32, scripts, and compliance public `redact_text` aliases; the iOS Console
  `REDACTED_EMAIL`, `REDACTED_URL`, `REDACTED_TOKEN`,
  `REDACTED_CERTIFICATE`, `REDACTED_TENANT_ID`, `REDACTED_DEVICE_ID`,
  `REDACTED_GUID`, `REDACTED_APP_ID`, and `REDACTED_ADDRESS` constants; and
  every public re-export or caller of those symbols. Workload-local grammar
  remains private implementation, not a callable legacy token API.

Each slice has a checked-in absence test for its assigned symbols/wires. The
final gate runs the union of that inventory. Discovering another obsolete
compatibility surface assigns it to a concrete vertical slice and adds it to the
same deletion test; there is no waiver or retained fallback path.

The script and remediation migrations have the same end-state rule but are two
separate issue-owned vertical slices. #359 moves its native orchestration,
Tauri response, and TypeScript consumer atomically to the typed script analyzer,
then deletes only duplicate script semantics from `event_tracker`. #360 does the
same for the typed remediation analyzer and only its duplicate remediation
semantics. `AgentExecutor` may remain admitted evidence in both workload-owned
analyzers because the two workloads interpret it differently. `event_tracker`
may retain genuinely workload-neutral IME records, but it does not preserve a
second workload semantic DTO or terminal-state machine.

### Leaf-owned Windows acquisition boundaries

There is no pre-landed universal Windows adapter. Store, Autopilot,
configuration, compliance, WUfB, portal logs, package state, and Device
Inventory retain leaf-owned input envelopes because their source and analysis
contracts differ. The first native reader, leaf-specific projection, analyzer
call, and application acceptance test land atomically as one working vertical
slice. Shared EVTX or report-decoding primitives are extracted only after a
second real consumer proves the same responsibility.

Every leaf-owned source envelope is versioned and carries source-level state,
not merely per-record state:

- expected source identity and source schema;
- adapter and collection-profile versions;
- `complete`, `missing`, `skipped`, `denied`, `capped`, `cancelled`,
  `timedOut`, `malformed`, `unsupported`, `unknownVersion`, or `partial`
  status;
- attempted and observed record counts and bytes;
- active member, byte, time, and record limits plus truncation details;
- deterministically ordered normalized records.

An empty record vector means "complete and empty" only when its source envelope
proves the expected source was successfully and completely queried. A denied,
missing, skipped, malformed, unsupported, unknown-version, timed-out,
cancelled, capped, or partial source cannot be normalized into a successful
empty capture. Source-envelope contract tests enumerate the complete status
vocabulary and prove that `unknownVersion` remains distinct from `malformed`
and `unsupported`.

Each normalized record carries artifact and record identity, source kind,
provider/channel and event ID where applicable, source schema version, original
timestamp text, parsed UTC instant only when justified, explicit offset/trust
state, typed fields plus retained unknowns, privacy classification, and a
source-local evidence reference. Native tests serialize the actual adapter
output, deserialize it through the pure contract, call the production analyzer,
and assert the projected result and coverage state.

### macOS acquisition boundary

Direct Company Portal and Intune agent logs use content-confirmed canonical
parsers after known-source discovery. Path hints can raise confidence but
cannot select a parser by themselves.

The native unified-log query emits bounded, versioned NDJSON or JSON bytes plus
query-execution metadata. It performs no record classification or supported
schema interpretation. Those bytes go through the pure `parse_capture` entry
point, and only that parser constructs `PortalUnifiedLogCaptureSet`. Consumers
move to the parser-produced type and the older `MacosUnifiedLogResult` shape is
deleted in the same slice. Malformed records, query denial, time-window
truncation, and caps remain visible coverage. The query has an elapsed execution
deadline; cancellation or timeout terminates and reaps the `log show` child and
produces distinct `cancelled` or `timedOut` envelopes. Native tests prove both
paths and verify no child remains running.

Saved diagnostic reports use a bounded importer in `src-tauri` built against
the admitted report format. It reuses the existing ESP archive implementation's
preflight, bounded-write, cleanup, and hostile-fixture patterns where their
contracts match. Every path, type, encryption, collision, integrity, or limit
violation fails the whole container before parser dispatch. Preflight covers
both raw and normalized member names, including separator, case-fold, and
Unicode-normalization collisions. It rejects:

- a selected container above the raw-byte cap or preflight-read budget;
- absolute and parent-traversal paths;
- normalized slash/backslash, case, Unicode, and duplicate-member collisions;
- symlinks, hard links, devices, and unsupported member types;
- encrypted or unsupported-compression members;
- CRC or declared/actual byte mismatches and decode-work overruns;
- per-member, actual streamed-byte, aggregate expanded-byte, member-count, and
  depth limits;
- nested containers, unless a later observed contract independently specifies
  and bounds them;
- cancellation, timeout, incomplete extraction, and permission-denied states.

Extraction occurs only in a unique current-user-private temporary root, never
overwrites an existing path, and cannot write outside that root. RAII cleanup is
proved on success, error, cancellation, timeout, and unwind. Member identities
and dispatch order are deterministic. Error output is bounded and redacted so
an identity-bearing unsafe member name cannot leak through logs, IPC, or retained
evidence.

The importer opens the selected file once, establishes its file identity and
raw SHA-256 under the raw-byte cap, and uses that same stable handle for
preflight and decoding. It never validates one path read and reopens the path for
extraction. The verified raw digest becomes the container identity in importer
provenance.

The pure report parser receives decoded members plus importer provenance. A
direct app-log member is actually passed to #368's parser; a marker saying it
"would delegate" is insufficient.

### Android imported-artifact boundary

Android support is import-only. CMTrace Open does not assume ADB, work-profile
filesystem access, app invocation, or diagnostic upload access.

Android format classification and record interpretation remain in the Android
leaf. #371 first implements the observed format directly. Only archive-safety
primitives that were proven by #369 and are genuinely identical are reused;
there is no speculative cross-platform container abstraction. Stable support
requires at least one safely acquired, sanitized, version-identified artifact
for each format claimed. Generic ZIPs and logcat are negative inputs.

An incident or upload identifier is evidence that an identifier was present,
not proof that an upload succeeded.

All import-only leaves, including #369, #371, and #372, have an application
acceptance route: desktop selection and dispatch, decoding, admission, analyzer,
and canonical redacted export. A pure parser test alone cannot close an import
leaf.

### Bounded direct-file and import reads

The source-envelope invariants are not Windows-only. Every direct log, supplied
report, and imported file, including #361, #368, #371, and #372, has a leaf-owned
versioned envelope with the complete status vocabulary and explicit raw-byte,
read-work, decode-work, record, and elapsed-time limits. The native side opens a
selected file once, establishes a stable handle/file identity and SHA-256 under
the raw cap, and streams or incrementally decodes from that same handle. It does
not perform an unbounded whole-file read or reopen a validated path.

Cancellation and timeout remain distinct coverage states and stop further
decode work. Oversized input is rejected or capped according to the leaf's
declared contract before analysis; partial bytes cannot become complete-empty
evidence. Every direct/import leaf has tests for raw oversize, record/decode cap,
cancellation, timeout, and path replacement after open. Leaf-owned envelopes
land first; a common stable-file helper is extracted only after a second
consumer proves identical handle, hashing, and limit responsibilities. #369's
archive rules add container/member constraints on top of this baseline.

### Source-contract admission

A stable parser grammar requires an observed, sanitized anchor. The current
Intune corpus contract is replaced rather than extended: `syntheticFixture` is
removed and every fixture declares exactly one provenance class:

- `observedSanitized`: a lab or public product artifact whose retained bytes
  anchor grammar and product semantics;
- `syntheticMutation`: a named mutation of an admitted anchor, used only for
  malformed, collision, boundary, and reducer-invariant assertions;
- `generatedImporterSecurity`: a generated archive or container used only for
  importer security properties.

Every manifest records:

- product and platform;
- app/agent version and management mode when applicable;
- collection flow and artifact origin;
- container/member schema and encoding;
- timestamp and timezone behavior;
- rotation or rollover behavior;
- privacy classes and sanitization transformations;
- SHA-256 of the retained sanitized fixture;
- sanitization method and review state;
- an opaque controlled-lab capture ID and SHA-256 of the raw lab capture;
- a closed capture-profile ID, privacy-safe command template using only the
  fixed controlled-root placeholder, and sanitizer tool/revision;
- source-contract and profile versions;
- the anchor reference for a mutation;
- the exact assertions the fixture is allowed to prove;
- capture-role and independent-review attestations over the digest of the
  complete canonical manifest projection.

The canonical manifest projection is a closed, deterministically encoded
object containing every support- or provenance-bearing field above: provenance
class, product, platform, app/agent version, management mode, collection flow,
artifact origin, container/member schema, encoding, time and rotation behavior,
privacy classes, sanitization transformations and review state, fixture and raw
digests, capture ID, safe profile/template, sanitizer tool/revision,
source-contract/profile versions, anchor reference, and allowed assertions. It
excludes only the signatures that cover its digest. The validator rebuilds
that projection from the committed manifest and compares every field before it
accepts either signature; a signed anchor cannot be relabeled to a different
product, version, mode, schema, or profile.

The capture tool writes the exact command only to the private controlled-lab
attestation before sanitization. The committed manifest carries the safe
profile/template, never a user path or free-form command. The admission
validator cross-links the private attestation, sanitizer output, and repository
manifest; `observedSanitized` cannot be selected with only a hand-authored
manifest. The same closed-schema privacy scan used for acceptance records runs
over every committed fixture manifest and rejects usernames, profile paths,
SIDs, accounts, tenant/device identifiers, private domains/URLs, tokens,
secrets, long encoded values, and unknown free-form provenance fields. The
shared fixture harness also rejects assertions outside the provenance class. A
synthetic mutation cannot establish a product grammar, version allowlist,
source identity, locale alias, terminal semantic, or support claim. Generated
hostile inputs prove importer behavior only.

A leaf may inherit an already-admitted source section only by referencing the
exact anchor manifest, source-contract/profile version, byte schema, and allowed
assertion that it consumes unchanged. Similar names or semantics are not
inheritance. The validator resolves the reference and rejects missing, broader,
or version-mismatched claims.

Phase 0 audits all current Intune manifests, including the 86 explicitly
synthetic and 40 unclassified manifests present at the audited baseline. Every
implemented leaf must gain an observed anchor for each grammar/version/locale it
claims. Until then the unsupported claim is deleted, the affected assertion is
downgraded to experimental, or the leaf remains non-public. This requirement
explicitly supersedes child-issue wording that allowed a merely synthetic
fixture to establish support. Known admission debt in #354, #366, #368, #370,
and #372 is scheduled in the closure ledger rather than hidden behind aggregate
tests.

Real customer artifacts, tenant identifiers, accounts, device identifiers,
serials, SIDs, tokens, private domains, private URLs, and raw diagnostics are
never committed. Raw lab captures stay outside the repository. Only minimal
sanitized derivatives and their provenance manifests enter the corpus.

Raw lab captures and raw acceptance output live only in the dedicated private
capture root during sanitization/review. The attestation records `deleteByUtc`;
the validator permits no more than seven days and epic closure requires the
state `deleted` with deletion time recorded. No customer artifact is eligible
for this lab workflow.

Those states are not trusted as self-authored JSON. Candidate `C` contains an
OpenSSH `allowed_signers` policy with distinct capture, run, review,
lab-cleanup, integration, and integration-review roles; no fingerprint appears
in more than one role. After sanitization, the capture tool signs a receipt
containing the canonical manifest digest and its capture/run attestation
digest. An independent reviewer with a different trusted key verifies the
bytes, support claims, and allowed assertions, then signs that same canonical
manifest digest plus the capture receipt digest. The cleanup tool closes capture handles,
deletes the raw paths, verifies that reopen and metadata lookup both report
absence, and signs a cleanup receipt binding the same canonical manifest and
capture digests, state `deleted`, deletion time, and both absence results. The
validator reconstructs the canonical projection, compares every manifest field
byte-for-byte, uses `ssh-keygen -Y verify`, rejects a capture and review signed
by the same fingerprint, and requires the cleanup receipt before closure. Only
privacy-safe receipts and public signatures are committed.

Official documentation can define collection behavior, but it cannot replace
a fixture for an undocumented wire grammar. Generated hostile archives can
prove importer safety, but they cannot prove a product schema.

### Redaction and publication boundary

Accepted ADR-004 Revision 1 is a shared foundation, not a final checklist
adjective. Accepted ADR-004 Revision 2 resolves the questions Revision 1 left
open. Before a new native or import route becomes callable, each Intune lane
converges on one export contract:

- the only publicly constructible published analysis/export type is projected;
- local-preserving intermediate analysis and reduction types are explicitly
  named, private to their lane, have no serialization implementation, and
  cannot cross Tauri IPC;
- versioned acquisition-input types may serialize for native-to-pure contract
  tests, but live in an input-only namespace and are forbidden as Tauri command
  responses, emitted events, saved exports, or clipboard payloads;
- projected DTO fields are private; projected DTOs and their opaque
  `ProjectedText`, `SensitiveToken`, and `RestrictedMarker` fields implement
  `Serialize` but not `Deserialize` or `Default`, expose no mutable/public
  constructors, and can be created only by the projection owner;
- every published analysis requires a caller-owned opaque
  `RedactionContext`; the no-context behavior for every Intune lane is
  **decline**, expressed by a required parameter rather than a fallback;
- `RedactionContext::try_fill` owns a non-`Copy`
  `Zeroizing<[u8; 32]>`, lets the caller fill it only through a temporary mutable
  borrow, exposes no raw-array constructor, accessor, parser, serializer,
  `Debug`, or semantic identity, is not emitted, and clears on every drop/error
  path;
- the desktop fills that owned storage directly with its existing OS-backed
  `getrandom` dependency for each analysis/import/collection operation and
  shares it only among outputs belonging to that operation; entropy failure
  declines analysis and never supplies a zero/default key;
- token derivation is HMAC-SHA-256 through the maintained `hmac` crate and the
  existing `sha2` dependency, domain-separated by schema version, lane, and
  semantic field;
- `Sensitive` values preserve equality only within one supplied context;
  different contexts do not compare equal;
- `Restricted` emits no value-derived representation: only absence or one
  constant marker, independent of content;
- projections are recursively exhaustive full constructions, with no
  clone-and-mutate, struct update, or default spread at any depth;
- masking grammar and derivation are shared where ADR-004 requires them, while
  each workload retains its own sensitivity classification and projection;
- no cross-lane or cross-analysis correlation is claimed.

The public context path is
`cmtraceopen_parser::intune::redaction::RedactionContext`. Its lower-layer
`derivation` and `management_text` owners are private within
`intune::redaction`; workload modules cannot publish or fork them.
`management_text` is only the byte-for-byte grammar already proven common to
Win32, scripts, remediations, configuration, and compliance. The current
app-owned `intune::apps::windows::common::redaction` path is deleted after those
five imports move. Store, Autopilot, ESP, Company Portal, macOS, Android, and iOS
retain their workload grammars. #366 shares context and derivation in the pilot,
not a speculative universal text grammar. Later grammar convergence requires an
observed corpus, parity tests, and an explicit ownership decision.

The shared context/minter does not land as unused horizontal infrastructure.
The existing ESP application route is its first complete consumer: the session
manager owns one context per analysis session; `analyze_esp_evidence`, session
updates, command responses, export, and frontend state move atomically to
parser-projected types; raw `EspDiagnosticsSnapshot`/`EspSessionUpdate` IPC and
event wires are deleted. #366 is the first child-issue consumer and retains its
proven ESP-derived text grammar while sharing the context and derivation. Each
subsequent lane atomically replaces its private minter/projection and public call
sites; no lane exposes old and new projection APIs in parallel. Existing
application-wired leaves migrate before new routes are added.

ESP file replay is retained through one replacement contract in that same
slice. Export writes a closed projected `EspSessionCaptureV2` that is
`Serialize`-only. Tauri, not the frontend, opens an imported capture once,
establishes a stable handle identity and SHA-256 under raw-byte and elapsed-time
caps, and deserializes the file into a distinct closed
`EspSessionCaptureImportV2` input that is `Deserialize`-only, denies unknown
fields, and accepts exactly version 2. The pure replay entry point requires a
fresh operation-scoped context, validates the complete V2 structure, treats
every imported Sensitive/projected-text string (including `cti1_`-shaped text)
as untrusted raw input, and returns only newly projected frontend state. It
never reconstructs a local-preserving snapshot. Restricted positions accept
only the V2 constant marker or absence.

For replay, each imported `ProjectedText` is segmented around every
non-overlapping fixed token span (`cti1_` plus exactly 43 URL-safe Base64
characters) at the start, middle, or end. Each complete old-token byte string
is reminted under the fresh context and the field's semantic domain; intervening
text runs through the ordinary workload grammar, and newly minted output is not
rescanned. Standalone `SensitiveToken` input uses the same remint rule. The
closed V2 field position selects this mandatory replacement; token shape never
proves safety or permits pass-through.

The current V1 envelope and bare-snapshot readers, direct frontend JSON parser,
TypeScript capture DTO and guard, permissive future-version check, tests, and
wires are deleted. There is no V1 migration or parallel reader. V1, bare,
unknown-field, malformed, oversized, timed-out, and future-version files yield
no partial state and only a closed `PublicDiagnostic`; imported values and file
names cannot enter its text. Replay preserves validated conclusions and
coverage, but intentionally rekeys equality under the importing operation.

A shared conformance harness runs against every Intune lane. It proves same
context/equal input equality, different-context inequality, domain separation,
different restricted inputs producing identical output, token-shaped raw input
being treated as raw, entropy failure declining without a zero/default key, and
unchanged non-sensitive conclusions. It injects a unique sentinel into every
sensitive/restricted field and nested unknown-value position and recursively
asserts that neither the sentinel nor an unprojected variant appears anywhere in
serialized output.

The ESP V2 replay cases additionally place exact old tokens at the start,
middle, and end of projected text, repeat them within one semantic domain, and
exercise standalone token fields. Serialized replay output must contain none of
the imported token bytes; every replacement differs from the imported token,
while repeated old tokens remain equal within the fresh replay context/domain.
Compiler visibility and missing serialization traits prevent local-preserving
types from reaching the publication boundary; Tauri and frontend tests prove
only projected values can reach IPC, event emission, file save, clipboard,
logs, errors, and retained acceptance evidence.

Recursive exhaustive construction is enforced exactly as Revision 1 specifies,
not attributed to a runtime helper. Each lane's independent review record lists
every projection and nested helper and confirms full struct literals with no
clone-then-mutate, struct update, or default spread. Once written that way, the
compiler rejects every later model field until the projection handles it.

Logs and errors use
`cmtraceopen_parser::intune::diagnostic::PublicDiagnostic`, whose fields are
closed enums, bounded counts, safe source kinds, and non-value-derived codes; it
accepts no free-form artifact text, path, external error string, or record
value. Local-preserving intermediate analysis/reduction types implement neither
`Debug`, `Display`, `Error`, nor `Serialize`; versioned acquisition-input types
retain their explicitly input-only serialization contract. A checked-in
architecture test rejects direct `log`,
`println`, `eprintln`, and `dbg` calls in Intune parser/adapters and requires
diagnostics to pass through the typed public sink. Boundary errors map private
causes to stable codes before IPC or logging.

### Deterministic analysis contract

The executable determinism oracle is:

> Identical admitted normalized inputs, source schema/profile version, and
> `RedactionContext` produce byte-identical canonical redacted analysis JSON.

Acquisition metadata that legitimately varies is segregated from that canonical
analysis projection. Reducers and serializers cannot use wall-clock time,
randomness, host paths, directory enumeration order, or process-local IDs.
Every reducer's conformance suite covers input permutations, duplicates,
irrelevant evidence, equal and malformed timestamps, archive/member and
filesystem order, coverage ordering, and limit/cap selection. Maps are
canonically key-sorted and record vectors have explicit stable sort/tie-break
rules before serialization.

### Documentation and build gates

The parser crate root becomes a real rustdoc landing page with:

- a minimal parse/analyze example;
- the four workload roots;
- links only to implemented leaves;
- a clear distinction between supplied-artifact and native-adapter contracts;
- schema/version and conservative-coverage policy.

The parser README mirrors the implemented family rather than describing
Intune as only IME extraction.

CI enforces, on the appropriate jobs:

```text
cargo test --locked -p cmtraceopen-parser
cargo test --locked -p cmtrace-open --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
npm test
npx tsc --noEmit
cargo fmt --check --all
git diff --check
```

The current formatting drift is corrected in a dedicated mechanical commit or
PR before the format gate is enabled. That diff contains no behavior changes.

## Work breakdown and merge order

### Phase 0: program truth and foundations

1. Publish this refreshed design and accepted ADR-004 Revision 2, then publish
   the task-by-task implementation plan.
2. Reconcile #356's stale checklist and annotate closed children whose original
   acceptance remains unproven.
3. Reopen an original child when its own acceptance criteria are still unmet;
   create a new child only for shared work that no existing issue owns.
4. Land the mechanical formatting baseline and enable fmt, diff, and wasm CI
   gates.
5. Land the canonical IME/ESP path slice and delete only its assigned obsolete
   paths, `ParsedEspEventBatch`, manifest fallback, and ESP relaunch wire after
   migrating their consumers. Redaction projection APIs remain for their later
   ADR-governed vertical slices.
6. Replace the synthetic-only fixture harness with the provenance classes,
   audit all Intune manifests, and open each missing observed-anchor acquisition
   lane. Remove or downgrade unsupported claims rather than grandfathering them.
7. Under accepted ADR-004 Revision 2, land the lower redaction primitive with
   the existing ESP command/event/frontend route as its first end-to-end
   consumer. In the same slice, land V2 projected capture export and bounded
   native replay, and delete every V1/bare-snapshot/frontend-direct replay path.
   Then migrate #366 as the first child consumer. Migrate each remaining lane in
   its own vertical slice before adding a new application/native route for that
   lane; do not block one leaf on unrelated leaf migrations.
8. Before any final candidate can be frozen, land the complete C-resident
   acceptance trust toolchain: immutable child/program-gate/aggregate schemas
   and ledger, exact record-path inventory, privacy and N/A policy,
   role-separated signer policy, canonical run/review/cleanup/final-endorsement
   builders and validators, clean-candidate build runner and exact Cargo
   artifact matcher, replacement-free Git wrapper and raw object-ID/tree/blob
   verifier, aggregate generator, and fresh-full-clone closure verifier. Its
   negative tests cover dirty and transiently changed candidates, signer/nonce
   swaps, symlink/type/filter/LFS indirection, replacement refs, grafts,
   alternates, malformed object IDs, omitted/extra blobs, and C/E/M tree drift.
9. Land the docs.rs landing page from implemented reality.

### Phase 1: close debt in existing vertical slices

1. Close #354's named timestamp, component, collision, serialization, CRLF,
   obsolete parse-selection wire, provenance, access-denied, and Windows
   acceptance gaps.
2. Close #357's degraded-artifact, true-negative, timestamp-trust, and admitted
   source-contract gaps; its desktop application handoff is owned explicitly by
   Phase 2.
3. Land #359's typed script consumer and delete only its duplicate event-tracker
   semantics.
4. Land #360's typed remediation consumer and delete only its duplicate
   event-tracker semantics.
5. Delete #367's complete legacy reader surface, then reprove canonical JSON
   acquisition and analysis.
6. Admit or narrow #366 and #372 source claims, then run their complete native
   or desktop-import routes at the exact committed head.
7. Correct only reproduced gaps and update tracker state from retained evidence.

### Phase 2: native handoffs for closed pure analyzers

1. Land #357's typed supplied-log desktop selection, Tauri dispatch, analyzer,
   projected export, and TypeScript consumer atomically, with no parallel
   generic Win32 response wire.
2. Land #358 as the first leaf-owned native-source vertical slice: source
   reader, source-level envelope, Store projection, analyzer call, and
   application acceptance atomically.
3. Land separate Autopilot, configuration, and compliance vertical slices for
   #362, #363, and #364. Extract shared EVTX/report decoding only when the second
   consumer demonstrates identical responsibilities.
4. Admit or narrow #368 and #370 source claims, then replace the parallel macOS
   direct-log and unified-log paths without native schema interpretation.
5. Run per-leaf native Windows and macOS acceptance on exact committed heads.

### Phase 3: remaining workload implementations

1. Implement #365 as leaf-owned registry, Windows Update event, update-log, and
   supplied-policy source slices; one source works end to end before the next is
   added.
2. Implement #361 package evidence as the first working vertical slice, then
   add shell-script evidence over the proven shared raw admission layer.
3. Implement #369 only after a saved-report schema is admitted and #368 native
   handoff is stable, using the existing ESP archive contract where compatible.
4. Implement #371 only after an Android artifact schema is admitted; reuse only
   archive-safety primitives proven identical by the observed format.

Observed-source acquisition for every unanchored leaf starts during Phase 0 and
runs in parallel. It never relaxes the admission gate or substitutes official
collection documentation for product bytes.

### Phase 4: aggregate proof and epic closure

1. Freeze exact candidate `C` only after every implementation, fixture,
   document, policy, signer allowlist, schema, validator, runner, and closure
   verifier is integrated. Materialize `C` into fresh runner-owned detached
   checkouts, prove their source/tree/lock cleanliness, and run every focused
   suite plus the full parser, Tauri, TypeScript, Clippy, wasm32, formatting,
   and diff gates there.
2. Verify the root docs in `C` expose every implemented leaf and no placeholder
   claims support. A failure changes source, creates a new `C`, and restarts
   Phase 4.
3. Run the shared redaction and determinism conformance suites against every
   public Intune output, the Windows x64
   `intune_esp_publication_acceptance` target, and the V2 replay/obsolete-wire
   frontend gates. Complete independent review/cleanup and construct the fully
   signed `espPublication` gate object bound to `C`.
4. On the required Windows MSVC host, run the Windows ARM64 build/package-only
   commands, hash their artifacts, independently review the result, and
   construct the fully signed `windowsArm64` gate object bound to `C`.
5. Run every row of the 17-child closure ledger and retain its exact SHA,
   executable/package hash, environment, source version, commands, artifact
   hashes, counts, coverage, and sanitized output; complete each record's
   independent review, cleanup, and final endorsements.
6. Construct and distinctly sign the aggregate over the frozen child blobs and
   the already-complete `espPublication` and `windowsArm64` objects. Commit only
   those enumerated regular evidence blobs as child `E` of `C`, then run the
   replacement-free raw-object validator against `C..E`.
7. Integrate `E` as `M`, fetch remote `main`, and mechanically reprove the
   complete C/E/M object, record, aggregate, signer, privacy, and tree contract
   in a fresh full unshared clone before any tracker change.
8. Reconcile every child issue and PR against its evidence before checking its
   epic box.
9. Close #356 only after current `main`, not a feature branch, satisfies the
   program exit criteria.

## Per-slice development contract

Every implementation slice follows:

1. fresh isolated worktree from exact current `origin/main`;
2. failing focused test that demonstrates the missing contract;
3. smallest production change that makes it pass;
4. focused green tests;
5. full relevant parser/native/frontend gates;
6. strict Clippy, wasm32, formatting, and diff checks;
7. exact committed-range review and independent verification;
8. commit and push before ending the cycle;
9. issue comment with exact branch, SHA, commands, counts, review state, native
   state, and remaining gaps;
10. merge only when no known P1 or contract blocker remains.

Recovery branches are inspected with `git show` or isolated donor worktrees.
They are never used as integration bases.

## Closure evidence and native acceptance

Every row below produces a machine-readable sanitized record under
`docs/acceptance/intune/records/`. Candidate `C` already contains the immutable
ledger, JSON schema, privacy policy, not-applicable allowlist, role-specific
trusted signers, enumerated record-instance paths, and validator outside that
records directory. The signer policy freezes role-specific OpenSSH principals,
namespaces, and pairwise-distinct fingerprints for `capture`, `run`, `review`,
`lab-cleanup`, `integration`, and `integration-review`; a signature valid for
one role is invalid for every other role. The validator never opens a
checkout/worktree record path; its sole evidence byte source is the committed
Git blob described below. It rejects
missing fields, malformed hashes, unapproved not-applicable reasons, records
whose issue number or test target is not in the ledger, and privacy violations
including user/profile paths, SIDs, account names, tenant/device identifiers,
private domains/URLs, tokens, long encoded values, and raw stdout/stderr.
Free-form diagnostics are not an evidence field. The record binds:

- full git SHA, git tree SHA, dependency-lock hashes, and SHA-256 of the actual
  executed test process, application executable, or package as applicable;
- OS edition/build/architecture and hardware architecture;
- product, app, agent, and source versions;
- adapter/collector/profile versions and privilege context;
- SHA-256 of each input artifact without its private path or identity-bearing
  name;
- exact commands, attempted/observed counts and bytes, active limits,
  coverage states, assertions, and sanitized output hashes;
- capture/run, distinct-review, and cleanup receipt digests plus verified signer
  fingerprints;
- cleanup state, deletion time, and separate reopen and metadata-lookup absence
  results; and an explicit pass, fail, or not-applicable result.

GitHub and repository evidence contains only sanitized commands, hashes,
summaries, counts, coverage, and non-sensitive projected output. Raw source and
raw program output remain in the controlled lab root only until attestation and
review, with a maximum seven-day `deleteByUtc`; closure requires every record to
say `deleted` and include its deletion time. A transport failure, unavailable
lab, or prepared-but-unrun package is not a pass.

The receipt graph is explicit and acyclic. Each body below is a closed canonical
object; a receipt is that body plus a detached OpenSSH signature over its
SHA-256. Signature bytes are never members of the body they sign.

1. The run body contains every execution truth field above: candidate `C` and
   tree, dependency-lock and executable/package hashes, random nonce,
   start/end times, complete environment and source versions, adapter/profile
   and privilege, exact privacy-safe commands and exits, input/output hashes,
   counts, limits, coverage, assertions, result, cleanup deadline, and
   fixture/capture receipt digests. The trusted `run` role signs it.
2. Before raw cleanup, the independent reviewer inspects the run and signs a
   review body containing the run-body digest, run-signature digest and
   fingerprint, reviewed assertions, and review decision. The trusted
   `review` fingerprint must differ from the run fingerprint.
3. The cleanup tool signs a cleanup body containing the run-body digest,
   candidate `C`, nonce, state `deleted`, deletion time, and distinct reopen and
   metadata-lookup absence results. Only the frozen `lab-cleanup` role is valid.
4. The final acceptance body contains an exact copy of the run body plus the
   body, signature, fingerprint, and digest references for all three receipts.
   It excludes only its two final endorsement signatures. After cleanup, the
   same run fingerprint and the same independent-review fingerprint each sign
   the final-body digest under their respective roles. Neither final signature
   is included in that digest.

The committed record contains those four bodies/signatures and no independent
truth field outside the final body. The validator reconstructs each canonical
body, verifies every role and link in that order, compares every duplicated
field byte-for-byte, and rejects a missing, circular, differently keyed,
different-candidate, or prior-run receipt. The final run/review endorsements
therefore cover the complete record, including cleanup, without a receipt
depending on a signature that depends on itself.

Every acceptance build starts in a new empty runner-owned root materialized as
a fresh detached worktree or clone at `C`; no developer checkout is eligible.
All ref and object resolution uses the replacement-free object protocol below.
Before dependency materialization, the runner proves `HEAD == C`,
`HEAD^{tree} == C^{tree}`, empty index and working-tree diffs, empty
`git status --porcelain=v1 --untracked-files=all`, no entry from
`git clean -ndx`, and exact clean submodule gitlinks. It hashes and compares all
dependency locks to `C`. Dependency, target, cache, and packaging directories
are newly created and enumerated by the runner. After dependency setup, tracked
candidate files are made read-only and every writable build/test root is
external or explicitly declared; a test that needs a mutable fixture receives a
hashed temporary copy. The runner repeats the complete HEAD/tree,
index/worktree, submodule, lock-hash, and undeclared-output checks (1)
immediately before compilation, (2) after compilation and immediately before
hashing/launching the selected executable, and (3) immediately after execution.
A dirty worktree, inherited ignored file, transiently writable tracked input,
modified lock, undeclared output, or source/tree mismatch invalidates the
record.

Final acceptance avoids a self-referential commit hash. Let `C` be the exact
integrated executable candidate. All 17 runs and package hashes bind to `C`.
Their records land in one evidence-only child commit `E` whose parent is `C`.
The validator and policy loaded from `C` hash-bind themselves in the aggregate
record and require every changed path in `C..E` to be one exact record-instance
path enumerated by `C`; `E` cannot change the ledger, schema, validator, privacy
rules, signer allowlist, or N/A policy. Let `M` be the exact remote `main`
integration commit; it may equal `E` or contain it through a merge, but its
tree must be exactly `E`'s tree: `git rev-parse M^{tree}` equals
`git rev-parse E^{tree}`. This freezes the complete source, fixture, provenance,
documentation, policy, and evidence tree, not only executable inputs. If any
non-record path changes after `C`, or any path changes after `E`, the candidate
is invalid and affected rows rerun. Thus the tested SHA remains exact without
asking a commit to contain its own hash.

All trust-bearing Git commands run through one checked-in wrapper with
`GIT_NO_REPLACE_OBJECTS=1` and Git's `--no-replace-objects` option. The wrapper
uses an isolated configuration, unsets `GIT_REPLACE_REF_BASE`, object-directory,
alternate-object-directory, and inherited worktree/common-directory overrides,
and rejects any `refs/replace/*`, graft file, object alternate, shallow state,
or promisor/partial-clone configuration. A linked worktree is acceptable for a
development slice, but not by itself as the final object-store proof.

The validator gets the repository object format from the verified repository
metadata and independently recomputes every accepted Git object ID as the hash
of `type + " " + decimal_byte_length + NUL + exact_raw_bytes`. It does this for
the `C`, `E`, and `M` commit objects, every tree object traversed to an evidence
path, and every evidence blob, then parses parent/tree/path relationships from
those verified raw objects. A Git-reported ID whose recomputed ID differs is a
hard failure. The final closure verifier repeats the complete C/E/M, signer,
schema, privacy, object-mode, object-ID, blob-byte, aggregate, and tree-equality
checks in a new full clone fetched from the expected remote URL at
`origin/main == M`, with no local-object sharing, alternates, replacements,
grafts, shallow state, or promisor objects.

Path permission is not enough. For every evidence JSON path, including the
aggregate, the validator reads `E`'s tree entry and requires exactly mode
`100644`, object type `blob`, and one object ID. Symlinks, executable blobs,
trees, gitlinks/submodules, missing entries, renames, copies, and type changes
are rejected. It reads bytes only from the replacement-free, raw-ID-verified
blob object and runs JSON-schema validation, receipt verification, and the
privacy scan on those exact bytes; it never follows a filesystem path.
Candidate `C` must give every record path an unspecified Git `filter`
attribute, and the validator rejects a Git LFS pointer header; no other pointer
or indirection schema is permitted. Because `.gitattributes` cannot change in
`C..E`, a clean/smudge rule cannot be added by the evidence commit.

The closed aggregate body contains candidate `C` and tree, frozen
ledger/schema/validator/privacy/signer-policy hashes, and a sorted entry for
each of the 17 child records: exact path, mode, Git blob object ID, byte length,
and SHA-256 of the bytes read from that object. It also contains the complete
`espPublication` and `windowsArm64` gate objects described below. No pass,
not-applicable, command, hash, or platform assertion exists outside that body.
The validator recomputes every child entry from `E` and rejects an omitted,
duplicate, or additional child blob.

Each program-gate object uses the same acyclic run/review/final-endorsement
construction as a child record. `espPublication` also requires the trusted
cleanup receipt when private lab bytes are used. `windowsArm64` has no private
source bytes and uses only the exact C-frozen cleanup N/A reason
`noPrivateCapture`; its run body and complete gate body still receive distinct
trusted run/review signatures. The aggregate body is then signed by the
`integration` role and a different `integration-review` fingerprint. The
aggregate cannot include its own object ID without becoming self-referential;
instead its exact canonical bytes are read from its own required `100644` blob,
privacy scanned, and authenticated by those two aggregate signatures. The
aggregate signatures are the only fields excluded from the aggregate-body
digest.

Each planned native target is built and executed by the checked-in runner from
`C` on the named source-bearing platform. The runner first builds and resolves
the one exact compiler artifact, then validates its native-acceptance test
contract before it launches that artifact:

In this protocol, `<target>` means only the native `cmtrace-open` acceptance
integration-test target named in the fourth closure-ledger table column, such as
`intune_issue_354_acceptance`. It never names the focused pure
`cmtraceopen-parser` target in the second column. Focused gates run separately
exactly as shown in that second column under `-p cmtraceopen-parser`. Native
artifact resolution remains `-p cmtrace-open --features full`.

```text
cargo test --locked -p cmtrace-open --features full --target <required-native-target-triple> --test <target> --no-run --message-format=json
<the sole matching compiler-artifact.executable> --list --format terse
<the sole matching compiler-artifact.executable> --list --ignored --format terse
<the same exact hashed compiler-artifact.executable> --ignored --nocapture
```

The immutable closure ledger entry for every native target includes a sorted,
non-empty `nativeIgnoredTests` list of its expected test names. Before the final
launch, the runner parses the terse names from both list invocations and
requires: the complete list is non-empty; the ignored list equals the complete list exactly; and both observed sorted lists equal `nativeIgnoredTests` exactly.
This proves every test compiled into that target is deliberately ignored before
`--ignored` is used, so an ordinary test cannot be silently skipped.

Every acceptance function in every native target carries exactly
`#[ignore = "native acceptance runner only"]`. The runner's source validation
reads the frozen target source named by the ledger and requires that exact
annotation for every `nativeIgnoredTests` function; a missing or different
annotation fails source review and runner validation. The ledger and source
review may not fabricate a target or test name merely to satisfy this protocol.

`cargo metadata --locked --no-deps` from `C` supplies the one expected
`cmtrace-open` package ID and integration-test source path. A compiler-artifact
matches only when its `package_id` is that exact ID, `target.name` is the ledger
target, `target.kind == ["test"]`, `target.src_path` is the expected file,
`profile.test` is true, `fresh` is false, and `executable` is non-null inside
the runner's declared target root for the required native target triple. The
runner also verifies the executable's machine type against that triple. Zero or
multiple matches are a hard failure; build-script, example, unit-test, and
dependency artifacts cannot match.

After the post-build/pre-launch cleanliness gate, the runner hashes that exact
executable, launches that exact path, hashes it again after exit, requires the
hashes to match, and records that digest as the actual executed test process.
It also hashes every production application executable or package exercised by
the test. Each pure target is run exactly as shown in the ledger. The native
test invokes the application acquisition/import boundary, round-trips the
leaf-owned wire envelope, calls the production parser and analyzer, and
verifies the canonical redacted output. It may not substitute a fixture-only
call to the parser.

### Native ignored-test contract self-check

This document-only check validates the frozen protocol wording; it does not
build or execute a native target:

```bash
set -euo pipefail
design=docs/superpowers/specs/2026-08-29-intune-parser-family-closeout-design.md
accepted_docs=(
  docs/architecture/decisions/ADR-004-redaction-scope-revision-2.md
  docs/superpowers/plans/2026-08-30-intune-parser-family-phase-0a-truth-and-quality-gates.md
  "$design"
)
em_dash="$(printf '\342\200\224')"
en_dash="$(printf '\342\200\223')"
protocol="$(sed -n '/^Each planned native target is built and executed/,/^### Native ignored-test contract self-check$/p' "$design")"
printf '%s\n' "$protocol" | rg -F -- '--list --format terse'
printf '%s\n' "$protocol" | rg -F -- '--list --ignored --format terse'
printf '%s\n' "$protocol" | rg -F -- 'complete list is non-empty'
printf '%s\n' "$protocol" | rg -F -- 'ignored list equals the complete list exactly'
printf '%s\n' "$protocol" | rg -F -- '#[ignore = "native acceptance runner only"]'
printf '%s\n' "$protocol" | rg -F -- '<target> means only the native `cmtrace-open` acceptance'
printf '%s\n' "$protocol" | rg -F -- 'It never names the focused pure `cmtraceopen-parser` target in the second column.'
printf '%s\n' "$protocol" | rg -F -- 'Focused gates run separately exactly as shown in that second column under `-p cmtraceopen-parser`.'
printf '%s\n' "$protocol" | rg -F -- 'Native artifact resolution remains `-p cmtrace-open --features full`.'
planned_rows="$(rg '^\| #(361|365|369|371) \|' "$design")"
test "$(printf '%s\n' "$planned_rows" | wc -l | tr -d ' ')" = 4
for doc in "${accepted_docs[@]}"; do
  test -z "$(rg -F "$em_dash" "$doc" || true)"
  test -z "$(rg -F "$en_dash" "$doc" || true)"
done
```

Expected: every assertion exits `0`; the four planned-target rows contain no em
dash, and the protocol continues to require deliberate ignored-only native
execution rather than ordinary-suite execution.

Because ESP publication/replay is a shared foundation rather than one child
row, the aggregate record has a required `espPublication` object bound to `C`.
It records the pure export/replay tests, frontend architecture tests, and a
Windows x64 native target `intune_esp_publication_acceptance`. That target
proves projected command/event/frontend state, V2 export, stable-handle bounded
native import, fresh-context replay, standalone and embedded token rekeying at
start/middle/end positions with repeated-span equality, raw/elapsed caps, and
no partial state for cancellation, timeout, malformed, unknown-field, V1,
bare, or future-version input. It also proves no imported token bytes survive
anywhere in serialized replay output. The checked-in obsolete-surface test
proves the old frontend parser, V1/bare readers, raw wires, and V1 DTOs are
absent. The aggregate validator rejects all 17 child records unless this object
passes.

Windows x64 runtime is required for every Windows row. Windows ARM64 is an
explicit program-wide compile/package-only gate for this epic. On a Windows
MSVC build host, candidate `C` must pass:

```text
cargo build --locked -p cmtrace-open --all-features --release --target aarch64-pc-windows-msvc
npm run tauri -- build --target aarch64-pc-windows-msvc --ci
```

The aggregate evidence record has a required `windowsArm64` object containing
the target triple, commands, pass result, produced executable/installer paths
reduced to safe artifact kinds, and SHA-256 hashes. It also says
`runtimeClaim: none` and `notApplicableReason: no required source-bearing ARM64
runtime in the approved matrix`. No ARM64 runtime-validation claim may be made.
If an ARM64 run is later available it is additional evidence, not a condition
silently changed mid-program.

| Child | Focused pure gate | Provenance gate | Required application/native proof |
| --- | --- | --- | --- |
| #354 | `cargo test --locked -p cmtraceopen-parser --test intune_device_inventory` | Observed sanitized Harvester, Adaptor, and RotationFailure anchors, or explicit experimental removal of any unanchored dialect; manifest hashes and bounded assertions | Windows x64 target `intune_issue_354_acceptance`: known-source discovery; disposable-profile/test-hive baseline, `.log_` register, detect, candidate launch, unregister, and restore with restoration asserted on success, failure, cancellation, and unwind; aggregate load, CRLF, tail, registry component, timestamp/offset behavior, and ACL denial |
| #357 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_win32` | Observed sanitized IME, AppWorkload, AppActionProcessor, AgentExecutor, and InstallerOutput anchors, or explicit narrowing of any unanchored source; degraded and true-negative corpus | Windows x64 target `intune_issue_357_acceptance`: desktop supplied-log dispatch through the typed Win32 analyzer and redacted export |
| #358 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_microsoft_store` and `cargo test --locked -p cmtraceopen-parser --test intune_windows_microsoft_store_semantics` | Observed sanitized IME, AppWorkload, StoreAgent, AppX event, package-fact, Assignments, and InstallerOutcomes anchors, an explicitly inherited admitted contract, or narrowing of an unanchored variant; truncated member marked incomplete | Windows x64 target `intune_issue_358_acceptance`: Store-owned AppX/package-fact acquisition envelope to Store analyzer, with denied/empty/partial distinctions |
| #359 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_scripts` | Observed sanitized AgentExecutor, IME, HealthScripts, and ScriptOutput anchors, an explicitly inherited admitted contract, or narrowing of an unanchored source | Windows x64 target `intune_issue_359_acceptance`: native command returns the typed script output consumed by TypeScript; no script semantic variant remains in `event_tracker` |
| #360 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_remediations` | Observed sanitized HealthScripts, AgentExecutor, IME, and ScriptOutput anchors, an explicitly inherited admitted contract, or narrowing of an unanchored source | Windows x64 target `intune_issue_360_acceptance`: native command returns the typed remediation output consumed by TypeScript; no remediation semantic variant remains in `event_tracker` |
| #361 | Planned target: the #361 issue-scoped plan must create before running: `cargo test --locked -p cmtraceopen-parser --test intune_macos_apps` | Observed sanitized daemon and per-user agent logs for every claimed app/agent version | macOS arm64 target `intune_issue_361_acceptance`: separate stable-handle discovery/open of the system daemon and current-user agent roots, rotations in deterministic order, denial/inaccessibility for each root, raw/record/decode/time caps and cancellation, package analysis, then script analysis, with separate outputs and explicit gaps |
| #362 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_autopilot` | Observed sanitized Autopilot event, diagnostics-report, `autopilot.identityFacts`, and `autopilot.espSession` anchors, explicitly inherited admitted contracts, or narrowing of unanchored sections | Windows x64 target `intune_issue_362_acceptance`: Autopilot-owned event/report envelopes to analyzer, including denied, unknown-version, and complete-empty cases |
| #363 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_configuration` | Observed sanitized or exactly inherited anchors for EventLog, Registry, DiagnosticReport, IME, CCM, Agent, PlainText, UnifiedLog, and Graph/SuppliedFact device/service authority, with explicit removal/narrowing of every unanchored source | Windows x64 target `intune_issue_363_acceptance`: configuration-owned event, registry, setting-report, and imported/supplied-fact envelopes to analyzer, with timezone, authority-side, unknown-node, and no-service-query coverage |
| #364 | `cargo test --locked -p cmtraceopen-parser --test intune_windows_compliance` | Observed sanitized compliance event/report, `custom_compliance`, `service_results`, `access_decisions`, and `device_context` anchors, explicitly inherited admitted contracts, or narrowing of unanchored inputs | Windows x64 target `intune_issue_364_acceptance`: compliance-owned event/report envelopes to analyzer, with incomplete evidence unable to prove compliance |
| #365 | Planned target: the #365 issue-scoped plan must create before running: `cargo test --locked -p cmtraceopen-parser --test intune_windows_updates` | Separate observed sanitized registry, Windows Update event, update-log, and supplied-policy anchors for each claimed profile | Windows x64 target `intune_issue_365_acceptance`: each leaf-owned source envelope plus combined reducer; unknown source yields no verdict, KB revision agreement and input-order independence are asserted |
| #366 | `cargo test --locked -p cmtraceopen-parser --test company_portal_windows_logs` | At least two observed sanitized supported-version anchors, or a narrowed single-profile contract | Windows x64 target `intune_issue_366_acceptance`: LocalState discovery, rotated aggregate load, access denial, append tail, and projected export |
| #367 | `cargo test --locked -p cmtraceopen-parser --test company_portal_windows_package_state` | Observed sanitized canonical AppX JSON anchor; no legacy-format provenance class exists | Windows x64 target `intune_issue_367_acceptance`: native AppX command emits canonical JSON, parser admits it, analyzer/export pass, and the old legacy reader/wire absence check passes |
| #368 | `cargo test --locked -p cmtraceopen-parser --test company_portal_macos_logs` | Observed sanitized logs for every supported version family; self-referential synthetic allowlists removed | macOS arm64 target `intune_issue_368_acceptance`: stable-handle known-source open, raw/record/decode/time caps, cancellation, content classification, canonical parser, malformed/rotation coverage, and projected export |
| #369 | Planned target: the #369 issue-scoped plan must create before running: `cargo test --locked -p cmtraceopen-parser --test company_portal_macos_diagnostics` | Observed sanitized saved report with container/member schema and #368 log anchor | macOS arm64 target `intune_issue_369_acceptance`: desktop import/dispatch, atomic archive admission, decoded member handoff to #368, analysis, redacted export, and cleanup on every outcome |
| #370 | `cargo test --locked -p cmtraceopen-parser --test company_portal_macos_unified_log` | Observed sanitized unified-log capture proving every supported subsystem/profile | macOS arm64 target `intune_issue_370_acceptance`: native query emits bounded bytes and metadata, pure `parse_capture` constructs the result, denied/malformed/capped coverage survives, and cancellation/timeout each terminate and reap the child with distinct coverage |
| #371 | Planned target: the #371 issue-scoped plan must create before running: `cargo test --locked -p cmtraceopen-parser --test company_portal_android_diagnostics` | Observed sanitized artifact for each supported format/version/mode; generic ZIP and logcat retained only as negatives | macOS arm64 desktop target `intune_issue_371_acceptance`: stable-handle file selection/dispatch, raw/record/decode/time caps, cancellation, atomic admission, decode, analyzer, projected export, and no device-access claim |
| #372 | `cargo test --locked -p cmtraceopen-parser --test company_portal_ios_console` | Observed sanitized Console export; each locale alias independently anchored or removed | macOS arm64 desktop target `intune_issue_372_acceptance`: stable-handle file selection/dispatch, raw/record/decode/time caps, cancellation, Console admission, analyzer, projected export, with automated-device-access explicitly not applicable |

The application import rows also run focused frontend tests proving selection
dispatches to the correct Tauri command and consumes only the projected schema.
The native target then invokes that command boundary with the admitted artifact,
so frontend mocking cannot stand in for decoding or analysis.

Hosted CI proves execution on its runner. It does not prove that a live source
exists or a known-source path works. A row passes only when its exact candidate
binary runs against its named source-bearing environment and the retained
record validates against the acceptance schema.

## Program exit criteria

Issue #356 can close only when all of the following are true on current
`main`:

- all 17 closure-ledger records validate and say pass, with explicit
  not-applicable reasons only where the ledger permits them;
- every child issue's named pure, provenance, application, and native contract
  is satisfied by its own record rather than an aggregate substitute;
- the epic checklist matches live verified state;
- no Intune leaf advertised as supported is empty or implementation-pending;
- every supported grammar/version/locale has an observed sanitized anchor, and
  synthetic/generated fixtures assert only what their provenance class allows;
- canonical IME/ESP ownership exists and the obsolete-symbol/wire/fallback
  absence gate passes, including deletion of #367's legacy reader;
- scripts and remediations each have one workload-owned typed analyzer and one
  application consumer path; shared AgentExecutor evidence does not create a
  generic second semantic ruleset in `event_tracker`;
- every native-source analyzer has an adapter-to-analyzer acceptance test;
- every import-only analyzer has a desktop dispatch-to-redacted-export
  acceptance test;
- required Windows x64 and macOS arm64 live acceptance is recorded against the
  exact executable/package hash; the Windows ARM64 build/package commands pass,
  their artifact hashes are retained, and no runtime claim is made;
- missing/denied/capped/skipped/unsupported/unknown-version/malformed/partial
  evidence remains explicit and cannot imply success;
- every public Intune analysis requires `RedactionContext` and is projected by
  construction; no raw/local-preserving value can reach IPC, emit, save,
  clipboard, logs, errors, or retained evidence;
- ESP replay accepts only projected capture V2 through the bounded native
  importer, returns freshly projected frontend state, and has no V1,
  bare-snapshot, or frontend-direct reader;
- shared redaction conformance proves per-analysis keyed equality,
  cross-analysis inequality, domain separation, value-independent Restricted
  output, token-shaped raw-input treatment, and unchanged non-sensitive
  conclusions for every lane;
- every lane's independent review record enumerates its recursive projection
  paths and confirms exhaustive construction; compiler checks then pin field
  coverage;
- canonical redacted bytes pass the determinism oracle under permutations,
  duplicates, irrelevant evidence, timestamp edge cases, enumeration order,
  coverage ordering, and caps;
- root rustdoc and README expose implemented reality;
- parser tests, strict Clippy, wasm32, formatting, diff, Tauri, and TypeScript
  gates pass;
- every native/package record was produced from a fresh candidate `C`
  materialization with exact tree/lock cleanliness and binds the actual
  executed process or package hash;
- remote `main` equals reviewed integration commit `M`; evidence commit `E` has
  tested candidate `C` as its parent; `C..E` changes only pre-enumerated record
  instances under the policy frozen at `C`; every evidence path is a directly
  validated regular `100644` Git blob with no filter/pointer indirection; the
  distinctly signed aggregate binds every child record object ID and byte hash
  plus the signed ESP-publication and Windows-ARM64 gate objects; and
  `M^{tree}` equals `E^{tree}`;
- all candidate/evidence Git resolution disables replacement objects and
  rejects grafts, alternates, shallow/promisor state, and inherited object-store
  overrides; every accepted commit, traversed tree, and evidence blob ID is
  recomputed from its raw type/length/bytes, and the entire proof passes again
  in a fresh full clone of remote `main`;
- no recovery-only branch is represented as accepted implementation.

## Non-goals

- No Graph, service-side Intune query, policy mutation, remediation execution,
  or diagnostic upload.
- No customer or tenant artifact enters the repository.
- No generic ZIP, logcat, event-log, or pipe-delimited parser is relabeled as
  an Intune product parser without product-specific admission.
- No UI redesign is required beyond the minimum wiring needed to exercise a
  native adapter and its canonical parser contract.
- No unrelated SCCM or whole-crate API migration is folded into this epic.
