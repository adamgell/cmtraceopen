# Windows Firewall log support implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve issue [#814](https://github.com/adamgell/cmtraceopen/issues/814) with dedicated Windows Firewall parsing, readable complete records, faithful local timestamps, snapshot/live-tail parity, and honest timeline coverage.

**Architecture:** A pure Rust firewall grammar and bounded stream feed the existing Log Explorer. A firewall-specific native decoder/checkpoint owns byte offsets and watcher generations. Optional firewall transport extends existing rows and responses. Timeline indexing and materialization retain schema/time provenance and validate one opened file handle per request. Other formats keep their existing lifecycle and decoding paths.

**Tech Stack:** Existing Rust workspace (`cmtraceopen-parser`, native package `cmtrace-open`/library `app_lib`), `encoding_rs`, Tauri, React, TypeScript, Zustand, Vitest and Playwright. No new dependency or signing change is planned.

**Spec:** `docs/superpowers/specs/2026-10-07-firewall-log-design.md`, approved by Adam on 2026-10-07 at 18:07:45 UTC. Exact signed documentation commit: `2564bbd1152e299e1191901f931b48a5a923bf7a`. Spec SHA-256: `16e0be5b1e9de258122339675888a55a3b7d24f0b53b92d5f7cb3fec7a804ba7`.

**Plan status:** Prepared for owner review. Product implementation, tests, builds, commits of this plan, pushes and PR creation have not been performed by this planning pass. The approved spec is unchanged.

## Owner review

The intended result is that a firewall log opens with its action, protocol and endpoints intact, local times remain exactly as logged, and continuing to tail it does not change interpretation. Missing evidence is visible. Timeline rows are included only when their timestamps can be placed absolutely.

Recommended execution: **Native execution in this existing isolated task**, using `superpowers:executing-plans`, one implementation slice at a time. The parser, byte decoder, ownership and transport contracts are tightly dependent; serial implementation makes those changes easier to inspect. Use independent review at the shared-interface checkpoints and on the final exact commit. Do not create another checkout or start parallel builders for this work.

Review these four delivery stages: pure parser/stream (Tasks 1–3), native open/tail and frontend transport (Tasks 4–6), viewer and timeline (Tasks 7–9), then final verification and a linked draft PR (Task 10). The plan and this execution method require owner approval before Task 1 changes product code. Approval of the design alone is not approval of this implementation plan.

## Global Constraints

- Continue branch `codex/issue-814-firewall-design` in `/Users/Adam.Gell/Documents/Codex/2026-10-07/task/cmtraceopen-issue814`. It contains only the signed approved spec above the investigated baseline; existing synthetic fixtures/tests remain untracked and preserved.
- Canonical GitHub `main` was refreshed during this planning pass through the connected GitHub app. It resolves to `497a7a06a882eaad886ea25ba11ac8a301e16630`, tree `74d4ba7b3272f56ea7af2b3dca17e99aff53a8d6`. GitHub comparison from that SHA to `main` is `identical`, ahead 0, behind 0, files 0. No base delta needs reconciliation now. Local `origin` is another local checkout and is not canonical remote evidence. Refresh canonical GitHub before implementation and again before PR; inspect any new delta before adapting the base. Never overwrite another checkout or force-push.
- Use only independently authored synthetic fixtures. Retain their README provenance, documentation IPv4/IPv6 and invented dates. Do not acquire, copy, sanitize, transform, publish or test with the private capture. Generate padding, encoding and chunk variations from synthetic strings only.
- Do not alter macOS signing configuration, manifests for signing, keychain settings, firewall settings, or deployment setup. Do not install or launch the native application. No merge or release. Browser-mocked acceptance is not native UI acceptance. Windows acceptance requires the exact candidate commit to run on Windows under separately authorized execution.
- No build or test is needed for planning. Before implementation compilation, report the exact command, checkout, target, concurrency and disk/resource estimate; verify the build slot is free. Use a fresh task-private Cargo target, one Cargo job, one test thread, one Rayon thread, and one frontend worker. Never use a shared target. Stop at a resource/authentication block and report the precise blocked action; do not silently install missing components or alter signing to get a green build.
- Keep the portable crate pure Rust and wasm32-compatible. Native identity, filesystem handles, decoder state and watch ownership stay in `src-tauri`. Do not generalize this into a new framework for all formats.
- Every implementation task records a focused RED result before its implementation and GREEN after it. Preserve historical baseline evidence, but replace `current_*` assertions that enshrine the defect with desired acceptance assertions. Do not retain a passing test whose requirement is that firewall rows remain IIS.
- Signed, issue-scoped commits follow approved execution and the repository's configured signing. Inspect staged paths before each commit. Current planning leaves the plan uncommitted. Push/PR work occurs only after owner approval of execution through that delivery checkpoint; the existing issue may be updated under Adam's explicit authorization. Adam alone merges.
- Source inference, observed parser tests, native adapter tests, browser tests, CI and actual Windows UI acceptance are separate evidence categories. Passing one never implies the others.

## Review Focus

1. No firewall information is lost or reassigned by schema changes, hyphens, missing PID, raw-copy or search.
2. Local/unknown wall-clock values never acquire an epoch through Rust, JavaScript, sorting, filtering, merging or timeline indexing.
3. Initial EOF followed by append converges with a full snapshot, including stable IDs, physical lines, full replacements and reversible coverage.
4. Decoder carry, line storage and warning samples are bounded; raw offsets belong to the bytes actually consumed from the identified handle.
5. Stale controls/workers cannot stop, commit to, or publish for a newer source/watch. Read/decode failures do not consume pending resets or advance checkpoints.
6. Timeline context and byte offsets describe one generation; errors reach users and invalidate stale caches instead of returning apparently successful empty evidence.
7. Genuine IIS, CCM, registry, Company Portal and ordinary timeline paths retain their prior contracts. No private data or signing changes enter the diff.

---

## Evidence already available

The earlier isolated investigation ran the normal portable parser API at the pinned baseline: 15 characterization tests passed, one prospective acceptance probe was ignored in that run, and its explicit run failed as expected with `parser=IisW3c`, message `- - → -`, and zero parse errors. This proves current parser behavior at that commit, not a historical regression or native UI acceptance. The one/two-row cases selected the generic parser; three rows selected IIS. The Local directive did not prevent UTC interpretation.

Task-private baseline artifacts are preserved alongside the checkout: `issue814-evidence.json`, `issue814-focused-test-output.txt`, `issue814-red-probe-output.txt`, and `issue814-synthetic.patch`. The fixture README and characterization test were inspected before this plan. They are the only source for extending the synthetic fixture set. Do not rerun a baseline build just for planning.

The requester confirmed the symptom in [comment 6040295484](https://github.com/adamgell/cmtraceopen/issues/814#issuecomment-6040295484). The authorized [status update](https://github.com/adamgell/cmtraceopen/issues/814#issuecomment-6043923613) states that synthetic reproduction is confirmed, design approved and the plan being prepared; it explicitly says no product fix or PR exists yet. Do not post that update again.

## File and responsibility map

Paths marked **new** are proposed; other paths were verified in the checkout. Co-locate focused unit tests unless an integration path is named.

| Area | Files | Responsibility |
|---|---|---|
| Synthetic acceptance | `crates/cmtraceopen-parser/tests/fixtures/issue_814/{README.md,firewall-local-18-fields.log,iis-w3c-control.log}`; existing `tests/issue_814_firewall_characterization.rs` (rename to `issue_814_firewall.rs` during Task 1) | Independent synthetic provenance, normal API acceptance, negative controls |
| Shared row model | `crates/cmtraceopen-parser/src/models/log_entry.rs`; **new** `models/firewall.rs`; `models/mod.rs`; `src/types/log.ts` | Optional firewall payload, enums, coverage and serialization parity |
| Pure parser | **new** `crates/cmtraceopen-parser/src/parser/windows_firewall.rs`, `firewall_stream.rs`; `parser/{mod.rs,detect.rs}` | Recognition, schema/time context, records, bounded framing and snapshot dispatch |
| Native decoder/snapshot | **new** `src-tauri/src/parser/firewall_source.rs`; `parser/mod.rs`; existing `fs_identity.rs` consumed | Same-handle bytes/identity/encoding, raw spans, continuation artifacts |
| Tail ownership | **new** `src-tauri/src/watcher/firewall.rs`; `watcher/{mod.rs,tail.rs}`; `state/app_state.rs`; `commands/{file_ops.rs,parsing.rs}` | Authoritative checkpoint, control admission, candidate commit, resets and scoped wire envelope |
| Frontend transport | `src/types/log.ts`; `src/lib/{commands.ts,tail-payload-validation.ts}` and adjacent tests; `src/hooks/use-file-watcher.ts` and tests; `src/stores/log-store.ts` and tests | Session tokens, validation, source epoch allocation, replacements and coverage snapshots |
| Viewer | `src/lib/{column-config.ts,date-time-format.ts,merge-entries.ts}` and tests; `src/components/log-view/{LogListView.tsx,InfoPane.tsx,DiffView.tsx}` and tests; **new** `FirewallCoverageNotice.tsx` and test | Fields, details, raw copy, exact display and coverage notice |
| Search/sort/filter | `src/stores/log-store.ts::getSearchableText`; `src/components/log-view/LogListView.tsx` Date/Time comparator; `src/lib/diff-entries.ts`; `src-tauri/src/commands/filter.rs`; **new** `src/lib/firewall-fields.ts` and test | Pure field access/search projection and within-source wall-clock sort; no epoch fabrication |
| Timeline | `src-tauri/src/timeline/{builder.rs,query.rs,models.rs,store.rs}`; **new** `timeline/firewall.rs`; `timeline/mod.rs`; `commands/timeline.rs`; `src/types/timeline.ts`; `src/stores/timeline-store.ts`; `src/components/timeline/{TimelineWorkspace.tsx,hooks/buildTimelineFromSources.ts,hooks/useTimelineEntries.ts,hooks/useIncidentDetail.ts}`; `src/workspaces/timeline/open-timeline-source.ts`; **new** `src/lib/timeline-errors.ts` and adjacent focused tests | Eligible index, sparse context, same-handle materialization, typed errors for initial build/rebuild and queries, stale-state presentation |
| Compatibility inventory | Existing parser-kind maps/validators found with `rg 'iisW3c|IisW3c'`, `LogEntry` literals, `src-tauri/src/commands/bundle_ops.rs`, `src-tauri/tests/parser_supported_formats.rs` | Exhaustive labels, bundle descriptions, wire validators and mechanical initializers only |
| End-to-end coverage/docs | **new** `e2e/firewall-log.spec.ts`; fixture README; approved spec and this plan; existing CI workflow read-only | Browser-mocked user flow and evidence/gate record; do not change CI to weaken gates |

Before touching each slice, repeat the focused call-site inventory for that interface and add exact paths to its commit record. A newly found consumer is not a reason to refactor unrelated formats.

## Interface contracts and dependency order

All new transport names use existing camelCase serde/TypeScript conventions. Missing optional firewall properties preserve existing non-firewall successful payloads. Use the repository's existing serializable integer convention and reject unsafe/invalid IDs in frontend validators.

**Portable, produced by Tasks 1–3 and consumed by Tasks 4–9:**

```text
ParserKind::WindowsFirewall / ParserImplementation::WindowsFirewall -> "windowsFirewall"
ResolvedParser::windows_firewall() -> ResolvedParser
  Dedicated / Structured / PhysicalLine / compatibility LogFormat::Timestamped

FirewallRecord { raw_line: String, declared_fields: Vec<String>,
  fields: Vec<FirewallField>, schema_origin: Header|Canonical|Unavailable,
  time_basis: Local|Utc|Unknown, record_kind: Traffic|EventsLost|Malformed,
  truncated: bool }
FirewallField { name: String, value: Option<String> }
LogEntry.firewall: Option<FirewallRecord>

FirewallContext: active validated schema plus time basis; Clone + equality
FirewallCoverage: fixed saturating counters and <=8 physical-line samples/category
FirewallRecordResult: entry plus its reversible coverage contribution
FirewallDelta: new entries, full-row replacements, cumulative coverage snapshot,
  observed physical-line coverage and context changes for interested callers
FirewallRowReplacement { expected_id: u64, expected_line_number: u32, entry: LogEntry }

MAX_FIREWALL_LINE_BYTES = 65_536 // decoded UTF-8 non-padding bytes
MAX_FIREWALL_WARNING_SAMPLES = 8 // per fixed category

FirewallStream::new(next_id: u64, next_line: u32) -> Self
FirewallStream::push_text(&mut self, text: &str, file_path: &str) -> FirewallDelta
FirewallStream::snapshot_eof(&mut self, file_path: &str) -> FirewallDelta
FirewallStream::context(&self) -> &FirewallContext
FirewallStream::reset_generation(&mut self, next_id: u64)
parse_record(line: &str, context: &FirewallContext,
  id: u64, line_number: u32, file_path: &str) -> FirewallRecordResult
```

Specify coverage fields explicitly in Task 1: NUL characters skipped, malformed records, oversized records, loss-event records, known lost-event count, unknown loss-count records, and records without an absolute timestamp. A capped malformed record must not count twice toward derived parse errors. Serialize initial coverage alongside parser output; native optional session metadata remains outside portable `ParseResult`. Finalize enum/string/null serialization with round-trip tests, not a parallel handwritten interpretation.

**Native, produced by Tasks 4–5 and consumed by Tasks 6 and 8–9:**

```text
FirewallEncoding = Undetermined | Utf8 | Windows1252 | Utf16Le | Utf16Be
FirewallDecoder: actual encoding, explicit-BOM flag, bounded undecided/scalar carry
FirewallSourceSnapshot: consumed raw offset, actual decoder,
  stream checkpoint and optional raw-row spans from the same snapshot
NativeParseArtifacts { result: ParseResult, selection: ResolvedParser,
  identity: Option<FileIdentity>, firewall: Option<FirewallSourceSnapshot> }
parse_file_with_artifacts(path: &str) -> Result<NativeParseArtifacts, String>
FirewallControlToken { source_session_id: String, watch_epoch: u64 }
FirewallCheckpoint: identity, generation, raw offset, decoder, FirewallStream
FirewallOpenState: source session, admitted/cancelled watch epoch, checkpoint,
  pending reset/encoding transition and publication ownership fence
FIREWALL_READ_CHUNK_BYTES = 65_536 // raw bytes per incremental read
```

`OpenFile` owns optional firewall open state. A worker may clone candidate state for parsing, but it commits only while holding the current owner's fence. Admission and cancellation compare both token fields before any old worker is stopped. Put testable admission/commit methods in `watcher/firewall.rs`; keep the Tauri command adapter thin. Never join a worker while holding a lock it needs. Existing Company Portal continuation stays separate.

Use `parse_file_with_artifacts` in `parser/mod.rs` for callers needing continuation/index state; retain `parse_file` and `parse_file_identified` for their ordinary snapshot-only consumers. Implement the artifact envelope without duplicating the parsed rows in memory: its optional firewall artifact owns only decoder/continuation/raw-span data while the result/selection/identity live once in the outer envelope. Single open, batch open and aggregate-folder open must all use the artifact path for firewall sources. Their optional native envelopes add `firewallSessionId`; tail adds `firewallControl`, `firewallReplacements`, `firewallCoverage` and a bounded decoding status. Test absent fields for non-firewall responses. Do not add native session/identity types to the portable model.

**Frontend, Tasks 6–7:** `parseTailPayload(value: unknown): TailPayload | null` keeps its existing signature and validates nested firewall fields. Source-owned store state allocates watch epochs across hook remounts. Command wrappers accept an optional `FirewallControlToken` on start/stop/pause/resume. Full-row replacement checks both expected ID and line; cumulative coverage replaces the source snapshot. `formatLogEntryTimestamp` expands its entry `Pick` to include optional `firewall` and returns logged firewall display tokens directly. Ordinary formats retain their current formatter.

**Timeline, Tasks 8–9:** `SourceRuntime` gains optional firewall identity/encoding/sparse referenced contexts. `FirewallReadSession` owns one validated opened handle per source per request. The fixed materializer interface is:

```text
materialize_firewall_entry(session: &mut FirewallReadSession,
  context: &FirewallContext, index: &EntryIndex)
  -> Result<LogEntry, FirewallMaterializationError>

FirewallMaterializationError = SourceChanged | GenerationUnverifiable |
  ReadDecodeFailure | InvalidIndexContext   // include source identity/path context
```

Map these variants into existing native/TypeScript timeline error transport without string matching. Keep non-firewall `materialize_log_entry` / `materialize_msg` behavior. Result-returning commands propagate errors; legacy `Option<String>` callbacks retain their first error and abort the enclosing operation before results are stored or published.

Dependencies are serial: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10. Tasks 8–9 could conceptually begin after Task 4, but keeping them serial avoids shared model/transport edits and competing builds.

## Validation commands and resource preflight

These are planned commands, not results. After approval and a free build slot, create a fresh private directory and report it before compilation. Reuse it only within this implementation lane. Do not reuse the earlier characterization target or another task's target.

```sh
ISSUE814_TARGET=$(mktemp -d /tmp/cmtrace-issue814-implementation-target.XXXXXX)
export CARGO_TARGET_DIR="$ISSUE814_TARGET"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export RUSTFLAGS='-C codegen-units=1'
export RAYON_NUM_THREADS=1 RUST_TEST_THREADS=1
```

Report available disk/memory and one-worker plan; do not promise a fixed peak. The previous parser-only target occupied roughly 340 MiB; native Full/Lite and feature checks can require substantially more. Run builds serially. Missing offline dependencies/toolchains/browser binaries are named blockers, not permission to install applications. Try available locked/offline dependencies first; obtain any needed authorization before network dependency installation.

Command aliases used below are prose shorthand, not new repository scripts:

- **P(issue):** `cargo test --offline --locked -p cmtraceopen-parser --test issue_814_firewall -j 1 -- --test-threads=1`
- **P(unit):** `cargo test --offline --locked -p cmtraceopen-parser --lib firewall -j 1 -- --test-threads=1`
- **N(unit):** `cargo test --offline --locked -p cmtrace-open --lib firewall -j 1 -- --test-threads=1`
- **F(files):** `npm run test -- <explicit test paths> --maxWorkers=1` using installed locked dependencies. Verify the checked-in Vitest CLI supports this option before execution; do not let `npx` fetch a tool implicitly.
- **TS:** `./node_modules/.bin/tsc --noEmit`.
- **WASM:** `cargo check --offline --locked -p cmtraceopen-parser --target wasm32-unknown-unknown -j 1`.

Use exact named tests/filters in recorded RED/GREEN evidence. A compile failure because an intended interface does not exist is acceptable RED only when captured explicitly; syntax/import typos are not the desired failure. Parser/unit tests must not spawn real watchers except native lifecycle integration tests with controlled temp files and barriers. Never replace deterministic races with sleep-based timing.

## Task 1: Establish the row contract and synthetic acceptance suite

**Files:** shared models/TypeScript, fixture README, renamed `tests/issue_814_firewall.rs`; mechanical `LogEntry` initializers and exhaustive validators affected by the optional field. **Consumes:** existing fixture provenance and spec §1–3. **Produces:** portable/TS firewall row enums, coverage model and acceptance target; existing parser behavior remains observable until Task 3 dispatches it.

- [ ] Preserve the baseline evidence artifacts. Rename the characterization test and convert defect-preserving cases into focused desired assertions; keep the original observed results in evidence, not executable requirements. Expand the README to distinguish initial investigation from implementation acceptance.
- [ ] Add model tests `firewall_wire_round_trips_missing_vs_hyphen`, `firewall_wire_preserves_unknown_field_order`, and `ordinary_entry_omits_firewall_payload`. Assert missing `Option` versus literal `"-"`, camelCase enum names, original spelling and absence of native session fields in pure JSON. Record RED with the exact parser model test command.
- [ ] Implement only optional model/serde/TS changes and necessary exhaustive initializers. Add no HTTP or DNS field reuse. GREEN the model tests, existing wire tests, TS and WASM; adding enum variants must not leave exhaustive switches broken.
- [ ] Add normal API cases named `firewall_short_files_detect_dedicated`, `firewall_rows_preserve_all_fields`, `firewall_local_time_has_no_epoch`, and `genuine_iis_remains_iis`. Record the expected behavioral RED at the current implementation. Keep these pending assertions clearly tracked for Task 3; do not commit a silently ignored acceptance suite or call the intermediate branch product-ready.
- [ ] Commit only the green model/wire slice, with a signed commit after inspecting staged paths. Keep behavioral API acceptance test changes outside that commit until Task 3 makes them green; preserve their RED output as evidence. Do not commit a suite that deliberately requires the defect or fails the full suite, and do not discard these pending test edits between slices.

**Representative assertions for Task 1 (`firewall_wire_round_trips_missing_vs_hyphen`):**

```rust
assert_eq!(decoded.fields[0].value.as_deref(), Some("-"));
assert_eq!(decoded.fields[1].value, None);
assert_eq!(decoded, original);
```

## Task 2: Implement record grammar, field mapping and detection probe

**Files:** new `windows_firewall.rs`, parser module exports and model helper tests. **Consumes:** Task 1 models. **Produces:** strict bounded recognition, `FirewallContext`, `parse_record`, reversible per-record coverage and summary. Do not wire normal snapshots to a separate loop.

- [ ] Add RED unit tests for 17/18-field canonical rows; signature-only/header-only/one-row evidence; 1/2/3 rows; arbitrary filename; case-insensitive directive names; HTTP `#Fields:` negative control; date/time-only and invalid-address false positives; signature at meaningful-line 21 and the exact 128-line/65,536-byte probe bounds. Leading NUL runs do not consume meaningful-text budget.
- [ ] Add RED schema tests for reordered/repeated fields, unknown extra fields, invalid duplicate-name header invalidating the previous schema, software-section reset, independent time directive and strict canonical fallback. Exact arity is required; only INFO-EVENTS-LOST may omit a declared final PID. Preserve unknown action informationally under a valid explicit schema.
- [ ] Add RED record tests for TCP/UDP/ICMP/numeric protocol; documentation IPv4/IPv6; placeholder ports; invalid/overflowing/absent loss count; full raw line and ordered fields; PID not thread; ALLOW/DROP Info versus loss Warning; malformed ambiguous row empty mapped fields. Summary brackets IPv6 only when needed and never invents port zero.
- [ ] Add RED time tests: Local/unknown/unrecognized directive → `None` epoch/offset; explicit UTC valid → epoch plus `Some(0)`, including genuine epoch zero; invalid date/time retained. Use invented DST-shaped strings without claiming future timezone rules. `parse_record` never consults host Local.
- [ ] Implement the smallest helpers and run P(unit) to GREEN; run existing IIS/detection controls. Keep the new probe before broad IIS matching but after authoritative signatures when dispatch is enabled in Task 3. Signed commit contains the green helper slice only; pending normal API test edits are committed in Task 3.

**Representative assertions for Task 2 (`firewall_local_time_has_no_epoch`):**

```rust
assert_eq!(entry.timestamp, None);
assert_eq!(entry.timezone_offset, None);
assert_eq!(entry.severity, Severity::Info); // synthetic DROP is not an error
assert_eq!(entry.firewall.as_ref().unwrap().fields.len(), 18);
```

## Task 3: Make bounded stream and normal snapshot parsing identical

**Files:** new `firewall_stream.rs`; `parser/{mod.rs,detect.rs}`; issue acceptance tests. **Consumes:** Task 2 context/record contract. **Produces:** `FirewallStream`, `FirewallDelta`, working `windowsFirewall` normal API, coverage and contextual snapshot outputs.

- [ ] Add RED `firewall_snapshot_and_all_text_splits_converge`: snapshot at every initial UTF-8 character boundary, call `snapshot_eof`, resume remaining text in variable chunks, and compare final entries/IDs/physical lines/fields/severity/time/coverage/context with one full snapshot. Include comments/blanks, split CRLF, split directive and split token.
- [ ] Add RED `firewall_eof_extension_replaces_full_row`: provisional malformed row becomes valid or its loss count receives another digit; replacement retains ID/line but replaces all fields/severity, removes provisional errors/samples, and commits contribution exactly once at newline. Exercise saturated committed counters separately. Unterminated headers cannot install a context.
- [ ] Add RED bound tests for 1-byte/4-KiB/1-MiB leading NUL, NUL-only spans, interior NUL, decoded line sizes cap−1/cap/cap+1, many overlong append chunks, recovery at the next newline and generation reset during a partial/provisional line. Assert retained buffer capacity/length and category sample count, not just short output. A capped record creates one parse error, not one per append or double-counted malformed+oversized error.
- [ ] Implement stream framing, bounded prefix/discard mode, committed versus provisional contributions and generation reset. Stream emits context changes but retains no history vector. `parse_content` firewall dispatch uses this same stream; do not add a second tokenization path.
- [ ] Run P(unit), P(issue), parser full suite and WASM GREEN. The former ignored acceptance probe must now run normally and pass. Explicitly verify 0/header-only/1/2/3 rows, the sample-window boundary, generic negative control and genuine IIS. Record a shared-interface review of the portable model/stream before native adoption; address verified findings. Signed commit.

**Representative assertions for Task 3 (`firewall_eof_extension_replaces_full_row`):**

```rust
assert_eq!(replacement.expected_id, initial.id);
assert_eq!(replacement.expected_line_number, initial.line_number);
assert_eq!(replacement.entry, complete_snapshot_entry);
assert_eq!(resumed_coverage, complete_snapshot_coverage);
assert!(retained_pending_bytes <= MAX_FIREWALL_LINE_BYTES);
```

## Task 4: Decode and snapshot firewall files from one handle

**Files:** new native `parser/firewall_source.rs`, `parser/mod.rs`, focused inline native tests. **Consumes:** Task 3 stream. **Produces:** native snapshot artifacts, actual encoding, raw spans and continuation. Keep existing snapshot wrappers for other callers.

- [ ] Add RED byte-matrix tests for UTF-8/no BOM/BOM and UTF-16 LE/BE BOM. For every byte split of these bounded synthetic inputs, take an initial snapshot EOF and resume; compare decoded rows and raw consumed offsets with a full snapshot. Include each BOM prefix and UTF-8 scalar boundary; UTF-16 even high-surrogate and high-surrogate-plus-odd-byte boundaries. Test Windows-1252 non-ASCII snapshot decoding here with definitive invalid UTF-8 already present in the initial snapshot; the every-split Windows-1252 matrix belongs to Task 5 because a prefix before its first invalid byte requires late fallback/reset.
- [ ] Add RED explicit-invalid UTF-8/UTF-16 tests asserting visible decoding-gap status and unchanged committed candidate. Initial incomplete scalar/BOM is pending, never lossy fallback. Definitive invalid no-BOM initial UTF-8 selects Windows-1252 for the entire same-handle snapshot before publication.
- [ ] Add RED same-handle tests interleaving growth/replacement after metadata/read admission, proving consumed bytes rather than old size or decoded length supply offset. Verify raw row spans retain BOM/padding accounting, including UTF-16 rows larger than 64 KiB raw but below the decoded cap.
- [ ] Implement bounded decoder carry (BOM ≤2 bytes; UTF-8 ≤3; UTF-16 odd+surrogate ≤3), exact spans and optional artifact result. Empty/new generation remains undecided. The initial snapshot may allocate whole-file bytes as explicitly allowed; do not claim full initial-open memory is bounded.
- [ ] N(unit), existing native parser handoff tests and P(issue) GREEN. Confirm ordinary encoding behavior remains unchanged and record dependency/toolchain blockers if native tests cannot run. Signed commit; do not substitute parser-only success for native proof.

**Representative assertions for Task 4 (the byte-split matrix):**

```rust
assert_eq!(resumed_entries, full_snapshot_entries);
assert_eq!(raw_consumed_offset, raw_input.len() as u64);
assert!(held_scalar_bytes <= 3);
assert!(held_bom_prefix_bytes <= 2);
```

## Task 5: Own firewall checkpoints and fence native watcher controls

**Files:** new `watcher/firewall.rs`, `watcher/{mod.rs,tail.rs}`, `state/app_state.rs`, `commands/{file_ops.rs,parsing.rs}`, native tests. **Consumes:** Task 4 artifacts. **Produces:** same-source persistent checkpoint, source sessions, control admission, transactional publication and optional native response fields.

- [ ] Add RED deterministic state-machine tests `firewall_stale_start_cannot_stop_new_watch`, `firewall_stop_before_start_cancels_epoch`, `firewall_old_session_controls_are_noops`, and `firewall_candidate_commit_checks_current_owner`. Cover retry-idempotency, stale/missing tokens, reopen during candidate parse, and commit/publication under the same ownership fence. Test lock ordering without worker joins under required locks.
- [ ] Add RED lifecycle tests: pause/resume and stop/start retain schema, pending text, provisional identity, byte carry and latest offset; explicit reopen revokes prior session; larger replacement and shrink reset generation; empty replacement clears old view; IDs continue while physical lines restart. Unknown identity is not evidence of replacement. Inject failed read/decode after replacement and prove the reset remains owed and the checkpoint unchanged.
- [ ] Add RED `firewall_late_invalid_utf8_resets_once_to_cp1252`: same-generation identity-checked reread yields one atomic replacement snapshot; no mixed rows; failure/raced generation retains pending transition and old cursor; Windows-1252 remains fixed until generation reset. Complete the every-byte-split Windows-1252 matrix here, including initial snapshot EOF before the first definitive invalid UTF-8 byte, and require full-snapshot convergence. Invalid explicit encoding produces a visible persistent gap without silently retrying as successful.
- [ ] Wire single, batch and aggregate-folder opens to native artifacts and one source session per actual file. Expose optional `firewallSessionId`. Start consumes native checkpoint rather than frontend cursor. Add optional full-row replacement/coverage/decoding/control payloads; ordinary-format fields and Company Portal finalization are unchanged.
- [ ] N(unit), native supported-formats/command tests, Full/Lite checks and existing Company Portal tail tests GREEN. Verify a batch containing zero new rows can still publish a reset/coverage/gap. Obtain independent shared native/IPC contract review before frontend adoption. Signed commit.

**Representative assertions for Task 5 (`firewall_candidate_commit_checks_current_owner`):**

```rust
assert_eq!(checkpoint_after_stale_candidate, checkpoint_before);
assert!(publications_from_stale_candidate.is_empty());
assert_eq!(active_source_session_after_old_stop, new_source_session);
```

## Task 6: Reconcile frontend control tokens, replacements and coverage

**Files:** `types/log.ts`, command wrappers and tests, payload validator and tests, watcher hook/tests, log store/tests. **Consumes:** Task 5 native envelope. **Produces:** source-owned epochs and idempotent, guarded frontend state transitions.

- [ ] Add RED validation tests rejecting malformed nested firewall rows, unknown enum values, invalid token/ID/line combinations, incomplete replacements and invalid coverage counters; absence of firewall extensions remains valid for ordinary formats.
- [ ] Add RED hook/store tests for start/stop/pause/resume token transport, remount monotonic epochs, stale same-path session events, stale watch events, delayed start after stop, full-row replacement with stable source ID/line, and repeated replacement idempotency. A reset with no entries clears that source and coverage.
- [ ] Add RED aggregate-folder tests proving source-local IDs map to the right displayed rows, replacement affects one source only, independent sessions/epochs remain independent, and cumulative coverage snapshots replace rather than sum. Derive current parse errors from authoritative firewall coverage so provisional repair removes an old error.
- [ ] Implement optional transports and store-owned epoch allocation. Maintain ordinary frontend byte-offset arguments only for non-firewall compatibility; firewall native cursor remains authoritative. Do not let missing firewall token silently take the ordinary control path.
- [ ] F(`src/lib/commands.test.ts src/lib/tail-payload-validation.test.ts src/hooks/use-file-watcher.test.tsx src/stores/log-store.test.ts`) and TS GREEN, followed by relevant existing watcher/aggregate tests. Signed commit.

**Representative assertions for Task 6 (replacement and aggregate coverage):**

```ts
expect(rowsAfterRepeatedReplacement).toEqual(rowsAfterFirstReplacement);
expect(untouchedSourceRowsAfter).toEqual(untouchedSourceRowsBefore);
expect(sourceCoverageAfter).toEqual(payload.firewallCoverage);
expect(parseErrorsAfterProvisionalRepair).toBe(0);
```

## Task 7: Render complete firewall information and preserve wall-clock display

**Files:** viewer/date-time/column/search/filter files from map, new coverage notice and field accessors, exhaustive labels/bundle maps. **Consumes:** row/coverage transport. **Produces:** useful Log Explorer and explicit coverage without invented timestamps.

- [ ] Add RED column/detail tests for default Severity/Date-Time/Message/Action/Protocol/endpoints/Path, all ordered unknown fields, literal hyphens, missing final PID, truncated raw text marking and dedicated raw-copy control. Search must find PID/flags/unknown values omitted from summary. Existing Copy Message semantics remain.
- [ ] Add RED formatter and DiffView tests that preserve Local/unknown/invalid display strings, DST-gap/repeated-hour spelling and UTC label. Run the formatter cases in separate `TZ=UTC`, `TZ=Europe/London`, `TZ=America/New_York` processes with one Vitest worker. Do not construct JavaScript `Date` in the firewall branch.
- [ ] Add RED sorting/filter tests: validated wall-clock tuple only within one source; unparseable ties follow physical order; cross-source ordering uses real epochs only; null firewall times excluded from absolute-time filters/correlation and never treated as 1970. Retain existing merged-tab null ordering.
- [ ] Add RED coverage UI tests for padding, known/unknown loss, malformed/capped rows, missing absolute time, pending decoder and explicit decoding gaps. One compact notice shows cumulative state; ALLOW/DROP stay Info and loss remains a Warning row. Do not generate a warning row per padding byte.
- [ ] Implement dedicated display accessors/notice, entry-aware DiffView formatter, search projection and scoped sorting/filter changes; complete parser labels and bundle descriptions. F(all changed adjacent tests), three TZ runs, TS and native filter tests GREEN. Signed commit.

**Representative assertions for Task 7 (repeat in each required timezone process):**

```ts
expect(formatLogEntryTimestamp(localEntry)).toBe(localEntry.timestampDisplay);
expect(formatLogEntryTimestamp(unknownEntry)).toBe(unknownEntry.timestampDisplay);
expect(localEntry.timestamp).toBeNull();
expect(absoluteRangeMatchIds).not.toContain(localEntry.id);
```

## Task 8: Build truthful firewall timeline indexes and same-handle materialization

**Files:** `timeline/{builder.rs,query.rs,models.rs,store.rs,mod.rs}`, new `timeline/firewall.rs`, native timeline unit tests. **Consumes:** native same-snapshot raw spans and portable context. **Produces:** eligible index metadata, sparse referenced context and typed contextual reader. New helper is testable before command dispatch changes in Task 9.

- [ ] Add RED `firewall_timeline_excludes_unplaced_before_counts`: Local/unknown/invalid epoch rows omitted before index/count/range; mixed sections eligible only where explicit UTC; legitimate epoch zero remains. All-local/header-only sources retain no context vector and report excluded count.
- [ ] Add RED sparse-context tests: repeated/reordered/invalidated schemas, software/time section reset, long runs of noneligible rows; only contexts referenced by eligible UTC rows retained and equal consecutive referenced contexts coalesce. Entry materialization uses the latest referenced context at its physical line, not a fresh stateless parser.
- [ ] Add RED materialization tests for same-byte-snapshot offsets, UTF-8 BOM/UTF-16/padding, a >64-KiB raw UTF-16 line below the decoded limit, truncated/capped rows, invalid index/context and decoding failures. Assert fields/severity/time equal the initial parsed row.
- [ ] Add RED identity tests: replacement before open → `SourceChanged`; unavailable identity → `GenerationUnverifiable`; replacement after opening the validated handle cannot mix generation bytes in one request; next request sees change. Reuse one `FirewallReadSession` per source within each request. Document same-identity/same-size mutation and truncate/regrow observation limits.
- [ ] Implement optional SourceRuntime state and firewall helper with bounded incremental decoding. Leave ordinary materializer API untouched. N(unit), existing native timeline tests, Full/Lite checks GREEN. Signed commit; command/UI activation follows Task 9 and is not claimed complete yet.

**Representative assertions for Task 8 (eligible index and generation):**

```rust
assert!(all_local_indexes.is_empty());
assert!(all_local_referenced_contexts.is_empty());
assert_eq!(explicit_utc_epoch_zero_index.timestamp_ms, 0);
assert!(matches!(replacement_error, FirewallMaterializationError::SourceChanged));
```

## Task 9: Propagate timeline failures and invalidate stale evidence visibly

**Files:** native `timeline/{builder.rs,query.rs}` and `commands/timeline.rs`; `src/types/timeline.ts`, `src/stores/timeline-store.ts`, timeline workspace/hooks/tests; `src/lib/commands.ts` and `.test.ts`; `src/workspaces/timeline/open-timeline-source.ts` and `.test.ts`; new `src/lib/timeline-errors.ts` and `.test.ts`. **Consumes:** Task 8 typed helper/errors and excluded-count metadata. **Produces:** end-to-end timeline builds and queries with visible coverage/stale notices. Export `formatTimelineError(error: unknown): string` from the new helper to format structured native failures consistently while preserving ordinary error messages.

- [ ] Add RED native tests for entry/page and incident/detail dispatch, initial sampling/incident construction and tunable recomputation. For legacy Option callbacks, retain the first firewall materialization error and fail the enclosing command before mutating stored incidents/tunables or publishing any partial successful result. Exercise failure after at least one successfully materialized row.
- [ ] Add RED frontend initial-build, append-source, drag/drop and rebuild rejection tests through the real `buildTimeline` command wrapper, `openTimelineSource`/`openTimelineFiles` and `buildTimelineFromSources`. Reject the mocked Tauri `invoke` at the command boundary; do not mock `buildTimeline` to bypass normalization. The current generic `invokeCommand` wrapper in `src/lib/commands.ts` normalizes rejected objects to plain `Error`, losing their typed kind/source metadata. Preserve scoped firewall timeline error metadata through a timeline-specific adapter before this conversion, keeping ordinary command normalization unchanged. Use the shared typed formatter in the open queue and workspace drop catches. A failed build/rebuild must retain actionable source-specific semantics, never install a partial bundle or clear a prior stale-source warning as if it succeeded.
- [ ] Add RED frontend tests that perform an actual query rejection for each typed error. `SourceChanged` clears affected cached pages/details, marks the bundle stale, stops further current-bundle row requests and displays “Source changed. Rebuild the timeline to continue.” A rebuild creates fresh state. Remaining counts/lanes are labelled stale. Other errors remain actionable notices and never become success-cached empty pages/null details.
- [ ] Add RED `late_timeline_completions_cannot_mutate_rebuilt_bundle`: start page/detail/build requests, invalidate or rebuild, then resolve an old success and reject an old request with `SourceChanged`. Neither completion may repopulate old pages/details or mark the new bundle stale. Capture the originating bundle ID plus `timelineGeneration` and check both before success or error store writes, including stale-state changes; effect-local cancellation alone is insufficient. Invalidation must revoke in-flight completions before a rebuild as well as after it.
- [ ] Add RED all-local/mixed-source notice tests showing excluded counts while the Log Explorer retains the rows. Exhaustive timeline parser-kind validation accepts `windowsFirewall` without relaxing other validators.
- [ ] Wire scoped native Result propagation and frontend handling, including initial open/rebuild, both existing swallowed query-hook catches and any tunable-command consumer found by the call-site inventory. N(unit), all changed timeline frontend tests (including `src/lib/commands.test.ts`, `src/workspaces/timeline/open-timeline-source.test.ts` and `src/components/timeline/hooks/buildTimelineFromSources.test.ts`), TS and full existing timeline suite GREEN. Request independent contract/adversarial review covering Tasks 4–9, resolve verified findings, and rerun only affected gates plus final aggregate checks. Signed commit.

**Representative assertions for Task 9 (reject a real query promise first):**

```ts
expect(screen.getByText("Source changed. Rebuild the timeline to continue.")).toBeVisible();
expect(useTimelineStore.getState().entryCache.size).toBe(0);
expect(oldBundleQueriesAfterInvalidation).toHaveLength(0);
expect(successfulEmptyResultsCached).toHaveLength(0);
```

## Task 10: Verify the integrated result and deliver a linked draft PR

**Files:** new `e2e/firewall-log.spec.ts`, synthetic fixture README, evidence and issue/PR text; fixes only when justified by observed failures/review. **Consumes:** Tasks 1–9. **Produces:** exact-commit evidence, draft PR linked to #814, clear remaining gate states. Execution authorization must include this delivery stage before pushing/creating a PR.

- [ ] Add RED then GREEN browser-mocked flow for initial open → fields/details/raw copy → coverage → tail full replacement/reset → local timestamp display → timeline excluded/stale-source notice. Use synthetic payloads and existing test mocks. Execute `npm run test:e2e -- e2e/firewall-log.spec.ts --workers=1` only with existing authorized browser runtime. State explicitly that this does not launch/test the native Windows app.
- [ ] Run local prepublication gates: final parser suite, WASM, native Full and Lite tests/checks/clippy, frontend TS/full suite, three timezone formatter processes, and full existing Playwright suite with one worker. Use `.github/workflows/cmtrace-ci.yml` as authority for additional feature/CI requirements rather than weakening or inventing green checks. Required commands/gates include:
  - `cargo fmt --all -- --check`; `git diff --check`.
  - `cargo test --locked -p cmtraceopen-parser -j 1 -- --test-threads=1`; parser clippy `--all-targets -- -D warnings`; WASM.
  - From `src-tauri`: Full `cargo check`, `cargo test -- --test-threads=1`, `cargo clippy --all-targets -- -D warnings`; repeat check/test/clippy with `--no-default-features`, all with the shared one-job environment and locked dependencies.
  - `cargo test --locked -p cmtrace-open --no-default-features --features event-log --lib --test event_log_export_cli -j 1 -- --test-threads=1`; standalone `collector` and `esp-diagnostics` lib checks; `cargo +1.88 check --workspace --all-features --locked -j 1` when the toolchain is already available/authorized.
  - `cargo deny check`, `cargo audit`, locked frontend dependency/security checks and the workflow's Node/Python contract suites. CI owns platform packages and native build provenance; report unavailable local checks accurately.
  - After draft PR creation, observe the required native CI build matrix macOS arm64 / Windows x64 / Linux x64, Windows feature suites and all-feature checks at the exact PR SHA. CI build success is not manual Windows UI acceptance.
- [ ] Inspect final source/fixture provenance, optional wire compatibility, signing-file diff, no-private-data boundaries and complete spec matrix below. Commit final changes signed and record SHA, commands, exit codes, target and evidence paths. Run available authorized CodeRabbit range review before publication and verify its findings against source. Obtain independent review on this head. Final PR CI and CodeRabbit approval are subsequent gates, not implied by these local checks.
- [ ] Refresh canonical `main`; inspect any delta. Resolve changes locally without force push, redo affected checks/reviews for the final SHA. Verify publication target is `adamgell/cmtraceopen` rather than the clone's local `origin`. Push only the authorized branch and verify remote head matches local signed head. If network/authentication prevents a verified push, preserve work and report exact blocker.
- [ ] Create a **draft** PR with the concrete symptom, resulting behavior, synthetic provenance, RED/GREEN evidence, exact review/gate states and `Fixes #814` linkage. Attach the created PR to this task. Add the actual draft PR URL to existing issue #814 under Adam's authorization; preserve others' content and keep issue open until the normal merge process. Return public issue and PR URLs. No fabricated link or completion/Windows claim.
- [ ] Observe CI and reviews after the draft exists: `cmtrace-ci.yml` runs this issue branch via the PR trigger, not an ordinary issue-branch push. Verify every required run/review targets the current PR SHA. Resolve verified failures/findings, sign and push new commits without force, and repeat affected local checks plus required CI/reviews at the new head. Require CodeRabbit `APPROVED` at head and a clean independent repository charter review posted to the PR; a green CodeRabbit status check alone is insufficient. Keep the PR draft and report blockers/pending gates truthfully. No merge or release.

## Spec-to-acceptance checklist

| Approved requirement | Owning tasks | Required observed evidence |
|---|---|---|
| Dedicated short-file detection, bounded meaningful probe, IIS/authoritative controls | 2–3 | Normal API tests at 0/1/2/3 rows and probe boundaries, genuine IIS unchanged |
| 17/18 fields, action/protocol/ports, schema permutations, unknowns, hyphens/missing PID | 1–3, 7 | Round-trip fields/raw and readable summary/details/search/copy |
| Local/unknown/UTC provenance, invalid/DST strings, filters/merging | 2, 7–9 | No invented epoch, three TZ runs, explicit epoch zero indexed |
| Same stream for snapshot and append, initial EOF/full replacement | 3–6 | Every representative text/byte split calls snapshot EOF before resuming |
| Bounded NUL/overlong state and reversible saturated coverage | 3–4, 6–7 | Internal retained-state assertions, sample caps, no phantom errors |
| Same handle, actual encoding, split BOM/scalars, pending/invalid/late fallback | 4–5 | Raw-offset/carry assertions and atomic retryable transition tests |
| Epoch admission, stale controls/workers, checkpoint restart, generation reset | 5–6 | Deterministic interleaving/state-machine tests including empty replacement |
| Single/batch/folder parity and aggregate ID ownership | 5–6 | Native handoff and frontend per-source replacement/reset tests |
| Eligible-only timeline counts/sparse contexts/raw spans | 8 | All-local/header-only/mixed/reordered input; bounded state vs index growth distinguished |
| Typed same-handle timeline errors through all callbacks/commands | 8–9 | Replacement/unknown identity and failure-after-first-row tests |
| Visible stale timeline state, no empty-success caches | 9–10 | Actual query rejection reaches notice, cache invalidation and rebuild |
| Other formats and platform compatibility | 1–10 | Existing control suites, Full/Lite, WASM, TS, CI/review at exact head |

## Approval and reporting checkpoint

The planning review checked this document against the approved spec and current source. Its actionable findings were incorporated: preserve typed build errors before generic command normalization, put late-fallback Windows-1252 split parity in Task 5, and observe/remediate exact-head CI after draft PR creation. The adversarial late-query completion case now guards bundle ID and generation on both success and error. This review is not implementation verification or the final repository charter gate.

This document is the concrete implementation proposal. The requested next decision is approval of this plan and **Native execution in this existing isolated task through verification and a draft PR**, followed by linking that PR on #814. No product implementation starts before that decision. This pause is explicitly required by the current delegation and the writing-plans workflow; the repository's general autonomous-lane rule does not override it.

Until then, preserve the synthetic files, signed spec and this plan. The only public change from planning is [the issue status comment](https://github.com/adamgell/cmtraceopen/issues/814#issuecomment-6043923613). Report any missing tool/runtime/gate as a specific limitation, not as product success.
