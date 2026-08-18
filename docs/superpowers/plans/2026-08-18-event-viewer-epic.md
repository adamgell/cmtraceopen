# Event viewer epic implementation plan

> **For agentic workers:** Use `subagent-driven-development` to execute this plan lane by lane. Each lane requires independent diff inspection and focused verification before the next dependent lane starts.

**Goal:** Complete all 26 unchecked acceptance items in issue #539 through isolated child lanes, with explicit coverage gaps and Windows verification on the Parallels `Windows 11` ARM64 VM.

**Architecture:** Reconcile the provider-capture scaffold with the full event-viewer foundation first. Then freeze portable provenance, coverage, filter, timeline, correlation, provider, export, and redaction contracts. Implement independent provider, UX, source, timeline, output, and diagnosis lanes against those contracts, and integrate only after focused tests, aggregate gates, and exact-head review.

**Tech Stack:** Tauri v2, Rust, `cmtraceopen-parser`, React 19, TypeScript, Fluent UI, Zustand, `evtx` 0.12.2, `rusqlite`, `flate2`, `serde`, `zip`, Vitest, Cargo, and the Parallels Windows 11 ARM64 guest.

---

## Execution boundary

This plan is drafted after the approved design sections. The committed design remains `Review requested` until the user reviews it. Do not edit implementation files, create child PRs, or dispatch code-writing agents until that review gate is satisfied.

The implementation must not use the Windows 11 CDW VM. Use the Parallels VM through `prlctl exec "Windows 11" ...` or its SSH endpoint. The current root checkout on `qa/user-story-tracker` remains untouched. Implementation work starts from the isolated orchestration branch and creates one worktree per child lane.

## Shared gates

Run these after each code lane, limited to the files owned by that lane before running the aggregate gate:

```bash
npm test -- <changed frontend test files>
npx tsc --noEmit
cargo test --manifest-path src-tauri/Cargo.toml --features event-log <focused Rust test filter>
cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo check --locked --manifest-path crates/cmtraceopen-parser/Cargo.toml --target wasm32-unknown-unknown
```

Use `cargo fmt --check` only for files changed by the lane. Do not run a repository-wide formatter. Windows-only behavior gets a guest run in addition to portable tests. A macOS compile is not Windows acceptance evidence.

Every code lane follows this sequence:

1. Create a dedicated worktree from the latest reviewed prerequisite commit.
2. Write a failing contract test for each new observable behavior.
3. Run the focused test and record the failure.
4. Implement the smallest end-to-end path without compatibility aliases.
5. Run the focused test, inspect the diff, and run the shared gates.
6. Commit a coherent issue-scoped change and open a draft PR.
7. Run independent review on the exact commit range before starting a dependent lane.

---

## Task 1: Reconcile the event-viewer foundation

**Lane:** `event-viewer-foundation`  
**Dependencies:** none  
**Closes:** prerequisite for all 26 acceptance items

**Files:**

- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `src-tauri/src/event_log/capture.rs`
- Modify: `src-tauri/src/event_log/provider_db.rs`
- Modify: `src-tauri/src/event_log/mod.rs`
- Modify: `src-tauri/src/lib.rs`
- Test: `src-tauri/src/event_log/commands.rs` and existing event-log tests
- Test: `src/workspaces/event-log/EventLogWorkspace.test.tsx`

**Steps:**

- Compare local `main` at `5b979752` with `origin/feat/provider-capture` at `117a7d16`, `418a6829`, and `be6e6c05`. Preserve the capture entry point and restore the real parse, query, export, map, provider, and timeline command bodies.
- Add a failing command-contract test that rejects unconditional empty parse/query results and zero-count exports.
- Restore the command registration needed by the frontend, including provider capture, without adding deprecated aliases.
- Make `EvtxParseResult`, coverage fields, and batch delivery match the current `evtx-store.ts` contract.
- Replace the placeholder capture metadata with the real provider-capture seam, but leave full Windows traversal to Task 3.
- Run `cargo test --manifest-path src-tauri/Cargo.toml --features event-log event_log` and `npm test -- src/workspaces/event-log/EventLogWorkspace.test.tsx`. Expected result: existing event-viewer flows exercise real command paths and no command returns a hard-coded empty success.

**Acceptance:** The frontend can parse, query, export, load maps, load providers, and build a timeline through real commands. Provider capture remains registered. No event-log command returns an unconditional empty result or zero count.

---

## Task 2: Complete Phase 0 evidence

**Lane:** `event-viewer-phase0-evidence`  
**Dependencies:** none after the Windows guest is reachable  
**Closes:** competitive matrix, frozen corpus, competitor measurements, copied interaction capture

**Evidence target:** GitHub issue #539 comment with attached hashes, tables, notes, and screenshots. Do not invent a repository fixture or claim a GUI measurement without running the tool.

**Steps:**

- Run `prlctl exec "Windows 11" cmd.exe /c ver` and record the guest build, architecture, CPU count, memory, and tool versions.
- Verify EventLogExpert remote access, export, grouping, and staged filtering; verify Event Log Explorer staged filtering behavior. Record each cell as observed, unsupported, or unverified.
- Build a sanitized corpus containing the available channel set and an `MDMDiagReport.zip` capture. Hash every member and store the manifest with the issue evidence.
- Measure cold start to first visible row, all-channel seven-day load, peak RSS, 100,000-row render, and Intune description resolution. Record guest hardware and OS build with every number.
- Capture notes and screenshots for grouping, saved filter libraries, and row highlights. Label any manual or uncontrolled comparison.
- Add one issue comment containing the corrected matrix, corpus manifest, measurement table, and interaction evidence. Do not claim a benchmark against FullEventLogView unless that exact run completes.

**Acceptance:** Issue #539 contains the corrected matrix and reproducible evidence for all four Phase 0 checkboxes.

---

## Task 3: Implement Windows provider metadata capture

**Lane:** `event-viewer-provider-capture`  
**Dependencies:** Task 1  
**Closes:** provider metadata capture

**Files:**

- Modify: `src-tauri/src/event_log/capture.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `src-tauri/src/event_log/provider_db.rs`
- Modify: `src-tauri/src/event_log/models.rs`
- Test: `src-tauri/src/event_log/capture.rs`
- Test: provider database tests under `src-tauri/src/event_log/`

**Steps:**

- Add Windows-only failing tests for publisher enumeration, provider name extraction, metadata property extraction, and composite provider/version storage. Add non-Windows tests that assert a structured unsupported error.
- Implement `EvtOpenPublisherEnum`, `EvtNextPublisherId`, `EvtOpenPublisherMetadata`, `EvtGetPublisherMetadataProperty`, `EvtGetObjectArrayProperty`, and `EvtGetObjectArraySize` traversal with bounded buffers and explicit per-provider errors.
- Serialize event descriptions, templates, messages, levels, tasks, opcodes, keywords, channel names, OS build metadata, and provider version keys into the EventLogExpert `ProviderDetails` schema.
- Preserve multiple `VersionKey` rows for one provider. Do not use `INSERT OR REPLACE` against provider name alone.
- Run focused tests on macOS for unsupported behavior, then run the capture tests on the Parallels guest. Record the guest command and output in the lane PR.

**Acceptance:** A real Windows provider walk produces a readable database with complete metadata categories. Non-Windows returns unsupported, not empty success.

---

## Task 4: Ship curated provider databases and import/export

**Lane:** `event-viewer-provider-distribution`  
**Dependencies:** Task 3 and existing portable provider reader  
**Closes:** curated databases and database export/import

**Files:**

- Modify: `src-tauri/src/event_log/provider_db.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `crates/cmtraceopen-parser/src/provider/`
- Modify: resource packaging configuration used by the existing application
- Test: provider database reader and rendering tests
- Add: sanitized provider database artifact and manifest in the existing resource location

**Steps:**

- Add a failing round-trip test that loads a captured provider database, exports it, reloads it, and compares provider/version rows and rendered descriptions.
- Generate sanitized provider data covering MDM, Autopilot, ESP, AAD, ConfigMgr client, AppX, and Windows Update. Record source Windows build and provider version in the manifest.
- Package the curated database through the existing Tauri resource mechanism. Do not add a second database format or silently discard unsupported provider rows.
- Verify a sanitized EVTX fixture on macOS renders descriptions from the packaged database, including typed values and unresolved placeholders as explicit coverage gaps.
- Run parser tests and the wasm32 check. Run the Windows capture and export/import scenario on the Parallels guest.

**Acceptance:** The seven named provider families are represented, import/export preserves all rows, and a non-Windows sanitized fixture renders descriptions without a provider registry.

---

## Task 5: Implement layered filters and quick-filter modes

**Lane:** `event-viewer-filter-pipeline`  
**Dependencies:** Task 1 and the portable filter contract  
**Closes:** layered filtering and quick-filter modes

**Files:**

- Modify: `crates/cmtraceopen-parser/src/event_query/`
- Modify: `src-tauri/src/event_log/live.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `src/workspaces/event-log/evtx-filter.ts`
- Modify: `src/workspaces/event-log/evtx-store.ts`
- Modify: `src/workspaces/event-log/evtx-filter-store.ts`
- Modify: `src/workspaces/event-log/EvtxFilterBar.tsx`
- Test: existing event query tests and event-log filter/store tests

**Steps:**

- Add failing tests for each quick mode, event-ID ranges, case sensitivity, visible-column scope, show/hide behavior, and invalid input.
- Add explicit before-load, on-load, and after-load criteria to the filter model. Keep unsupported XPath criteria for on-load or after-load evaluation.
- Centralize the visible-record predicate so `evtx-filter.ts` and `EvtxTimeline.tsx` cannot diverge.
- Preserve the filter model in saved filters and ensure time-window refetch does not drop on-load state.
- Validate impossible server filters against the existing service-validated query tests. Run frontend filter tests and Rust event-query tests.

**Acceptance:** Server and local evaluation return equivalent records for supported criteria. Every listed quick mode works and persists without silently broadening the query.

---

## Task 6: Add row highlights and EVTX markers

**Lane:** `event-viewer-triage`  
**Dependencies:** Task 5 and stable event identity from Task 1

**Files:**

- Modify: `src/workspaces/event-log/EvtxTimeline.tsx`
- Modify: `src/workspaces/event-log/EvtxTimelineRow.tsx`
- Modify: `src/workspaces/event-log/EvtxDetailPane.tsx`
- Modify: `src/stores/marker-store.ts` only through the existing adapter seam
- Add or modify: EVTX marker adapter beside `src/workspaces/event-log/`
- Test: row, filter, marker, and keyboard interaction tests

**Steps:**

- Add failing tests for highlight precedence, selected-row contrast, marker persistence, sort/group/refetch stability, and keyboard marker actions.
- Key markers by stable source and event identity, never by array index or unstable row ID.
- Render filter highlights with text and ARIA state in addition to color. Preserve selected, marker, and severity states through one deterministic precedence function.
- Add tag/bookmark actions that reuse existing marker categories and persistence behavior.
- Run focused Vitest tests and the TypeScript gate.

**Acceptance:** Users can tag and bookmark event rows, markers survive streaming and reordering, and filter matches remain accessible without relying on color.

---

## Task 7: Complete event-viewer font metrics

**Lane:** `event-viewer-font-metrics`  
**Dependencies:** Task 1

**Files:**

- Modify: `src/workspaces/event-log/ChannelPicker.tsx`
- Modify: `src/workspaces/event-log/SourcePicker.tsx`
- Modify: `src/workspaces/event-log/EvtxDetailPane.tsx`
- Modify: `src/workspaces/event-log/EvtxFilterBar.tsx`
- Modify: `src/workspaces/event-log/EvtxTimeline.tsx`
- Modify: `src/stores/ui-store.ts` only if the existing metrics API lacks a required value
- Test: event-viewer workspace and font-size tests

**Steps:**

- Add a failing test that changes `logListFontSize` and `logDetailsFontSize` and asserts row, virtualizer, picker, filter, and detail metrics change together.
- Replace hard-coded event-viewer sizes with `getLogListMetrics` and the existing details metric. Keep list and detail sizes separate.
- Verify keyboard focus, row height, and detail overflow at the minimum and maximum persisted sizes.
- Run focused frontend tests and `npx tsc --noEmit`.

**Acceptance:** All event-viewer controls follow shared UI metrics and the virtualizer remains aligned at both size limits.

---

## Task 8: Extend provenance and unified timeline merge

**Lane:** `event-viewer-timeline-provenance`  
**Dependencies:** Task 1 and the source/coverage contract

**Files:**

- Modify: `src-tauri/src/event_log/models.rs`
- Modify: `src-tauri/src/event_log/timeline.rs`
- Modify: `crates/cmtraceopen-parser/src/unified_timeline/`
- Modify: `src/workspaces/event-log/unified-timeline.ts`
- Modify: `src/workspaces/event-log/UnifiedTimelineView.tsx`
- Test: unified timeline parser, adapter, and view tests

**Steps:**

- Add failing tests for multiple EVTX files, multiple live channels, multiple machines, equal timestamps, live append, and missing timestamps.
- Extend timeline origin/provenance to preserve source, machine, bundle, channel, provider, process, activity, and record identity.
- Implement stable deterministic merge ordering and explicit unplaced items.
- Update the view to show source and machine provenance and coverage without dropping records.
- Run parser tests, frontend timeline tests, and the wasm32 check.

**Acceptance:** A multi-source timeline is deterministic, provenance-preserving, appendable, and explicit about unplaced events.

---

## Task 9: Ingest `MDMDiagReport.zip`

**Lane:** `event-viewer-bundle-intake`  
**Dependencies:** Task 8 and bounded archive infrastructure

**Files:**

- Modify: `src-tauri/src/esp/archive.rs` only through reusable generic extraction seams
- Modify: `src-tauri/src/commands/bundle_ops.rs`
- Modify: `src-tauri/src/collector/artifacts.rs` only for manifest routing
- Add: event-log bundle intake command/module under `src-tauri/src/event_log/`
- Modify: event-log source-open frontend files
- Test: archive bounds, member routing, and event-log bundle tests

**Steps:**

- Add failing tests for valid EVTX/text/registry members, traversal paths, duplicate members, entry limits, byte limits, malformed members, and skipped binary members.
- Stage the archive in a bounded temporary directory and preserve member path, SHA-256, type, parser result, and coverage outcome.
- Route EVTX and text members through existing parser adapters and expose registry/unsupported members as inventory or coverage, not silent drops.
- Add frontend source-open and coverage presentation for bundle members.
- Run portable archive and parser tests, then run the sanitized bundle scenario on the Parallels guest.

**Acceptance:** Opening a diagnostic bundle produces one provenance-preserving timeline input and reports every unsupported or malformed member.

---

## Task 10: Add exact-first event correlation

**Lane:** `event-viewer-correlation`  
**Dependencies:** Tasks 8 and 9

**Files:**

- Modify: `crates/cmtraceopen-parser/src/unified_timeline/`
- Modify: `crates/cmtraceopen-parser/src/esp/correlation.rs` only for shared ordering primitives
- Modify: `src-tauri/src/event_log/models.rs`
- Modify: `src-tauri/src/event_log/timeline.rs`
- Modify: event-viewer timeline TypeScript models and view
- Test: correlation and timeline tests

**Steps:**

- Add failing tests for exact process identity, PID plus start time, session, activity/related-activity, device, and user identifiers across same-machine and multi-machine inputs.
- Build machine-scoped correlation edges with confidence, ambiguity, evidence references, and coverage gaps.
- Reuse exact-first ordering from ESP without importing ESP-specific I/O or allowing timestamp-only causality.
- Render ambiguous and unsupported correlations explicitly.
- Run parser and frontend tests plus wasm32 validation.

**Acceptance:** Exact validated identifiers produce evidence-backed edges; ambiguous or timestamp-only relationships remain non-causal and visible.

---

## Task 11: Add remote event sources

**Lane:** `event-viewer-remote-source`  
**Dependencies:** Task 1 and source provenance contract

**Files:**

- Modify: `src-tauri/src/event_log/live.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `src-tauri/src/event_log/models.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: event-viewer source picker and store files
- Test: Windows-gated remote command tests and frontend source tests

**Steps:**

- Add failing Windows tests for session creation, remote channel query, credential failure, and session cleanup.
- Implement `EvtOpenSession` through the operating-system credential path. Do not persist usernames, passwords, or tokens in filters or settings.
- Return remote machine provenance and permission gaps through the existing coverage model.
- Run portable unsupported tests on macOS and the remote scenario on the Parallels guest against a reachable Windows source. If no second Windows source exists, record the scenario as unavailable rather than claiming success.

**Acceptance:** Remote sessions use OS credentials, clean up handles, and distinguish denied, unavailable, and empty sources.

---

## Task 12: Add folder, wildcard, archive, and VSS sources

**Lane:** `event-viewer-path-sources`  
**Dependencies:** Task 1 and provenance contract

**Files:**

- Modify: `src-tauri/src/event_log/parser.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `src-tauri/src/commands/file_ops.rs` only through existing bounded listing APIs
- Modify: event-viewer source-open and picker files
- Test: source expansion and path coverage tests

**Steps:**

- Add failing tests for recursive folders, wildcard matching, case normalization, duplicate paths, rotated files, `Archive-*` channels, and VSS paths.
- Expand source selection into deterministic source manifests instead of passing an unbounded path list to the parser.
- Gate archive and VSS access behind Windows/elevation checks and return explicit unsupported or denied results elsewhere.
- Preserve source identity across folder members and timeline merges.
- Run portable path tests and Windows archive/VSS scenarios on the Parallels guest.

**Acceptance:** Folder, wildcard, archived, and VSS sources load or fail with precise provenance and coverage outcomes.

---

## Task 13: Characterize damaged and dirty EVTX recovery

**Lane:** `event-viewer-recovery`  
**Dependencies:** Task 1 and Task 12

**Files:**

- Modify: `src-tauri/src/event_log/parser.rs`
- Modify: `src-tauri/src/event_log/models.rs`
- Modify: event-viewer coverage files
- Add: sanitized damaged/dirty EVTX fixtures and parser tests

**Steps:**

- Add fixture cases for truncated chunks, malformed records, missing chunks, invalid XML, and readable records after a damaged region.
- Record exactly what `evtx` 0.12.2 recovers and what it rejects. Keep readable records and attach unrecoverable regions to coverage gaps.
- Remove any silent `.ok()` path that hides parser failures from the event-viewer result.
- Run focused parser and coverage tests on macOS and the fixture suite on Windows if the guest can open the same files.

**Acceptance:** Recovery behavior is documented by fixtures and every unrecoverable region is visible to the user.

---

## Task 14: Add streaming export, CLI export, and redaction

**Lane:** `event-viewer-output`  
**Dependencies:** Task 1, normalized records, and redaction contract
**Closes:** headless CLI export and export redaction

**Files:**

- Modify: `src-tauri/src/event_log/export.rs`
- Add: shared streaming writer beside `src-tauri/src/event_log/export.rs`
- Add: CLI entry point using the repository binary conventions
- Modify: `src-tauri/src/lib.rs` for shared command/service wiring
- Modify: `crates/cmtraceopen-parser/src/esp/redaction.rs` or the shared redaction module
- Modify: frontend export invocation
- Test: export, CLI, redaction, and raw XML tests

**Steps:**

- Add failing tests for direct file output, stdout, CSV, TSV, JSON, XML, HTML, raw XML, large-record streaming, and empty output.
- Move serialization behind one writer interface used by GUI and CLI. Keep formula neutralization for delimited formats.
- Apply redaction to normalized fields and raw XML before serialization. Cover secrets, identities, paths, tenant data, serials, hardware identifiers, and oversized content.
- Ensure the CLI accepts the same filter and source manifest shape as the GUI and returns coverage diagnostics.
- Run focused Rust tests, CLI smoke scenarios, and frontend export tests. Verify a large fixture does not require materializing all records.

**Acceptance:** GUI and CLI produce equivalent redacted output, support stdout and direct file paths, and expose errors and coverage without silent truncation.

---

## Task 15: Add subscription tail and guarded channel clearing

**Lane:** `event-viewer-live-ops`  
**Dependencies:** Task 1, Task 11 session primitives, and Task 14 output contracts

**Files:**

- Modify: `src-tauri/src/event_log/live.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Modify: `src-tauri/src/elevation.rs` only through existing elevation APIs
- Modify: frontend event-log store, workspace, and confirmation UI
- Test: Windows-gated subscription/clear tests and frontend transition tests

**Steps:**

- Add failing tests for subscription delivery, cancellation, dropped batches, polling fallback, confirmation cancellation, non-elevated clear, and successful elevated clear.
- Implement `EvtSubscribe` with sequence and coverage tracking. Use polling only when subscription is unavailable and expose the mode.
- Require explicit confirmation and the existing application elevation state before `EvtClearLog`. Restore the original process state after an elevation transition.
- Run portable unsupported tests and guest scenarios with `prlctl exec "Windows 11" powershell.exe ...`. Do not use the CDW VM.

**Acceptance:** Push and polling modes preserve records and gaps, and channel clearing cannot occur without confirmation and elevation.

---

## Task 16: Implement operational diagnosis and summaries

**Lane:** `event-viewer-diagnosis`  
**Dependencies:** Tasks 4, 8, 9, 10, and 14
**Closes:** operational rules, error enrichment, and cross-source summary

**Files:**

- Add: parser-side event diagnosis modules beside `crates/cmtraceopen-parser/src/`
- Modify: `crates/cmtraceopen-parser/src/error_db/lookup.rs`
- Modify: existing Intune, ESP, DSRegCmd, and SCCM finding models only through shared evidence interfaces
- Modify: `src-tauri/src/event_log/models.rs`
- Modify: event-viewer workspace diagnosis panels
- Test: pure rule, enrichment, summary, and coverage tests

**Steps:**

- Add failing fixtures for Autopilot, ESP, MDM enrollment, and ConfigMgr client event families, including missing, malformed, contradictory, and unsupported evidence.
- Implement evidence-backed rules that emit finding severity, confidence, evidence references, next checks, and coverage gaps. Do not classify a coverage gap as healthy or failed.
- Adapt `error_db` lookup to event fields while preserving raw, decimal, hexadecimal, unknown, and malformed values.
- Build a cross-source summary over event findings, text-log findings, timeline edges, and coverage. Use explicit precedence and ambiguity rather than timestamp-only causality.
- Run parser, wasm32, TypeScript, and fixture tests. Verify the summary preserves every source reference and gap.

**Acceptance:** Device-management diagnosis is operational and evidence-backed, error fields remain lossless, and cross-source summaries never overclaim from missing coverage.

---

## Final integration task

After all 26 acceptance tasks close:

- Re-read issue #539 and mark only directly evidenced checklist items complete.
- Update the issue with child PR links, branch SHAs, focused and aggregate commands, Windows guest evidence, and unresolved limitations.
- Run the complete applicable Rust, parser wasm32, TypeScript, frontend test, and diff gates from a clean integration worktree.
- Request CodeRabbit and independent review against the exact integration range.
- Do not close #539 until every item has an observable acceptance record.
