# Event diagnosis output repair implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan task by task.

**Goal:** Make the Event Log diagnosis useful on a real Windows 11 ARM64 event set without hiding genuine evidence loss.

**Architecture:** Keep source ingestion, diagnosis semantics, and presentation separate. The workspace sends only its filtered record/timeline projection to diagnosis; the parser treats normal unclassified or uncorrelated events as neutral; the live Windows reader emits typed provider coverage independently from record-loss errors; and the panel presents a compact, bounded projection of the resulting summary.

**Tech Stack:** React 19, TypeScript 7, Fluent UI 9, Vitest, Rust, Tauri v2, Windows Event Log API, Cargo.

**Spec:** `docs/superpowers/specs/2026-08-29-event-diagnosis-output.md`

## Global constraints

- Start from PR #583 commit `39ee0b4f6f2e42e5845c6d86f5f9b03fa06e0c84` in the existing isolated worktree.
- Follow strict red-green-refactor: add each regression first, run it and record the expected failure, then implement the smallest change and rerun it.
- Do not alter the user's dirty root checkout.
- Do not add compatibility paths or parse structured state back out of display strings.
- Preserve every successfully decoded event record and every genuine source-loss gap.
- Use Computer Use, not SSH or guest-execution commands, for all interaction with the Windows VM.
- Do not launch the newly built Windows executable until the required action-time confirmation is obtained.

---

## Task 1: Bound and scope the diagnosis UI

**Files:**

- Modify: `src/workspaces/event-log/EventDiagnosisPanel.tsx`
- Modify: `src/workspaces/event-log/EventDiagnosisPanel.test.tsx`
- Modify: `src/workspaces/event-log/EventLogWorkspace.tsx`
- Modify: `src/workspaces/event-log/EventLogWorkspace.integration.test.tsx`

### Steps

- [ ] Extend `EventDiagnosisPanel.test.tsx` with failing contracts that assert the panel is collapsed
  initially, does not render the summary-wide `Evidence:` paragraph, renders one copy of an
  actionable finding, ignores evidence-only events, groups identical coverage gaps with an
  occurrence count, and exposes omitted-count text when a capped section is expanded.
- [ ] Run
  `npm test -- src/workspaces/event-log/EventDiagnosisPanel.test.tsx` and record the red result.
- [ ] Replace the unbounded card body with a compact header/overview and a native disclosure whose
  body uses `maxHeight` plus `overflowY: "auto"`. Add small pure helpers for actionable findings,
  exact coverage-gap grouping, and capped section projections. Use one shared cap of 100 rows per
  detailed section.
- [ ] Remove `summary.evidence` rendering. Keep evidence on individual actionable findings and on
  error-token event details only. Remove finding rendering from `EventRow`.
- [ ] Update the overview copy to report actionable findings and source coverage separately.
- [ ] Change the integration contract from the full dataset to the filtered projection. Feed
  `visibleRecords` and `visibleTimeline` into the diagnosis pump and include them in its freshness
  dependencies; leave acquisition coverage and scoped text logs attached.
- [ ] Add a failing integration case with one visible and one filtered-out record, then verify
  `diagnoseEventRecords` receives only the visible record and its filtered timeline.
- [ ] Run
  `npm test -- src/workspaces/event-log/EventDiagnosisPanel.test.tsx src/workspaces/event-log/EventLogWorkspace.integration.test.tsx`
  and `npx tsc --noEmit`.
- [ ] Inspect the diff for duplicate rendering, stale-timeline races, and inaccessible disclosure
  behavior; commit the task.

### Acceptance

- The collapsed diagnosis occupies only its header and overview.
- Expanding it cannot grow beyond the bounded internal viewport.
- Raw source-wide evidence and repeated findings are absent.
- Filters change the records and timeline sent to diagnosis.

---

## Task 2: Make normal unclassified and uncorrelated events neutral

**Files:**

- Modify: `crates/cmtraceopen-parser/src/diagnosis.rs`
- Modify: `crates/cmtraceopen-parser/src/unified_timeline/mod.rs`
- Modify: `crates/cmtraceopen-parser/tests/diagnosis_contract.rs`
- Test: unit tests in `crates/cmtraceopen-parser/src/unified_timeline/mod.rs`

### Steps

- [ ] Replace the existing unsupported-family contract with a failing test named
  `unsupported_event_family_is_neutral` that requires `EventFamily::Other`, zero findings, retained
  event evidence, and no false confirmed failure.
- [ ] Add a failing timeline unit test proving that a known-machine observation with no explicit or
  secondary keys produces neither an edge nor a coverage gap.
- [ ] Run
  `cargo test --manifest-path crates/cmtraceopen-parser/Cargo.toml unsupported_event_family_is_neutral`
  and the focused timeline test; record both red results.
- [ ] Remove the `EventFamily::Other` synthetic coverage finding from
  `adapt_event_entry_with_data_and_raw_xml` while retaining parsed evidence and error tokens.
- [ ] Remove only the branch that inserts a gap when both exact and secondary keys are empty.
  Preserve the existing secondary-only low-confidence gap, producer gaps, missing-machine gaps,
  explicit identity conflicts, ambiguity, fan-out, and output budget gaps.
- [ ] Run the focused tests, then
  `cargo test --manifest-path crates/cmtraceopen-parser/Cargo.toml diagnosis_contract` and
  `cargo test --manifest-path crates/cmtraceopen-parser/Cargo.toml unified_timeline`.
- [ ] Run `cargo fmt --check --manifest-path crates/cmtraceopen-parser/Cargo.toml`, inspect the diff,
  and commit the task.

### Acceptance

- Ordinary unrelated Application/System events do not inflate finding or coverage totals.
- No-key observations remain visible in the timeline without implying missing evidence.
- Genuine correlation restrictions remain explicit.

---

## Task 3: Separate provider-description gaps from record loss

**Files:**

- Modify: `src-tauri/src/event_log/live.rs`
- Modify: `src-tauri/src/event_log/commands.rs`
- Test: unit tests in `src-tauri/src/event_log/live.rs`
- Test: unit tests in `src-tauri/src/event_log/commands.rs`

### Steps

- [ ] Add portable failing helper tests for a provider gap that assert channel/provider source,
  `EvtxCoverageGapKind::Provider`, exact stage, error code, and stable operator text.
- [ ] Add a failing command aggregation test showing a scan with delivered records plus a provider
  gap keeps `parse_errors == 0`, while a true record-loss gap still increments it.
- [ ] On Windows, add focused tests for `ERROR_FILE_NOT_FOUND`,
  `ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND`, and `ERROR_EVT_MESSAGE_NOT_FOUND`, asserting the stage is
  `EvtOpenPublisherMetadata` or `EvtFormatMessage` as appropriate.
- [ ] Run the focused portable tests and record the red result.
- [ ] Add a typed provider-gap collection to `ChannelScan`. Return a small message-render outcome
  carrying either text or a provider gap; cache metadata failures with their original stage/code.
  Deduplicate per provider and stage inside a scan.
- [ ] Map provider gaps directly into `EvtxParseResult.coverage_gaps` and `error_messages` without
  incrementing `parse_errors`. Keep existing record-loss strings on the record-error path. Convert
  provider gaps to strings only at the live-tail boundary that still transports string diagnostics.
- [ ] Run focused tests, then
  `cargo test --manifest-path src-tauri/Cargo.toml event_log::live` and
  `cargo test --manifest-path src-tauri/Cargo.toml event_log::commands`.
- [ ] Run `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets`, and
  `cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings`.
- [ ] Inspect the diff for record loss, string parsing, provider-stage mislabeling, or unbounded
  diagnostics; commit the task.

### Acceptance

- Successfully delivered records are not counted as parse failures because their description DLL
  is missing.
- Provider, channel, stage, and Windows code are visible and typed.
- XML/render/record loss still reports a parse error.

---

## Task 4: Aggregate verification and Windows ARM64 validation

### Steps

- [ ] Run all changed frontend tests, `npm test`, `npx tsc --noEmit`, and `npm run frontend:build`.
- [ ] Run the focused Rust suites, parser workspace tests, Tauri event-log tests, format checks,
  `cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets`, and clippy with warnings
  denied.
- [ ] Run an independent whole-branch review over the exact merge-base-to-HEAD diff and resolve every
  load-bearing finding under a scoped re-review.
- [ ] Make the reviewed branch reachable to the Windows guest without touching the dirty root.
- [ ] Through Computer Use, open the clean Windows 11 ARM64 VM, fetch/check out the reviewed commit,
  run the focused tests, and build the executable natively.
- [ ] Obtain action-time confirmation immediately before launching the newly built executable.
- [ ] Load real Application/System events and verify the compact default card, disclosure behavior,
  reachable timeline/grid, filter-scoped counts, neutral ordinary events, and provider-specific
  resource gap presentation.
- [ ] Record only privacy-bounded screenshots and command summaries; do not export raw Event Log
  evidence from the VM.

### Acceptance

- Portable gates and native ARM64 build/tests pass on the reviewed commit.
- The live Event Viewer is usable without scrolling through a raw evidence wall.
- Any remaining provider resource problem is accurately identified and does not imply lost records.
