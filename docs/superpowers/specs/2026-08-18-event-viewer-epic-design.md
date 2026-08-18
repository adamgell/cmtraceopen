# Event viewer epic design

**Date:** 2026-08-18  
**Issue:** [#539 Event Viewer: become best in class](https://github.com/adamgell/cmtraceopen/issues/539)  
**Status:** Review requested

## Goal

Complete every unchecked acceptance item in issue #539 through isolated, dependency-ordered child lanes. Keep #539 as the umbrella issue. Close the epic only after every lane has a green implementation, independent review, and the required Windows-lab evidence.

The product differentiator remains an evidence-first event viewer that combines Windows events with parsed text logs and device-management diagnosis. The implementation does not attempt to reproduce every feature of a SIEM or a security threat-hunting product.

## Current baseline

The isolated implementation worktree starts from local `main` at `5b979752` (`feat(event-log): implement infrastructure for provider metadata capture`). That commit adds `src-tauri/src/event_log/capture.rs` but leaves the event-log command surface scaffolded. The complete event-viewer command implementation and provider-database work are on `origin/feat/provider-capture` through `117a7d16`, with earlier provider database commits `be6e6c05` and `418a6829`.

The first implementation lane reconciles these two states. Later lanes do not build on placeholder commands or silently discard the provider-capture work. The current root checkout on `qa/user-story-tracker` is unrelated user work and remains untouched.

## Non-goals

- No backward-compatibility shims, fallback APIs, or duplicate parser paths.
- No SIEM, retention, alerting, compliance reporting, or security-Sigma detection product.
- No AGPLv3 or closed-source code reuse. Adopted schemas and interaction models remain independently implemented.
- No operating-system I/O, SQLite, registry access, WMI, Tauri, or network access in `cmtraceopen-parser`.
- No causality inferred from timestamp proximity alone.
- No fabricated Windows acceptance. Windows-specific behavior requires a real Windows-lab run.
- No real tenant data, user names, SIDs, serials, or secrets in fixtures or shipped examples.

## Architecture

### Source-to-output flow

```text
live, remote, EVTX, ETL, folder, archive, VSS, and bundle adapters
                                  |
                                  v
normalized events + source provenance + explicit coverage gaps
             |                    |                    |
             v                    v                    v
       filter stages       unified timeline       diagnosis rules
             |                    |                    |
             +--------------------+--------------------+
                                  |
                                  v
                    redaction projection before serialization
                                  |
                                  v
                    shared streaming writers for GUI and CLI
```

Source adapters own acquisition and platform-specific behavior. The parser crate owns portable event normalization, map application, provider message rendering, error-code enrichment, timeline semantics, correlation rules, and redaction projections. Tauri owns Windows APIs, SQLite, gzip, archive staging, filesystem access, credentials, elevation, and IPC.

### Provenance and coverage

Every normalized event carries a `SourceProvenance` value with:

- machine identity when known;
- bundle and archive-member identity when applicable;
- channel or file path;
- source kind, such as live channel, EVTX, ETL, text log, or bundle member;
- stable source identifier;
- optional parser and provider metadata.

Every source operation returns records plus `CoverageGap` values. Gaps include denied, partial, malformed, truncated, unsupported, skipped, and capped input. A zero-record result is not success evidence unless the source proves that it is empty. Frontend coverage banners and CLI diagnostics expose the same gap model.

Event identity uses `(source_id, event_record_id)` when the source provides a record ID. The implementation uses a deterministic source/content fallback when no record ID exists. Array position is never an identity.

### Filtering

One typed filter model drives all three filter stages:

1. **Before load:** push only predicates representable in the validated Event Log XPath subset.
2. **On load:** apply portable predicates while records stream from an adapter.
3. **After load:** apply the interactive visibility and highlighting predicate in the workspace.

The model includes level, provider, channel, time, event-ID ranges, search terms, quick-filter mode, case sensitivity, visible-column scope, and show or hide behavior. Saved filters serialize the complete model, including quick-filter semantics and grouping state. If a criterion cannot be pushed into XPath, the backend keeps it for a later stage instead of broadening or dropping it. Impossible filters return zero records rather than all records.

### Provider metadata

`src-tauri/src/event_log` owns Windows provider enumeration, SQLite reads and writes, gzip compression, and JSON serialization. The parser crate owns pure rendering of descriptions, typed template values, maps, keywords, tasks, opcodes, and error codes.

The reader and writer use the EventLogExpert `ProviderDetails` schema, including the composite `(ProviderName, VersionKey)` identity and compressed JSON BLOBs. A provider database can contain multiple OS-build versions of one provider. The implementation does not introduce a second database format.

### Timeline and correlation

The unified timeline merges event and text-log items with deterministic timestamp ordering and a stable tie-breaker based on source identity and record identity. Items without usable timestamps remain in an explicit unplaced collection.

Timeline items retain machine, bundle, source, process, session, activity, related-activity, device, and user identifiers when available. Correlation edges are machine-scoped and carry confidence, evidence references, ambiguity, and coverage. Exact validated identifiers outrank normalized identifiers. Timestamp proximity can order items but cannot establish a root cause.

### Markers and highlights

Event markers reuse the existing marker categories and persistence model through an EVTX adapter. The adapter uses stable source and event identity, so sorting, grouping, refetching, and streaming do not move a marker to a different record.

Filter highlights are separate from markers. Selection, marker state, severity, and filter highlights have an explicit precedence order. Every state has a non-color representation through text, icon, or ARIA metadata. Keyboard navigation and context-menu actions follow the existing log-view patterns while preserving accessible roles and focus behavior.

### Export and redaction

A pure redaction projection transforms normalized event records and raw XML before serialization. CSV, TSV, JSON, XML, HTML, and raw event XML all use that projection. Formula neutralization remains an additional delimited-output rule.

GUI export and headless CLI export call the same streaming writer. The writer supports direct file output and stdout without materializing the entire record set. Redaction occurs before serialization, so no format can bypass it.

## Delivery lanes

Each lane has an isolated worktree, an issue-scoped branch, and a draft PR. A lane can close multiple checklist items only when it records separate acceptance evidence for each item. Agents edit only the files assigned to their lane and skip repo-wide gates. The orchestrator independently reviews every diff and runs gates after the lane returns.

### Foundation reconciliation

Restore the complete event-viewer command surface into the provider-capture baseline. Preserve the provider-capture entry point while restoring real parsing, querying, exporting, map loading, provider loading, and timeline command behavior. Remove placeholder bodies rather than adding compatibility aliases.

Acceptance: existing event-viewer frontend flows invoke real commands, provider capture remains registered, and no event-log command returns an unconditional empty result or zero count.

### Phase 0 evidence

Run four independent evidence tasks on the provisioned Windows host:

1. Verify the contested competitive-matrix cells for remote access, export, grouping, and staged filtering.
2. Build and hash a frozen reference corpus containing the machine channel set and an `MDMDiagReport.zip` capture.
3. Measure tool versions, cold start to first row, all-channel seven-day load time, peak RSS, 100,000-row rendering, and Intune description resolution. Record CPU count and OS build with every measurement.
4. Capture notes and screenshots for grouping, filter libraries, and filter-driven highlights.

The issue comment receives the corrected matrix, corpus manifest, measurement table, and interaction evidence. Uncontrolled comparisons remain labeled as such.

### Provider metadata

Complete Windows provider traversal with `EvtOpenPublisherEnum`, `EvtOpenPublisherMetadata`, publisher metadata properties, and object-array properties. Persist event descriptions, message tables, levels, tasks, opcodes, keywords, channel names, templates, and source metadata. Add explicit unsupported behavior outside Windows.

Generate and ship curated provider databases covering MDM, Autopilot, ESP, AAD, ConfigMgr client, AppX, and Windows Update providers. Use sanitized source material and record the Windows build and provider version metadata. Add import and export commands that preserve all provider versions and round-trip compressed JSON without loss.

Acceptance: a real Windows capture opens through the existing provider reader, a sanitized EVTX on macOS or Linux renders descriptions from the curated database, and import/export round-trips pass structural and rendering tests.

### Analysis UX

Implement the layered filter pipeline and all quick-filter modes: multiple words, multiple strings, all words, all strings, Event ID lists with ranges, case sensitivity, and show or hide behavior. Keep the server-side XPath subset validated and preserve on-load and after-load criteria. Persist the expanded model in saved filters.

Add filter-driven row highlighting with deterministic precedence and accessible labels. Add row tags and bookmarks through the stable EVTX marker adapter. Complete the event-viewer font migration to `logListFontSize`, `logDetailsFontSize`, and `getLogListMetrics` for the workspace, pickers, filter controls, detail pane, and virtualizer.

Acceptance: filter predicates produce the same result whether pushed down or evaluated locally, markers survive ordering and streaming changes, and a font-size change updates both row and detail layout.

### Unified sources

Extend the unified timeline to interleave multiple EVTX files, multiple live channels, and multiple machines. Preserve source and machine provenance, deterministic ordering, live append behavior, and unplaced coverage.

Stage `MDMDiagReport.zip` through the bounded archive implementation. Inventory EVTX, text-log, registry, and command-output members. Route supported members through existing parsers and preserve member paths, hashes, duplicate decisions, size limits, malformed data, and skipped members in coverage output.

Add exact-first, machine-scoped correlation for process, session, activity, related-activity, device, and user identifiers. Reuse the ESP correlation ordering where it applies, but expose ambiguity rather than selecting a convenient match.

### Source expansion

Add remote computer sources through `EvtOpenSession` and the operating-system credential path. Do not persist credentials in configuration files. Add recursive folder and wildcard loading with stable source identity and deterministic deduplication.

Support archived channels and Volume Shadow Copy paths with explicit Windows elevation boundaries. Characterize the `evtx` 0.12.2 recovery behavior for damaged and dirty files, and surface unrecoverable chunks as coverage gaps instead of silently skipping them.

Acceptance: local, remote, folder, archive, VSS, and damaged-file scenarios each return records plus precise errors or gaps. Windows-only behavior has Windows-lab evidence.

### Output and live behavior

Add a shared streaming writer for CSV, TSV, JSON, XML, HTML, and raw event XML. Add headless CLI export with direct file and stdout destinations. The CLI uses the same normalized records, filter model, redaction projection, and serializers as the GUI.

Add `EvtSubscribe` push tailing with polling fallback where subscription is unavailable. Preserve sequence and coverage reporting across both modes. Add channel clearing only behind explicit confirmation, an elevation check, and the existing application elevation and restoration path.

Acceptance: large exports do not require an in-memory copy of all records, subscription and polling produce equivalent normalized events, and clear operations cannot run without confirmation and elevation.

### Diagnosis and redaction

Implement operational rules for Autopilot, ESP, MDM enrollment, and ConfigMgr client health over normalized events. Reuse evidence-backed finding shapes from existing Intune, ESP, DSRegCmd, and SCCM rule engines. Every finding includes evidence references, confidence, next checks, and coverage gaps.

Add `error_db` enrichment for event data fields while preserving raw, decimal, hexadecimal, unknown, and malformed values. Add a cross-source “what went wrong” summary that consumes event findings, text-log findings, timeline edges, and coverage gaps without converting gaps into failures.

Apply the shared redaction projection to every export format, including raw XML. Redaction tests cover secrets, identities, paths, tenant data, serials, hardware identifiers, and oversized content.

## Dependency graph

```text
Foundation
   |
   +--> Phase 0 evidence
   +--> Provider capture --> curated DB + import/export
   +--> filter model --> quick filters --> highlights and markers
   +--> portable provenance and coverage
                |
                +--> archive and bundle intake --> multi-source merge
                |                                      |
                |                                      +--> correlation
                +--> source expansion                  |
                +--> streaming export --> CLI ---------+
                +--> redaction ------------------------+
                                                       |
                                                       v
                                              operational diagnosis
```

Phase 0 evidence can run in parallel with portable parser-side work after the Foundation lane. Provider capture and remote live work remain Windows lanes. Filter UX, portable export, and parser-side provider rendering can proceed in parallel when their contracts are frozen. Timeline merge waits for provenance and source adapters. Diagnosis waits for normalized events, correlation, and redaction projections.

## Error handling and security

- Unsupported platforms return structured unsupported results, not empty success.
- Permission failures remain distinguishable from empty sources.
- Batch loss, truncation, malformed records, skipped archive members, and incomplete metadata remain visible as coverage.
- Remote credentials use the operating-system credential path and never enter persisted filter or source configuration.
- Archive extraction keeps existing entry, size, path, and total-byte limits. Member paths cannot escape the staging directory.
- Export redaction runs before serialization, and formula neutralization runs for spreadsheet-oriented formats.
- Provider and map inputs are treated as untrusted data. Decompression, JSON, YAML, and XML limits prevent unbounded allocation.

## Verification policy

For every code lane:

1. Add a failing contract test for each new observable behavior.
2. Implement the smallest end-to-end path.
3. Run focused Rust or frontend tests and inspect the exact diff independently.
4. Run applicable aggregate gates: Rust tests, strict Clippy, wasm32 check for parser changes, TypeScript check, and diff checks.
5. Run Windows-lab scenarios for Windows APIs, capture, remote access, subscriptions, channel clearing, archive/VSS paths, and performance.
6. Review the exact committed range with CodeRabbit and an independent reviewer before proposing integration.

The project does not claim Windows acceptance from macOS compilation. The issue remains open until all 26 unchecked items have direct evidence and the child PRs are independently reviewed.
