# Task 4 fix report: provider database distribution and import/export

Date: 2026-08-18

## Scope

Fixed the five P1/P2 findings recorded in `task-4-brief.md` at the integrated Task 4 HEAD. The implementation is limited to provider database distribution, provider row selection, parser coverage, and the corresponding IPC wire type handling.

## Fixes

- **Packaged artifact provenance (P1):** A real Windows/EventLogExpert `ProviderDetails` database is not available in this macOS repository, so no `.db` was fabricated. The packaged resource now contains `src-tauri/resources/provider-db/provider-manifest.json`, which deterministically reports `status: "unavailable"`, the missing Windows-capture reason, and all seven required provider families (MDM, Autopilot, ESP, AAD, ConfigMgr client, AppX, and Windows Update). `packaged_provider_directory` requires and validates this manifest; an unavailable manifest is an explicit load error and `.gitkeep` cannot be treated as successful coverage. The implementation makes no Windows-runtime or curated-database claim.
- **Unresolved insertions (P1):** Provider rendering now returns a structured `DescriptionOutcome`. Missing insertion positions are recorded as `EvtxCoverageGapKind::Provider` gaps tied to the source and event record, added to parser error messages, and then use the existing field/payload fallback. `%n` markers are therefore never silently discarded.
- **All provider/version rows (P1):** `ProviderStore` caches all captured rows for a provider instead of only the first/highest row. Event lookup searches all rows, chooses an exact event version before falling back to another row defining the event, and preserves the existing deterministic row ordering and `VersionKey` identities.
- **Provider payload failures (P1):** `ProviderStore::provider` and event lookup now return `Result`; corrupt/unsupported gzip or JSON payloads propagate as errors. The parser converts those failures into structured provider coverage gaps and user-facing error messages rather than a normal metadata miss.
- **Parameters coverage (P2):** Generated `ProviderDetails.Parameters` now contains `{"unavailableCategories":[...]}`, the reader-compatible coverage object. The dedicated `ProviderCaptureState` remains intact, and the reader's Parameters fallback now retains declared unavailable-category coverage for databases without the auxiliary state table.
- **Wire contract:** Added the `provider` coverage kind to the frontend EVTX coverage union and validator so structured provider gaps survive IPC validation and are displayed with the existing coverage banner.

## TDD evidence

The focused red run was:

```text
cargo test -p cmtrace-open --lib event_log::provider_db::tests::
```

It failed to compile the newly added tests because the required production seam was absent: `provider_for_event` did not exist, `ProviderStore::provider` could not return `expect_err`, the parser had no `DescriptionOutcome`, and the packaged manifest constant did not exist. This was the expected pre-fix failure for the provider/version, payload-error, insertion-coverage, Parameters, and provenance contracts.

## Focused green verification

All commands were run from the Task 4 worktree.

```text
cargo test -p cmtrace-open --lib event_log::provider_db::tests::
```

Result: **20 passed** (provider DB focused suite; 782 filtered).

```text
cargo test -p cmtrace-open --lib event_log::parser::
```

Result: **40 passed, 3 ignored** (parser-focused suite; 759 filtered). The ignored tests require a real provider database via `CMTRACEOPEN_PROVIDER_DB` and remain truthful about that unavailable input.

```text
cargo check -p cmtrace-open --lib --features event-log
```

Result: **Finished** successfully for `cmtraceopen-parser` and `cmtrace-open`.

```text
npm test -- --run src/workspaces/event-log/evtx-coverage.test.ts
```

Result: **1 test file passed; 14 tests passed**.

```text
git diff --check -- src-tauri/src/event_log/models.rs \
  src-tauri/src/event_log/parser.rs src-tauri/src/event_log/provider_db.rs \
  src/workspaces/event-log/evtx-coverage.ts src/workspaces/event-log/types.ts
```

Result: no whitespace errors.

## Explicit blocker

No truthful packaged `.db` can be generated from the current repository contents: the required Windows capture and its source-build/provider-version provenance are absent. The checked-in manifest reports this as unavailable instead of claiming coverage. Windows runtime evidence and real curated provider rows remain an external prerequisite for changing the manifest to `available`.

## Interoperability and atomic-replacement follow-up

- Provider writes now use the EventLogExpert canonical Maps dictionary (`levels: { Entries, IsBitMap: false }`) and an empty compressed message-model list for Parameters. Unavailable-category coverage remains in the keyed `ProviderCaptureState` table, with the legacy Parameters object retained only as a reader fallback.
- Imported nullable VersionKey and payload BLOBs are normalized without dropping rows; row reads retain deterministic source-build/VersionKey/rowid ordering, and malformed required schema columns return precise errors.
- Export validates the staged copy before publication, and write/export staging uses exclusive creation and cleanup. Same-directory replacement uses `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` on Windows and rename replacement elsewhere.

Focused tests were added for canonical payload shapes, nullable imported rows, malformed schema errors, duplicate/failed writes, and deterministic replacement behavior. They were not run in this lane per the parent validation constraint. Direct Windows API/runtime behavior remains unverified on macOS; a Windows build/runtime with the existing `windows` dependency and a real EventLogExpert capture is required to verify replacement and packaged provider provenance.
