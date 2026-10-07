# Windows Firewall log support: design for issue #814

Status: approved; implemented and tested with synthetic data in [PR #818](https://github.com/adamgell/cmtraceopen/pull/818). Review corrections and exact-head CI remain tracked on the PR. The inspected baseline below is historical; this status is not Windows UI acceptance or merge authorization.

Issue: https://github.com/adamgell/cmtraceopen/issues/814

Inspected baseline: `497a7a06a882eaad886ea25ba11ac8a301e16630`

## Outcome and boundaries

Open Windows Firewall `pfirewall.log` in the existing Log Explorer, with a dedicated parser, readable traffic summaries, every original field available in details, and equivalent results when the same bytes arrive through live tail. ALLOW and DROP are informational observations. INFO-EVENTS-LOST is a warning about missing evidence, not a traffic decision.

Local wall-clock timestamps must remain exactly as logged. Neither the reader's timezone nor a guessed UTC offset may supply an epoch. Records without a trustworthy absolute timestamp are excluded from the unified timeline. NUL padding and loss events must produce visible, bounded coverage information.

There is no new workspace, packet analysis engine, firewall configuration change, network lookup, automatic timezone selection, or reinterpretation of DROP as an error. The parser remains pure Rust and wasm32-compatible. Native file identity, encoding and watcher ownership remain in `src-tauri`.

Use only the already-authorized synthetic fixture set and clearly documented synthetic transformations. The private capture is not an input to implementation, publication, tests, screenshots or this design. The existing uncommitted characterization files need to be read in the original execution task when access returns; they are not available in the inspected GitHub baseline.

## Evidence from the actual code

1. `parser/detect.rs` uses the first 20 non-empty lines for most formats. IIS's record predicate accepts only the shape of a leading date and time, and three such matches select IIS. It does not require HTTP fields. This explains how firewall rows can become IIS records.
2. `parser/iis_w3c.rs::parse_lines` initializes its field list afresh on every call, ignores comment lines other than `#Fields:`, constructs an HTTP summary from missing method/URI/status fields, and interprets its date/time as UTC. A firewall header can therefore produce `- - → -` with no parser error.
3. `parser/mod.rs` dispatches physical-line batches statelessly. `ResolvedParser` contains selection metadata, not the active W3C field schema or time basis.
4. Native `open_log_file` stores selection, initial offset, file identity and a Company Portal-specific continuation seed. `start_tail` obtains offsets/IDs/line numbers from the frontend and consumes only that one-shot continuation seed. `TailReader` does not write an updated parser checkpoint back to `OpenFile`.
5. `TailReader::read_new_entries` already detects same-path replacement by file identity, keeps a reset pending across failed reads, and refreshes encoding on reset. These are valuable contracts to preserve. Its ordinary physical-line path concatenates the previous fragment and a whole append, however, so a NUL-only or unterminated append can accumulate without the bounds used by its specialized logical-record paths.
6. `date-time-format.ts::formatLogEntryTimestamp` sends display strings through JavaScript `Date`. Returning a zoneless string with a null epoch alone does not protect the logged time from host timezone/DST interpretation.
7. `timeline/builder.rs` converts every missing epoch to zero and re-reads the file independently to calculate byte offsets. `timeline/query.rs` later reads one raw line and calls `ResolvedParser::parse_one_line`. A dedicated parser alone would still lose a reordered field schema and section time basis during timeline materialization.
8. The frontend's merged-tab implementation already puts null-epoch records after timestamped records and excludes them from timestamp correlation. Preserve that behavior. It is distinct from the unified timeline workspace.

The earlier characterization run was reported as 15 passing baseline tests plus an intentionally failing acceptance test. This design pass inspected source through GitHub; it did not rerun those tests or inspect the private capture.

## Approach and alternatives

Recommended: add a dedicated firewall parser and a small, explicit firewall stream state. Use it for snapshot parsing, live tail and contextual timeline materialization. Add optional firewall-owned checkpoint, control-token and replacement data to the existing transport. Preserve other formats' present lifecycle, decoding and materialization paths; this issue does not introduce an all-format session framework.

Rejected: extend the IIS parser with firewall branches. Its HTTP projection, UTC assumption and stateless batch contract are the wrong ownership boundaries, and changes would risk genuine IIS behavior.

Rejected: select the generic timestamp parser or display raw text alone. This retains some text but does not solve field mapping, loss-event semantics, time provenance or open/tail parity.

## 1. Detection and field interpretation

Add `ParserKind::WindowsFirewall`, `ParserImplementation::WindowsFirewall`, serialized as `windowsFirewall`, and `ResolvedParser::windows_firewall()`. Its metadata is Dedicated, Structured, PhysicalLine. Follow the existing non-CCM convention: compatibility `LogFormat::Timestamped`; the dedicated parser selection and firewall payload identify the format. Do not create a separate `LogFormat` merely to duplicate the selection.

Run the firewall-specific probe before the broad IIS date/time predicate. Preserve existing authoritative CCM/registry signatures and genuine IIS controls.

The firewall probe recognizes:

- A Windows Firewall software signature, with directive names compared ASCII-case-insensitively
- A `#Fields:` schema containing the distinct keys `date`, `time`, `action`, `protocol`, `src-ip`, `dst-ip`, `src-port`, `dst-port`
- In the absence of a header, one strictly validated canonical firewall-shaped record: valid date/time, known action, 17 or 18 canonical tokens, protocol token, syntactically valid IP addresses or documented placeholders, and numeric-or-placeholder transport fields

A filename alone is not evidence. A leading date/time alone is not evidence. Do not accept an IIS `cs-method`/`cs-uri-stem` schema as firewall. Headerless evidence uses the known canonical 17/18-column order, never arbitrary positional guessing.

Probe at most 64 KiB of non-NUL text and 128 non-empty physical lines. Leading padding is scanned without copying and does not consume the text budget. This deliberately covers the existing 20-line boundary regression without scanning an unbounded meaningful preamble. A signature outside the documented budget is not claimed; users can still see the generic/raw content. A `pfirewall.log` path may prioritize a candidate but does not waive grammar checks.

Canonical 18-column order, supplied by the characterization handoff:

`date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid`

The 17-column variant omits trailing `pid`. Explicit headers determine order and names, including additional unknown columns. `-` remains a literal placeholder in the preserved representation, not a fabricated zero. Numeric protocols remain their original numeric tokens; no service or protocol-name lookup is required.

Mapping rules:

- A valid header replaces the active schema for subsequent records only
- A repeated identical header is harmless; a reordered header takes effect at its own boundary
- `#Time Format:` updates time basis independently of the schema
- A new `#Software:` section resets both schema and time basis before collecting its new directives
- An invalid or duplicate-name field schema invalidates the active schema; do not silently keep the old mapping
- When there is no usable header, canonical mapping is allowed only if the entire record passes the strict headerless grammar; record its schema origin as `canonical`
- Exact field/value counts map normally. The only accepted short-record exception is INFO-EVENTS-LOST with the sole omitted field being a declared final `pid`; preserve that as missing, distinct from literal `-`
- Other count mismatches remain visible as malformed raw records. Do not zip a short row onto a header and accidentally shift values into the wrong fields

The source's `info` integer in a loss event is preserved. If it parses as an unsigned count, the summary may state that count. If absent, invalid or overflowing, retain the raw value and say the loss count is unavailable. Do not convert a loss row into a packet row.

## 2. Public row data and display

Add one optional nested `firewall` field to `LogEntry`, mirrored in TypeScript. Use domain types in `models/log_entry.rs` (or a neighboring firewall model module re-exported there):

```text
FirewallRecord {
  raw_line: String,
  declared_fields: Vec<String>,
  fields: Vec<FirewallField>,
  schema_origin: Header | Canonical | Unavailable,
  time_basis: Local | Utc | Unknown,
  record_kind: Traffic | EventsLost | Malformed,
  truncated: bool
}
FirewallField { name: String, value: Option<String> }
```

`raw_line` preserves the text excluding its physical line terminator, with padding handled separately. `declared_fields` preserves field names and order. For a mapped record, `fields` preserves every value, including unknown names and `-`. For a structurally ambiguous record, leave `fields` empty and retain the header and raw text rather than inventing associations. Oversized rows are visibly marked truncated under the bound below.

Store no sensitive source-specific metadata beyond the opened record. Use strings for source field values so ports, flags, large counters, capitalization and numeric protocol spelling round-trip without loss. Typed display accessors may derive bounded numeric sorts without mutating the stored text. Do not overload DNS fields or HTTP client/server fields.

Default columns: Severity, Date/Time, Message, Action, Protocol, Source IP, Source Port, Destination IP, Destination Port, Path. Details show all declared/mapped fields in original order and the complete bounded raw line. `pid` is a process identifier; it must not populate `thread`.

Traffic message: action, protocol and endpoints, with IPv6 brackets when a port is present. Missing ports display without an invented `:0`. The message is a readable summary; full data remains in details. Search/copy tests must prove access to fields omitted from that summary. A dedicated raw-line copy control is sufficient; do not silently change every format's existing Copy Message behavior.

Severity is Info for ALLOW and DROP, Warning for INFO-EVENTS-LOST. Unknown actions in an explicit schema are retained informationally, without a made-up traffic verdict. Malformed data is not labelled a firewall failure; its coverage warning and parse error explain the limitation.

Update all exhaustive parser maps and validators, including parser labels, column mapping, timeline parser validation and bundle descriptions. Existing Rust `LogEntry` struct literals must receive the new optional field or use an appropriate existing default; this is a mechanical compile-time inventory, not a reason to refactor unrelated parsers.

## 3. Timestamp contract

| Source evidence | `timestamp` | `timezone_offset` | Display |
|---|---|---|---|
| `#Time Format: Local` | `None` | `None` | Original date and time tokens |
| Missing or unrecognized time directive | `None` | `None` | Original date and time tokens, if present |
| Explicit UTC and valid date/time | UTC epoch milliseconds | `Some(0)` | Original tokens with a UTC label |
| Invalid date/time | `None` | `None` | Preserve source text; no normalized date |

Do not call `local_wall_clock_millis`, `Local`, JavaScript `Date`, or the reader's timezone for local/unknown firewall stamps. A local source might have been copied from a different computer; the viewer's zone is not evidence.

Make `formatLogEntryTimestamp` accept the optional firewall metadata and return its display string directly. Route `DiffView` through this entry-aware formatter too; it currently bypasses it. Existing formats keep their existing formatting. This direct branch must preserve DST-gap and repeated-hour strings identically under UTC, Europe/London and America/New_York test processes.

Within a single firewall source, Date/Time sorting may compare validated wall-clock components without manufacturing an epoch. Preserve source line order for unparseable ties. Across sources, only real epochs are comparable; null-epoch firewall records remain outside absolute-time filtering/correlation. Timestamp filters must not treat their missing epoch as January 1970.

## 4. Stateful parser and bounded framing

Create a dedicated parser module and a neighboring stream/framing module rather than growing `tail.rs` with another large grammar implementation. A pure `FirewallStream` owns:

- Current field schema and time basis
- Current physical line number and next stable row ID
- At most 64 KiB of pending non-padding line text
- A counter and starting line for a leading contiguous NUL run, without retaining its bytes
- A discarding-overlong-line flag, so an oversized physical line remains one line
- An optional provisional EOF row identity and its reversible coverage contribution
- Fixed-size cumulative coverage counters and at most eight source-line samples per warning kind

Its outputs contain new rows, full-row replacements, physical-line coverage, bounded coverage counters, and context-change checkpoints needed by a timeline caller. It does not retain all past checkpoints or rows internally.

Proposed pure interface:

```text
FirewallStream::new(next_id: u64, next_line: u32) -> Self
FirewallStream::push_text(&mut self, text: &str, file_path: &str) -> FirewallDelta
FirewallStream::snapshot_eof(&mut self, file_path: &str) -> FirewallDelta
FirewallStream::context(&self) -> &FirewallContext
FirewallStream::reset_generation(&mut self, next_id: u64)
parse_record(line: &str, context: &FirewallContext,
             id: u64, line_number: u32, file_path: &str) -> FirewallRecordResult
```

The parser's ordinary snapshot API uses this same stream, not a second tokenization loop. Native code retains the resulting stream checkpoint rather than reconstructing it from already-projected entries.

### EOF and chunk boundaries

Treat CRLF, a split CR/LF pair, split directives and split field tokens as framing boundaries, not new records. IDs and line numbers count actual physical lines, including comments and blanks; padding with no newline does not create additional lines.

An initial file without a final newline must still show its last record. `snapshot_eof` emits that bounded final row provisionally and leaves its text and identity in the checkpoint. If append extends the same physical line, emit a full-row replacement with the same ID and line number. Do not append a second partial row or try to amend only its message while leaving stale fields/severity. An unterminated header is retained until its newline; it must not prematurely install a schema that could still change.

For normal tail appends, hold an unfinished new line until newline or an explicit snapshot request requires its presentation. Pausing, stopping and restarting a watcher are not file EOF: preserve the checkpoint rather than finalize and forget it. Resetting a source generation discards its old partial/provisional state; no old-generation row is finalized into the replacement.

### Padding and bounds

- `MAX_FIREWALL_LINE_BYTES = 65_536` UTF-8 bytes of decoded non-padding text, shared by snapshot and tail
- `FIREWALL_READ_CHUNK_BYTES = 65_536` raw bytes per native incremental read
- `MAX_FIREWALL_WARNING_SAMPLES = 8` per fixed warning category
- Firewall decoder carry follows the explicit small bounds in section 5; schema size is bounded by the same physical header-line cap

Strip/count NUL padding only at the start of a physical line or in a padding-only span. Never remove an interior NUL and fuse two tokens; escape/preserve the affected raw record and report malformed coverage. A 1 MiB leading NUL run must require a counter, not a 1 MiB pending string or a million warning rows. Count characters as NUL characters unless the native byte decoder supplies an exact byte count; do not mislabel UTF-16 counts as bytes.

An oversized non-padding line retains one bounded prefix, marks `truncated`, increments one coverage/parse error, and discards through its newline. A later valid record parses normally. No silent truncation and no repeated warnings per append of the same overlong line.

This bounds additional stream state and incremental read allocation. The existing initial-open path still materializes a snapshot of the file; eliminating its whole-file allocation is a separate project and is not claimed here.

### Coverage reporting

Use cumulative, generation-scoped `FirewallCoverage` with fixed fields: NUL characters skipped, malformed records, oversized records, loss-event records, known lost-event count, unknown loss-count records, and timestamps without an absolute placement. Keep at most eight line samples for each category. Counters use saturating arithmetic.

Return a snapshot with initial open and updated snapshots with tail batches. The frontend replaces the current generation's counters; it does not add cumulative snapshots together. Show one compact coverage banner in the existing viewer. Loss events remain individual Warning rows; the banner summarizes them without injecting a warning row for every NUL or parser iteration. Valid loss records, known padding and missing timezone are not parser syntax errors. Malformed/capped records are.

Keep the current provisional EOF row's contribution, including warning samples, separate from committed counters. A source snapshot projects committed counters plus that one contribution; extending the row replaces its contribution, and newline commits it once. Thus a provisional malformed row that becomes valid, or a loss count whose last digit arrives later, does not leave a phantom error or double-counted loss. Never subtract provisional values from saturated committed counters. The firewall frontend derives its current parse-error count from the authoritative coverage snapshot instead of adding replacement deltas to the initial error count. Add this reconciliation to the parity tests.

## 5. Native initial-open, tail and generation ownership

Use one opened file handle to obtain the bytes, actual decoding choice, consumed raw byte count and `FileIdentity`. Carry that decoding state from the read; firewall tail setup must not reopen the pathname to infer metadata for bytes already consumed.

Add optional firewall continuation/index artifacts to the native parse output alongside the ordinary `ParseResult`, `ResolvedParser` and source snapshot identity/encoding. Keep the public pure parser free of `FileIdentity`, filesystem access and watcher state. A small native response envelope may add optional firewall session metadata without changing other formats' successful wire representation. `parse_file` may discard continuation artifacts when its caller truly needs only a snapshot; firewall single/batch/folder opens and the timeline builder request the relevant artifacts.

### Firewall decoding contract

The current shared decoder is not sufficient for this contract: its UTF-8 snapshot fallback does not expose whether Windows-1252 was actually used, and its UTF-16 tail path retains an odd byte but not an aligned high-surrogate suffix. Add a firewall-owned byte decoder in the native adapter, using the existing `encoding_rs` dependency. Feed initial raw bytes and later raw chunks through this same decoder. Other parsers keep their existing decoder behavior.

- Encoding state is `Undetermined`, `Utf8`, `Windows1252`, `Utf16Le` or `Utf16Be`; also retain whether a BOM made the choice explicit
- At the start of each empty/new generation, retain at most two possible BOM-prefix bytes until the prefix is confirmed or ruled out. Recognize UTF-8, UTF-16 LE and UTF-16 BE BOMs across separate writes. Do not decode a split BOM as content or padding
- With no BOM, start with strict UTF-8. A trailing sequence that could be completed retains at most three bytes. Initial EOF must keep that suffix resumable; it is not a reason to choose Windows-1252 or emit replacement characters
- If definitive invalid UTF-8 is present in the initial no-BOM snapshot, select Windows-1252 for the entire same-handle snapshot before publishing entries, and retain `Windows1252` as the actual decoding choice
- If a no-BOM generation previously published as UTF-8 later supplies definitive invalid UTF-8, perform one same-generation reparse from byte zero as Windows-1252, using one identity-checked opened handle. Publish an atomic firewall reset with the re-decoded snapshot and replacement checkpoint, not mixed-encoding append rows. Once selected, Windows-1252 remains fixed until source-generation reset. This exceptional reparse uses the already-declared snapshot allocation allowance; normal incremental reads remain capped. If the reread fails or belongs to a different generation, retain the pending transition and do not commit the new encoding/cursor
- A UTF-8 BOM prohibits Windows-1252 fallback. Truly invalid explicitly encoded UTF-8/UTF-16 produces a visible firewall decoding-gap status and leaves the candidate checkpoint uncommitted; never silently substitute characters or spin without a visible reason
- UTF-16 retains an odd byte and an unmatched high surrogate, including a high surrogate exactly at an even-byte chunk boundary. These total at most three raw bytes. Wait for the low surrogate before producing its scalar. Unexpected low surrogates or high-surrogate/non-low pairs are definitive errors under the preceding rule
- The decoder does not normalize CRLF per chunk. Preserve decoded CR/LF characters for the single stream framer, which handles a split pair consistently

An initial snapshot ending in an undecided BOM or incomplete scalar reports a bounded pending-decoding notice while preserving readable prior rows and the exact raw suffix. Snapshot EOF does not flush those bytes lossy; pause/stop also preserves them. Closing the source discards them. Raw consumed offset includes held bytes, whose carry owns them so append cannot replay them. Timeline reads use the resolved actual encoding and do not call unconditional `String::from_utf8_lossy` on firewall records.

Prove this with initial EOF inside every UTF-8 scalar position, an even-byte UTF-16 surrogate split, high-surrogate-plus-odd-byte carry, split BOM after an empty/new generation, actual Windows-1252 non-ASCII data, and late fallback reset. The full open/tail parity test must call `snapshot_eof` at the initial split before resuming.

### Firewall command and worker ownership

For firewall sources, `OpenFile` owns the authoritative checkpoint. It binds together raw consumed offset, file identity, actual encoding/decoder carry, `FirewallStream`, next IDs/line coverage, a source-session identifier and active watch epoch. `TailStart` carries that checkpoint into the worker. Frontend byte offsets are not a substitute for it and must never combine an old schema with a new cursor.

The native firewall open response exposes optional `firewallSessionId`. Each firewall watcher effect uses a `FirewallControlToken { sourceSessionId, watchEpoch }`, with a monotonically increasing epoch allocated in source-owned frontend state, not a component-local counter that resets on remount. Include this token on firewall start, stop, pause and resume commands and on firewall tail/replacement/coverage publications. Existing non-firewall commands omit it and remain on their existing path. A command for a currently open firewall source without its matching token cannot mutate the source.

Validate the source-session ID and atomically admit a new watch epoch before stopping/replacing a worker. Higher epochs supersede lower ones; retrying the active epoch is idempotent. A stale epoch is a harmless rejected/no-op control. A stop arriving before its delayed start records that epoch as cancelled, so the later start cannot revive it. A stop/pause/resume for an older same-path source or watch cannot remove or affect the current worker. Optional token support is format-specific ownership, not a backwards-compatibility layer.

Workers parse into candidate state, then under the same ownership fence verify both token fields against the current `OpenFile` owner, commit the checkpoint and enqueue the corresponding publication. Checking only a worker's private copied token is insufficient. Explicit reopen revokes the old owner before installing the new one. Once superseded, a worker may neither write back a cursor nor publish/finalize pending input. Only one epoch can commit a given source's state. Preserve the current checkpoint across stop/start; do not join a worker while holding a map/checkpoint lock it needs. Frontend listeners also reject mismatched tokens. The same rules apply to each aggregate-folder source and its source-local ID mapping.

Checkpoint semantics:

1. Initial open creates a fresh source-session ID and stores the bounded continuation from the exact snapshot returned to the frontend
2. Pause keeps the same reader/checkpoint. Resume continues from its raw consumed offset
3. Stop/start for the same open source retains and resumes its most recent checkpoint, including pending text and decoder carry; do not reuse the original one-shot seed
4. Explicit reopen creates a fresh source session and supersedes the old watcher. Serialize stop/start ownership and fence old publications; stopping an old session must not remove a newer one
5. An observed identity change or shrink starts a new file generation. Reset schema, time basis, coverage, pending text, EOF replacement identity and decoder carry; refresh encoding from the replacement's own bytes. Continue monotonically increasing row IDs within the same open source session; physical line numbering restarts at one
6. Preserve the existing pending-reset behavior on read/decode failure. Do not advance offsets, commit a new identity or lose the owed reset until the candidate read succeeds
7. A larger same-path replacement still resets through file identity. An empty replacement clears the old view and retains an undecided firewall context until new headers/data arrive
8. Unknown identity remains unknown, not proof of replacement. Document the existing limit: a truncate-and-regrow that occurs wholly between observations and preserves identity may not be distinguishable from append

Include full-row replacement payloads with the firewall control token, expected row ID and line number. A repeated replacement is idempotent. Reuse existing reset behavior to replace the generation's view and reset coverage before processing its new records. Preserve Company Portal's current finalization behavior on its separate non-firewall path.

Keep filesystem decoding transactional and preserve raw-byte offsets. Never derive a seek offset from decoded UTF-8 string length, stripped NUL length, displayed text or row count. Test UTF-8 BOM and UTF-16 decoding boundaries in addition to the supplied UTF-8/CRLF fixtures.

## 6. Unified timeline materialization

Exclude a firewall row whenever its epoch is `None`. Do this before index insertion and count/range calculation; do not map it to zero or borrow a neighboring row's time. Explicit UTC records, including a legitimate zero epoch, remain eligible. Preserve other formats' current behavior in this issue.

Report excluded firewall counts in each timeline source's metadata and render a source notice so a source with all-local timestamps does not appear to be an empty successful capture. Omitted records remain available in Log Explorer. This is a coverage notice, not a failed file read.

For eligible UTC firewall rows only, retain sparse context checkpoints consisting of the first eligible source line using a context and its schema/time basis. Observe schema changes while parsing, but retain a context only when an actual eligible indexed row references it; equal consecutive referenced contexts coalesce. An all-local or header-only source retains no timeline context vector. `SourceRuntime` owns optional firewall materialization state and selects the latest referenced context at or before an indexed row. Pass that context to `parse_record`; never call a fresh stateless parser on a reordered-header row. This index state is proportional to eligible rows, not fixed-size stream state.

Compute raw row offsets from the same byte snapshot used to parse that source. The existing independent parse/read sequence can observe different file generations. Offsets must be encoding-aware, include BOM/padding bytes, and select the actual row text rather than a removed NUL prefix. Store source identity and actual decoding choice in the optional firewall runtime state.

For each materialization request, open the firewall source once, obtain identity/metadata from that handle, validate against the indexed snapshot, and read all needed firewall row bytes from that same handle. A `FirewallReadSession` holds the validated handle for the request; never validate the pathname then reopen it in the row helper. A replacement before open produces a typed changed-source error. Replacement after open cannot mix new-generation bytes into the validated read; the next request detects the new pathname generation. If identity is unavailable, fail conservatively with a distinct generation-unverifiable notice rather than assert a match. Same-identity, same-size in-place mutation remains a documented snapshot limitation; this change does not claim cryptographic immutability.

Introduce the scoped helper `materialize_firewall_entry(session: &mut FirewallReadSession, context: &FirewallContext, index: &EntryIndex) -> Result<LogEntry, FirewallMaterializationError>`. Errors distinguish `SourceChanged`, `GenerationUnverifiable`, read/decode failure and invalid index/context. Decode from the stored actual encoding using bounded chunks through the decoded-line cap; do not reuse the old one-shot 64 KiB raw read, which can truncate a valid UTF-16 firewall row before its 64 KiB decoded limit. Keep ordinary-format `materialize_log_entry`/`materialize_msg` on their existing paths rather than universally refactoring their signatures.

At firewall dispatch sites, propagate these typed errors through the already-Result-returning timeline commands; native entry/detail query helpers may become `Result` internally as required. Do not convert a firewall error to `None`, an empty preview or a successful shorter page. Where existing incident callbacks require `Option<String>`, a narrow adapter must retain the first typed error and make the enclosing command fail before publishing or storing its computed result. Apply that rule to initial sampling/incident construction and tunable recomputation as well as ordinary row/detail queries.

Add matching typed frontend handling: the existing `useTimelineEntries` catch currently swallows errors and `useIncidentDetail` replaces them with null, so both must record a visible firewall source notice. On `SourceChanged`, clear affected cached pages, mark the bundle stale, stop requesting current rows from it, and show “Source changed. Rebuild the timeline to continue.” Rebuild creates a fresh bundle. Other scoped errors receive their own actionable notice and must not be shown as successful empty results. Counts/lanes left on screen are labelled as the stale snapshot until rebuild. The changed-source test must reach this user-visible outcome after an actual query.

## Verification and acceptance

The implementation plan contains the detailed matrix and commands. A PR is ready only when:

- Firewall detection beats the former IIS misclassification and genuine IIS controls remain green
- All valid 17/18-field records, schema permutations and unknown fields round-trip
- The same source snapshot and chunked stream converge on equal rows, IDs, source line numbers, fields, severity, time basis and coverage
- Local/unknown strings are identical across test timezones and never become timeline epoch zero
- Tail restarts, truncation, replacement, failed-read retries and aggregate-folder behavior preserve the defined checkpoint contract
- The 1 MiB NUL and overlong-line tests measure the state bound, not merely output length
- Full/Lite Rust, parser wasm32, TypeScript, frontend, Playwright and exact-commit review gates pass
- Any Windows-native acceptance claim names the exact commit actually run on Windows

## Decisions still requiring evidence

No new product-preference question is needed for the accepted scope. Two implementation prerequisites remain:

1. Reopen the existing execution task and inspect its uncommitted synthetic fixture README/tests before naming or changing those fixtures. The token and schema above are verified handoff facts; exact sample rows were deliberately not invented here
2. Confirm optional firewall control/replacement transport and materialization dispatch against actual `OpenFile`, `TailStart`, native-open, batch/folder and `SourceRuntime` call sites in the checkout. The scoped semantics above are fixed; this read-only pass was not a compiler-driven call-site inventory

Review this written design before implementation. It materially touches shared parser/native/frontend contracts beyond adding a single parser module.

## Pinned source references

- [Detection and selection](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/crates/cmtraceopen-parser/src/parser/detect.rs)
- [IIS parser](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/crates/cmtraceopen-parser/src/parser/iis_w3c.rs)
- [Pure parser dispatch](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/crates/cmtraceopen-parser/src/parser/mod.rs)
- [Row and parser models](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/crates/cmtraceopen-parser/src/models/log_entry.rs)
- [Native parser/read handoff](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/parser/mod.rs)
- [Native open commands](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/commands/file_ops.rs)
- [OpenFile state](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/state/app_state.rs)
- [Tail IPC](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/commands/parsing.rs)
- [Tail reader and lifecycle](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/watcher/tail.rs)
- [Timestamp display](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src/lib/date-time-format.ts)
- [Frontend tail handling](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src/hooks/use-file-watcher.ts)
- [Unified timeline builder](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/timeline/builder.rs)
- [Timeline materialization](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src-tauri/src/timeline/query.rs)
- [Merged-tab ordering and correlation](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/src/lib/merge-entries.ts)
- [Repository execution gates](https://github.com/adamgell/cmtraceopen/blob/497a7a06a882eaad886ea25ba11ac8a301e16630/.claude/skills/cmtraceopen/references/execution-charter.md)
