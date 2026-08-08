# Intune Device Inventory Log Ingestion and Parsing

## Status

Approved by the repository owner on 2026-07-30.

This design expands issue #354 from a single known file and severity prefix into
complete CMTrace Open ingestion for the log family observed under the Microsoft
Device Inventory Agent log directory.

## Outcome

CMTrace Open will discover and open the complete Device Inventory Agent log
folder, including current files, timestamped rotations, underscore rotations,
and rotation-failure evidence. Each observed wire format will be parsed by a
dedicated Device Inventory implementation rather than falling through to the
generic timestamped or plain-text parsers.

The pure parser API will be discoverable at:

```rust
cmtraceopen_parser::intune::device::windows::inventory
```

Native filesystem discovery remains in `src-tauri`.

## Problem

The Device Inventory Agent writes multiple files under:

```text
C:\Program Files\Microsoft Device Inventory Agent\Logs
```

Issue #354 originally covered only:

```text
IntuneInventoryHarvesterLog.log
```

That is incomplete. The observed directory contains at least:

```text
IntuneInventoryHarvesterLog.log
IntuneInventoryHarvesterLog-YYYY-MM-DD-HHMMSS.log
InventoryAdaptor.log
InventoryAdaptor.log_
```

Additional evidence observed during parser exploration used a
rotation-failure artifact containing ISO-8601 records followed by a .NET
exception and stack trace.

Current behavior loses important structure:

- the harvester timestamp is parsed, but `[Information]`, `[Warning]`, and
  `[Error]` remain in the message;
- generic keyword severity can override the producer's explicit level;
- an explicit warning containing `error` is rendered as Error;
- Inventory Adaptor records fall back to plain text, losing timestamp and PID;
- continuation JSON is detached from the record that introduced it;
- rotation-failure exception and stack-trace lines become unrelated physical
  records;
- the known-location menu does not expose this source family.

## Scope

This change includes:

1. native known-source discovery for the Device Inventory Agent folder and its
   primary files;
2. folder aggregation that includes `.log`, timestamped rotations, and the
   literal trailing-underscore `.log_` rotation;
3. Windows file-association support for the producer's literal `.log_`
   extension;
4. content-first detection for the three observed formats;
5. dedicated parsing, severity, timestamp, PID, and logical-record framing;
6. the canonical Intune device inventory public module;
7. sanitized fixtures and regression contracts;
8. compatibility metadata for existing CMTrace Open consumers.

This change does not include:

- semantic diagnosis of whether inventory collection or upload succeeded;
- correlation with Intune service-side inventory state;
- Graph, WMI, registry, service-control, or SQLite access in the parser crate;
- parsing or committing the original customer/device artifacts;
- changing the generic timestamp parser for unrelated producers;
- application-wide elevation support, which is a separate issue and PR.

## Observed source contracts

### Harvester

Observed names:

```text
IntuneInventoryHarvesterLog.log
IntuneInventoryHarvesterLog-YYYY-MM-DD-HHMMSS.log
```

Wire format:

```text
M/d/yyyy h:mm:ss tt [Level] <message>
```

Example using synthetic values:

```text
7/30/2026 6:00:53 AM [Information] Successfully created Inventory Entity Set with 1 entities.
7/30/2026 10:08:52 AM [Warning] Reporting dropped attribute error for ExampleField: ErrorCode=404.
7/30/2026 10:08:53 AM [Error] Harvester error code: 404, Message: ExampleField result is null.
```

Contract:

- date order is MonthFirst;
- AM/PM is required for this dialect;
- the bracketed level is authoritative;
- recognized levels are Information, Warning, and Error, compared
  case-insensitively;
- the level token is removed from the displayed message;
- a secondary bracketed token such as `[Registry]` remains in the message and
  may populate component metadata only if that transformation is lossless;
- one valid header normally frames one physical record;
- malformed lines are preserved rather than discarded.

### Inventory Adaptor

Observed names:

```text
InventoryAdaptor.log
InventoryAdaptor.log_
```

Wire format:

```text
[ddd MMM d HH:mm:ss yyyy][pid] - <message>
<optional continuation payload>
```

Example using synthetic identifiers:

```text
[Thu Jul 30 13:05:01 2026][8604] - ===== Starting ExecuteAction =====
[Thu Jul 30 13:05:02 2026][8604] - Adapter result:
{"Status":200,"HResult":"0x00000000","Data":{"Example":"value"}}
[Thu Jul 30 13:05:03 2026][8604] - Completed action with HRESULT 0x0, MI_Result 0x0.
```

Contract:

- the English weekday and month tokens are parsed independently of the
  operating-system display locale;
- the second bracket is a decimal process ID and maps to thread/PID metadata;
- the ` - ` delimiter is removed from the displayed message;
- a line without a valid new header is a continuation of the previous record;
- continuation JSON remains intact in the preceding record message;
- a continuation before the first valid header is preserved as an orphan
  record with reduced parse quality;
- the trailing-underscore filename is a supported rotation, not an unknown
  extension.

The producer does not provide an authoritative severity token in this dialect.
The parser therefore preserves Info as the neutral default and may use existing
error-code annotations for highlighting. It must not convert every mention of
`HRESULT` or `ErrorDescription` into an Error record.

### Rotation failure

Observed shape:

```text
<ISO-8601 timestamp> <rotation failure message>
<.NET exception>
<stack trace continuation>
```

Contract:

- a valid ISO-8601 header starts a new record;
- exception and `at ...` stack-trace lines are continuations of the preceding
  record;
- the complete exception stays visible in one logical message;
- the record is Error only when the header or exception content identifies a
  failure, rather than because a continuation happens to contain a generic
  keyword;
- incomplete final records are returned, not dropped;
- filename hints can strengthen detection but cannot be the only signature.

The implementation fixture must be based on a sanitized observed example. If
the original artifact cannot be recovered, this dialect remains fixture-backed
but explicitly experimental until another real sample is validated.

## Public parser design

Add the canonical module:

```text
cmtraceopen_parser
└── intune
    └── device
        └── windows
            └── inventory
```

The module owns:

- Device Inventory format signatures;
- the public dialect enum;
- pure content parsing;
- record framing;
- authoritative harvester-level mapping;
- Inventory Adaptor PID extraction;
- sanitized test helpers and fixtures.

The initial public contract should expose an additive dialect identifier:

```rust
pub enum DeviceInventoryLogDialect {
    Harvester,
    InventoryAdaptor,
    RotationFailure,
}
```

The application dispatcher may add:

```rust
ParserKind::IntuneDeviceInventory
ParserImplementation::IntuneDeviceInventory
ParserSpecialization::{
    IntuneDeviceInventoryHarvester,
    IntuneDeviceInventoryAdaptor,
    IntuneDeviceInventoryRotationFailure,
}
```

The exact serialization names remain camelCase. The compatibility
`LogFormat` may remain `Timestamped` so existing renderers do not need a
breaking format migration. Parser selection metadata must still report the
dedicated implementation and dialect specialization.

The parser must remain:

- pure Rust;
- deterministic;
- free of filesystem and platform APIs;
- compatible with `wasm32-unknown-unknown`;
- additive to existing public APIs.

## Detection

Detection is content-first and conservative.

### Harvester signature

Require multiple sampled records matching all of:

- slash date plus 12-hour time and AM/PM;
- bracketed recognized level immediately after the timestamp;
- non-empty message.

The known filename or Device Inventory directory raises confidence but must not
turn unrelated content into this parser.

### Inventory Adaptor signature

Require multiple sampled records matching:

- bracketed English weekday/month timestamp;
- bracketed decimal PID;
- ` - ` delimiter.

Continuation lines do not count as independent positive signatures.

### Rotation-failure signature

Require:

- at least one valid ISO-8601 header;
- rotation-failure or .NET exception evidence;
- at least one compatible continuation when sufficient sample lines exist.

Generic ISO logs must continue to resolve to the generic timestamped parser.

### Collision behavior

The regression corpus must prove:

- generic US slash-date logs without `[Level]` remain generic;
- bracketed syslog-like timestamps without a PID and delimiter do not match;
- arbitrary JSON does not select Inventory Adaptor;
- generic ISO exception logs without Device Inventory/rotation evidence do not
  match the rotation-failure dialect;
- path hints alone never select the dedicated parser.

## Native known sources

Add a `windows-intune` group:

```text
group_id: intune-device-inventory
group_label: Device Inventory Agent
group_order: 15
```

Add these source intents:

| ID | Kind | Behavior |
| --- | --- | --- |
| `windows-intune-device-inventory-logs` | Folder | Open the complete top-level folder as an aggregate |
| `windows-intune-device-inventory-harvester-log` | File | Open the current harvester log directly |
| `windows-intune-device-inventory-adaptor-log` | File | Open the current Inventory Adaptor log directly |

The folder patterns must include:

```text
IntuneInventoryHarvesterLog*.log
InventoryAdaptor.log
InventoryAdaptor.log_
*.log
*.log_
```

The folder source deliberately has no preferred-file auto-selection. Selecting
the folder entry loads the aggregate so the user actually receives every
relevant file. The direct file entries provide focused single-file shortcuts.

Listing remains bounded to the top-level log directory. SQLite databases under
the separate `InventoryService` directory are not log files and are not opened
by this source.

The Windows association contract currently registers `.log` and `.lo_`.
Register the producer's distinct `.log_` extension as well so
`InventoryAdaptor.log_` can be opened directly from Explorer. Existing
association detection and removal must treat all three extensions
consistently.

## Folder and tail behavior

- Initial folder loading parses every supported top-level file independently,
  then combines entries using the existing aggregate path.
- Each file retains its own parser selection and artifact path.
- Aggregate ordering must remain deterministic under identical timestamps.
- `InventoryAdaptor.log_` must be listed and parsed even though it does not end
  in `.log`.
- The active current files may be tailed.
- Immutable timestamped and underscore rotations are parsed but should not
  produce duplicate live-tail sessions.
- A continuation appended during tailing must attach to its logical record
  using the same framing contract as the initial parse.

If the current tail API cannot safely amend the prior logical record, that
limitation must be covered by a focused regression test and resolved in this
PR rather than silently emitting detached JSON/stack lines.

## Severity and display behavior

Harvester severity mapping:

| Producer level | CMTrace Open severity |
| --- | --- |
| Information | Info |
| Warning | Warning |
| Error | Error |

The explicit level always wins over keyword inference. In particular:

```text
[Information] 0 failed to collect
```

remains Info, and:

```text
[Warning] Reporting dropped attribute error
```

remains Warning.

Inventory Adaptor records default to Info because the producer does not provide
a level. Explicit typed failure analysis belongs in a later semantic analyzer.
Known HRESULT spans may be annotated without changing the record's severity.

Rotation-failure records preserve the entire exception and map a confirmed
failure record to Error.

## Privacy and fixture policy

The discovered source artifacts contain sensitive values, including device
names, domains, serial numbers, usernames, policy/report IDs, paths, pipe
names, and inventory payloads.

The original files must not be committed.

Fixtures must:

- use synthetic device, user, domain, path, GUID, and policy values;
- contain only the minimum lines required to prove the grammar;
- replace real hardware and application inventory;
- preserve punctuation, delimiters, line endings, and continuation shape;
- include an explicit comment or manifest field stating that the data is
  synthetic;
- avoid copying large JSON payloads when a small structurally equivalent object
  proves framing.

## Test matrix

### Pure parser tests

1. Harvester Information maps to Info and strips the level.
2. Harvester Warning containing `error` remains Warning.
3. Harvester Information containing `failed` remains Info.
4. Harvester Error maps to Error.
5. MonthFirst AM/PM timestamps normalize correctly.
6. Unknown bracketed level fails conservatively.
7. Secondary `[Registry]` context is preserved.
8. Inventory Adaptor timestamp parses.
9. Inventory Adaptor PID maps to thread/PID metadata.
10. Multiline JSON remains one logical record.
11. Large continuation payload is bounded safely without corrupting framing.
12. Orphan continuation is preserved.
13. `.log_` path selects the same dialect as `.log` when content matches.
14. Rotation-failure exception and stack trace remain one logical record.
15. Truncated final record is retained.
16. Generic timestamped collision remains generic.
17. Generic ISO collision remains generic.
18. Path-only collision remains generic/plain.
19. UTF-8 and CRLF inputs produce equivalent entries.
20. Serialization of parser selection and dialect is stable.

### Native/application tests

1. Windows known-source metadata contains the folder and two direct files.
2. The source is grouped under Windows Intune / Device Inventory Agent.
3. The folder entry does not auto-select only the harvester file.
4. Folder listing includes `InventoryAdaptor.log_`.
5. Aggregate loading contains entries from each fixture file.
6. Per-file parser selection survives aggregate caching.
7. File-association registration, detection, and removal include `.log_`.
8. Access denied returns a stable structured error consumable by the separate
   application-wide elevation feature.

### Native Windows acceptance

On a Windows device with the agent installed:

1. Open File > Known Locations > Windows Intune > Device Inventory Agent.
2. Confirm current and rotated harvester and adaptor files are listed.
3. Confirm the folder entry loads the aggregate.
4. Confirm Information/Warning/Error rendering follows producer levels.
5. Confirm Inventory Adaptor timestamps and PIDs are populated.
6. Confirm JSON and exception continuations stay with their parent records.
7. Append a new record to each current file and confirm tail behavior.
8. Repeat from a standard, non-elevated process and record whether ACLs permit
   access.

macOS or Linux may prove pure parsing and metadata construction but cannot
claim the native Windows source or ACL acceptance.

## Implementation boundaries

The implementation should be delivered in phases of no more than five files
per phase:

1. pure parser contract and failing fixtures;
2. parser implementation and dispatcher integration;
3. native known-source metadata and folder inclusion;
4. tail/logical-record integration if required;
5. documentation and full verification.

Each phase begins with a failing focused test and ends with the focused test
green. Structural cleanup of files over 300 lines, if required, is a separate
commit before behavior changes.

## Verification

From the repository root:

```bash
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo test --locked --manifest-path src-tauri/Cargo.toml
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
npx tsc --noEmit
npx eslint . --quiet
cargo fmt --check --all
git diff --check
```

Native Windows CI remains the acceptance boundary for Windows compilation,
known-location visibility, ACL behavior, and live tailing.

## Issue and PR boundary

Expand issue #354 to this complete source-family contract. The parser and
known-source work belong in one issue-scoped PR because the user-visible
outcome is that CMTrace Open can discover and understand the entire folder.

The PR closes only #354 and references epic #356.

Application-wide elevation is deliberately tracked and reviewed separately.
