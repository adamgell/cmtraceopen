# Intune Device Inventory Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CMTrace Open discover, aggregate, parse, and tail every observed Microsoft Device Inventory Agent log format under issue #354.

**Architecture:** Add a pure parser at `cmtraceopen_parser::intune::device::windows::inventory` with explicit Harvester, Inventory Adaptor, and Rotation Failure dialects. Route it through the existing parser-selection contract, then add Windows known sources and `.log_` association support without weakening generic format detection.

**Tech Stack:** Rust 1.88, `regex`, `chrono`, `serde`, Tauri v2, React 19/TypeScript, Cargo integration tests, Vitest.

## Global Constraints

- Keep `cmtraceopen-parser` pure Rust and compatible with `wasm32-unknown-unknown`.
- Do not add filesystem, registry, WMI, Graph, EVTX, Tauri, Tokio, or Windows dependencies to the parser crate.
- Treat harvester `[Information]`, `[Warning]`, and `[Error]` tokens as authoritative severity.
- Preserve Inventory Adaptor JSON and rotation-failure exception continuations as logical records.
- Detection is content-first; path hints alone cannot select the dedicated parser.
- Preserve `LogFormat::Timestamped` as the compatibility format.
- Additive serialized fields use camelCase and do not break current consumers.
- Never commit the original Device Inventory artifacts; fixtures are synthetic and minimized.
- Register `.log_` independently from existing `.log` and `.lo_` associations.
- A non-Windows run cannot claim native Windows source, file-association, ACL, or tail acceptance.
- Each implementation phase touches no more than five files.
- Begin every behavior change with a focused failing test.

---

## File Structure

### Pure parser

- Create `crates/cmtraceopen-parser/src/intune/device/mod.rs`: device family namespace.
- Create `crates/cmtraceopen-parser/src/intune/device/windows/mod.rs`: Windows device namespace.
- Create `crates/cmtraceopen-parser/src/intune/device/windows/inventory.rs`: signatures, dialect detection, parsing, framing, timestamp/PID/severity extraction.
- Modify `crates/cmtraceopen-parser/src/intune/mod.rs`: export `device`.
- Modify `crates/cmtraceopen-parser/src/models/log_entry.rs`: add parser kind, implementation, and three specializations.
- Modify `crates/cmtraceopen-parser/src/parser/detect.rs`: construct and detect the dedicated selections.
- Modify `crates/cmtraceopen-parser/src/parser/mod.rs`: dispatch the new implementation.

### Tests and fixtures

- Create `crates/cmtraceopen-parser/tests/intune_device_inventory.rs`: pure public-API, dispatcher, and collision contract using inline synthetic samples.
- Modify `src-tauri/tests/parser_regression_corpus.rs`: application integration snapshot.
- Modify `src-tauri/tests/parser_supported_formats.rs`: supported-format contract.
- Modify `src/types/log.ts`: serialized parser unions.

### Native source integration

- Modify `src-tauri/src/commands/known_sources.rs`: Device Inventory group, aggregate folder, and direct file entries.
- Modify `src-tauri/src/commands/file_association.rs`: `.log_` registration/detection/removal.
- Modify `src-tauri/src/watcher/tail.rs`: preserve logical continuation records across appended batches.
- Modify `src/lib/log-source.ts`: ensure the Device Inventory folder intent opens aggregate content.
- Add focused tests beside the modified Rust/TypeScript owners.

## Interfaces

The pure module produces:

```rust
pub enum DeviceInventoryLogDialect {
    Harvester,
    InventoryAdaptor,
    RotationFailure,
}

pub fn detect_dialect(path: &str, content: &str) -> Option<DeviceInventoryLogDialect>;

pub fn parse_content(
    content: &str,
    file_path: &str,
    dialect: DeviceInventoryLogDialect,
) -> (Vec<LogEntry>, u32);
```

The dispatcher produces these serialized selections:

```rust
ParserKind::IntuneDeviceInventory
ParserImplementation::IntuneDeviceInventory
ParserSpecialization::IntuneDeviceInventoryHarvester
ParserSpecialization::IntuneDeviceInventoryAdaptor
ParserSpecialization::IntuneDeviceInventoryRotationFailure
```

All three use `LogFormat::Timestamped` and `RecordFraming::LogicalRecord`.

Harvester was planned as `RecordFraming::PhysicalLine` because one header
normally frames one physical line. Implementation review corrected that: the
parser attaches a non-header line to the record above it in every dialect, so
reporting `PhysicalLine` would have both misdescribed the parse for consumers
and let tailing emit a harvester continuation as a detached record while the
initial parse attached it.

---

### Task 1: Implement the pure Device Inventory parser with a green contract

**Files:**
- Create: `crates/cmtraceopen-parser/tests/intune_device_inventory.rs`
- Create: `crates/cmtraceopen-parser/src/intune/device/mod.rs`
- Create: `crates/cmtraceopen-parser/src/intune/device/windows/mod.rs`
- Create: `crates/cmtraceopen-parser/src/intune/device/windows/inventory.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/mod.rs`

**Interfaces:**
- Consumes: `LogEntry`, `LogFormat`, `Severity`, `chrono`, and `regex`.
- Produces: the green public `DeviceInventoryLogDialect`, `detect_dialect`,
  and `parse_content` contract for all three dialects.

- [ ] **Step 1: Write failing public-API tests with inline synthetic samples**

Define these minimal synthetic strings directly in the test file:

```text
7/30/2026 6:00:53 AM [Information] Completed harvesting signed policies: 118 succeeded, 0 failed to collect.
7/30/2026 10:08:52 AM [Warning] Reporting dropped attribute error for ExampleField: ErrorCode=404.
7/30/2026 10:08:53 AM [Error] Harvester error code: 404, Message: ExampleField result is null.
```

```text
[Thu Jul 30 13:05:01 2026][8604] - Adapter result:
{"Status":200,"HResult":"0x00000000","Data":{"Example":"value"}}
[Thu Jul 30 13:05:03 2026][8604] - Completed action with HRESULT 0x0, MI_Result 0x0.
```

```text
2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.
System.IO.IOException: The process cannot access the file.
   at Synthetic.Inventory.Rotate()
```

- [ ] **Step 2: Assert the direct pure-module contract**

Call the planned public module directly:

```rust
let (entries, parse_errors) =
    cmtraceopen_parser::intune::device::windows::inventory::parse_content(
    HARVESTER,
    "IntuneInventoryHarvesterLog.log",
    DeviceInventoryLogDialect::Harvester,
);
assert_eq!(parse_errors, 0);
assert_eq!(entries[0].severity, Severity::Info);
assert_eq!(
    entries[0].message,
    "Completed harvesting signed policies: 118 succeeded, 0 failed to collect."
);
assert_eq!(entries[1].severity, Severity::Warning);
assert_eq!(entries[2].severity, Severity::Error);
```

Add equivalent assertions for Adaptor PID `8604`, two logical entries, embedded
JSON, rotation-failure stack framing, dialect detection, path-only rejection,
unknown levels, CRLF normalization, orphan continuations, and truncated final
records.

- [ ] **Step 3: Run the focused test and verify RED**

Run:

```bash
cargo test --locked -p cmtraceopen-parser --test intune_device_inventory
```

Expected: compilation fails because `intune::device` does not exist.

- [ ] **Step 4: Export the canonical hierarchy**

```rust
// intune/mod.rs
pub mod device;

// intune/device/mod.rs
pub mod windows;

// intune/device/windows/mod.rs
pub mod inventory;
```

- [ ] **Step 5: Implement strict signatures and parsing**

Use lazily initialized regexes with these anchors:

```rust
r"^(?P<date>\d{1,2}/\d{1,2}/\d{4}) (?P<time>\d{1,2}:\d{2}:\d{2} [AP]M) \[(?P<level>Information|Warning|Error)\] (?P<message>.*)$"
r"^\[(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]\[(?P<pid>\d+)\] - (?P<message>.*)$"
r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^ ]+) (?P<message>.*)$"
```

Parse Harvester dates with `%m/%d/%Y %I:%M:%S %p` and map Information,
Warning, and Error directly to `Severity::Info`, `Severity::Warning`, and
`Severity::Error`. Implement Adaptor PID extraction, JSON continuation
framing, rotation-failure exception framing, orphan preservation, and
`detect_dialect`. Require two Harvester/Adaptor headers unless a matching
filename provides the path hint; path alone never matches. Keep the parser
pure and set every emitted entry's format to `LogFormat::Timestamped`.

- [ ] **Step 6: Run the focused test and verify GREEN**

```bash
cargo test --locked -p cmtraceopen-parser --test intune_device_inventory
```

Expected: every direct public-module test passes with pristine output.

- [ ] **Step 7: Commit the green task**

```bash
git add crates/cmtraceopen-parser/src/intune crates/cmtraceopen-parser/tests/intune_device_inventory.rs
git commit -m "feat(intune): parse Device Inventory log dialects"
```

---

### Task 2: Integrate parser selection and serialization

**Files:**
- Modify: `crates/cmtraceopen-parser/src/models/log_entry.rs`
- Modify: `crates/cmtraceopen-parser/src/parser/detect.rs`
- Modify: `crates/cmtraceopen-parser/src/parser/mod.rs`
- Modify: `src/types/log.ts`
- Modify: `crates/cmtraceopen-parser/tests/intune_device_inventory.rs`

**Interfaces:**
- Consumes: Task 1's dialect detector and parser.
- Produces: stable dedicated parser-selection metadata in Rust and TypeScript.

- [ ] **Step 1: Add the serialized variants**

Add `IntuneDeviceInventory` to `ParserKind` and `ParserImplementation`. Add the
three specialization variants exactly as declared in the Interfaces section.
Mirror their camelCase names in `src/types/log.ts`. Extend
`intune_device_inventory.rs` with dispatcher assertions for parser,
implementation, specialization, compatibility format, record framing, and
generic timestamp/path-only collisions.

- [ ] **Step 2: Add a resolved-parser constructor**

```rust
pub fn intune_device_inventory(dialect: DeviceInventoryLogDialect) -> Self {
    let specialization = match dialect {
        DeviceInventoryLogDialect::Harvester => {
            ParserSpecialization::IntuneDeviceInventoryHarvester
        }
        DeviceInventoryLogDialect::InventoryAdaptor => {
            ParserSpecialization::IntuneDeviceInventoryAdaptor
        }
        DeviceInventoryLogDialect::RotationFailure => {
            ParserSpecialization::IntuneDeviceInventoryRotationFailure
        }
    };
    Self::new(
        ParserKind::IntuneDeviceInventory,
        ParserImplementation::IntuneDeviceInventory,
        ParserProvenance::Dedicated,
        ParseQuality::Structured,
        RecordFraming::LogicalRecord,
        DateOrder::MonthFirst,
        Some(specialization),
    )
}
```

Return `LogFormat::Timestamped` from `compatibility_format`.

- [ ] **Step 3: Detect before generic timestamps**

Call `inventory::detect_dialect(path, content)` after unambiguous registry/DHCP
headers and before the generic timestamp count fallback. Return the dedicated
selection only when it returns `Some`.

- [ ] **Step 4: Dispatch whole-content parsing**

In `parse_content_with_selection`, handle
`ParserImplementation::IntuneDeviceInventory` before physical line splitting:

```rust
let dialect = inventory::dialect_from_specialization(selection.specialization)
    .expect("Device Inventory selection carries a dialect");
let (entries, parse_errors) = inventory::parse_content(content, file_path, dialect);
```

Keep error-code annotation as the common post-processing step.

- [ ] **Step 5: Run the public contract**

```bash
cargo test --locked -p cmtraceopen-parser --test intune_device_inventory
```

Expected: all three dialect and collision tests pass.

- [ ] **Step 6: Run parser-crate regression gates**

```bash
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
```

Expected: both commands pass.

- [ ] **Step 7: Commit dispatcher integration**

```bash
git add crates/cmtraceopen-parser/src/models/log_entry.rs crates/cmtraceopen-parser/src/parser/detect.rs crates/cmtraceopen-parser/src/parser/mod.rs src/types/log.ts crates/cmtraceopen-parser/tests/intune_device_inventory.rs
git commit -m "feat(parser): detect Device Inventory formats"
```

---

### Task 3: Add application parser regression coverage

**Files:**
- Create: `src-tauri/tests/corpus/intune_device_inventory/clean/IntuneInventoryHarvesterLog.log`
- Create: `src-tauri/tests/corpus/intune_device_inventory/clean/InventoryAdaptor.log_`
- Modify: `src-tauri/tests/parser_regression_corpus.rs`
- Modify: `src-tauri/tests/parser_supported_formats.rs`

**Interfaces:**
- Consumes: dedicated parser selections from Task 2.
- Produces: app-level regression snapshots and supported-format enumeration.

- [ ] **Step 1: Add synthetic app fixtures**

Copy only the minimal synthetic shapes from Task 1 into the application corpus.
Do not copy original device values.

- [ ] **Step 2: Add failing selection snapshots**

Assert parser `IntuneDeviceInventory`, implementation
`IntuneDeviceInventory`, correct specialization, Timestamped compatibility,
PID extraction, authoritative warning severity, and JSON logical framing.

- [ ] **Step 3: Run focused app tests**

```bash
cargo test --locked --manifest-path src-tauri/Cargo.toml --test parser_regression_corpus intune_device_inventory
cargo test --locked --manifest-path src-tauri/Cargo.toml --test parser_supported_formats
```

Expected: pass.

- [ ] **Step 4: Commit application contracts**

```bash
git add -f src-tauri/tests/corpus/intune_device_inventory src-tauri/tests/parser_regression_corpus.rs src-tauri/tests/parser_supported_formats.rs
git commit -m "test(parser): cover Device Inventory formats"
```

---

### Task 4: Add Device Inventory known sources

**Files:**
- Modify: `src-tauri/src/commands/known_sources.rs`
- Modify: `src/lib/log-source.ts`
- Test: `src-tauri/src/commands/known_sources.rs`
- Create: `src/lib/log-source.test.ts`

**Interfaces:**
- Consumes: existing `KnownSourceMetadata` and aggregate folder loading.
- Produces: one aggregate folder source and two direct file sources.

- [ ] **Step 1: Write failing metadata tests**

Assert exact IDs, group `intune-device-inventory`, order `15`, Program Files
paths, patterns including `*.log_`, and `default_file_intent == None` for the
folder.

- [ ] **Step 2: Add the three known sources**

Add:

```text
windows-intune-device-inventory-logs
windows-intune-device-inventory-harvester-log
windows-intune-device-inventory-adaptor-log
```

The folder points to
`C:\Program Files\Microsoft Device Inventory Agent\Logs` and has no preferred
file. Direct files point to `IntuneInventoryHarvesterLog.log` and
`InventoryAdaptor.log`.

- [ ] **Step 3: Prove aggregate folder intent**

Add a TypeScript test showing the folder source reaches the folder batch loader
without `selectedFilePath`, while each direct file reaches
`openLogSourceFile`.

- [ ] **Step 4: Run focused tests**

```bash
cargo test --locked --manifest-path src-tauri/Cargo.toml known_sources
npx vitest run src/lib/log-source.test.ts
```

Expected: pass.

- [ ] **Step 5: Commit source discovery**

```bash
git add src-tauri/src/commands/known_sources.rs src/lib/log-source.ts src/lib/log-source.test.ts
git commit -m "feat(intune): add Device Inventory known sources"
```

---

### Task 5: Register the `.log_` Windows association

**Files:**
- Modify: `src-tauri/src/commands/file_association.rs`
- Test: `src-tauri/src/commands/file_association.rs`

**Interfaces:**
- Consumes: the current `.log`/`.lo_` association loop.
- Produces: symmetric registration, detection, and removal for `.log_`.

- [ ] **Step 1: Write a failing extension-set test**

Extract a platform-independent constant:

```rust
const LOG_FILE_EXTENSIONS: &[&str] = &[".log", ".lo_", ".log_"];
```

Test that the set is unique and includes all three exact strings.

- [ ] **Step 2: Replace duplicated extension arrays**

Use `LOG_FILE_EXTENSIONS` for association creation, status detection, and
removal. Do not normalize `.log_` into `.lo_`.

- [ ] **Step 3: Run focused tests**

```bash
cargo test --locked --manifest-path src-tauri/Cargo.toml file_association
```

Expected: pass on the host; native registry behavior remains a Windows gate.

- [ ] **Step 4: Commit association support**

```bash
git add src-tauri/src/commands/file_association.rs
git commit -m "feat(windows): associate Device Inventory log rotations"
```

---

### Task 6: Preserve logical records during tailing

**Files:**
- Modify: `src-tauri/src/watcher/tail.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/device/windows/inventory.rs`
- Test: `src-tauri/src/watcher/tail.rs`
- Test: `crates/cmtraceopen-parser/src/intune/device/windows/inventory.rs`

**Interfaces:**
- Consumes: Device Inventory logical framing.
- Produces: deterministic continuation handling for appended Adaptor JSON and exception lines.

- [ ] **Step 1: Write failing split-append tests**

Simulate one poll ending with:

```text
[Thu Jul 30 13:05:02 2026][8604] - Adapter result:
```

and the next poll beginning with JSON before the pending-record debounce
expires. Assert the result is one logical record, not a detached plain entry.
Repeat for an ISO failure header followed by a stack trace.

- [ ] **Step 2: Add a bounded pending-record state**

Store a pending Device Inventory logical record only for selections whose
framing is `LogicalRecord`. Track `last_updated: Instant`, hold the newest
record for a 250 ms quiet-period debounce, and append continuation bytes that
arrive before the debounce expires. Bound pending bytes to 1 MiB. Flush on a
new valid header, 250 ms of quiescence, explicit session stop, parser change,
or overflow. On overflow, emit the bounded record and increment parse errors
rather than discarding content.

- [ ] **Step 3: Reuse parser framing helpers**

Expose pure helpers from `inventory.rs` that accept a pending record and new
lines. Do not duplicate timestamp or header regexes in `tail.rs`.

- [ ] **Step 4: Run focused tests**

```bash
cargo test --locked -p cmtraceopen-parser intune::device::windows::inventory
cargo test --locked --manifest-path src-tauri/Cargo.toml watcher::tail
```

Expected: split-append tests pass and existing tail tests remain green.

- [ ] **Step 5: Commit tail framing**

```bash
git add crates/cmtraceopen-parser/src/intune/device/windows/inventory.rs src-tauri/src/watcher/tail.rs
git commit -m "fix(tail): preserve Device Inventory logical records"
```

---

### Task 7: Complete documentation and verification

**Files:**
- Modify: `crates/cmtraceopen-parser/README.md`
- Modify: `crates/cmtraceopen-parser/src/lib.rs`
- Modify: `docs/superpowers/plans/2026-07-30-intune-device-inventory-ingestion.md`

**Interfaces:**
- Consumes: completed implementation.
- Produces: docs.rs navigation, verification evidence, and completed plan checkboxes.

- [ ] **Step 1: Document the canonical public path**

Add a root-doc example that parses synthetic content through
`intune::device::windows::inventory`, lists the three dialects, and states that
native discovery belongs to the desktop adapter. Mark Rotation Failure
detection as experimental until a second recoverable real artifact validates
the synthetic contract.

- [ ] **Step 2: Run full verification**

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

Expected: all host-valid commands pass.

- [ ] **Step 3: Run native Windows acceptance**

Use the eight acceptance steps in the approved design. Record the Windows
commit SHA, agent version, source paths, standard-user ACL result, and tail
result in the PR.

- [ ] **Step 4: Commit documentation**

```bash
git add crates/cmtraceopen-parser/README.md crates/cmtraceopen-parser/src/lib.rs docs/superpowers/plans/2026-07-30-intune-device-inventory-ingestion.md
git commit -m "docs(parser): document Device Inventory support"
```

- [ ] **Step 5: Open the dedicated PR**

Push `codex/intune-device-inventory` and open a PR that references epic #356
and closes only #354. Include focused test commands, full gate results, native
Windows status, and an explicit statement that original logs were not
committed.
