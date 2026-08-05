# Lossless Bounded Device Inventory Framing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make initial Device Inventory parsing and incremental tailing use one parser-owned, UTF-8-safe, lossless logical-record framing contract with a single 1 MiB production limit.

**Architecture:** The Device Inventory module owns `MAX_LOGICAL_RECORD_BYTES`, incremental framing, explicit final flush, and projection of already-framed records. Initial `parse_content`/`parse_lines` frame and flush before projection; the watcher imports the same limit and projects framed records directly, retaining only debounce, file-fragment, identity, and physical-line rebasing concerns.

**Tech Stack:** Rust, `cmtraceopen-parser`, Tauri watcher, Cargo tests/clippy/fmt, TypeScript compiler.

---

## File structure

- Modify `crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs`: define the sole production bound; make framing use it; add explicit flush; replace the unbounded parse path with bounded framing plus framed-record projection.
- Modify `crates/cmtraceopen-parser/tests/intune_device_inventory.rs`: prove exact limits, lossless UTF-8 splitting, all dialects, line/error semantics, and `parse_content`/`parse_lines` equality.
- Modify `src-tauri/src/watcher/tail.rs`: import the parser limit, use the shared framer/flush/projector for every tail path, and verify initial-load/tail equality.
- Modify `library.md`: route issue #507 work to this plan.

### Task 1: Lock the lossless framing contract with parser tests

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/intune_device_inventory.rs`

- [x] **Step 1: Replace caller-selected bounds in existing framing tests**

Import `MAX_LOGICAL_RECORD_BYTES` and update every `frame_logical_records` call to the production signature:

```rust
use cmtraceopen_parser::intune::device::windows::inventory::{
    detect_dialect, frame_logical_records, parse_content, parse_lines,
    DeviceInventoryLogDialect, MAX_LOGICAL_RECORD_BYTES,
};

let first = frame_logical_records(DeviceInventoryLogDialect::Harvester, None, &[header]);
```

- [x] **Step 2: Add exact-limit, limit-plus-one, and UTF-8 reconstruction tests**

Build a valid header plus deterministic continuation padding so one record is exactly `MAX_LOGICAL_RECORD_BYTES`, then append one ASCII byte for the overflow case. Assert the exact-limit result has no completed records/errors before flush, while limit-plus-one has one overflow, every emitted/pending chunk is bounded, and concatenating chunk content reproduces every sentinel byte. Repeat with an emoji crossing the cut and assert every chunk remains valid UTF-8 and reconstructs the normalized input exactly.

```rust
assert_eq!(exact.pending_record.as_ref().unwrap().len(), MAX_LOGICAL_RECORD_BYTES);
assert_eq!(exact.overflow_count, 0);
assert_eq!(overflow.overflow_count, 1);
assert!(all_chunks.iter().all(|chunk| chunk.len() <= MAX_LOGICAL_RECORD_BYTES));
assert_eq!(all_chunks.concat(), original);
```

- [x] **Step 3: Add whole-input bounded parsing tests for all dialects**

For Harvester, InventoryAdaptor, and RotationFailure, create a valid header followed by a multiline continuation and an oversized single physical line. Assert `parse_content` and `parse_lines` return equal projected entries, line numbers, severities, and parse-error counts; assert overflow increments parse errors and trailing sentinels remain present across emitted messages.

- [x] **Step 4: Run focused tests and confirm the old API/path fails**

Run:

```bash
cargo test -p cmtraceopen-parser --test intune_device_inventory -- --nocapture
```

Expected: FAIL because framing still accepts a caller-provided bound, has no explicit final-flush API, and initial parsing remains unbounded.

### Task 2: Make the parser own framing and projection

**Files:**
- Modify: `crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs`
- Test: `crates/cmtraceopen-parser/tests/intune_device_inventory.rs`

- [x] **Step 1: Add the sole production byte limit and remove the public limit argument**

```rust
pub const MAX_LOGICAL_RECORD_BYTES: usize = 1024 * 1024;

pub fn frame_logical_records(
    dialect: DeviceInventoryLogDialect,
    mut pending_record: Option<String>,
    new_lines: &[&str],
) -> LogicalRecordFramingResult {
    // Split only with String::split_off at previous_char_boundary(...).
}
```

Delete `max_pending_bytes` from the contract and compare only against `MAX_LOGICAL_RECORD_BYTES`. Keep `String::split_off`; do not slice, drain, truncate, or discard the remainder.

- [x] **Step 2: Add an explicit final flush**

Add a consuming method that completes the retained record without changing overflow accounting:

```rust
impl LogicalRecordFramingResult {
    pub fn flush_pending(mut self) -> Self {
        if let Some(content) = self.pending_record.take() {
            self.completed_records
                .push(FramedLogicalRecord::complete(content));
        }
        self
    }
}
```

- [x] **Step 3: Separate bounded framing from projection**

Replace `parse_records(lines: impl Iterator<...>)` with `parse_framed_records(file_path, records, dialect)`. The projector may parse continuations only inside a `FramedLogicalRecord`; it must preserve record-relative physical line positions, then advance the next record start by `physical_lines` (including zero for a mid-line split piece). It returns header-field parse errors only; callers add `overflow_count` once.

```rust
pub fn parse_framed_records(
    file_path: &str,
    records: &[FramedLogicalRecord],
    dialect: DeviceInventoryLogDialect,
) -> (Vec<LogEntry>, u32)
```

- [x] **Step 4: Route both initial entry points through framing and explicit flush**

```rust
let framed = frame_logical_records(dialect, None, lines).flush_pending();
let (entries, projection_errors) =
    parse_framed_records(file_path, &framed.completed_records, dialect);
(
    entries,
    projection_errors.saturating_add(framed.overflow_count),
)
```

`parse_content` collects `content.lines()` and delegates to `parse_lines`; there is no unbounded continuation parser or compatibility fallback left.

- [x] **Step 5: Run focused and full parser suites**

Run:

```bash
cargo test -p cmtraceopen-parser --test intune_device_inventory
cargo test -p cmtraceopen-parser
```

Expected: PASS, including #506 rotation-signature tests.

### Task 3: Route the watcher through the same parser contract

**Files:**
- Modify: `src-tauri/src/watcher/tail.rs`

- [x] **Step 1: Import the parser-owned limit and delete the watcher limit**

```rust
use cmtraceopen_parser::intune::device::windows::inventory::{
    self, DeviceInventoryLogDialect, FramedLogicalRecord, MAX_LOGICAL_RECORD_BYTES,
};
```

Delete `MAX_PENDING_LOGICAL_RECORD_BYTES`; every completed-line and unterminated-fragment bound check uses `MAX_LOGICAL_RECORD_BYTES`.

- [x] **Step 2: Use the no-argument framer on completed and partial lines**

Update normal reads and `enforce_unterminated_logical_bound` to call:

```rust
inventory::frame_logical_records(dialect, pending, &lines)
```

Preserve `pending_fragment` separately until it is a complete physical line or must be split for the bound. Store every returned remainder; never clear it without transferring it to a framed record.

- [x] **Step 3: Use explicit parser flush and direct framed projection**

In `flush_pending_logical_record`, pass the pending record and optional fragment through `frame_logical_records(...).flush_pending()`. In `parse_logical_records`, call `inventory::parse_framed_records`, annotate error-code spans, add framing errors exactly once, rebase entry lines from the current `next_line`, and advance `next_line` by the sum of record `physical_lines`.

```rust
let physical_lines = records
    .iter()
    .fold(0u32, |total, record| total.saturating_add(record.physical_lines));
let (mut entries, projection_errors) =
    inventory::parse_framed_records(&path_str, &records, dialect);
parser::annotate_error_code_spans(&mut entries);
```

- [x] **Step 4: Delete the recursive per-record dispatcher path**

Remove the loop that calls `parser::parse_content_with_selection` for each framed record. The watcher must never re-enter whole-input framing after it already owns frozen framed records.

### Task 4: Prove tail/open parity and bounded retention

**Files:**
- Modify: `src-tauri/src/watcher/tail.rs`

- [x] **Step 1: Update existing overflow tests to the parser constant**

Replace watcher-local constant references with `MAX_LOGICAL_RECORD_BYTES`. Assert every live retained buffer and every emitted logical record remains within the production bound.

- [x] **Step 2: Add an initial-load versus tail harness**

For each dialect, write the same input to an initially empty file in multiple appends (splitting continuations and UTF-8 text across read calls without creating invalid file bytes), collect `TailBatch` entries/errors including explicit debounce flush, and compare against `inventory::parse_content` by these owned fields:

```rust
fn projection(entries: &[LogEntry]) -> Vec<(u32, Severity, String)> {
    entries.iter().map(|entry| (
        entry.line_number,
        entry.severity,
        entry.message.clone(),
    )).collect()
}
```

- [x] **Step 3: Cover all acceptance scenarios in the parity harness**

Use Harvester, InventoryAdaptor, and RotationFailure cases containing multiline records, exact-limit and limit-plus-one logical records, oversized single physical lines, emoji near the split boundary, leading/trailing sentinels, and a later header. Assert identical entries, line numbers, severity, and aggregate parse errors between initial and tail parses.

- [x] **Step 4: Run watcher and full app tests**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml watcher::tail
cargo test --manifest-path src-tauri/Cargo.toml
```

Expected: PASS with no tail/open drift.

### Task 5: Quality gates and delivery

**Files:**
- Modify: only files listed above if a gate exposes an issue

- [x] **Step 1: Format only the Rust files in scope**

Run:

```bash
rustfmt crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs crates/cmtraceopen-parser/tests/intune_device_inventory.rs src-tauri/src/watcher/tail.rs
git diff --check
```

Expected: formatting succeeds and `git diff --check` prints nothing.

- [x] **Step 2: Run strict Rust lint gates**

Run:

```bash
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

Expected: PASS with zero warnings.

- [x] **Step 3: Run the required frontend type gate**

Run:

```bash
npx tsc --noEmit
```

Expected: PASS. Browser E2E is not applicable because this change has no frontend or IPC behavior.

- [x] **Step 4: Inspect the final scoped diff and rerun focused tests**

Run:

```bash
git diff --stat main...HEAD
git diff -- crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs crates/cmtraceopen-parser/tests/intune_device_inventory.rs src-tauri/src/watcher/tail.rs library.md docs/superpowers/plans/2026-08-05-issue-507-lossless-device-inventory-framing.md
cargo test -p cmtraceopen-parser --test intune_device_inventory
cargo test --manifest-path src-tauri/Cargo.toml watcher::tail
```

Expected: only the planned files change, #506 behavior remains covered, and focused suites pass.

- [x] **Step 5: Commit, push, and open the unmerged PR**

Run:

```bash
git add library.md docs/superpowers/plans/2026-08-05-issue-507-lossless-device-inventory-framing.md crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs crates/cmtraceopen-parser/tests/intune_device_inventory.rs src-tauri/src/watcher/tail.rs
git commit -m "fix: bound device inventory logical records"
git push -u origin codex/issue-507-lossless-device-inventory-framing
gh pr create --base main --head codex/issue-507-lossless-device-inventory-framing --title "fix: make Device Inventory framing lossless and bounded" --body-file /tmp/issue-507-pr-body.md
```

The PR body must contain `Closes #507`, frozen commit SHA, base SHA `162f1c2985dfa6fdda0bdcc7717232829316c2f2`, validation commands/results, and an evidence pack: target branch/SHA, test viewing conditions, claims, reproduction commands, and out-of-scope frontend behavior. Do not merge.
