# Device Inventory Rotation Detection Narrowing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent generic ISO-timestamped failures from being classified as Device Inventory rotation failures while preserving registered rotation phrases and .NET exception evidence.

**Architecture:** Keep the existing content-only dialect detector and shared rotation severity predicate. Pin the intended semantics through direct detection, dispatcher, and forced-dialect severity tests, then delete only the generic prefix branches; do not add filename fallback or alter continuation framing.

**Tech Stack:** Rust, Cargo test, Clippy, rustfmt

---

### Task 1: Pin the rotation-detection contract with failing tests

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/intune_device_inventory.rs:118-193`
- Modify: `crates/cmtraceopen-parser/tests/intune_device_inventory.rs:409-431`

- [x] Add direct-detection cases proving ISO headers beginning with `Failed ` and `Unhandled ` return no Device Inventory dialect for both `unrelated.log` and `IntuneDeviceInventory.log`.
- [x] Add dispatcher cases proving the same content selects `ParserKind::Timestamped` with `ParserImplementation::GenericTimestamped` and no specialization for both filenames.
- [x] Add positive cases for `failed to rotate`, `rotation failed`, and `failed to roll`, plus ISO-header records whose only failure evidence is a .NET exception continuation.
- [x] Add forced-rotation parsing cases proving generic failure prefixes remain `Severity::Info` rather than claiming rotation severity.
- [x] Run the new negative tests and confirm they fail before the implementation change:

```bash
cargo test -p cmtraceopen-parser --test intune_device_inventory generic_failure_prefixes
cargo test -p cmtraceopen-parser --test intune_device_inventory dispatcher_keeps_generic_failure_prefixes
```

### Task 2: Narrow the shared predicate and validate the parser

**Files:**
- Modify: `crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs:319-331`
- Create: `library.md`

- [x] Remove only `lowered.starts_with("failed ")` and `lowered.starts_with("unhandled ")` from `rotation_header_states_failure`; retain all three registered rotation phrases and exception detection.
- [x] Add the root library route for this implementation plan.
- [x] Run focused and full parser validation:

```bash
cargo test -p cmtraceopen-parser --test intune_device_inventory
cargo test -p cmtraceopen-parser
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
rustfmt --edition 2021 --check crates/cmtraceopen-parser/src/intune/device/windows/inventory/mod.rs crates/cmtraceopen-parser/tests/intune_device_inventory.rs
npx tsc --noEmit
git diff --check
git status --short --branch
```

- [ ] Commit and push the branch, then open a pull request that closes GitHub issue #506 without merging it.
