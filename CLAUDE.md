# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CMTrace Open is an open-source log viewer and Windows troubleshooting tool built with **Tauri v2 + React + TypeScript + Rust**. It replaces Microsoft's CMTrace.exe with modern features including Intune diagnostics, DSRegCmd analysis, and real-time log tailing.

## Build & Development Commands

```bash
# Install dependencies (run once after clone)
npm ci

# Development - full Tauri app with hot reload
npm run app:dev

# Development - frontend only (Vite dev server on :1420)
npm run frontend:dev

# Production builds
npm run app:build:release       # Full release with bundler (MSI, DMG, etc.)
npm run app:build:debug         # Debug build (incremental)
npm run app:build:exe-only      # Executable only, no bundler

# Frontend only
npm run frontend:build          # tsc + vite build
```

### Rust Commands (run from `src-tauri/`)

```bash
cargo check                     # Type check
cargo test                      # Run all tests
cargo clippy -- -D warnings     # Lint (CI enforces zero warnings)
cargo bench                     # Criterion benchmarks (intune_pipeline, timeline)
```

### TypeScript Check

```bash
npx tsc --noEmit
```

### CI Checks (what PR gates enforce)

1. `cargo check` + `cargo test` + `cargo clippy -- -D warnings` (Ubuntu)
2. `npx tsc --noEmit` (Node 20)
3. Tauri build on macOS-arm64, Windows-x64, Linux-x64

## Architecture

### Two-Process Model (Tauri v2)

- **Frontend** (`src/`): React 19 + TypeScript, Fluent UI components, Zustand stores, TanStack Virtual for scrolling
- **Backend** (`src-tauri/src/`): Rust, exposes IPC commands via `tauri::generate_handler!` in `lib.rs`

Communication is through Tauri's `invoke()` (frontend→backend) and `emit()` (backend→frontend events, e.g., tail updates).

### Backend Module Map (`src-tauri/src/`)

Pure log/Intune/ESP/DSRegCmd parsing lives in the separate `crates/cmtraceopen-parser/` crate (wasm32-compatible, no OS I/O). The `src-tauri` crate hosts the Tauri app and the native, OS-facing modules:

| Module | Purpose |
|--------|---------|
| `commands/` | Tauri IPC command handlers — the API surface between frontend and backend |
| `intune/`, `esp/`, `dsregcmd/`, `sysmon/`, `secureboot/`, `macos_diag/`, `jamf/`, `event_log/` | Native, OS-facing halves of each workspace (registry, EVTX, process, live capture) |
| `graph_api/` | Microsoft Graph / WAM client |
| `timeline/`, `collector/`, `elevation/` | Cross-source timeline, evidence collection, admin elevation |
| `parser/` | App-local parse glue (e.g. DNS audit); the log parsers themselves live in the parser crate |
| `state/` | `AppState` (Mutex-wrapped) — tracks open files, tail sessions |
| `watcher/` | File watching and real-time tailing via `notify` crate |
| `menu.rs` | Native application menu |

Shared types (`LogEntry`, `FilterCriteria`) and the embedded error-code database (700+ Windows/SCCM/Intune/MSI codes) live in the parser crate's `models/` and `error_db/` modules.

### Frontend Module Map (`src/`)

| Module | Purpose |
|--------|---------|
| `components/log-view/` | Main log list with virtual scrolling, row rendering, info pane |
| `components/layout/` | AppShell, toolbar, sidebar, status bar |
| `components/dialogs/` | Modal dialogs (find, filter, error lookup) |
| `workspaces/` | Feature workspaces: log, intune, esp-diagnostics, dsregcmd, sysmon, secureboot, event-log, dns-dhcp, deployment, macos-diag, macos-jamf, timeline |
| `stores/` | Zustand stores: log, filter, ui, marker, registry, timeline (workspaces add their own domain stores) |
| `hooks/` | Custom hooks for drag-drop, menus, file association |
| `types/` | TypeScript type definitions |

### Parser Architecture

The parser system lives in the `crates/cmtraceopen-parser/` crate (pure Rust, wasm32-compatible, no OS I/O) and uses a `ResolvedParser` that bundles:
- `ParserKind` — format variant (CCM, Simple, ReportingEvents, etc.)
- `ParserImplementation` — actual parsing logic
- `ParseQuality` — Structured / SemiStructured / Unstructured
- `RecordFraming` — PhysicalLine vs LogicalRecord (multi-line)
- `ParserSpecialization` — optional (e.g., IME for Intune logs)

Format detection (`detect.rs`) samples the first lines of a file to auto-select the parser.

### Key Patterns

- **IPC commands** are defined in `commands/*.rs` and registered in `lib.rs` via `invoke_handler`
- **State** is shared across commands via Tauri's `manage()` with `AppState` (Mutex<HashMap>)
- **Encoding fallback**: UTF-8 → Windows-1252 (via `encoding_rs`)
- **Parallelism**: Rayon for batch log line processing, Tokio for async file I/O
- **Windows-specific code** is gated with `#[cfg(target_os = "windows")]` and the `windows`/`winreg` crates
- **Windows-only workspaces** (Sysmon, parts of Intune) need platform gating in Rust commands and conditional handling in frontend tests

## Testing

- **Unit/integration tests**: `src-tauri/tests/` and `crates/cmtraceopen-parser/tests/` — parser regression and workspace tests with synthetic fixtures
- **Benchmarks**: `src-tauri/benches/` — Criterion benchmarks for the Intune pipeline (`intune_pipeline`, 10K records) and the cross-source timeline (`timeline`)
- Run a single test: `cargo test test_name` from `src-tauri/`
- Run benchmarks: `cargo bench` from `src-tauri/`

## Prerequisites

- Node.js 18+ (v20 LTS recommended)
- Rust 1.88+ (MSVC toolchain on Windows)
- Windows: Visual Studio Build Tools with C++ workload + Windows SDK + WebView2 Runtime
- Automated Windows setup: `powershell -ExecutionPolicy Bypass -File .\scripts\Install-CMTraceOpenBuildPrereqs.ps1`

## Agent Directives: Mechanical Overrides

### Pre-Work

1. **Step 0 Rule**: Before ANY structural refactor on a file >300 LOC, first remove all dead props, unused exports, unused imports, and debug logs. Commit this cleanup separately before starting the real work.
2. **Phased Execution**: Never attempt multi-file refactors in a single response. Break work into explicit phases. Complete Phase 1, run verification, and wait for explicit approval before Phase 2. Each phase must touch no more than 5 files.

### Code Quality

3. **Senior Dev Override**: If architecture is flawed, state is duplicated, or patterns are inconsistent — propose and implement structural fixes. Ask: "What would a senior, experienced, perfectionist dev reject in code review?" Fix all of it.
4. **Forced Verification**: You are FORBIDDEN from reporting a task as complete until you have run `npx tsc --noEmit` (and `npx eslint . --quiet` if configured) and fixed ALL resulting errors.

### Context Management

5. **Sub-Agent Swarming**: For tasks touching >5 independent files, launch parallel sub-agents (5–8 files per agent). Sequential processing of large tasks guarantees context decay.
6. **Context Decay Awareness**: After 10+ messages in a conversation, re-read any file before editing it. Do not trust memory of file contents — auto-compaction may have silently destroyed that context.
7. **File Read Budget**: Each file read is capped at 2,000 lines. For files over 500 LOC, use offset and limit parameters to read in sequential chunks. Never assume you have seen a complete file from a single read.
8. **Tool Result Blindness**: Tool results over 50,000 characters are silently truncated. If any search or command returns suspiciously few results, re-run with narrower scope. State when you suspect truncation occurred.

### Edit Safety

9. **Edit Integrity**: Before EVERY file edit, re-read the file. After editing, read it again to confirm the change applied correctly. Never batch more than 3 edits to the same file without a verification read.
10. **No Semantic Search**: When renaming or changing any function/type/variable, search separately for: direct calls, type-level references, string literals containing the name, dynamic imports/require() calls, re-exports/barrel file entries, and test files/mocks.
