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
cargo bench                     # Criterion benchmarks (intune_pipeline)
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

| Module | Purpose |
|--------|---------|
| `commands/` | Tauri IPC command handlers — the API surface between frontend and backend |
| `parser/` | Log format auto-detection and parsing (CCM, simple, CBS, DISM, Panther, plain text) |
| `intune/` | IME diagnostics pipeline: event tracking, timeline, download stats, EVTX parsing |
| `dsregcmd/` | Device registration analysis: output parsing, diagnostic rules, registry hives |
| `error_db/` | Embedded error code database (120+ Windows/SCCM/Intune codes) |
| `models/` | Shared types: `LogEntry`, `ParseResult`, `FilterCriteria` |
| `state/` | `AppState` (Mutex-wrapped) — tracks open files, tail sessions |
| `watcher/` | File watching and real-time tailing via `notify` crate |
| `menu.rs` | Native application menu |

### Frontend Module Map (`src/`)

| Module | Purpose |
|--------|---------|
| `components/log-view/` | Main log list with virtual scrolling, row rendering, info pane |
| `components/layout/` | AppShell, toolbar, sidebar, status bar |
| `components/dialogs/` | Modal dialogs (find, filter, error lookup) |
| `components/intune/` | Intune analysis workspace |
| `components/dsregcmd/` | DSRegCmd troubleshooting workspace |
| `stores/` | 5 Zustand stores: log, filter, intune, dsregcmd, ui |
| `hooks/` | Custom hooks for drag-drop, menus, file association |
| `types/` | TypeScript type definitions |

### Parser Architecture

The parser system in `src-tauri/src/parser/` uses a `ResolvedParser` that bundles:
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

## Testing

- **Unit/integration tests**: `src-tauri/tests/` — parser regression tests with synthetic fixtures
- **Benchmarks**: `src-tauri/benches/intune_pipeline.rs` — Criterion benchmarks for the Intune pipeline (10K records)
- Run a single test: `cargo test test_name` from `src-tauri/`
- Run benchmarks: `cargo bench` from `src-tauri/`

## Prerequisites

- Node.js 18+ (v20 LTS recommended)
- Rust 1.77.2+ (MSVC toolchain on Windows)
- Windows: Visual Studio Build Tools with C++ workload + Windows SDK + WebView2 Runtime
- Automated Windows setup: `powershell -ExecutionPolicy Bypass -File .\scripts\Install-CMTraceOpenBuildPrereqs.ps1`
