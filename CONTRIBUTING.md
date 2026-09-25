# Contributing to CMTrace Open

Thanks for your interest in contributing. This guide covers development setup, build commands, project architecture, and coding conventions.

## Prerequisites

- [Node.js](https://nodejs.org/) v18+ (v20 LTS recommended)
- [Rust](https://www.rust-lang.org/tools/install) 1.88+ (MSVC toolchain on Windows)
- [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/)

### Windows-specific

- Visual Studio Build Tools with C++ workload
- Windows 10/11 SDK
- WebView2 Runtime (included in Windows 11, install separately on Windows 10)

Automated setup:

```bash
powershell -ExecutionPolicy Bypass -File .\scripts\Install-CMTraceOpenBuildPrereqs.ps1
```

## Build and Development

```bash
# Install dependencies (run once after clone)
npm ci

# Development — full Tauri app with hot reload
npm run app:dev

# Development — frontend only (Vite dev server on :1420)
npm run frontend:dev

# Production builds
npm run app:build:release       # Full release with bundler (MSI, DMG, etc.)
npm run app:build:debug         # Debug build (incremental)
npm run app:build:exe-only      # Executable only, no bundler

# Frontend only
npm run frontend:build          # tsc + vite build
```

### Rust Commands

Run from `src-tauri/`:

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

### CI Checks

Six required status checks, on the `Protect` ruleset over `main`:

1. **Check & Test (Rust)** — `cargo check`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, then the same with `--no-default-features` for the Lite edition, then the parser crate's tests and clippy, then `cargo deny` and `cargo audit`.
2. **TypeScript Check** — the `frontend` job, which is more than its name: `npm ci`, `npx tsc --noEmit`, `npm run test` (the vitest suite), the bundle-output and release-script contract tests under `scripts/` via `node --test`, and `npm audit --audit-level=high`.
3. **E2E (Playwright)** — `npm run test:e2e`.
4. **Build** — macOS-arm64, Windows-x64 and Linux-x64, three separate required contexts.

Three more jobs run on every PR but are not required to merge:

- **Source Quality** — `cargo fmt --all -- --check`, changed-range whitespace, and `cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown`. The wasm check is a purity constraint: the parser crate must stay wasm32-compatible.
- **Rust MSRV (1.88)** — on Ubuntu and Windows. Anything added has to build on 1.88, not only on the pinned toolchain.
- **ESP Diagnostics (Windows)** — the Windows-only diagnostics suite.

The Windows jobs are also the only place `#[cfg(target_os = "windows")]` code is compiled. `cargo check` and `cargo test` on Linux or macOS skip it entirely, tests included, and pass without reading a line of it. A change under that gate is therefore verified by CI alone until the Windows jobs run, and it is worth saying so in the pull request rather than implying local coverage. Two compile errors in one pull request reached CI that way — one an unqualified path, one a missing import for a Windows-gated test — which is what #763 records.

## Before you push

Every required check has a local equivalent, and running them here is faster than reading about them in CI output:

```bash
cargo fmt --all -- --check                                  # Source Quality, the formatting half
cd src-tauri && cargo check && cargo test                   # Check & Test (Rust)
cd src-tauri && cargo clippy --all-targets -- -D warnings
cargo test -p cmtraceopen-parser                            # the parser crate's own suite
npx tsc --noEmit                                            # TypeScript Check
npm run test                                                # the vitest suite
```

`cargo fmt --all -- --check` is the one most easily missed. A hand-wrapped expression that compiles and passes every test it touches still fails `Source Quality`, and the fix is a single `cargo fmt --all`.

## Changelog

Every user-visible change gets an entry in `CHANGELOG.md` under `## [Unreleased]`, added in the
pull request that makes the change. The section documents fixes as well as features, including
internal ones — the updater-manifest job and the supply-chain bump are both in it — so the test
is whether a reader of the changelog would otherwise not know it happened.

Keep entries to what changed and why it mattered; the diff is the record of how.

## MCP Servers (optional)

The repo ships an `.mcp.json` with three dev/debug MCP servers that MCP-aware clients (Claude Code, Cursor, VS Code with Copilot) pick up automatically:

| Server | Purpose | Prerequisites |
|--------|---------|---------------|
| `github` | PRs, issues, CI logs via the official GitHub MCP (remote, OAuth) | Browser sign-in on first use |
| `chrome-devtools` | Inspect DOM, console, and network on `http://localhost:1420` | Chrome Stable installed locally; Node ≥ 20.19 |
| `playwright` | Scripted headless browser for UI repros and smoke checks | Triggers a ~150 MB Chromium download on first run; pre-run `npx playwright install chromium` to avoid the wait |

Both browser servers drive real Chrome over CDP — they can debug the **Vite dev server** (`npm run frontend:dev`) but cannot attach to the running Tauri app (which uses WebView2 on Windows and WKWebView on macOS). Use them for pure-frontend UI debugging.

Opting out: delete `.mcp.json` locally (do not commit), or disable individual servers in your client's MCP settings.

## Architecture

### Two-Process Model (Tauri v2)

- **Frontend** (`src/`): React 19 + TypeScript, Fluent UI components, Zustand stores, TanStack Virtual for scrolling
- **Backend** (`src-tauri/src/`): Rust, IPC commands via `tauri::generate_handler!` in `lib.rs`

Communication uses Tauri's `invoke()` (frontend to backend) and `emit()` (backend to frontend events, e.g., tail updates).

### Backend Modules (`src-tauri/src/`)

| Module | Purpose |
|--------|---------|
| `commands/` | Tauri IPC command handlers — the API surface |
| `parser/` | Log format auto-detection and parsing (CCM, simple, CBS, DISM, Panther, plain text) |
| `intune/` | IME diagnostics pipeline: event tracking, timeline, download stats, EVTX parsing |
| `dsregcmd/` | Device registration analysis: output parsing, diagnostic rules, registry hives |
| `error_db/` | Embedded error code database (700+ Windows/SCCM/Intune/MSI codes) |
| `models/` | Shared types: `LogEntry`, `ParseResult`, `FilterCriteria` |
| `state/` | `AppState` (Mutex-wrapped) — tracks open files, tail sessions |
| `watcher/` | File watching and real-time tailing via `notify` crate |
| `menu.rs` | Native application menu |

### Frontend Modules (`src/`)

| Module | Purpose |
|--------|---------|
| `components/log-view/` | Main log list with virtual scrolling, row rendering, info pane |
| `components/layout/` | AppShell, toolbar, sidebar, status bar |
| `components/dialogs/` | Modal dialogs (find, filter, error lookup) |
| `components/intune/` | Intune analysis workspace |
| `components/dsregcmd/` | DSRegCmd troubleshooting workspace |
| `stores/` | Zustand stores: log, filter, intune, dsregcmd, ui |
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
- **Encoding fallback**: UTF-8 then Windows-1252 (via `encoding_rs`)
- **Parallelism**: Rayon for batch log line processing, Tokio for async file I/O
- **Windows-specific code** is gated with `#[cfg(target_os = "windows")]`

## Testing

- **Unit/integration tests**: `src-tauri/tests/` with synthetic fixtures
- **Benchmarks**: `src-tauri/benches/intune_pipeline.rs` (Criterion, 10K records)

```bash
# Run all tests
cd src-tauri && cargo test

# Run a single test
cd src-tauri && cargo test test_name

# Run benchmarks
cd src-tauri && cargo bench
```

## Project Links

- [Changelog](CHANGELOG.md)
- [Feature Roadmap](FEATURE_IMPROVEMENTS.md)
- [DSRegCmd Troubleshooting Guide](DSREGCMD_TROUBLESHOOTING.md)
- [Disclaimer](DISCLAIMER.md)
