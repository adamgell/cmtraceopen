# Phase 1 — Parser Crate Extraction

**Status**: in progress (branch `feat/platform-split`)
**Scope**: core extraction (workspace + `parser/` + `models/` + `error_db/`)
**Out of scope for this phase**: `intune/`, `dsregcmd/`, `collector/` pure parts (follow-on PRs)

## Why

CMTrace Open's parsing engine (24 log-format parsers, error-code DB, serializable entry model) is being reused in three places:

1. The existing Tauri desktop app (today).
2. A new sibling web viewer at `F:\Repo\cmtraceopen-web` (Vite + React + TS, WASM parser).
3. A new log-collection API server (Rust + Axum, Docker-packaged) that parses bundles shipped from Windows endpoint agents.

To support all three without duplication, the parsing core must live in a pure-Rust library crate with no Tauri, tokio, notify, evtx, windows, winreg, rayon, or filesystem dependencies — so it compiles cleanly to both native (Linux for the API server, Windows/macOS for desktop) and `wasm32-unknown-unknown` (for the web viewer).

The full platform plan is captured elsewhere (see the private plan file maintained with the author); this document is the spec for the **first atomic PR** that enables the rest.

## Success criteria

All five must hold after this PR merges:

1. `cargo check --workspace` passes from `F:\Repo\cmtraceopen\`.
2. `cargo test --workspace` passes (every test that ran on `main` still runs).
3. `cargo clippy --workspace -- -D warnings` passes.
4. `cargo build -p cmtraceopen-parser --target wasm32-unknown-unknown` succeeds. **This is the linchpin check.** If a native dependency leaks into the new crate, this fails.
5. `npm run app:dev` opens logs of every major format (CCM, CBS, Panther, IME, DNS EVTX via `event-log` feature) indistinguishably from the pre-refactor build.

## Target repository layout

```
cmtraceopen/
├── Cargo.toml                          [NEW] [workspace] root
├── src-tauri/                          existing app crate — becomes a workspace member
│   ├── Cargo.toml                      gains `cmtraceopen-parser = { path = "../crates/cmtraceopen-parser" }`
│   └── src/
│       ├── lib.rs                      gains `pub use cmtraceopen_parser::{models, error_db};`
│       └── parser/
│           ├── mod.rs                  trimmed shim: re-exports crate items + keeps `parse_file` wrapper + EVTX branch
│           └── dns_audit.rs            stays here (native-only, `evtx` crate)
└── crates/
    └── cmtraceopen-parser/             [NEW] pure-Rust library crate
        ├── Cargo.toml
        └── src/
            ├── lib.rs
            ├── models/                 moved from src-tauri/src/models/
            ├── error_db/               moved from src-tauri/src/error_db/
            └── parser/                 moved from src-tauri/src/parser/ except dns_audit.rs
```

## Execution order (one commit per step; all land in one PR)

### Step A — Workspace scaffolding

- Create `F:\Repo\cmtraceopen\Cargo.toml`:
  ```toml
  [workspace]
  members = ["src-tauri", "crates/cmtraceopen-parser"]
  resolver = "2"
  ```
- Create `crates/cmtraceopen-parser/Cargo.toml` with minimum deps (`serde`, `serde_json`, `regex`, `chrono`, `encoding_rs`, `log`, `thiserror`) and empty `src/lib.rs`.
- Verify: `cargo check --workspace` from repo root.

### Step B — Move `models/`

- Move `src-tauri/src/models/` to `crates/cmtraceopen-parser/src/models/`.
- In `crates/cmtraceopen-parser/src/lib.rs`: `pub mod models;`.
- In `src-tauri/src/lib.rs`: replace `mod models;` with `pub use cmtraceopen_parser::models;`.
- In `src-tauri/Cargo.toml`: add the path dep on `cmtraceopen-parser`.
- Verify: `cd src-tauri && cargo check`, `cargo test`.

### Step C — Move `error_db/`

- Move `src-tauri/src/error_db/` to `crates/cmtraceopen-parser/src/error_db/`.
- In crate `lib.rs`: `pub mod error_db;`.
- In `src-tauri/src/lib.rs`: replace `pub mod error_db;` with `pub use cmtraceopen_parser::error_db;`.
- `models/log_entry.rs` uses `crate::error_db::lookup::ErrorCodeSpan` — inside the crate this becomes `crate::error_db::lookup::ErrorCodeSpan`, same path; no edit required at the source level.
- Verify: `cargo test --workspace`.

### Step D — Move `parser/` (except `dns_audit.rs`) and split `parse_file`

- Move every file in `src-tauri/src/parser/` except `dns_audit.rs` to `crates/cmtraceopen-parser/src/parser/`.
- In `crates/cmtraceopen-parser/src/parser/mod.rs`:
  - Remove `parse_file` (native-only — does `std::fs::read`).
  - Keep `parse_content_with_selection`, `parse_lines_with_selection`, `detect_encoding`, `decode_bytes`.
  - Add new pure entry point:
    ```rust
    pub fn parse_content(content: &str, file_path: &str, file_size: u64)
        -> (ParseResult, ResolvedParser)
    ```
  - Remove `#[cfg(feature = "event-log")] pub mod dns_audit;` (stays in src-tauri).
- In the crate's parser, all `crate::models::*` and `crate::error_db::*` paths keep working because `models/` and `error_db/` now live in the same crate.
- Trim `src-tauri/src/parser/mod.rs` to a shim:
  ```rust
  pub use cmtraceopen_parser::parser::*;

  #[cfg(feature = "event-log")]
  pub mod dns_audit;

  use crate::parser::{ParseResult, ResolvedParser};

  pub fn parse_file(path: &str) -> Result<(ParseResult, ResolvedParser), String> {
      // EVTX + ETL special cases (as today)
      // then: let content = read_file_content(path)?;
      //       let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
      //       let (result, selection) = cmtraceopen_parser::parser::parse_content(&content, path, size);
      //       Ok((result, selection))
  }

  fn read_file_content(path: &str) -> Result<String, String> { /* unchanged */ }
  ```
- Keep `parser::ccm::{build_timestamp, format_thread_display, severity_from_type_field, naive_to_utc_millis}` and `parser::severity::detect_severity_from_text` **`pub`** in the crate — `intune/ime_parser.rs` depends on them today.
- Verify:
  - `cargo test --workspace`
  - `cargo clippy --workspace -- -D warnings`
  - `cargo build -p cmtraceopen-parser --target wasm32-unknown-unknown` ← the linchpin
  - `npm run app:dev` + manually open CCM / CBS / Panther / IME / DNS-EVTX logs

### Step E — Fixups (if any)

- `npx tsc --noEmit` — should be unaffected; run it to confirm.
- `npm run app:build:exe-only` — Tauri build still produces an exe.
- Address any clippy warnings surfaced by the new crate's own build.
- Add CI step (follow-on PR, not required for Phase 1 merge) for `cargo build -p cmtraceopen-parser --target wasm32-unknown-unknown` as a wasm canary.

## Invariants the PR must preserve

- Every existing `crate::parser::*`, `crate::models::*`, `crate::error_db::*`, `app_lib::parser::*`, `app_lib::models::*`, `app_lib::error_db::*` reference keeps resolving. Re-exports in `src-tauri/src/lib.rs` carry this.
- Existing parser regression tests pass unchanged.
- Existing Tauri feature flags (`collector`, `deployment`, `dsregcmd`, `event-log`, `intune-diagnostics`, `macos-diag`, `secureboot`, `sysmon`) continue to gate `src-tauri` the same way. The new crate has no feature flags.
- Bench (`src-tauri/benches/intune_pipeline.rs`) unaffected.

## What is explicitly NOT in this PR

- Moving pure files out of `intune/`, `dsregcmd/`, `collector/` — follow-on PRs.
- Changes to `scripts/`, `installer/`, `tauri.conf.json`, or `package.json`.
- Any new API server / agent / web viewer code.
- CI matrix changes (wasm build job, api-server build job) — separate PR.

## Risk register

| Risk | Probability | Mitigation |
|---|---|---|
| A moved parser file has a hidden `tokio::` / `rayon::` / `notify::` / `evtx::` import → wasm build breaks | medium | `cargo build -p cmtraceopen-parser --target wasm32-unknown-unknown` is the gate. Grep before merging. |
| `serde_json` missing from crate deps but needed by `reporting_events.rs` | low | Declared in the crate Cargo.toml; verify at step D. |
| `parser/ccm.rs` helpers accidentally made non-pub → `intune/ime_parser.rs` breaks | medium | Keep them `pub`; document in the PR body as now-crate-public. |
| Test fixtures under `src-tauri/tests/fixtures/` referenced by absolute-relative paths that break when tests move | medium | Leave moved parser tests in `src-tauri/tests/` referencing `app_lib::parser::*` via the re-export shim — no fixture-path changes needed. |
| Downstream breakage in `commands/*.rs` that imports `crate::parser::parse_file` | low | The shim `parse_file` stays at the same path; no call site should need to change. |

## How to pick up if interrupted

Any step above can be resumed by:
1. `git -C F:\Repo\cmtraceopen checkout feat/platform-split`
2. `cargo check --workspace` to see where the build currently stands.
3. Pick the next uncompleted step in the execution order.

---

*This spec is intentionally narrow. It exists to make the first change small, reversible, and verifiable so the rest of the platform work can proceed on a stable foundation.*
