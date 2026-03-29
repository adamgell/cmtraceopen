# Codebase Improvements: Testing, Error Architecture, Decomposition, Performance

## Context

Deep audit of CMTrace Open (32K LOC Rust backend, 31K LOC TypeScript frontend) revealed systemic improvements needed across testing, error handling, file structure, performance, and CI. The codebase has strong fundamentals but has grown organically, resulting in oversized files, zero frontend tests, stringly-typed errors, and missing React optimizations. This spec defines a bottom-up improvement pass: testing foundation first, then error architecture, file decomposition, performance, and CI hardening.

---

## Phase 1: Testing Foundation

### 1A: Frontend Testing Setup (Vitest)

**Add dependencies:**
- `vitest` (Vite-native test runner)
- `@testing-library/react` + `@testing-library/jest-dom`
- `jsdom` (DOM environment for component tests)

**Configuration:** `vitest.config.ts`
- Environment: `jsdom`
- Setup file: `src/test-setup.ts` (mock `@tauri-apps/api/core` invoke/emit)
- Coverage: `@vitest/coverage-v8`
- Include: `src/**/*.test.{ts,tsx}`

**Tauri Mock Strategy:**
```typescript
// src/test-setup.ts
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: vi.fn(),
}));
```

**Priority Store Tests:**

| Store | Test File | Key Scenarios |
|-------|-----------|---------------|
| `log-store` | `stores/log-store.test.ts` | setEntries, clearEntries, entry lookup by ID |
| `filter-store` | `stores/filter-store.test.ts` | addClause, removeClause, setFilteredIds, clear |
| `ui-store` | `stores/ui-store.test.ts` | theme switching, font size controls, tab management, column persistence |
| `intune-store` | `stores/intune-store.test.ts` | setAnalysisResult, state transitions (idle→analyzing→complete→failed) |
| `dsregcmd-store` | `stores/dsregcmd-store.test.ts` | setAnalysisResult, state transitions |

**CI Integration:**
- Add `npm run test` to `cmtrace-ci.yml` after `npx tsc --noEmit`
- Script in package.json: `"test": "vitest run"`, `"test:watch": "vitest"`

### 1B: Rust Test Expansion

**Parser Test Corpus Expansion** (`src-tauri/tests/corpus/`):
- Add malformed CCM files (truncated `<![LOG[` without close, broken timestamps)
- Add encoding edge cases (UTF-16LE BOM, Windows-1252 with special chars, mixed encoding)
- Add large synthetic files (10K+ lines for performance regression)
- Add CBS/DISM/Panther/MSI sample files (currently only CCM fixtures exist)

**IPC Command Integration Tests** (`src-tauri/tests/`):
- Create `command_tests.rs` with mock `AppState`
- Test `open_log_file` with valid/invalid paths
- Test `parse_files_batch` with multiple files
- Test `apply_filter` with various clause combinations
- Test `start_tail`/`stop_tail` lifecycle
- Test error propagation: verify error strings are descriptive

**Add to CI:**
- `cargo-deny` check in CI (supply chain security)
- Add `deny.toml` with license allowlist and advisory database check

---

## Phase 2: Error Architecture

### 2A: Rust Error Types

**Create `src-tauri/src/error.rs`:**
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error in {file} at line {line}: {reason}")]
    Parse { file: String, line: u32, reason: String },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("State error: {0}")]
    State(String),

    #[error("Platform not supported: {0}")]
    PlatformUnsupported(String),

    #[error("Analysis failed: {0}")]
    Analysis(String),
}
```

**Tauri IPC integration:**
```rust
impl From<AppError> for tauri::ipc::InvokeError {
    fn from(err: AppError) -> Self {
        tauri::ipc::InvokeError::from(err.to_string())
    }
}
```

**Add `thiserror` to Cargo.toml dependencies.**

**Migration order** (by command file):
1. `commands/error_lookup.rs` (16 lines - smallest, test the pattern)
2. `commands/filter.rs` (small)
3. `commands/fonts.rs` (small)
4. `commands/parsing.rs` (tail management)
5. `commands/file_ops.rs` (largest - 2,292 lines)
6. `commands/intune.rs` (3,876 lines)
7. DSRegCmd and collector commands

### 2B: Fix Unsafe Patterns

- Replace `lock().unwrap()` with `lock().expect("mutex poisoned: <context>")` (1 location in `collector/engine.rs`)
- Replace `String::from_utf16(...).unwrap()` with `.unwrap_or_else()` in `error_db/lookup.rs`
- Verify all `Regex::new().unwrap()` are in `Lazy` statics with `.expect("invalid regex: <pattern>")`

### 2C: Frontend Error Handling

- Create `src/lib/errors.ts` with typed error parsing:
  ```typescript
  interface AppError {
    kind: "io" | "parse" | "input" | "state" | "platform" | "analysis";
    message: string;
  }
  function parseBackendError(error: string): AppError;
  ```
- Use in stores to provide user-friendly error messages
- Eventually replace with structured JSON errors from backend (future improvement)

---

## Phase 3: File Decomposition

### 3A: Rust Backend Splitting

**`commands/intune.rs` (3,876 lines) -> 4 files:**

| New File | Responsibility | Approx Lines |
|----------|---------------|-------------|
| `commands/intune_analysis.rs` | Core `analyze_intune_logs` command + orchestration | ~800 |
| `commands/intune_progress.rs` | Progress event emission, status tracking | ~400 |
| `commands/intune_bundle.rs` | Evidence bundle inspection, manifest parsing | ~600 |
| `commands/intune_diagnostics.rs` | Diagnostic insights, failure detection, suggestions | ~500 |

Re-export all public commands from `commands/intune/mod.rs`.

**`dsregcmd/rules.rs` (3,049 lines) -> 3 files:**

| New File | Responsibility | Approx Lines |
|----------|---------------|-------------|
| `dsregcmd/derive.rs` | Fact derivation from raw data | ~1,000 |
| `dsregcmd/rules.rs` | Rule evaluation engine | ~1,200 |
| `dsregcmd/confidence.rs` | Confidence scoring, severity assignment | ~500 |

**`commands/file_ops.rs` (2,292 lines) -> 4 files:**

| New File | Responsibility | Approx Lines |
|----------|---------------|-------------|
| `commands/file_parsing.rs` | `open_log_file`, `parse_files_batch`, encoding | ~600 |
| `commands/registry_ops.rs` | Registry file inspection commands | ~400 |
| `commands/bundle_ops.rs` | Evidence bundle inspection | ~500 |
| `commands/known_sources.rs` | Known log source patterns, folder scanning | ~400 |

**Extract shared constants:**
- Move `DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS` from both `commands/intune.rs:44` and `commands/file_ops.rs:20` to a shared `constants.rs`

### 3B: Frontend Component Splitting

**`DsregcmdWorkspace.tsx` (2,927 lines) -> 5+ files:**

| New Component/File | Responsibility |
|-------------------|---------------|
| `PolicyEvidencePane.tsx` | Policy data display, multi-source evidence rendering |
| `DiagnosticInsightsCard.tsx` | Diagnostic insight cards with severity indicators |
| `CertificateSection.tsx` | Certificate validity display and formatting |
| `FactGroupRenderer.tsx` | Generic fact group display with expandable sections |
| `dsregcmd-formatters.ts` | Extracted formatting functions (formatBool, formatValue, formatEvidenceSource, getPolicyDisplayValue, toneForBool) |

**`IntuneDashboard.tsx` (2,606 lines) -> 4+ files:**

| New Component/File | Responsibility |
|-------------------|---------------|
| `IntuneDashboardHeader.tsx` | Source info, analysis status, action buttons |
| `IntuneDashboardNavBar.tsx` | Tab strip + summary statistics |
| `TimeWindowFilter.tsx` | Time window selection with label computation |
| `useTimeWindowFilter.ts` | Hook: time window filtering logic + memoized selectors |

**`NewIntuneWorkspace.tsx` (1,408 lines):**
- Extract each surface (Overview, Timeline, Downloads, EventLogs) into its own component file
- Keep workspace as thin orchestrator

### 3C: Shared Utilities Extraction

**Frontend:**
- `src/lib/file-paths.ts`: `getBaseName()`, `getDirectoryName()`, `getFileName()` (currently duplicated in 3+ files)
- `src/lib/tone-mapping.ts`: Status color/tone utilities (duplicated across DsregcmdWorkspace, EventTimeline, DownloadStats)
- `src/hooks/useTabSwitcher.ts`: Tab availability + auto-switch logic (repeated in 3 workspaces)

---

## Phase 4: Performance & React Optimization

### 4A: React.memo on Hot Path Components

**Critical targets:**
- `LogRow.tsx`: Wrap in `React.memo` with custom comparator (compare `entry.id`, `isSelected`, `isFindMatch`)
- EventTimeline row items: Extract to memoized component
- DownloadStats row items: Same pattern

### 4B: Store Selector Hooks

Create composed selector hooks to reduce 15-20 individual subscriptions:
```typescript
// src/hooks/useIntuneTimelineState.ts
export const useIntuneTimelineState = () => ({
  events: useIntuneStore(s => s.events),
  downloads: useIntuneStore(s => s.downloads),
  timeWindow: useIntuneStore(s => s.timeWindow),
  setTimeWindow: useIntuneStore(s => s.setTimeWindow),
});
```

### 4C: Reduce Unnecessary Clones

**Hot paths in Rust:**
- `intune/timeline.rs:76-114`: 8x `.clone()` per event when building timeline. Use references in intermediate struct, collect to owned at end.
- `intune/ime_parser.rs:319,599,601`: Clone timestamp/message before struct construction. Use `Cow<str>` or move semantics.
- Audit all `.to_string()` in loops — replace with `&str` borrowing where lifetimes allow.

### 4D: Inline Styles -> makeStyles

During component splitting (Phase 3), convert inline styles to `makeStyles` in the new smaller components. This happens naturally — no separate migration pass needed.

Replace hardcoded hex colors in `EvidenceBundleDialog.tsx` (lines 72-96) with Fluent UI tokens.

---

## Phase 5: Build & CI Hardening

### 5A: Cargo Feature Flags

Add to `Cargo.toml`:
```toml
[features]
default = ["windows-diagnostics", "macos-diagnostics"]
windows-diagnostics = ["windows", "winreg"]
macos-diagnostics = ["plist"]
```

Gate platform-specific code:
- `#[cfg(feature = "windows-diagnostics")]` on dsregcmd, collector, file_association modules
- `#[cfg(feature = "macos-diagnostics")]` on macos_diag module

### 5B: Dependency Modernization

- Replace `once_cell::sync::Lazy` with `std::sync::LazyLock` (stable since Rust 1.80, MSRV 1.77.2 — need to verify; if not available, keep `once_cell`)
- Remove `log` crate if unused, or integrate structured logging with `log::*` macros replacing `eprintln!()`

### 5C: CI Additions

- Add `cargo deny check` step (create `deny.toml` with license allowlist)
- Add `npm run test` step (Vitest)
- Consider adding `biome` for TypeScript lint + format (single fast tool, replaces ESLint + Prettier)

---

## Verification

### After Phase 1 (Testing):
- `npm run test` passes with 15+ store tests
- `cargo test` passes with expanded corpus + command tests
- CI pipeline runs both

### After Phase 2 (Error types):
- All commands return `Result<T, AppError>` instead of `Result<T, String>`
- `cargo clippy -- -D warnings` still passes
- Frontend displays error messages correctly

### After Phase 3 (Decomposition):
- No file over 1,000 lines in either backend or frontend
- All existing tests still pass
- `cargo check` and `npx tsc --noEmit` pass
- App functionality unchanged (manual smoke test: open file, filter, intune analysis, dsregcmd)

### After Phase 4 (Performance):
- LogRow re-renders only on relevant prop changes (verify with React DevTools Profiler)
- Intune timeline scrolling smooth at 1000+ events
- `cargo bench` shows no regressions

### After Phase 5 (CI):
- `cargo deny check` passes in CI
- Feature flags compile correctly on all platforms
- Full CI green on macOS, Windows, Linux

---

## Files to Modify

### New Files
- `vitest.config.ts`
- `src/test-setup.ts`
- `src/stores/*.test.ts` (5 files)
- `src-tauri/src/error.rs`
- `src-tauri/src/constants.rs`
- `src-tauri/tests/command_tests.rs`
- `src-tauri/tests/corpus/` (5+ new fixtures)
- `deny.toml`
- `src/lib/errors.ts`
- `src/lib/file-paths.ts`
- `src/lib/tone-mapping.ts`
- `src/hooks/useTabSwitcher.ts`
- `src/hooks/useIntuneTimelineState.ts`
- Split component files (~15 new .tsx files)
- Split Rust command files (~11 new .rs files)

### Modified Files
- `package.json` (add vitest, testing-library deps)
- `src-tauri/Cargo.toml` (add thiserror, feature flags)
- `.github/workflows/cmtrace-ci.yml` (add test + deny steps)
- `src-tauri/src/lib.rs` (update module declarations, command handler registration)
- All 35+ command files (error type migration)
- `src/components/log-view/LogRow.tsx` (React.memo)
- `src/components/intune/EventTimeline.tsx` (React.memo on rows)
- Parent components of split files (import path updates)

### Existing Utilities to Reuse
- `src-tauri/src/parser/detect.rs` — parser detection (no changes, just more test coverage)
- `src/stores/*` — Zustand stores (test, don't restructure yet)
- `src/components/log-view/LogListView.tsx:getLogListMetrics()` — font metrics utility (reuse in new components per memory: feedback_accessibility_font_sizes.md)
