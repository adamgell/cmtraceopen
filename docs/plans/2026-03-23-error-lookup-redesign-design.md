# Error Lookup UI/UX Redesign

**Date:** 2026-03-23
**Status:** Approved
**Approach:** Enhanced Fluent UI Dialog + Inline Log Annotations

## Problem

The current error lookup dialog uses raw inline CSS instead of Fluent UI, has no search-by-description, no history, no copy functionality, and is discoverable only via menu or Ctrl+E. The 161-code static database lacks categories and covers limited scenarios.

## Goals

- Rebuild the dialog with Fluent UI components matching the rest of the app
- Add unified search (auto-detects code vs. description queries)
- Highlight recognized error codes inline in log rows
- Expand the error database to 500-800 categorized codes
- Improve discoverability with toolbar button and context menu

## Non-Goals

- Online/API-based error lookup (stay offline-only)
- User-editable custom error code databases
- Full error explorer workspace/sidebar

---

## Design

### 1. Enhanced Error Lookup Dialog

**Component:** Fluent UI `Dialog` (consistent with FindDialog/FilterDialog patterns).
**Width:** ~560px (`min(560px, calc(100vw - 32px))`).

**Layout (top to bottom):**

1. **DialogTitle:** "Error Code Lookup"
2. **Unified SearchBox:** Single `Input` with search icon. Auto-detects input type:
   - Hex/decimal pattern → exact code lookup (instant)
   - Text → case-insensitive substring search across descriptions
3. **Results list:** Scrollable area showing matching results as compact rows:
   - Category `Badge` (colored by category — blue=Windows, orange=Intune, green=ConfigMgr, etc.)
   - Code in monospace: `0x80070005 / -2147024891`
   - Description text
   - Copy icon button (copies formatted string: `0x80070005 - E_ACCESSDENIED - Access is denied`)
4. **History section:** Collapsible "Recent" section showing last 10 lookups (session-only, stored in `ui-store`). Each item clickable to re-show details.
5. **DialogActions:** Close button.

**Keyboard:** Enter triggers search, Escape closes, Tab navigates results.

### 2. Inline Log Error Code Detection

**Rust parser changes:**

Add error code span detection during parsing. A lightweight regex (`0x[0-9A-Fa-f]{8}`) scans each log message. Matched codes found in the error DB produce `ErrorCodeSpan` annotations on `LogEntry`:

```rust
pub struct ErrorCodeSpan {
    pub start: usize,    // character index in message (for JS String.slice())
    pub end: usize,
    pub code_hex: String,
    pub description: String,
    pub category: String,
}
```

Stored as `Vec<ErrorCodeSpan>` on `LogEntry` (empty vec for lines with no recognized codes).

**Frontend rendering (LogRow.tsx):**

When an entry has error code spans, the message text splits into segments:
- Plain text segments render normally
- Error code segments render as `<span>` with:
  - Dotted underline (`tokens.colorPaletteRedBorder2`)
  - Hover: subtle background highlight
  - `cursor: pointer`
  - `title` tooltip with description

**Click behavior:**

Clicking an error code span:
1. Opens the info pane (if closed)
2. Displays "Error Code Details" view in the info pane: hex, decimal, description, category badge, "Open full lookup" link

**Performance:** Detection runs during the existing parsing pass. Spans cached on `LogEntry`. Only visible rows (virtual list) do span-based rendering.

### 3. Expanded Error Code Database

**New category enum:**

```rust
pub enum ErrorCategory {
    Windows,        // General Windows/HRESULT
    WindowsUpdate,  // WUA errors
    BITS,           // Background Intelligent Transfer
    ConfigMgr,      // SCCM/ConfigMgr
    Intune,         // Intune/MDM
    DeliveryOpt,    // Delivery Optimization
    AppInstall,     // MSI/App-V/WinGet
    Certificate,    // Certificate/PKI
    Network,        // WinHTTP, WinInet, DNS
    Security,       // Authentication, authorization
    Registry,       // Registry operations
    FileSystem,     // File/disk operations
}
```

**Data structure change:**

```rust
// Before: (u32, &str)
// After:
pub struct ErrorCode {
    pub code: u32,
    pub description: &'static str,
    pub category: ErrorCategory,
}
```

**Expansion:** Grow from 161 to ~500-800 codes. Sources:
- Microsoft Win32 System Error Code documentation (public)
- Microsoft Intune troubleshooting documentation (public)
- ConfigMgr/SCCM error reference documentation (public)
- Windows Update Agent error reference (public)
- Existing 161 codes as foundation

All codes manually curated for quality and relevance to the tool's target audience (IT admins troubleshooting Windows/Intune/SCCM).

**New IPC command:**

```rust
#[tauri::command]
pub fn search_error_codes(query: String) -> Vec<ErrorSearchResult> {
    // If query matches hex/decimal pattern → exact lookup
    // Otherwise → substring search across descriptions
    // Returns up to 50 results, sorted: exact match > starts-with > contains
}

pub struct ErrorSearchResult {
    pub code_hex: String,
    pub code_decimal: String,
    pub description: String,
    pub category: String,
    pub found: bool,
}
```

Existing `lookup_error_code` command unchanged for backward compatibility.

### 4. Toolbar & Discoverability

**Toolbar button:** New button using Fluent icon (`BugRegular` or `ErrorCircleRegular`) with label "Error Lookup". Follows existing `getToolbarControlStyle` pattern. Tooltip shows keyboard shortcut (Ctrl+E).

**Keyboard shortcut:** Ctrl+E preserved (CMTrace legacy binding).

**Context menu:** Right-clicking text in log view that contains a recognized error code adds "Lookup Error Code" option, pre-filling the dialog.

**Info pane enhancement:** When displaying a log entry containing error codes, show clickable category badges at the top of the info pane.

---

## Component Summary

| Component | Changes |
|-----------|---------|
| `ErrorLookupDialog.tsx` | Full rebuild with Fluent UI, unified search, results list, history |
| `LogRow.tsx` | Error code span rendering with highlights and click handling |
| `InfoPane.tsx` | New "Error Code Details" view for clicked error codes |
| `error_db/codes.rs` | Expanded to 500-800 codes with `ErrorCategory` |
| `error_db/lookup.rs` | New `search_error_codes` function with substring search |
| `commands/error_lookup.rs` | New `search_error_codes` IPC command |
| `models/` | `ErrorCodeSpan` struct, updated `LogEntry` |
| `parser/` | Error code detection during parsing |
| `Toolbar.tsx` | New error lookup button |
| `ui-store.ts` | Lookup history state |
| `lib.rs` | Register new command |

## Testing

- Unit tests for regex-based error code detection in messages
- Unit tests for `search_error_codes` (exact match, substring, empty results)
- Unit tests for expanded error database (no duplicate codes, all categories valid)
- Integration test: parse a log file with known error codes, verify spans
- Frontend: verify dialog opens/closes, search works, copy button works
