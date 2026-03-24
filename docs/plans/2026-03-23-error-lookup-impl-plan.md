# Error Lookup UI/UX Redesign Implementation Plan

> Implementation note: Follow this plan step-by-step during development and update it if implementation details change.

**Goal:** Redesign the error lookup feature with Fluent UI dialog, unified search, inline log error code highlighting, expanded categorized database, and improved discoverability.

**Architecture:** The Rust backend gets an expanded error code database with categories, a new `search_error_codes` IPC command with substring search, and error code span detection during parsing. The React frontend gets a rebuilt Fluent UI dialog with unified search + results list, inline error code highlighting in log rows, and an enhanced info pane.

**Tech Stack:** Rust (Tauri v2 IPC, regex, serde), React 19 + TypeScript, Fluent UI v9, Zustand, TanStack Virtual

---

### Task 1: Add ErrorCategory enum and ErrorCode struct to Rust error_db

**Files:**
- Modify: `src-tauri/src/error_db/codes.rs:1-161`

**Step 1: Write the failing test**

Add to bottom of `src-tauri/src/error_db/lookup.rs`:

```rust
#[cfg(test)]
mod tests {
    // ... existing tests ...

    #[test]
    fn test_error_codes_have_categories() {
        use super::super::codes::{ERROR_CODES, ErrorCategory};
        // Verify at least one code has a non-default category
        let intune_count = ERROR_CODES.iter()
            .filter(|ec| matches!(ec.category, ErrorCategory::Intune))
            .count();
        assert!(intune_count > 0, "Should have Intune-categorized codes");
    }

    #[test]
    fn test_no_duplicate_error_codes() {
        use super::super::codes::ERROR_CODES;
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for ec in ERROR_CODES.iter() {
            assert!(seen.insert(ec.code), "Duplicate error code: 0x{:08X}", ec.code);
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd src-tauri && cargo test test_error_codes_have_categories -- --nocapture`
Expected: FAIL — `ErrorCategory` doesn't exist yet.

**Step 3: Implement ErrorCategory enum and ErrorCode struct**

Replace the contents of `src-tauri/src/error_db/codes.rs` with the new structure. The `ErrorCategory` enum:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCategory {
    Windows,
    WindowsUpdate,
    Bits,
    ConfigMgr,
    Intune,
    DeliveryOpt,
    AppInstall,
    Certificate,
    Network,
    Security,
    Registry,
    FileSystem,
}

impl ErrorCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::WindowsUpdate => "Windows Update",
            Self::Bits => "BITS",
            Self::ConfigMgr => "ConfigMgr",
            Self::Intune => "Intune",
            Self::DeliveryOpt => "Delivery Optimization",
            Self::AppInstall => "App Install",
            Self::Certificate => "Certificate",
            Self::Network => "Network",
            Self::Security => "Security",
            Self::Registry => "Registry",
            Self::FileSystem => "File System",
        }
    }
}

pub struct ErrorCode {
    pub code: u32,
    pub description: &'static str,
    pub category: ErrorCategory,
}

pub static ERROR_CODES: &[ErrorCode] = &[
    // Common Windows/HRESULT errors
    ErrorCode { code: 0x00000000, description: "S_OK - The operation completed successfully", category: ErrorCategory::Windows },
    ErrorCode { code: 0x00000001, description: "S_FALSE - The operation completed with a non-critical warning", category: ErrorCategory::Windows },
    // ... (convert all existing 161 entries to the new struct format with appropriate categories)
    // ... (add new codes to expand to ~500-800 total)
];
```

Convert all existing entries, assigning categories based on the comment sections already in the file:
- `Common Windows/HRESULT errors` → `ErrorCategory::Windows`
- `Windows Update Agent errors` → `ErrorCategory::WindowsUpdate`
- `BITS errors` → `ErrorCategory::Bits`
- `ConfigMgr/SCCM specific` → `ErrorCategory::ConfigMgr`
- `Delivery Optimization` → `ErrorCategory::DeliveryOpt`
- `App installation / MSI` → `ErrorCategory::AppInstall`
- `Certificate errors` → `ErrorCategory::Certificate`
- `Intune/MDM specific` → `ErrorCategory::Intune`
- `WinGet` → `ErrorCategory::AppInstall`

**Step 4: Update lookup.rs to use the new ErrorCode struct**

In `src-tauri/src/error_db/lookup.rs`, update the code matching from `ERROR_CODES.iter().find(|(ec, _)| *ec == c)` to `ERROR_CODES.iter().find(|ec| ec.code == c)` and include `ec.description` / `ec.category`.

**Step 5: Run tests to verify they pass**

Run: `cd src-tauri && cargo test -- --nocapture`
Expected: All existing tests + new tests PASS.

**Step 6: Commit**

```bash
git add src-tauri/src/error_db/codes.rs src-tauri/src/error_db/lookup.rs
git commit -m "feat(error-db): add ErrorCategory enum and ErrorCode struct"
```

---

### Task 2: Add search_error_codes function with substring search

**Files:**
- Modify: `src-tauri/src/error_db/lookup.rs`

**Step 1: Write the failing tests**

Add to test module in `src-tauri/src/error_db/lookup.rs`:

```rust
#[test]
fn test_search_exact_hex() {
    let results = search_error_codes("0x80070005");
    assert_eq!(results.len(), 1);
    assert!(results[0].found);
    assert!(results[0].description.contains("Access is denied"));
    assert_eq!(results[0].category, "Windows");
}

#[test]
fn test_search_by_description() {
    let results = search_error_codes("access denied");
    assert!(!results.is_empty());
    assert!(results.iter().any(|r| r.description.contains("Access is denied")));
}

#[test]
fn test_search_empty_query() {
    let results = search_error_codes("");
    assert!(results.is_empty());
}

#[test]
fn test_search_no_match() {
    let results = search_error_codes("xyznonexistentxyz");
    assert!(results.is_empty());
}

#[test]
fn test_search_max_results() {
    // Search for a common term that might match many codes
    let results = search_error_codes("error");
    assert!(results.len() <= 50, "Should cap at 50 results");
}
```

**Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test test_search_exact_hex -- --nocapture`
Expected: FAIL — `search_error_codes` function doesn't exist yet.

**Step 3: Implement search_error_codes**

Add to `src-tauri/src/error_db/lookup.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorSearchResult {
    pub code_hex: String,
    pub code_decimal: String,
    pub description: String,
    pub category: String,
    pub found: bool,
}

/// Search error codes by exact hex/decimal match or by description substring.
/// Returns up to 50 results sorted by relevance.
pub fn search_error_codes(query: &str) -> Vec<ErrorSearchResult> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }

    // Try exact code lookup first
    let exact = try_parse_error_code(query);
    if let Some(code_val) = exact {
        if let Some(ec) = ERROR_CODES.iter().find(|ec| ec.code == code_val) {
            return vec![ErrorSearchResult {
                code_hex: format!("0x{:08X}", ec.code),
                code_decimal: format!("{}", ec.code as i32),
                description: ec.description.to_string(),
                category: ec.category.label().to_string(),
                found: true,
            }];
        }
        // Known code format but not in DB
        return vec![ErrorSearchResult {
            code_hex: format!("0x{:08X}", code_val),
            code_decimal: format!("{}", code_val as i32),
            description: "Unknown error code".to_string(),
            category: String::new(),
            found: false,
        }];
    }

    // Substring search across descriptions
    let query_lower = query.to_lowercase();
    let mut results: Vec<(usize, &ErrorCode)> = ERROR_CODES
        .iter()
        .filter_map(|ec| {
            let desc_lower = ec.description.to_lowercase();
            if desc_lower.starts_with(&query_lower) {
                Some((0, ec)) // starts-with gets priority 0
            } else if desc_lower.contains(&query_lower) {
                Some((1, ec)) // contains gets priority 1
            } else {
                None
            }
        })
        .collect();

    results.sort_by_key(|(priority, _)| *priority);
    results.truncate(50);

    results
        .into_iter()
        .map(|(_, ec)| ErrorSearchResult {
            code_hex: format!("0x{:08X}", ec.code),
            code_decimal: format!("{}", ec.code as i32),
            description: ec.description.to_string(),
            category: ec.category.label().to_string(),
            found: true,
        })
        .collect()
}
```

Also refactor the hex/decimal parsing into a shared `try_parse_error_code(input: &str) -> Option<u32>` helper, used by both `lookup_error_code` and `search_error_codes`.

**Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test -- --nocapture`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src-tauri/src/error_db/lookup.rs
git commit -m "feat(error-db): add search_error_codes with substring search"
```

---

### Task 3: Expose search_error_codes as Tauri IPC command

**Files:**
- Modify: `src-tauri/src/commands/error_lookup.rs`
- Modify: `src-tauri/src/lib.rs:62`

**Step 1: Add the new command**

In `src-tauri/src/commands/error_lookup.rs`, add:

```rust
use crate::error_db::lookup::{
    lookup_error_code as do_lookup,
    search_error_codes as do_search,
    ErrorLookupResult,
    ErrorSearchResult,
};

#[tauri::command]
pub fn search_error_codes(query: String) -> Vec<ErrorSearchResult> {
    do_search(&query)
}
```

**Step 2: Register in lib.rs**

In `src-tauri/src/lib.rs`, add `commands::error_lookup::search_error_codes` to the `generate_handler!` macro (line 62, after `commands::error_lookup::lookup_error_code`).

**Step 3: Run cargo check and tests**

Run: `cd src-tauri && cargo check && cargo test`
Expected: PASS — no compilation errors, all tests pass.

**Step 4: Commit**

```bash
git add src-tauri/src/commands/error_lookup.rs src-tauri/src/lib.rs
git commit -m "feat(ipc): expose search_error_codes Tauri command"
```

---

### Task 4: Add ErrorLookupHistory to ui-store

**Files:**
- Modify: `src/stores/ui-store.ts`

**Step 1: Add history state**

Add to the `UiState` interface in `src/stores/ui-store.ts`:

```typescript
// In UiState interface (after showFileAssociationPrompt):
errorLookupHistory: ErrorLookupHistoryEntry[];
addErrorLookupHistoryEntry: (entry: ErrorLookupHistoryEntry) => void;
clearErrorLookupHistory: () => void;
```

Add the type above the interface:

```typescript
export interface ErrorLookupHistoryEntry {
  codeHex: string;
  codeDecimal: string;
  description: string;
  category: string;
  found: boolean;
  timestamp: number;
}
```

Add the implementation in the store creator (after `setShowFileAssociationPrompt`):

```typescript
errorLookupHistory: [],
addErrorLookupHistoryEntry: (entry) =>
  set((state) => ({
    errorLookupHistory: [
      entry,
      ...state.errorLookupHistory.filter((e) => e.codeHex !== entry.codeHex),
    ].slice(0, 10),
  })),
clearErrorLookupHistory: () => set({ errorLookupHistory: [] }),
```

Note: History is NOT persisted (not added to `partialize`). It's session-only.

**Step 2: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS.

**Step 3: Commit**

```bash
git add src/stores/ui-store.ts
git commit -m "feat(store): add error lookup history to ui-store"
```

---

### Task 5: Rebuild ErrorLookupDialog with Fluent UI

**Files:**
- Modify: `src/components/dialogs/ErrorLookupDialog.tsx`

**Step 1: Rewrite the dialog component**

Replace the entire contents of `ErrorLookupDialog.tsx` with a Fluent UI implementation following the FindDialog pattern:

```typescript
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Badge,
  Button,
  Caption1,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Input,
  tokens,
} from "@fluentui/react-components";
import {
  CopyRegular,
  SearchRegular,
  DismissRegular,
  HistoryRegular,
} from "@fluentui/react-icons";
import { invoke } from "@tauri-apps/api/core";
import { useUiStore, type ErrorLookupHistoryEntry } from "../../stores/ui-store";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";

interface ErrorSearchResult {
  codeHex: string;
  codeDecimal: string;
  description: string;
  category: string;
  found: boolean;
}

interface ErrorLookupDialogProps {
  isOpen: boolean;
  onClose: () => void;
}
```

The dialog layout:
1. `Dialog` + `DialogSurface` (width: `min(560px, calc(100vw - 32px))`)
2. `DialogTitle`: "Error Code Lookup"
3. `DialogContent`:
   - `Input` with `contentBefore={<SearchRegular />}`, placeholder "Search by code (0x80070005) or description (access denied)"
   - Results list: scrollable `div` (max-height: 320px, overflow-y: auto) containing result rows
   - Each result row: category `Badge`, code in monospace, description, copy `Button` (icon only)
   - Collapsible "Recent" section using `<details>` with `<summary>` containing `HistoryRegular` icon
4. `DialogActions`: Close button

Key behaviors:
- On input change: if input looks like hex/decimal (starts with `0x`, `-`, or is all hex digits ≥6 chars), call `invoke("search_error_codes", { query })` immediately
- If input looks like text (other), debounce 300ms then call `invoke("search_error_codes", { query })`
- On result click or copy: add to history via `addErrorLookupHistoryEntry`
- Copy button: writes `"0x80070005 - E_ACCESSDENIED - Access is denied"` to clipboard via `writeText` from `@tauri-apps/plugin-clipboard-manager`

Category badge colors (using Fluent tokens):
- Windows: `"informative"` (blue)
- Intune: `"warning"` (orange)
- ConfigMgr: `"success"` (green)
- WindowsUpdate: `"informative"` (blue)
- BITS: `"informative"` (blue)
- AppInstall: `"important"` (red)
- Certificate: `"severe"` (dark orange)
- Network: `"informative"` (blue)
- Security: `"important"` (red)
- Others: `"informative"` (blue)

**Step 2: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS.

**Step 3: Visual verification**

Run: `npm run frontend:dev`
Open browser at http://localhost:1420, press Ctrl+E to open dialog. Verify:
- Dialog opens with Fluent UI styling
- Search input auto-focuses
- Typing hex code shows instant result
- Typing description shows debounced results
- Category badges display with colors
- Copy button works
- History section shows recent lookups
- Escape closes dialog

**Step 4: Commit**

```bash
git add src/components/dialogs/ErrorLookupDialog.tsx
git commit -m "feat(ui): rebuild ErrorLookupDialog with Fluent UI and unified search"
```

---

### Task 6: Add ErrorCodeSpan to Rust LogEntry model

**Files:**
- Modify: `src-tauri/src/models/log_entry.rs:108-135`
- Modify: `src/types/log.ts:94-108`

**Step 1: Write the failing test**

Add to `src-tauri/src/error_db/lookup.rs` tests:

```rust
#[test]
fn test_detect_error_code_spans() {
    let spans = detect_error_code_spans("Failed with error 0x80070005 during install");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start, 18); // character index of "0x80070005" (for JS string slicing)
    assert_eq!(spans[0].end, 28);
    assert_eq!(spans[0].code_hex, "0x80070005");
    assert!(spans[0].description.contains("Access is denied"));
    assert_eq!(spans[0].category, "Windows");
}

#[test]
fn test_detect_multiple_error_code_spans() {
    let spans = detect_error_code_spans("Error 0x80070005 and then 0x80070002");
    assert_eq!(spans.len(), 2);
}

#[test]
fn test_detect_no_error_code_spans() {
    let spans = detect_error_code_spans("Everything is fine, no errors here");
    assert!(spans.is_empty());
}

#[test]
fn test_detect_unrecognized_code_ignored() {
    let spans = detect_error_code_spans("Code 0xDEADBEEF is not in our database");
    assert!(spans.is_empty(), "Unknown codes should not produce spans");
}
```

**Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test test_detect_error_code_spans -- --nocapture`
Expected: FAIL — function doesn't exist.

**Step 3: Implement ErrorCodeSpan and detect_error_code_spans**

Add to `src-tauri/src/error_db/lookup.rs`:

```rust
use regex::Regex;
use once_cell::sync::Lazy;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorCodeSpan {
    pub start: usize,
    pub end: usize,
    pub code_hex: String,
    pub description: String,
    pub category: String,
}

static HEX_CODE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"0[xX][0-9A-Fa-f]{8}").unwrap()
});

/// Scan a message string for recognized error codes and return their spans.
pub fn detect_error_code_spans(message: &str) -> Vec<ErrorCodeSpan> {
    HEX_CODE_RE
        .find_iter(message)
        .filter_map(|m| {
            let hex_str = &message[m.start()..m.end()];
            let code_val = u32::from_str_radix(&hex_str[2..], 16).ok()?;
            let ec = ERROR_CODES.iter().find(|ec| ec.code == code_val)?;
            Some(ErrorCodeSpan {
                start: m.start(),
                end: m.end(),
                code_hex: format!("0x{:08X}", ec.code),
                description: ec.description.to_string(),
                category: ec.category.label().to_string(),
            })
        })
        .collect()
}
```

**Step 4: Add `error_code_spans` field to Rust `LogEntry`**

In `src-tauri/src/models/log_entry.rs`, add to the `LogEntry` struct after `timezone_offset`:

```rust
/// Spans of recognized error codes within the message text
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub error_code_spans: Vec<crate::error_db::lookup::ErrorCodeSpan>,
```

This requires making `error_db` module public in `lib.rs`: change `mod error_db;` to `pub mod error_db;`.

Update all places that construct `LogEntry` to include `error_code_spans: Vec::new()` (search for `LogEntry {` in parser files). The spans will be populated in a subsequent task.

**Step 5: Add `errorCodeSpans` to TypeScript `LogEntry`**

In `src/types/log.ts`, add to the `LogEntry` interface after `timezoneOffset`:

```typescript
errorCodeSpans?: ErrorCodeSpan[];
```

And add the type:

```typescript
export interface ErrorCodeSpan {
  start: number;
  end: number;
  codeHex: string;
  description: string;
  category: string;
}
```

**Step 6: Run tests and type check**

Run: `cd src-tauri && cargo test && cd .. && npx tsc --noEmit`
Expected: All PASS.

**Step 7: Commit**

```bash
git add src-tauri/src/error_db/lookup.rs src-tauri/src/models/log_entry.rs src-tauri/src/lib.rs src/types/log.ts
git commit -m "feat(model): add ErrorCodeSpan detection and LogEntry field"
```

---

### Task 7: Integrate error code span detection into the parsing pipeline

**Files:**
- Modify: Parser files that construct `LogEntry` (find all with `grep -rn "LogEntry {" src-tauri/src/parser/`)
- The main entry point is likely a function that builds entries from parsed lines

**Step 1: Find the integration point**

Search for where `LogEntry` instances are constructed in the parser module. The detection should run after the message is parsed, before the entry is returned. Look for a shared post-processing function or add one.

**Step 2: Add span detection call**

After each `LogEntry` is constructed with its `message` field populated, call:

```rust
entry.error_code_spans = crate::error_db::lookup::detect_error_code_spans(&entry.message);
```

If there's a central place where all parsed entries pass through (e.g., a `finalize_entry` or the rayon batch processing), add it there. Otherwise, add it at each construction site.

The most efficient approach: add a post-processing step in whatever function collects all entries before returning `ParseResult`. This avoids touching every parser individually.

**Step 3: Write integration test**

Add to `src-tauri/tests/` (or the parser test module):

```rust
#[test]
fn test_parsed_entries_have_error_spans() {
    // Create a synthetic log line containing an error code
    let line = "<![LOG[Installation failed with error 0x80070005]LOG]!><time=\"10:00:00.000\" date=\"01-01-2024\" component=\"TestComp\" context=\"\" type=\"3\" thread=\"1234\" file=\"test.log\">";
    // Parse it and verify spans are populated
    // (exact parsing call depends on the parser API)
}
```

**Step 4: Run tests**

Run: `cd src-tauri && cargo test`
Expected: PASS.

**Step 5: Commit**

```bash
git add src-tauri/src/parser/
git commit -m "feat(parser): detect error code spans during log parsing"
```

---

### Task 8: Render inline error code highlights in LogRow

**Files:**
- Modify: `src/components/log-view/LogRow.tsx:55-88` (the `highlightMessage` function)

**Step 1: Extend LogRow props**

The `LogRow` component already receives `entry: LogEntry`. Since `errorCodeSpans` is now on `LogEntry`, no prop changes needed.

**Step 2: Modify message rendering**

Update the `highlightMessage` function (or create a new `renderMessageWithSpans` function) to split the message text into segments based on `entry.errorCodeSpans`:

```typescript
function renderMessageWithSpans(
  text: string,
  spans: ErrorCodeSpan[] | undefined,
  highlight: string,
  caseSensitive: boolean,
  palette: LogSeverityPalette,
  isSelected: boolean,
  onSpanClick: (span: ErrorCodeSpan) => void
): React.ReactNode {
  if (!spans || spans.length === 0) {
    return highlightMessage(text, highlight, caseSensitive, palette);
  }

  const segments: React.ReactNode[] = [];
  let lastEnd = 0;

  for (const span of spans) {
    // Plain text before this span
    if (span.start > lastEnd) {
      const plainText = text.slice(lastEnd, span.start);
      segments.push(highlightMessage(plainText, highlight, caseSensitive, palette));
    }

    // The error code span itself
    const codeText = text.slice(span.start, span.end);
    segments.push(
      <span
        key={`span-${span.start}`}
        title={`${span.codeHex} - ${span.description} [${span.category}]`}
        onClick={(e) => {
          e.stopPropagation();
          onSpanClick(span);
        }}
        style={{
          textDecoration: "underline dotted",
          textDecorationColor: isSelected
            ? tokens.colorNeutralForegroundOnBrand
            : tokens.colorPaletteRedBorder2,
          textUnderlineOffset: "2px",
          cursor: "pointer",
          borderRadius: "2px",
        }}
        onMouseEnter={(e) => {
          (e.target as HTMLElement).style.backgroundColor =
            tokens.colorNeutralBackground1Hover;
        }}
        onMouseLeave={(e) => {
          (e.target as HTMLElement).style.backgroundColor = "";
        }}
      >
        {codeText}
      </span>
    );

    lastEnd = span.end;
  }

  // Remaining text after last span
  if (lastEnd < text.length) {
    segments.push(highlightMessage(text.slice(lastEnd), highlight, caseSensitive, palette));
  }

  return <>{segments}</>;
}
```

**Step 3: Add onSpanClick callback to LogRow**

Add a new prop `onErrorCodeClick?: (span: ErrorCodeSpan) => void` to `LogRowProps`. Wire it from `LogListView.tsx` to open the info pane and set a "focused error code" state.

**Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/components/log-view/LogRow.tsx src/components/log-view/LogListView.tsx
git commit -m "feat(ui): render inline error code highlights in log rows"
```

---

### Task 9: Enhance InfoPane with Error Code Details view

**Files:**
- Modify: `src/components/log-view/InfoPane.tsx`
- Modify: `src/stores/ui-store.ts` (add focused error code state)

**Step 1: Add focused error code state to ui-store**

In `src/stores/ui-store.ts`, add:

```typescript
// In UiState interface:
focusedErrorCode: { codeHex: string; description: string; category: string } | null;
setFocusedErrorCode: (code: { codeHex: string; description: string; category: string } | null) => void;
```

Implementation:

```typescript
focusedErrorCode: null,
setFocusedErrorCode: (code) => set({ focusedErrorCode: code }),
```

**Step 2: Show error code details in InfoPane**

In `InfoPane.tsx`, read `focusedErrorCode` from `useUiStore`. When set, show a details section at the top of the info pane:

```typescript
const focusedErrorCode = useUiStore((s) => s.focusedErrorCode);
const setFocusedErrorCode = useUiStore((s) => s.setFocusedErrorCode);
const setShowErrorLookupDialog = useUiStore((s) => s.setShowErrorLookupDialog);
```

Render (before the existing metadata line):

```tsx
{focusedErrorCode && (
  <div style={{
    padding: "6px 8px",
    marginBottom: "8px",
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: "4px",
    display: "flex",
    alignItems: "center",
    gap: "8px",
  }}>
    <Badge appearance="filled" color="informative">{focusedErrorCode.category}</Badge>
    <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontWeight: 600 }}>
      {focusedErrorCode.codeHex}
    </span>
    <span style={{ flex: 1 }}>{focusedErrorCode.description}</span>
    <Button
      size="small"
      appearance="subtle"
      onClick={() => {
        setShowErrorLookupDialog(true);
        setFocusedErrorCode(null);
      }}
    >
      Open Lookup
    </Button>
    <Button
      size="small"
      appearance="subtle"
      icon={<DismissRegular />}
      onClick={() => setFocusedErrorCode(null)}
    />
  </div>
)}
```

**Step 3: Wire the click handler from LogListView**

In `LogListView.tsx`, pass an `onErrorCodeClick` handler to each `LogRow` that:
1. Opens the info pane if closed: `useUiStore.getState().showInfoPane || useUiStore.getState().toggleInfoPane()`
2. Sets `focusedErrorCode` on the ui-store

**Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/components/log-view/InfoPane.tsx src/stores/ui-store.ts src/components/log-view/LogListView.tsx
git commit -m "feat(ui): add error code details view to InfoPane"
```

---

### Task 10: Expand error code database

**Files:**
- Modify: `src-tauri/src/error_db/codes.rs`

**Step 1: Research and compile additional error codes**

Expand the database from 161 to ~500-800 codes. Priority areas:
1. **More Windows HRESULT codes** (~100 additional): Common HRESULT_FROM_WIN32 values, COM errors, RPC errors
2. **Intune enrollment/compliance** (~80 additional): MDM enrollment, compliance policy, app protection
3. **SCCM/ConfigMgr** (~60 additional): Task sequence, software distribution, client health
4. **Windows Update expanded** (~50 additional): Component-based servicing, driver install
5. **Network errors** (~40 additional): WinHTTP, WinInet, DNS, TLS/SSL
6. **Security/Auth** (~30 additional): Kerberos, NTLM, credential provider
7. **File system/Registry** (~20 additional): Common I/O, registry access

Sources: Microsoft public documentation for Win32 error codes, Intune troubleshooting docs, ConfigMgr error reference.

**Step 2: Add codes to ERROR_CODES array**

Follow the existing pattern with the new `ErrorCode` struct format:

```rust
ErrorCode { code: 0xNNNNNNNN, description: "NAME - Description text", category: ErrorCategory::Xxx },
```

**Step 3: Write validation test**

```rust
#[test]
fn test_expanded_database_size() {
    assert!(
        ERROR_CODES.len() >= 400,
        "Expected at least 400 error codes, got {}",
        ERROR_CODES.len()
    );
}
```

**Step 4: Run tests**

Run: `cd src-tauri && cargo test`
Expected: PASS — no duplicates, all categories valid, ≥400 codes.

**Step 5: Commit**

```bash
git add src-tauri/src/error_db/codes.rs
git commit -m "feat(error-db): expand database to 500+ categorized error codes"
```

---

### Task 11: Final integration testing and cleanup

**Files:**
- All modified files from previous tasks

**Step 1: Run full Rust test suite**

Run: `cd src-tauri && cargo test && cargo clippy -- -D warnings`
Expected: All tests PASS, zero clippy warnings.

**Step 2: Run TypeScript type check**

Run: `npx tsc --noEmit`
Expected: PASS.

**Step 3: Run full app dev mode and manually test**

Run: `npm run frontend:dev`

Manual verification checklist:
- [ ] Error lookup dialog opens via Ctrl+E
- [ ] Dialog opens via toolbar button
- [ ] Unified search works for hex codes (instant)
- [ ] Unified search works for description text (debounced)
- [ ] Results show category badges with correct colors
- [ ] Copy button copies formatted error string
- [ ] History section shows recent lookups
- [ ] History items are clickable
- [ ] Dialog follows Fluent UI theme (light/dark)
- [ ] Escape closes dialog
- [ ] Log rows with error codes show dotted underline
- [ ] Hovering error code shows tooltip
- [ ] Clicking error code opens info pane with details
- [ ] Info pane shows "Open Lookup" link
- [ ] Dismiss button clears focused error code

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: integration test fixes for error lookup redesign"
```

**Step 5: Run final verification**

Run: `cd src-tauri && cargo test && cargo clippy -- -D warnings && cd .. && npx tsc --noEmit`
Expected: All PASS.
