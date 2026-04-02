# Settings Dialog — Design Spec

**Issue:** #51 — Setting to enable or disable check for updates
**Date:** 2026-04-01

## Overview

Replace the existing `AccessibilityDialog` with a comprehensive, tabbed Settings dialog that consolidates all user preferences and adds new configuration options. Accessible via menu "Settings..." (Ctrl+,).

## Tab Layout

### Tab 1: Appearance

Consolidates all visual/typography settings currently in `AccessibilityDialog`.

| Setting | Control | Source |
|---------|---------|--------|
| Theme | Dropdown (8 themes) | `ui-store.themeId` |
| Font family | Dropdown + search filter | `ui-store.fontFamily` |
| Log list font size | Slider (11-20px) | `ui-store.logListFontSize` |
| Details font size | Slider (11-24px) | `ui-store.logDetailsFontSize` |
| Live preview | Read-only sample text | Shows current settings applied |
| Reset Appearance | Button | Calls `resetLogAccessibilityPreferences()` |

This tab is a direct migration of `AccessibilityDialog.tsx` content. No new settings, just relocated.

### Tab 2: Columns

| Setting | Control | Source |
|---------|---------|--------|
| Column order | Drag-reorder list | `ui-store.columnOrder` |
| Column visibility | Checkbox per column | New: `ui-store.hiddenColumns` |
| Reset Columns | Button | Calls `resetColumns()` |

**New capability:** Users can hide columns they don't need (e.g., ipAddress, macAddress for non-IIS logs). Currently all detected columns are always shown.

### Tab 3: Behavior

| Setting | Control | Source |
|---------|---------|--------|
| Default parser | Dropdown (Auto-detect, CCM, Simple, etc.) | New: `ui-store.defaultParser` |
| Show info pane on startup | Toggle | New: `ui-store.defaultShowInfoPane` |
| Confirm before closing tabs | Toggle | New: `ui-store.confirmTabClose` |

### Tab 4: Updates

| Setting | Control | Source |
|---------|---------|--------|
| Auto-check for updates | Toggle | New: `ui-store.autoUpdateEnabled` (default: true) |
| Current version | Label | Read from `tauri.conf.json` |
| Check Now | Button | Triggers manual update check |
| Skipped version | Label + Clear button | `localStorage: cmtraceopen-skipped-update-version` |

The update checker hook (`use-update-checker.ts`) reads `autoUpdateEnabled` before its startup check. When disabled, the 5-second silent check is skipped entirely. Manual "Check Now" always works regardless.

### Tab 5: File Associations (Windows only)

| Setting | Control | Source |
|---------|---------|--------|
| Associate .log files | Button | Calls `associate_log_files_with_app` command |
| Association status | Label | Shows current state |
| Suppress association prompt | Toggle | `file-association-preferences.json` |

This tab is hidden on macOS/Linux where file associations are handled differently.

## Architecture

### New Component
`src/components/dialogs/SettingsDialog.tsx`
- Uses Fluent UI `Dialog`, `TabList`, `Tab` components
- Each tab is a separate sub-component for maintainability
- Reads/writes directly to `ui-store` (changes apply immediately, no "Save" button needed)

### Retiring AccessibilityDialog
- `AccessibilityDialog.tsx` is deleted
- All references updated to open `SettingsDialog` instead
- The "Accessibility Settings" menu item becomes "Settings..." with Ctrl+, shortcut
- `showAccessibilityDialog` state renamed to `showSettingsDialog` in ui-store

### New Persisted State
Add to `ui-store.ts` persisted partition:

```typescript
autoUpdateEnabled: boolean;        // default: true
hiddenColumns: ColumnId[];         // default: []
defaultParser: ParserKind | null;  // default: null (auto-detect)
defaultShowInfoPane: boolean;      // default: true
confirmTabClose: boolean;          // default: false
```

## Files

| File | Action | Purpose |
|------|--------|---------|
| `src/components/dialogs/SettingsDialog.tsx` | New | Main settings dialog with tabs |
| `src/components/dialogs/AccessibilityDialog.tsx` | Delete | Replaced by SettingsDialog |
| `src/stores/ui-store.ts` | Modify | Add new persisted fields, rename dialog state |
| `src/hooks/use-update-checker.ts` | Modify | Check `autoUpdateEnabled` before startup check |
| `src-tauri/src/menu.rs` | Modify | Rename menu item, update shortcut |
| `src/components/layout/AppShell.tsx` | Modify | Update dialog references |

## Design Principles

- **Immediate apply** — no "Save/Cancel" buttons. Changes take effect as the user adjusts them, matching modern app settings patterns (VS Code, Discord, etc.)
- **Reset per-section** — each tab has its own reset button, not a global "Reset All"
- **Platform-aware** — File Associations tab hidden on non-Windows platforms

## Verification

1. Open Settings (Ctrl+,) → tabbed dialog appears
2. Appearance tab: change theme → applies immediately, change font → applies immediately
3. Updates tab: disable auto-update → restart app → no update check on startup
4. Updates tab: click "Check Now" → update check runs even if auto-update is disabled
5. Columns tab: hide a column → column disappears from log view
6. Close and reopen app → all settings persist
7. Verify old "Accessibility Settings" menu item no longer exists
