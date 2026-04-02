# Settings Dialog — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Accessibility Settings dialog with a comprehensive, tabbed Settings dialog that consolidates all preferences and adds new options (update toggle, column visibility, behavior settings).

**Architecture:** Create a new `SettingsDialog.tsx` with 5 tabs using Fluent UI `TabList`. Tab 1 (Appearance) migrates all content from the existing `AccessibilityDialog`. New persisted state fields are added to `ui-store.ts`. The existing dialog state, menu item, and keyboard handling are renamed from "accessibility" to "settings". Changes apply immediately — no save/cancel flow.

**Tech Stack:** React, Fluent UI, Zustand (persist), Tauri v2

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/components/dialogs/SettingsDialog.tsx` | Create | Main tabbed settings dialog |
| `src/components/dialogs/settings/AppearanceTab.tsx` | Create | Theme, fonts, preview (migrated from AccessibilityDialog) |
| `src/components/dialogs/settings/ColumnsTab.tsx` | Create | Column visibility toggles, order reset |
| `src/components/dialogs/settings/BehaviorTab.tsx` | Create | Default parser, info pane default, confirm tab close |
| `src/components/dialogs/settings/UpdatesTab.tsx` | Create | Auto-update toggle, check now, version info |
| `src/components/dialogs/settings/FileAssociationsTab.tsx` | Create | Associate .log files, suppress prompt (Windows only) |
| `src/components/dialogs/AccessibilityDialog.tsx` | Delete | Replaced by SettingsDialog |
| `src/stores/ui-store.ts` | Modify | Add new persisted fields, rename dialog state |
| `src/hooks/use-update-checker.ts` | Modify | Check `autoUpdateEnabled` before startup check |
| `src/hooks/use-app-menu.ts` | Modify | Rename accessibility action to settings |
| `src/hooks/use-keyboard.ts` | Modify | Update dialog reference |
| `src/components/layout/AppShell.tsx` | Modify | Swap AccessibilityDialog for SettingsDialog |
| `src-tauri/src/menu.rs` | Modify | Rename menu item label and ID |

---

### Task 1: Add new persisted state to ui-store

**Files:**
- Modify: `src/stores/ui-store.ts`

- [ ] **Step 1: Add new state fields to the interface**

In `src/stores/ui-store.ts`, add these fields to the persisted state section of the `UiState` interface (near line 162, alongside `showAccessibilityDialog`):

```typescript
  showSettingsDialog: boolean;
  autoUpdateEnabled: boolean;
  hiddenColumns: string[];
  defaultShowInfoPane: boolean;
  confirmTabClose: boolean;
```

Add the corresponding setters:

```typescript
  setShowSettingsDialog: (show: boolean) => void;
  setAutoUpdateEnabled: (enabled: boolean) => void;
  setHiddenColumns: (columns: string[]) => void;
  toggleColumnVisibility: (columnId: string) => void;
  setDefaultShowInfoPane: (show: boolean) => void;
  setConfirmTabClose: (confirm: boolean) => void;
```

- [ ] **Step 2: Add defaults and implementations**

In the `create<UiState>` block, add defaults (in the persisted section, near line 292):

```typescript
  showSettingsDialog: false,
  autoUpdateEnabled: true,
  hiddenColumns: [],
  defaultShowInfoPane: true,
  confirmTabClose: false,
```

Add setter implementations:

```typescript
  setShowSettingsDialog: (show) => set({ showSettingsDialog: show }),
  setAutoUpdateEnabled: (enabled) => set({ autoUpdateEnabled: enabled }),
  setHiddenColumns: (columns) => set({ hiddenColumns: columns }),
  toggleColumnVisibility: (columnId) =>
    set((state) => {
      const hidden = state.hiddenColumns;
      return {
        hiddenColumns: hidden.includes(columnId)
          ? hidden.filter((c) => c !== columnId)
          : [...hidden, columnId],
      };
    }),
  setDefaultShowInfoPane: (show) => set({ defaultShowInfoPane: show }),
  setConfirmTabClose: (confirm) => set({ confirmTabClose: confirm }),
```

- [ ] **Step 3: Remove old accessibility dialog state**

Remove `showAccessibilityDialog` and `setShowAccessibilityDialog` from the interface, defaults, and implementation. Replace all references with `showSettingsDialog` and `setShowSettingsDialog`.

- [ ] **Step 4: Run TypeScript check (expect failures from references)**

Run: `npx tsc --noEmit`
Expected: FAIL — references to `showAccessibilityDialog` in other files still exist. We'll fix them in later tasks.

- [ ] **Step 5: Commit**

```bash
git add src/stores/ui-store.ts
git commit -m "feat: add settings dialog state and new preference fields to ui-store"
```

---

### Task 2: Create AppearanceTab (migrate from AccessibilityDialog)

**Files:**
- Create: `src/components/dialogs/settings/AppearanceTab.tsx`

- [ ] **Step 1: Create the AppearanceTab component**

Create `src/components/dialogs/settings/AppearanceTab.tsx`. This is a migration of the body of `AccessibilityDialog.tsx` — all the theme selection, font family dropdown, font size sliders, and live preview. Strip the dialog wrapper (overlay, close button, title bar) — this component is just the tab content.

The component should:
- Use all the same `useUiStore` selectors as `AccessibilityDialog` (logListFontSize, logDetailsFontSize, fontFamily, themeId)
- Load system fonts via `invoke<SystemFontList>("list_system_fonts")`
- Include the font filter search, font size sliders, theme dropdown
- Include the live preview section
- Include the "Reset Appearance" button calling `resetLogAccessibilityPreferences()`
- Accept no props — it reads/writes directly to the store

```typescript
export function AppearanceTab() {
  // Migrate the entire body of AccessibilityDialog here
  // Remove dialog wrapper (overlay, backdrop, close button, title bar)
  // Keep all settings controls and preview section
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: May still fail from other references. The component itself should type-check.

- [ ] **Step 3: Commit**

```bash
git add src/components/dialogs/settings/AppearanceTab.tsx
git commit -m "feat: create AppearanceTab migrated from AccessibilityDialog"
```

---

### Task 3: Create remaining settings tabs

**Files:**
- Create: `src/components/dialogs/settings/ColumnsTab.tsx`
- Create: `src/components/dialogs/settings/BehaviorTab.tsx`
- Create: `src/components/dialogs/settings/UpdatesTab.tsx`
- Create: `src/components/dialogs/settings/FileAssociationsTab.tsx`

- [ ] **Step 1: Create ColumnsTab**

Create `src/components/dialogs/settings/ColumnsTab.tsx`:

```typescript
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";
import { ALL_COLUMN_DEFINITIONS } from "../../../lib/column-config";

export function ColumnsTab() {
  const hiddenColumns = useUiStore((s) => s.hiddenColumns);
  const toggleColumnVisibility = useUiStore((s) => s.toggleColumnVisibility);
  const resetColumns = useUiStore((s) => s.resetColumns);

  return (
    <div style={{ padding: "16px", display: "grid", gap: "12px" }}>
      <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground2 }}>
        Toggle which columns are visible in the log view.
      </div>
      <div style={{ display: "grid", gap: "6px" }}>
        {ALL_COLUMN_DEFINITIONS.map((col) => (
          <label
            key={col.id}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              fontSize: "13px",
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={!hiddenColumns.includes(col.id)}
              onChange={() => toggleColumnVisibility(col.id)}
            />
            {col.label}
          </label>
        ))}
      </div>
      <button
        type="button"
        onClick={resetColumns}
        style={{
          justifySelf: "start",
          padding: "6px 12px",
          fontSize: "12px",
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          cursor: "pointer",
        }}
      >
        Reset Columns
      </button>
    </div>
  );
}
```

Note: `ALL_COLUMN_DEFINITIONS` may need to be exported from `src/lib/column-config.ts`. Check what's exported and adjust the import.

- [ ] **Step 2: Create BehaviorTab**

Create `src/components/dialogs/settings/BehaviorTab.tsx`:

```typescript
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";

export function BehaviorTab() {
  const defaultShowInfoPane = useUiStore((s) => s.defaultShowInfoPane);
  const setDefaultShowInfoPane = useUiStore((s) => s.setDefaultShowInfoPane);
  const confirmTabClose = useUiStore((s) => s.confirmTabClose);
  const setConfirmTabClose = useUiStore((s) => s.setConfirmTabClose);

  return (
    <div style={{ padding: "16px", display: "grid", gap: "16px" }}>
      <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", cursor: "pointer" }}>
        <input
          type="checkbox"
          checked={defaultShowInfoPane}
          onChange={(e) => setDefaultShowInfoPane(e.target.checked)}
        />
        Show info pane by default
      </label>
      <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", cursor: "pointer" }}>
        <input
          type="checkbox"
          checked={confirmTabClose}
          onChange={(e) => setConfirmTabClose(e.target.checked)}
        />
        Confirm before closing tabs
      </label>
    </div>
  );
}
```

- [ ] **Step 3: Create UpdatesTab**

Create `src/components/dialogs/settings/UpdatesTab.tsx`:

```typescript
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";
import { getVersion } from "@tauri-apps/api/app";
import { useEffect, useState } from "react";

export function UpdatesTab() {
  const autoUpdateEnabled = useUiStore((s) => s.autoUpdateEnabled);
  const setAutoUpdateEnabled = useUiStore((s) => s.setAutoUpdateEnabled);
  const [version, setVersion] = useState<string>("");

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion("unknown"));
  }, []);

  const skippedVersion = localStorage.getItem("cmtraceopen-skipped-update-version");

  return (
    <div style={{ padding: "16px", display: "grid", gap: "16px" }}>
      <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", cursor: "pointer" }}>
        <input
          type="checkbox"
          checked={autoUpdateEnabled}
          onChange={(e) => setAutoUpdateEnabled(e.target.checked)}
        />
        Automatically check for updates on startup
      </label>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
        Current version: {version || "…"}
      </div>
      {skippedVersion && (
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, display: "flex", gap: "8px", alignItems: "center" }}>
          <span>Skipped version: {skippedVersion}</span>
          <button
            type="button"
            onClick={() => localStorage.removeItem("cmtraceopen-skipped-update-version")}
            style={{
              fontSize: "11px",
              padding: "2px 8px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "3px",
              backgroundColor: tokens.colorNeutralBackground1,
              color: tokens.colorNeutralForeground1,
              cursor: "pointer",
            }}
          >
            Clear
          </button>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Create FileAssociationsTab**

Create `src/components/dialogs/settings/FileAssociationsTab.tsx`:

```typescript
import { useState } from "react";
import { tokens } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { useUiStore } from "../../../stores/ui-store";

export function FileAssociationsTab() {
  const platform = useUiStore((s) => s.currentPlatform);
  const [associating, setAssociating] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  if (platform !== "windows") {
    return (
      <div style={{ padding: "16px", fontSize: "13px", color: tokens.colorNeutralForeground3 }}>
        File associations are managed by the operating system on this platform.
      </div>
    );
  }

  const handleAssociate = async () => {
    setAssociating(true);
    setResult(null);
    try {
      await invoke("associate_log_files_with_app");
      setResult("File associations updated successfully.");
    } catch (err) {
      setResult(`Failed: ${err}`);
    } finally {
      setAssociating(false);
    }
  };

  return (
    <div style={{ padding: "16px", display: "grid", gap: "16px" }}>
      <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground2 }}>
        Associate .log and .lo_ files with CMTrace Open so they open directly in this app.
      </div>
      <button
        type="button"
        onClick={handleAssociate}
        disabled={associating}
        style={{
          justifySelf: "start",
          padding: "8px 16px",
          fontSize: "13px",
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          cursor: associating ? "not-allowed" : "pointer",
        }}
      >
        {associating ? "Associating..." : "Associate .log Files"}
      </button>
      {result && (
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>{result}</div>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: May have some issues depending on imports. Fix any type errors.

- [ ] **Step 6: Commit**

```bash
git add src/components/dialogs/settings/
git commit -m "feat: create Columns, Behavior, Updates, and FileAssociations settings tabs"
```

---

### Task 4: Create SettingsDialog shell and wire it up

**Files:**
- Create: `src/components/dialogs/SettingsDialog.tsx`
- Modify: `src/components/layout/AppShell.tsx`
- Delete: `src/components/dialogs/AccessibilityDialog.tsx`

- [ ] **Step 1: Create SettingsDialog**

Create `src/components/dialogs/SettingsDialog.tsx`:

```typescript
import { useState, useRef, useEffect } from "react";
import { tokens } from "@fluentui/react-components";
import { AppearanceTab } from "./settings/AppearanceTab";
import { ColumnsTab } from "./settings/ColumnsTab";
import { BehaviorTab } from "./settings/BehaviorTab";
import { UpdatesTab } from "./settings/UpdatesTab";
import { FileAssociationsTab } from "./settings/FileAssociationsTab";
import { useUiStore } from "../../stores/ui-store";

type SettingsTab = "appearance" | "columns" | "behavior" | "updates" | "file-associations";

const TABS: { id: SettingsTab; label: string; windowsOnly?: boolean }[] = [
  { id: "appearance", label: "Appearance" },
  { id: "columns", label: "Columns" },
  { id: "behavior", label: "Behavior" },
  { id: "updates", label: "Updates" },
  { id: "file-associations", label: "File Associations", windowsOnly: true },
];

interface SettingsDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SettingsDialog({ isOpen, onClose }: SettingsDialogProps) {
  const [activeTab, setActiveTab] = useState<SettingsTab>("appearance");
  const platform = useUiStore((s) => s.currentPlatform);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);

  const visibleTabs = TABS.filter((t) => !t.windowsOnly || platform === "windows");

  useEffect(() => {
    if (isOpen) {
      previouslyFocusedElementRef.current = document.activeElement as HTMLElement;
      requestAnimationFrame(() => dialogRef.current?.focus());
    } else {
      previouslyFocusedElementRef.current?.focus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "rgba(0, 0, 0, 0.4)",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-label="Settings"
        style={{
          width: "640px",
          maxHeight: "80vh",
          display: "flex",
          flexDirection: "column",
          backgroundColor: tokens.colorNeutralBackground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "8px",
          boxShadow: tokens.shadow16,
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "16px 20px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        }}>
          <span style={{ fontSize: "16px", fontWeight: 600 }}>Settings</span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{
              background: "none",
              border: "none",
              fontSize: "18px",
              cursor: "pointer",
              color: tokens.colorNeutralForeground2,
              padding: "4px",
            }}
          >
            ✕
          </button>
        </div>

        {/* Tabs */}
        <div style={{
          display: "flex",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          padding: "0 20px",
        }}>
          {visibleTabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: "10px 16px",
                fontSize: "13px",
                background: "none",
                border: "none",
                borderBottom: activeTab === tab.id
                  ? `2px solid ${tokens.colorBrandForeground1}`
                  : "2px solid transparent",
                color: activeTab === tab.id
                  ? tokens.colorNeutralForeground1
                  : tokens.colorNeutralForeground3,
                fontWeight: activeTab === tab.id ? 600 : 400,
                cursor: "pointer",
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {activeTab === "appearance" && <AppearanceTab />}
          {activeTab === "columns" && <ColumnsTab />}
          {activeTab === "behavior" && <BehaviorTab />}
          {activeTab === "updates" && <UpdatesTab />}
          {activeTab === "file-associations" && <FileAssociationsTab />}
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Update AppShell to use SettingsDialog**

In `src/components/layout/AppShell.tsx`:

Replace the import:
```typescript
// Remove:
import { AccessibilityDialog } from "../dialogs/AccessibilityDialog";
// Add:
import { SettingsDialog } from "../dialogs/SettingsDialog";
```

Replace the store selectors (lines 62-63, 77-78):
```typescript
// Replace showAccessibilityDialog with showSettingsDialog
const showSettingsDialog = useUiStore((s) => s.showSettingsDialog);
const setShowSettingsDialog = useUiStore((s) => s.setShowSettingsDialog);
```

Replace the JSX (lines 503-506):
```tsx
<SettingsDialog
  isOpen={showSettingsDialog}
  onClose={() => setShowSettingsDialog(false)}
/>
```

- [ ] **Step 3: Delete AccessibilityDialog**

```bash
rm src/components/dialogs/AccessibilityDialog.tsx
```

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: FAIL — still need to update menu.rs, use-app-menu.ts, use-keyboard.ts

- [ ] **Step 5: Commit**

```bash
git add src/components/dialogs/SettingsDialog.tsx src/components/layout/AppShell.tsx
git rm src/components/dialogs/AccessibilityDialog.tsx
git commit -m "feat: create SettingsDialog and replace AccessibilityDialog in AppShell"
```

---

### Task 5: Update menu, keyboard, and action references

**Files:**
- Modify: `src-tauri/src/menu.rs`
- Modify: `src/hooks/use-app-menu.ts`
- Modify: `src/hooks/use-keyboard.ts`

- [ ] **Step 1: Update Rust menu item**

In `src-tauri/src/menu.rs`:

Replace line 24:
```rust
pub const MENU_ID_WINDOW_SETTINGS: &str = "window.settings";
```

Replace lines 99-102 (the MenuItem creation):
```rust
let settings = MenuItem::with_id(
    app,
    MENU_ID_WINDOW_SETTINGS,
    "Settings...",
    true,
    Some("CmdOrCtrl+,"),
)?;
```

Update the reference in the submenu builder (line 133) — replace `&accessibility_settings` with `&settings`.

Update the menu event handler (line 421) — replace `"show_accessibility_settings"` with `"show_settings"`, and update the ID match.

- [ ] **Step 2: Update use-app-menu.ts**

In `src/hooks/use-app-menu.ts`:

Replace `showAccessibilityDialog` with `showSettingsDialog` in the destructured actions (line 27) and in the switch case (line 79-80):

```typescript
case "show_settings":
  showSettingsDialog();
  return;
```

Update the dependency array (line 133).

- [ ] **Step 3: Update use-keyboard.ts**

In `src/hooks/use-keyboard.ts`:

Replace `showAccessibilityDialog` references (lines 114-115) with `showSettingsDialog`:

```typescript
const showSettingsDialogOpen = useUiStore(
  (state) => state.showSettingsDialog
);
```

Update all references in the keyboard handler and dependency array.

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 5: Run cargo check**

Run: `cd src-tauri && cargo check`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/menu.rs src/hooks/use-app-menu.ts src/hooks/use-keyboard.ts
git commit -m "feat: rename Accessibility Settings to Settings in menu and keyboard handlers"
```

---

### Task 6: Wire autoUpdateEnabled to update checker

**Files:**
- Modify: `src/hooks/use-update-checker.ts`

- [ ] **Step 1: Check autoUpdateEnabled before startup check**

In `src/hooks/use-update-checker.ts`, find the `useEffect` that runs the silent startup check (the one with the 5-second `setTimeout`). Add a check at the top:

```typescript
useEffect(() => {
  const autoUpdateEnabled = useUiStore.getState().autoUpdateEnabled;
  if (!autoUpdateEnabled) return;

  // ... existing 5-second delay and check logic
}, []);
```

Add the import if not present:
```typescript
import { useUiStore } from "../stores/ui-store";
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/hooks/use-update-checker.ts
git commit -m "feat: respect autoUpdateEnabled setting in update checker"
```

---

### Task 7: Final verification

- [ ] **Step 1: Run all checks**

Run: `npx tsc --noEmit`
Expected: PASS

Run: `cd src-tauri && cargo check && cargo clippy -- -D warnings`
Expected: PASS

Run: `npm run frontend:build`
Expected: PASS

- [ ] **Step 2: Manual testing**

Run: `npm run frontend:dev`
1. Open Settings via menu or Ctrl+, → tabbed dialog appears
2. Appearance tab: change theme → applies immediately
3. Appearance tab: change font size → applies immediately
4. Columns tab: uncheck a column → column disappears from log view
5. Updates tab: uncheck auto-update → restart → no update check on startup
6. Updates tab: click version info → displays correctly
7. Close and reopen app → all settings persist
8. File Associations tab (Windows): button shows, click associates files
9. File Associations tab (non-Windows): shows platform message
