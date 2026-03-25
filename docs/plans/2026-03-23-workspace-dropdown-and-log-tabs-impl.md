# Workspace Dropdown & Log File Tabs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the 5 workspace buttons with a single dropdown, add a tab strip for switching between multiple open log files, move Pause/Refresh/Streaming to the sidebar footer, move Bundle Summary to the Tools menu, and reorganize the toolbar layout.

**Architecture:** The workspace dropdown replaces buttons in `Toolbar.tsx`. A new `TabStrip.tsx` component is inserted between toolbar and content in `AppShell.tsx`. Tab state is managed in `ui-store.ts` with an `openTabs` array and `activeTabIndex`. The sidebar gains a footer section with Pause/Refresh/Streaming controls. The Rust menu gains a Bundle Summary item in the Tools submenu.

**Tech Stack:** React 19, TypeScript, Zustand, Fluent UI, Tauri v2 (Rust backend for menu changes)

**Design doc:** `docs/plans/2026-03-23-workspace-dropdown-and-log-tabs-design.md`
**Mockup:** `docs/mockups/approach-a-full.html`

---

### Task 1: Add Tab State to ui-store

**Files:**
- Modify: `src/stores/ui-store.ts`

**Step 1: Add TabState type and tab-related state fields**

Add after line 14 (after the `AppView` type):

```typescript
export interface TabState {
  id: string;
  filePath: string;
  fileName: string;
  scrollPosition: number;
  selectedLineId: number | null;
}
```

Add to the UiState interface (after line 85, after `themeId`):

```typescript
  openTabs: TabState[];
  activeTabIndex: number;
```

Add tab actions to the UiState interface (after the existing action methods, before the closing `}`):

```typescript
  openTab: (filePath: string, fileName: string) => void;
  closeTab: (index: number) => void;
  switchTab: (index: number) => void;
  saveTabScrollState: (index: number, scrollPosition: number, selectedLineId: number | null) => void;
```

**Step 2: Implement tab actions in the store creator**

Add default values in the store initial state (after `themeId: DEFAULT_THEME_ID`):

```typescript
openTabs: [],
activeTabIndex: -1,
```

Add action implementations after the existing actions (before the persist config):

```typescript
openTab: (filePath, fileName) => {
  const { openTabs } = get();
  const existingIndex = openTabs.findIndex((t) => t.filePath === filePath);
  if (existingIndex >= 0) {
    set({ activeTabIndex: existingIndex });
    return;
  }
  const newTab: TabState = {
    id: `tab-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    filePath,
    fileName,
    scrollPosition: 0,
    selectedLineId: null,
  };
  set({
    openTabs: [...openTabs, newTab],
    activeTabIndex: openTabs.length,
  });
},

closeTab: (index) => {
  const { openTabs, activeTabIndex } = get();
  if (index < 0 || index >= openTabs.length) return;
  const newTabs = openTabs.filter((_, i) => i !== index);
  let newActive = activeTabIndex;
  if (newTabs.length === 0) {
    newActive = -1;
  } else if (index === activeTabIndex) {
    newActive = Math.min(index, newTabs.length - 1);
  } else if (index < activeTabIndex) {
    newActive = activeTabIndex - 1;
  }
  set({ openTabs: newTabs, activeTabIndex: newActive });
},

switchTab: (index) => {
  const { openTabs } = get();
  if (index < 0 || index >= openTabs.length) return;
  set({ activeTabIndex: index });
},

saveTabScrollState: (index, scrollPosition, selectedLineId) => {
  const { openTabs } = get();
  if (index < 0 || index >= openTabs.length) return;
  const updated = [...openTabs];
  updated[index] = { ...updated[index], scrollPosition, selectedLineId };
  set({ openTabs: updated });
},
```

**Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS (no type errors)

**Step 4: Commit**

```bash
git add src/stores/ui-store.ts
git commit -m "feat: add tab state management to ui-store"
```

---

### Task 2: Create TabStrip Component

**Files:**
- Create: `src/components/layout/TabStrip.tsx`

**Step 1: Create the TabStrip component**

```typescript
import { useCallback, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { useUiStore, type TabState } from "../../stores/ui-store";

export function TabStrip() {
  const openTabs = useUiStore((s) => s.openTabs);
  const activeTabIndex = useUiStore((s) => s.activeTabIndex);
  const switchTab = useUiStore((s) => s.switchTab);
  const closeTab = useUiStore((s) => s.closeTab);
  const [showOverflow, setShowOverflow] = useState(false);
  const overflowRef = useRef<HTMLDivElement>(null);

  const MAX_VISIBLE_TABS = 6;
  const visibleTabs = openTabs.slice(0, MAX_VISIBLE_TABS);
  const overflowTabs = openTabs.slice(MAX_VISIBLE_TABS);

  const handleTabClick = useCallback(
    (index: number) => {
      switchTab(index);
    },
    [switchTab],
  );

  const handleCloseClick = useCallback(
    (e: React.MouseEvent, index: number) => {
      e.stopPropagation();
      closeTab(index);
    },
    [closeTab],
  );

  const handleOverflowClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      setShowOverflow((prev) => !prev);
    },
    [],
  );

  const handleOverflowItemClick = useCallback(
    (index: number) => {
      switchTab(index);
      setShowOverflow(false);
    },
    [switchTab],
  );

  if (openTabs.length === 0) {
    return null;
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "stretch",
        background: tokens.colorNeutralBackground3,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        height: "34px",
        flexShrink: 0,
        overflow: "hidden",
      }}
    >
      {visibleTabs.map((tab, i) => (
        <div
          key={tab.id}
          onClick={() => handleTabClick(i)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "0 6px 0 12px",
            fontSize: "11px",
            color:
              i === activeTabIndex
                ? tokens.colorNeutralForeground1
                : tokens.colorNeutralForeground3,
            cursor: "pointer",
            borderRight: `1px solid ${tokens.colorNeutralStroke3}`,
            whiteSpace: "nowrap",
            maxWidth: "200px",
            minWidth: "80px",
            position: "relative",
            background:
              i === activeTabIndex
                ? tokens.colorNeutralBackground1
                : "transparent",
            borderBottom:
              i === activeTabIndex
                ? `2px solid ${tokens.colorBrandBackground}`
                : "2px solid transparent",
          }}
        >
          <span
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              flex: 1,
            }}
          >
            {tab.fileName}
          </span>
          <span
            onClick={(e) => handleCloseClick(e, i)}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: "18px",
              height: "18px",
              borderRadius: "3px",
              fontSize: "15px",
              lineHeight: 1,
              color: tokens.colorNeutralForeground3,
              flexShrink: 0,
              cursor: "pointer",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background =
                "rgba(255,255,255,0.1)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "transparent";
            }}
          >
            &times;
          </span>
        </div>
      ))}

      {overflowTabs.length > 0 && (
        <div
          ref={overflowRef}
          onClick={handleOverflowClick}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "4px",
            padding: "0 10px",
            fontSize: "11px",
            color: tokens.colorNeutralForeground3,
            cursor: "pointer",
            borderLeft: `1px solid ${tokens.colorNeutralStroke3}`,
            marginLeft: "auto",
            whiteSpace: "nowrap",
            flexShrink: 0,
            position: "relative",
          }}
        >
          {overflowTabs.length} more...
          {showOverflow && (
            <div
              style={{
                position: "absolute",
                top: "100%",
                right: 0,
                background: tokens.colorNeutralBackground3,
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                borderRadius: "6px",
                boxShadow: "0 8px 30px rgba(0,0,0,0.5)",
                minWidth: "240px",
                zIndex: 100,
                padding: "4px",
                marginTop: "2px",
              }}
            >
              {overflowTabs.map((tab, i) => {
                const realIndex = MAX_VISIBLE_TABS + i;
                return (
                  <div
                    key={tab.id}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOverflowItemClick(realIndex);
                    }}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      padding: "6px 10px",
                      fontSize: "11px",
                      color: tokens.colorNeutralForeground1,
                      borderRadius: "4px",
                      cursor: "pointer",
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background =
                        tokens.colorNeutralBackground1Hover;
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background =
                        "transparent";
                    }}
                  >
                    {tab.fileName}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
```

**Step 2: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

**Step 3: Commit**

```bash
git add src/components/layout/TabStrip.tsx
git commit -m "feat: create TabStrip component with overflow dropdown"
```

---

### Task 3: Toolbar Redesign -- Workspace Dropdown & Layout Changes

**Files:**
- Modify: `src/components/layout/Toolbar.tsx`

**Step 1: Replace workspace buttons with dropdown**

In the Toolbar JSX return (around lines 1010-1031), replace the workspace button mapping:

```tsx
{([
  ["log", "Log Explorer"],
  ["intune", "Intune Diagnostics"],
  ["new-intune", "New Intune Workspace"],
  ["dsregcmd", "Troubleshoot with dsregcmd"],
  ["macos-diag", "macOS Diagnostics"],
] as const).map(([workspaceId, label]) => (
  <Button
    key={workspaceId}
    onClick={() => setActiveView(workspaceId)}
    title={`Switch to ${label}`}
    aria-pressed={activeView === workspaceId}
    size="small"
    appearance={activeView === workspaceId ? "primary" : "secondary"}
  >
    {label}
  </Button>
))}
```

With a labeled select dropdown:

```tsx
<label
  style={{
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    whiteSpace: "nowrap",
  }}
>
  Workspace:
</label>
<select
  value={activeView}
  onChange={(e) => setActiveView(e.target.value as WorkspaceId)}
  title="Switch workspace"
  style={{
    ...getToolbarControlStyle({ disabled: false, active: true }),
    padding: "5px 28px 5px 10px",
    fontSize: "11px",
    fontWeight: 600,
    minWidth: "160px",
    appearance: "none",
    WebkitAppearance: "none",
    backgroundImage:
      "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='5' viewBox='0 0 8 5'%3E%3Cpath d='M0 0l4 5 4-5z' fill='%23888'/%3E%3C/svg%3E\")",
    backgroundRepeat: "no-repeat",
    backgroundPosition: "right 9px center",
    borderColor: tokens.colorBrandStroke1,
  }}
>
  <option value="log">Log Explorer</option>
  <option value="intune">Intune Diagnostics</option>
  <option value="new-intune">New Intune Workspace</option>
  <option value="dsregcmd">dsregcmd</option>
  <option value="macos-diag">macOS Diagnostics</option>
</select>
```

**Step 2: Remove Pause, Refresh, and Streaming badge from toolbar**

Remove the Pause/Resume button, Refresh button, and Streaming status badge from the toolbar left section (around lines 870-920). These will be moved to the sidebar footer in Task 5.

**Step 3: Remove Bundle Summary button from toolbar**

Remove the Bundle Summary button (around line 967-975). It will be accessible via the Tools menu only.

**Step 4: Remove the "Highlight:" label**

Remove the `<label>` element for "Highlight:" (keep the input, just change placeholder to "Highlight...").

**Step 5: Reorganize toolbar layout**

Restructure the toolbar return JSX to flow left to right as a single section with a spacer pushing Theme to the far right:

Left group: Open... | Open Known Log Source... | (divider) | Highlight input | (divider) | Error Lookup | (divider) | Details | Info | (divider) | Workspace: [dropdown]

(spacer)

Right group: Theme

**Step 6: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

**Step 7: Commit**

```bash
git add src/components/layout/Toolbar.tsx
git commit -m "feat: replace workspace buttons with dropdown, reorganize toolbar layout"
```

---

### Task 4: Wire TabStrip into AppShell

**Files:**
- Modify: `src/components/layout/AppShell.tsx`

**Step 1: Import TabStrip**

Add import at top of file (after line 6):

```typescript
import { TabStrip } from "./TabStrip";
```

**Step 2: Insert TabStrip between Toolbar and content area**

In the JSX return (around line 259-261), add the TabStrip after Toolbar and before the main content div. It should only render when `activeView === "log"`:

```tsx
<Toolbar />
{activeView === "log" && <TabStrip />}
<div style={{ display: "flex", flex: 1, ... }}>
```

**Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

**Step 4: Commit**

```bash
git add src/components/layout/AppShell.tsx
git commit -m "feat: wire TabStrip into AppShell below toolbar"
```

---

### Task 5: Add Sidebar Footer with Pause/Refresh/Streaming

**Files:**
- Modify: `src/components/layout/FileSidebar.tsx`

**Step 1: Add SidebarFooter sub-component**

Add a new `SidebarFooter` function component inside `FileSidebar.tsx` (before the main `FileSidebar` export). This component renders the Pause/Resume button, Refresh button, and Streaming/Paused badge.

```typescript
function SidebarFooter({
  isPaused,
  isLoading,
  hasActiveSource,
  onTogglePause,
  onRefresh,
}: {
  isPaused: boolean;
  isLoading: boolean;
  hasActiveSource: boolean;
  onTogglePause: () => void;
  onRefresh: () => void;
}) {
  return (
    <div
      style={{
        marginTop: "auto",
        padding: "6px 8px",
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        display: "flex",
        alignItems: "center",
        gap: "5px",
        flexShrink: 0,
      }}
    >
      <Button
        size="small"
        appearance="secondary"
        onClick={onTogglePause}
        disabled={!hasActiveSource}
        style={{ fontSize: "10px", padding: "3px 8px" }}
      >
        {isPaused ? "Resume" : "Pause"}
      </Button>
      <Button
        size="small"
        appearance="secondary"
        onClick={onRefresh}
        disabled={!hasActiveSource}
        style={{ fontSize: "10px", padding: "3px 8px" }}
      >
        Refresh
      </Button>
      <Badge
        size="small"
        appearance="filled"
        color={isPaused ? "warning" : isLoading ? "brand" : "success"}
        style={{ fontSize: "9px", padding: "2px 6px" }}
      >
        {isPaused ? "Paused" : isLoading ? "Loading" : "Streaming"}
      </Badge>
    </div>
  );
}
```

Note: You may need to import `Badge` from `@fluentui/react-components` if not already imported. Check what's available and use the appropriate Fluent UI component, or fall back to a styled `<span>`.

**Step 2: Render SidebarFooter in the sidebar layout**

In the `FileSidebar` component's return JSX, add `<SidebarFooter />` as the last child inside the `<aside>` element, after the conditional workspace content. Pass the required props from the log store and app actions.

**Step 3: Wire up onTogglePause and onRefresh**

These should call the same handlers that the toolbar Pause and Refresh buttons used. Import `useLogStore` to get `isPaused` and `isLoading`, and reference the toggle/refresh actions from `useAppActions` or directly from the store.

**Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

**Step 5: Commit**

```bash
git add src/components/layout/FileSidebar.tsx
git commit -m "feat: add Pause/Refresh/Streaming footer to sidebar"
```

---

### Task 6: Add Tab Count to StatusBar

**Files:**
- Modify: `src/components/layout/StatusBar.tsx`

**Step 1: Import tab state from ui-store**

Add to the existing useUiStore selector:

```typescript
const openTabs = useUiStore((s) => s.openTabs);
const activeTabIndex = useUiStore((s) => s.activeTabIndex);
```

**Step 2: Add tab indicator to the status bar left section**

When `activeView === "log"` and `openTabs.length > 0`, add a segment after the filename display:

```tsx
{openTabs.length > 0 && (
  <>
    <span style={{ margin: "0 6px", opacity: 0.4 }}>|</span>
    <span>Tab {activeTabIndex + 1} of {openTabs.length}</span>
  </>
)}
```

**Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

**Step 4: Commit**

```bash
git add src/components/layout/StatusBar.tsx
git commit -m "feat: show tab count in status bar"
```

---

### Task 7: Connect Tab Opening to File Load Actions

**Files:**
- Modify: `src/components/layout/Toolbar.tsx` (or `src/lib/log-source.ts`)
- Modify: `src/components/layout/FileSidebar.tsx`

**Step 1: Open a tab when a log file is loaded**

When `loadLogSource` or `loadPathAsLogSource` is called, also call `useUiStore.getState().openTab(filePath, fileName)`. The best place to hook this in is wherever `setOpenFilePath` is called after a successful file load.

Find all call sites where a log file is opened:
- `Toolbar.tsx` `openSourceFileDialog` handler
- `Toolbar.tsx` `openSourceFolderDialog` handler
- `FileSidebar.tsx` `handleSelectFile` handler
- `src/hooks/use-drag-drop.ts` drag-drop handler
- `src/hooks/use-file-association.ts` file association handler

For each call site, after the file is successfully loaded, add:

```typescript
const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
useUiStore.getState().openTab(filePath, fileName);
```

**Step 2: Switch log content when tab is switched**

When the user switches tabs (via `switchTab` action), the corresponding file needs to be loaded. Add an effect in `AppShell.tsx` that watches `activeTabIndex` and `openTabs`:

```typescript
const activeTabIndex = useUiStore((s) => s.activeTabIndex);
const openTabs = useUiStore((s) => s.openTabs);

useEffect(() => {
  if (activeTabIndex < 0 || activeTabIndex >= openTabs.length) return;
  const tab = openTabs[activeTabIndex];
  const currentPath = useLogStore.getState().openFilePath;
  if (currentPath === tab.filePath) return;
  loadPathAsLogSource(tab.filePath, "tab-switch").catch((err) => {
    console.error("[tab-switch] failed to load", tab.filePath, err);
  });
}, [activeTabIndex, openTabs]);
```

**Step 3: Sync sidebar selection with active tab**

In `FileSidebar.tsx`, the `selectedSourceFilePath` should reflect the active tab's file. This may already work if `loadPathAsLogSource` sets `selectedSourceFilePath`. Verify and add sync if needed.

**Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

**Step 5: Test manually**

- Open a file via Open... dialog -- should create a tab
- Open a second file -- should create a second tab, both visible in tab strip
- Click between tabs -- log content should switch
- Close a tab -- should switch to neighbor
- Sidebar click -- should switch to corresponding tab

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: connect tab creation to file load, tab switching loads file content"
```

---

### Task 8: Add Bundle Summary to Rust Tools Menu

**Files:**
- Modify: `src-tauri/src/menu.rs`

**Step 1: Add menu constant**

Add after line 15 (`MENU_ID_TOOLS_ERROR_LOOKUP`):

```rust
pub const MENU_ID_TOOLS_BUNDLE_SUMMARY: &str = "tools.bundle_summary";
```

**Step 2: Create menu item and add to Tools submenu**

In `build_app_menu` (around line 64-70), add a new MenuItem:

```rust
let bundle_summary = MenuItem::with_id(
    app,
    MENU_ID_TOOLS_BUNDLE_SUMMARY,
    "Bundle Summary...",
    true,
    None::<&str>,
)?;
```

Update the tools_menu construction (line 102) to include it:

```rust
let tools_menu = Submenu::with_items(app, "Tools", true, &[&error_lookup, &bundle_summary])?;
```

**Step 3: Add event payload for the new menu item**

In `payload_for_menu_id` (around line 208), add a new match arm after the `MENU_ID_TOOLS_ERROR_LOOKUP` case:

```rust
MENU_ID_TOOLS_BUNDLE_SUMMARY => AppMenuActionPayload {
    version: 1,
    menu_id: MENU_ID_TOOLS_BUNDLE_SUMMARY,
    action: "show_evidence_bundle",
    category: "tools",
    trigger: "menu",
    preset_id: None,
    platform: None,
},
```

**Step 4: Handle the menu event on the frontend**

In the frontend menu event handler (check `src/hooks/use-keyboard.ts` or wherever `app-menu-action` events are handled), add handling for `"show_evidence_bundle"` to call `useUiStore.getState().setShowEvidenceBundleDialog(true)`.

**Step 5: Build and test**

Run from `src-tauri/`:
```bash
cargo check
cargo clippy -- -D warnings
```
Expected: PASS

Run from project root:
```bash
npx tsc --noEmit
```
Expected: PASS

**Step 6: Commit**

```bash
git add src-tauri/src/menu.rs
git add -A  # any frontend menu handler changes
git commit -m "feat: add Bundle Summary to Tools menu"
```

---

### Task 9: Full Integration Test

**Files:**
- No new files

**Step 1: Run all Rust tests**

From `src-tauri/`:
```bash
cargo test
```
Expected: All tests pass

**Step 2: Run Rust linter**

From `src-tauri/`:
```bash
cargo clippy -- -D warnings
```
Expected: No warnings

**Step 3: Run TypeScript type check**

From project root:
```bash
npx tsc --noEmit
```
Expected: No errors

**Step 4: Run frontend build**

From project root:
```bash
npm run frontend:build
```
Expected: Build succeeds

**Step 5: Manual smoke test**

Start the dev server:
```bash
npm run frontend:dev
```

Verify in browser:
1. Toolbar shows left-to-right: Open... | Open Known Log Source... | Highlight... | Error Lookup | Details | Info | Workspace: [Log Explorer v] ... (spacer) ... Theme
2. No workspace buttons visible
3. Workspace dropdown switches between workspaces
4. Tab strip appears only in Log Explorer workspace
5. Opening files creates tabs
6. Clicking tabs switches log content
7. Close button on tabs works
8. Overflow dropdown appears when many tabs are open
9. Sidebar footer shows Pause | Refresh | Streaming
10. Pause/Resume toggles correctly
11. Bundle Summary is in Tools menu, not toolbar
12. Status bar shows "Tab N of M" when tabs are open

**Step 6: Commit any fixes**

```bash
git add -A
git commit -m "fix: integration test fixes for tab UI"
```

---

## Task Summary

| Task | Description | Est. Complexity |
|------|-------------|-----------------|
| 1 | Add tab state to ui-store | Small |
| 2 | Create TabStrip component | Medium |
| 3 | Toolbar redesign (workspace dropdown, layout) | Medium |
| 4 | Wire TabStrip into AppShell | Small |
| 5 | Sidebar footer (Pause/Refresh/Streaming) | Medium |
| 6 | Tab count in StatusBar | Small |
| 7 | Connect tab opening to file loads + tab switching | Large |
| 8 | Bundle Summary in Rust Tools menu | Small |
| 9 | Full integration test | Medium |

## Dependencies

- Tasks 1 must complete before Tasks 2, 4, 6, 7
- Task 2 must complete before Task 4
- Tasks 3 and 5 are independent of each other
- Task 7 depends on Tasks 1, 2, 3, 4
- Task 8 is fully independent
- Task 9 depends on all other tasks
