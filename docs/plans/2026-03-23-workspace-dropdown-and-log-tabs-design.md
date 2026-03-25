# Design: Workspace Dropdown & Log File Tabs

**Date:** 2026-03-23
**Status:** Approved
**Mockup:** `docs/mockups/approach-a-full.html`

## Summary

Replace the five workspace buttons in the toolbar with a single dropdown selector, and introduce a dedicated tab strip below the toolbar for switching between multiple open log files. This redesign declutters the toolbar, enables multi-file workflows, and reorganizes several toolbar items for a cleaner layout.

## Problem Statement

The current UI has two issues:

1. **Five workspace buttons consume significant toolbar space.** The buttons (Log Explorer, Intune Diagnostics, New Intune Workspace, dsregcmd, macOS Diagnostics) take roughly 350px of horizontal toolbar real estate. On narrower windows, they cause the toolbar to wrap onto multiple lines. Only one workspace is active at a time, making buttons an inefficient use of space.

2. **Only one log file can be viewed at a time.** Opening a new log file replaces the current one. IT admins working support cases routinely need to cross-reference 5-10 log files from the same machine. The current UI forces them to re-open files every time they want to switch context.

## Design Decision: Approach A (Dedicated Tab Strip)

Three approaches were evaluated:

- **Approach A (chosen):** Workspace dropdown in toolbar + dedicated tab strip below toolbar
- **Approach B (rejected):** Tabs embedded inside the toolbar row (too cramped, doesn't scale past 3-4 files)
- **Approach C (rejected):** Unified combo bar combining workspace selector and tabs (mixes two different concepts, confusing)

Approach A was selected because it provides the most space for file tabs, uses a familiar VS Code/browser pattern, and cleanly separates workspace selection from file navigation.

## Detailed Changes

### 1. Menu Bar (unchanged structure, content additions)

The native menu bar remains at the top: **File | Edit | Tools | Window | Help**

**Tools menu additions:**
- "Bundle Summary..." moves from the toolbar into the Tools menu. This action is contextual (only enabled when an evidence bundle is active) and does not warrant permanent toolbar space.

No other menu changes.

### 2. Toolbar Redesign

The toolbar is a single horizontal row below the menu bar. All items flow left to right with a spacer pushing Theme to the far right.

**Layout (left to right):**

| Position | Control | Type | Notes |
|----------|---------|------|-------|
| 1 | Open... | Dropdown select | Options: Open File..., Open Folder... |
| 2 | Open Known Log Source... | Dropdown select | Grouped by source type (SCCM/ConfigMgr, Intune) |
| 3 | (divider) | Vertical divider | |
| 4 | Highlight... | Text input | Placeholder text "Highlight...", no label |
| 5 | (divider) | Vertical divider | |
| 6 | Error Lookup | Button | Opens error code lookup dialog |
| 7 | (divider) | Vertical divider | |
| 8 | Details | Toggle button | Toggles details pane, highlighted when active |
| 9 | Info | Toggle button | Toggles info pane, highlighted when active |
| 10 | (divider) | Vertical divider | |
| 11 | Workspace: | Label | Static text label, muted color |
| 12 | [Log Explorer v] | Dropdown select | Options: Log Explorer, Intune Diagnostics, New Intune Workspace, dsregcmd, macOS Diagnostics |
| (spacer) | | Flex spacer | Pushes Theme to far right |
| 13 | Theme | Button | Far right, isolated from other controls |

**Changes from current toolbar:**
- **Removed:** 5 workspace buttons (replaced by single "Workspace:" dropdown at position 11-12)
- **Removed:** "Highlight:" label (placeholder text is sufficient)
- **Removed:** Bundle Summary button (moved to Tools menu)
- **Removed:** Pause button (moved to sidebar footer)
- **Removed:** Refresh button (moved to sidebar footer)
- **Removed:** Streaming/Paused status badge (moved to sidebar footer)
- **Moved:** Theme button to far right, separated by flex spacer
- **Added:** "Workspace:" label before the workspace dropdown

### 3. Workspace Dropdown

**Location:** Toolbar, after the Details/Info toggle buttons

**Behavior:**
- Displays the currently active workspace name
- Prefixed with a "Workspace:" label in muted text so the user understands what the dropdown controls
- Styled with an accent-colored border to visually distinguish it from other toolbar dropdowns
- Darker background (`#1a2a3a`) and bold text to indicate it's a primary navigation control

**Options:**
1. Log Explorer (default on app start)
2. Intune Diagnostics
3. New Intune Workspace
4. dsregcmd
5. macOS Diagnostics

**When changed:**
- The `setActiveWorkspace()` and `setActiveView()` Zustand actions are called (same as current button click behavior)
- The tab strip visibility toggles: visible only when workspace is "log"
- The sidebar content switches to the appropriate workspace sidebar
- The main content area switches to the appropriate workspace component

### 4. Tab Strip (New Component)

**Location:** Immediately below the toolbar, above the main content area. Only visible when the active workspace is "log".

**Visual design:**
- Background: `colorNeutralBackground3` (darker than toolbar, `#252526` in dark theme)
- Height: 34px
- Bottom border: 1px solid `colorNeutralStroke2`

**Tab appearance:**
- Each tab shows the filename (no path, no icon)
- Tabs have a close button (x) on the right side
- Close button is hidden by default, visible on hover or when tab is active
- Active tab has a lighter background matching the content area and a 2px blue accent bottom border
- Inactive tabs have the tab strip background color
- Tabs have a max-width of 200px and min-width of 80px
- Long filenames are truncated with ellipsis
- Tabs are separated by 1px borders

**Tab interactions:**
- Click a tab to switch to that log file
- Click the close button to close the tab (with fade-out animation)
- Closing the active tab switches to the nearest remaining tab
- Opening a file (via Open..., Open Known Log Source..., sidebar, drag-drop, or file association) creates a new tab or switches to an existing tab if the file is already open
- Opening a folder creates one tab per log file in the folder

**Overflow behavior:**
- When tabs exceed available horizontal space, visible tabs fill the bar
- A "N more..." button appears at the right end of the tab strip
- Clicking it opens a dropdown menu listing all overflow tabs with their filenames and source paths
- Clicking an item in the overflow menu switches to that tab

### 5. Sidebar Footer (New Section)

**Location:** Bottom of the file sidebar, pinned with `margin-top: auto`

**Contents (left to right):**
- Pause/Resume button (smaller size: 10px font, 3px 8px padding)
- Refresh button (same smaller size)
- Streaming/Paused status badge (9px font, 2px 6px padding)

**Styling:**
- Separated from sidebar content by a 1px top border
- 6px vertical padding, 8px horizontal padding
- Buttons and badge are compact to fit within the sidebar width (~200px)

**Behavior:**
- Pause button toggles to "Resume" when paused
- Status badge changes from green "Streaming" to yellow "Paused"
- These controls affect the active log tab's tailing state

### 6. Sidebar Synchronization

The sidebar's file list stays in sync with the tab strip:
- Clicking a sidebar item switches the corresponding tab
- Clicking a tab highlights the corresponding sidebar item
- The sidebar continues to show all files from the current source (folder contents), while tabs show only explicitly opened files
- The sidebar groups files under "Open Files" and "Overflow" sections with line count badges

### 7. Status Bar Updates

The status bar at the bottom gains tab awareness:
- Left side: `Log Explorer | <filename> | Tab N of M`
- Right side: `<line count> lines | UTF-8 | <format>` (unchanged)

The "Tab N of M" segment updates when switching tabs or opening/closing tabs.

## State Management Changes

### New Zustand State (ui-store or new tab-store)

```
openTabs: TabState[]          // Array of open tab descriptors
activeTabIndex: number        // Index into openTabs
```

Each `TabState` contains:
```
id: string                    // Unique tab identifier
filePath: string              // Absolute path to the log file
fileName: string              // Display name (basename)
source: LogSource             // The LogSource object for this tab
scrollPosition: number        // Preserved scroll position when switching away
selectedLineId: number | null // Preserved selection when switching away
```

### Tab Lifecycle

1. **Open:** When a file is opened, check if a tab with that `filePath` already exists. If yes, switch to it. If no, create a new `TabState`, append to `openTabs`, and set `activeTabIndex` to the new tab.

2. **Switch:** When switching tabs, save the current tab's scroll position and selected line, then load the new tab's log entries and restore its scroll/selection state.

3. **Close:** Remove the tab from `openTabs`. If it was the active tab, switch to the nearest neighbor (prefer left, fall back to right). If it was the last tab, the tab strip remains empty and shows no content.

4. **Reorder (future):** Not in initial implementation, but the data model supports reordering by rearranging the `openTabs` array.

### Backend Considerations

The Rust backend already supports having multiple files loaded via `AppState` (which tracks open files in a `HashMap`). No backend changes are needed for basic multi-tab support. Each tab's file watcher and tail session are independent.

## What This Design Does NOT Change

- **Non-log workspaces:** Intune, dsregcmd, and macOS Diagnostics workspaces are unchanged internally. They don't get tabs. The only change is how you navigate to them (dropdown instead of button).
- **Native menu structure:** File, Edit, Window, Help menus keep their existing items and shortcuts. Only Tools gains "Bundle Summary...".
- **Parser system:** No changes to log parsing, format detection, or encoding.
- **File sidebar content:** The sidebar still shows source files from the active log source. It gains a footer section and sync with tabs.
- **Keyboard shortcuts:** All existing shortcuts (Ctrl+F, Ctrl+L, Ctrl+H, etc.) remain unchanged. Future work may add Ctrl+Tab / Ctrl+Shift+Tab for tab cycling, but that is out of scope for this design.
- **Drag-and-drop:** Drag-drop still works; dropped files open as new tabs instead of replacing the current view.

## Migration Path

This is a breaking UI change but not a data change. No migration is needed. The `activeWorkspace` state persists the same way (defaults to "log" on app start). Tab state is ephemeral and not persisted across sessions.

## Files Affected

### Frontend (modify)
- `src/components/layout/Toolbar.tsx` -- Toolbar redesign, workspace dropdown, remove workspace buttons
- `src/components/layout/AppShell.tsx` -- Insert TabStrip component, conditional rendering
- `src/components/layout/FileSidebar.tsx` -- Add footer section (Pause/Refresh/Streaming), sync with tabs
- `src/components/layout/StatusBar.tsx` -- Add tab count display
- `src/stores/ui-store.ts` -- Add tab state management (openTabs, activeTabIndex, actions)

### Frontend (create)
- `src/components/layout/TabStrip.tsx` -- New component: tab bar with overflow dropdown
- `src/components/layout/TabStrip.css` or inline styles -- Tab styling

### Frontend (no changes)
- `src/components/intune/` -- Unchanged
- `src/components/dsregcmd/` -- Unchanged
- `src/components/macos-diag/` -- Unchanged
- `src/stores/log-store.ts` -- May need minor changes to support per-tab log state
- `src/stores/filter-store.ts` -- Filters apply to the active tab

### Backend (no changes expected)
- `src-tauri/src/` -- No changes needed. AppState already supports multiple concurrent file handles.

### Menu (modify)
- `src-tauri/src/menu.rs` -- Add "Bundle Summary..." to Tools submenu

## Mockup Reference

Interactive mockup: `docs/mockups/approach-a-full.html`

To view: run a local HTTP server from `docs/mockups/` and open `approach-a-full.html` in a browser. The mockup supports clicking tabs, switching workspace via dropdown, closing tabs, opening the overflow dropdown, toggling pause/resume, and opening menus.
