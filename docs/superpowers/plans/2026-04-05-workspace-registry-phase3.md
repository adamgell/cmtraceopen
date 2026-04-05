# Workspace Registry Phase 3: Wire Consumers to Registry

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace workspace-specific if/else chains in consumer files with registry lookups so that adding a new workspace only requires adding a definition — not touching AppShell, Toolbar, FileSidebar, or ui-store.

**Architecture:** Create shim `WorkspaceDefinition` entries for all non-migrated workspaces that point to their current component locations. Then refactor consumers to use the registry. The shims are temporary — Phase 4 will replace them with real self-contained workspace folders.

**Tech Stack:** React 19, TypeScript, Zustand, Tauri v2, Fluent UI, React.lazy/Suspense

---

## File Structure

**New files to create:**
- `src/workspaces/log/index.ts` — Shim definition
- `src/workspaces/intune/index.ts` — Shim definition
- `src/workspaces/new-intune/index.ts` — Shim definition
- `src/workspaces/dsregcmd/index.ts` — Shim definition
- `src/workspaces/macos-diag/index.ts` — Shim definition
- `src/workspaces/deployment/index.ts` — Shim definition
- `src/workspaces/event-log/index.ts` — Shim definition

**Files to modify:**
- `src/workspaces/registry.ts` — Register all workspaces
- `src/components/layout/AppShell.tsx` — Replace renderWorkspace() with registry lookup
- `src/components/layout/FileSidebar.tsx` — Replace sidebar routing with registry lookup
- `src/stores/ui-store.ts` — Remove WORKSPACE_PLATFORM_MAP, use registry
- `src/components/layout/Toolbar.tsx` — Replace WORKSPACE_LABELS, file filters, action labels with registry lookups

---

### Task 1: Create shim workspace definitions

Create a shim `WorkspaceDefinition` for each non-migrated workspace. Each shim:
- Lives in `src/workspaces/{id}/index.ts`
- Uses `React.lazy()` to import the existing component from its current location
- Captures the metadata (label, platforms, file filters, action labels) currently hardcoded in Toolbar.tsx and ui-store.ts
- Does NOT include `onOpenSource` yet (Phase 3b concern)

**Files to create:**

- [ ] **Step 1: Create `src/workspaces/log/index.ts`**

Read `src/components/layout/Toolbar.tsx` to get exact filter constants (LOG_FILE_DIALOG_FILTERS at lines 76-81). Then create:

```typescript
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const logWorkspace: WorkspaceDefinition = {
  id: "log",
  label: "Log Explorer",
  platforms: "all",
  component: lazy(() =>
    import("../../components/log-view/LogListView").then((m) => ({
      default: m.LogListView,
    }))
  ),
  capabilities: {
    tabStrip: true,
    findBar: true,
    detailsPane: true,
    infoPane: true,
    footerBar: true,
    multiFileDrop: true,
    fontSizing: true,
  },
  fileFilters: [
    { name: "Log Files", extensions: ["log", "txt", "csv", "json", "xml", "evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
};
```

Note: The log workspace is the most complex — it has DiffView, TabStrip, etc. The `component` field only needs to point to the main view. The special rendering logic (DiffView switching, TabStrip) will remain in AppShell for now, gated by `workspace.capabilities?.tabStrip`. Read AppShell to understand the log workspace's renderWorkspace() logic and adapt the shim accordingly.

- [ ] **Step 2: Create `src/workspaces/intune/index.ts`**

```typescript
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const intuneWorkspace: WorkspaceDefinition = {
  id: "intune",
  label: "Intune Diagnostics",
  platforms: "all",
  component: lazy(() =>
    import("../../components/intune/IntuneDashboard").then((m) => ({
      default: m.IntuneDashboard,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.IntuneSidebar,
    }))
  ),
  fileFilters: [
    { name: "IME Log Files", extensions: ["log", "txt", "cab", "zip"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open IME Log File",
    folder: "Open IME Or Evidence Folder",
    placeholder: "Open Intune Source...",
  },
};
```

Note: Check that `IntuneDashboard` and `IntuneSidebar` are exported from their current files. If IntuneSidebar is not exported from FileSidebar.tsx, add the export.

- [ ] **Step 3: Create `src/workspaces/new-intune/index.ts`**

```typescript
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const newIntuneWorkspace: WorkspaceDefinition = {
  id: "new-intune",
  label: "New Intune Workspace",
  platforms: "all",
  component: lazy(() =>
    import("../../components/intune/NewIntuneWorkspace").then((m) => ({
      default: m.NewIntuneWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.IntuneSidebar,
    }))
  ),
  fileFilters: [
    { name: "IME Log Files", extensions: ["log", "txt", "cab", "zip"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open IME Log File",
    folder: "Open IME Or Evidence Folder",
    placeholder: "Open Intune Source...",
  },
};
```

- [ ] **Step 4: Create `src/workspaces/dsregcmd/index.ts`**

```typescript
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const dsregcmdWorkspace: WorkspaceDefinition = {
  id: "dsregcmd",
  label: "dsregcmd",
  platforms: ["windows"],
  component: lazy(() =>
    import("../../components/dsregcmd/DsregcmdWorkspace").then((m) => ({
      default: m.DsregcmdWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.DsregcmdSidebar,
    }))
  ),
  fileFilters: [
    { name: "Text Files", extensions: ["txt"] },
    { name: "Log Files", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open Text File",
    folder: "Open Evidence Folder",
    placeholder: "Open dsregcmd Source...",
  },
};
```

- [ ] **Step 5: Create remaining shim definitions**

Create `src/workspaces/macos-diag/index.ts`, `src/workspaces/deployment/index.ts`, `src/workspaces/event-log/index.ts` following the same pattern.

For each, read the relevant component imports in AppShell.tsx and the platform map in ui-store.ts to get the correct values:
- macos-diag: `platforms: ["macos"]`, component = MacosDiagWorkspace
- deployment: `platforms: ["windows"]`, component = DeploymentWorkspace, `capabilities: { footerBar: true }`
- event-log: `platforms: "all"`, component = EventLogWorkspace

For sidebar: check which sidebar each workspace uses in FileSidebar.tsx routing. Log, deployment, and macos-diag all use LogSidebar. Event-log may use LogSidebar or have no sidebar — check the code.

- [ ] **Step 6: Register all workspaces in registry.ts**

Update `src/workspaces/registry.ts` to import and register all 8 workspace definitions (sysmon is already registered).

- [ ] **Step 7: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add src/workspaces/
git commit -m "feat(workspaces): add shim definitions for all workspaces"
```

---

### Task 2: Refactor AppShell to use registry

Replace the `renderWorkspace()` if/else chain with a registry lookup.

**Files:**
- Modify: `src/components/layout/AppShell.tsx`

- [ ] **Step 1: Read AppShell.tsx fully to understand the current rendering logic**

The log workspace has special rendering (DiffView, TabStrip, highlight results) that other workspaces don't. Understand this before simplifying.

- [ ] **Step 2: Replace renderWorkspace() with registry lookup**

The new pattern:

```typescript
import { Suspense } from "react";
import { getWorkspace } from "../../workspaces/registry";

// In renderWorkspace():
const workspace = getWorkspace(activeView);
const WorkspaceComponent = workspace.component;
return (
  <Suspense fallback={<div />}>
    <WorkspaceComponent />
  </Suspense>
);
```

IMPORTANT: The log workspace currently has special inline rendering with DiffView, highlightResults, tab-close cleanup, etc. that is NOT just rendering `<LogListView />`. You need to handle this. Options:
- Keep the log special case as a single `if (activeView === "log") { ... } else { registry lookup }` — this is acceptable since log is the primary workspace with unique complexity
- Or create a wrapper component that handles the log-specific rendering and point the log workspace definition's `component` to that wrapper

The second approach is cleaner. Create a `LogWorkspaceView` wrapper if one doesn't exist, or point the lazy import to the existing log rendering logic.

- [ ] **Step 3: Replace capability-gated UI**

```typescript
const workspace = getWorkspace(activeView);
// Replace: {activeView === "log" && <TabStrip />}
// With: {workspace.capabilities?.tabStrip && <TabStrip />}

// Replace: {showFindBar && activeView === "log" && ...}
// With: {showFindBar && workspace.capabilities?.findBar && ...}
```

- [ ] **Step 4: Remove old workspace component imports that are now lazy-loaded via registry**

Remove direct imports of IntuneDashboard, NewIntuneWorkspace, MacosDiagWorkspace, SysmonWorkspace, DeploymentWorkspace, EventLogWorkspace, DsregcmdWorkspace from AppShell.tsx. They're now loaded via `React.lazy()` in the workspace definitions.

- [ ] **Step 5: Verify types compile**

Run: `npx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git add src/components/layout/AppShell.tsx
git commit -m "refactor(appshell): use workspace registry for component routing"
```

---

### Task 3: Refactor FileSidebar to use registry

Replace the sidebar if/else chain with a registry lookup.

**Files:**
- Modify: `src/components/layout/FileSidebar.tsx`

- [ ] **Step 1: Read the current sidebar routing and understand exports**

The sidebar routing at ~line 1020-1026 dispatches to LogSidebar, IntuneSidebar, SysmonSidebar, DsregcmdSidebar. SysmonSidebar is already imported from the workspace. The others are inline in FileSidebar.tsx.

For the registry to work, IntuneSidebar and DsregcmdSidebar need to be exported from FileSidebar.tsx (or extracted). LogSidebar is used by log, deployment, and macos-diag workspaces.

- [ ] **Step 2: Export sidebar components that aren't yet exported**

Add `export` to `IntuneSidebar`, `DsregcmdSidebar`, and `LogSidebar` function definitions in FileSidebar.tsx. Also export `SidebarFooter` if it's used by workspace definitions.

- [ ] **Step 3: Update workspace shim definitions to point to correct sidebars**

Ensure each workspace definition's `sidebar` field points to the correct component. Log, deployment, and macos-diag should point to LogSidebar. Update the shim index.ts files if needed.

- [ ] **Step 4: Replace sidebar routing with registry lookup**

```typescript
import { getWorkspace } from "../../workspaces/registry";

// Replace the if/else chain with:
const workspace = getWorkspace(activeView);
const SidebarComponent = workspace.sidebar;
return SidebarComponent ? (
  <Suspense fallback={null}><SidebarComponent /></Suspense>
) : <LogSidebar />;
```

Also handle the footer conditional:
```typescript
{workspace.capabilities?.footerBar && <SidebarFooter />}
```

- [ ] **Step 5: Verify types compile**

Run: `npx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git add src/components/layout/FileSidebar.tsx src/workspaces/
git commit -m "refactor(sidebar): use workspace registry for sidebar routing"
```

---

### Task 4: Refactor ui-store to use registry

Remove `WORKSPACE_PLATFORM_MAP` and delegate to registry.

**Files:**
- Modify: `src/stores/ui-store.ts`

- [ ] **Step 1: Read ui-store.ts to understand current usage of WORKSPACE_PLATFORM_MAP and getAvailableWorkspaces**

- [ ] **Step 2: Replace getAvailableWorkspaces()**

Import `getAvailableWorkspaces` from the registry and re-export or replace the ui-store version:

```typescript
import { getAvailableWorkspaces as getAvailableWorkspaceDefs } from "../workspaces/registry";

export function getAvailableWorkspaces(
  platform: PlatformKind,
  enabledWorkspaces?: readonly WorkspaceId[] | null,
): WorkspaceId[] {
  return getAvailableWorkspaceDefs(platform, enabledWorkspaces).map((ws) => ws.id);
}
```

Note: The ui-store version returns `WorkspaceId[]` while the registry version returns `WorkspaceDefinition[]`. Keep the ui-store signature for backwards compatibility — it just delegates to the registry now.

- [ ] **Step 3: Remove WORKSPACE_PLATFORM_MAP**

Delete the `WORKSPACE_PLATFORM_MAP` constant (lines 42-51). All platform data now comes from the registry.

- [ ] **Step 4: Verify types compile**

Run: `npx tsc --noEmit`

- [ ] **Step 5: Commit**

```bash
git add src/stores/ui-store.ts
git commit -m "refactor(ui-store): delegate platform gating to workspace registry"
```

---

### Task 5: Refactor Toolbar metadata lookups

Replace WORKSPACE_LABELS, getOpenFileDialogFilters(), getOpenActionLabels() with registry lookups.

**Files:**
- Modify: `src/components/layout/Toolbar.tsx`

- [ ] **Step 1: Read Toolbar.tsx to understand all workspace metadata usage**

- [ ] **Step 2: Replace WORKSPACE_LABELS**

Remove the `WORKSPACE_LABELS` constant. Wherever it's used (workspace dropdown, etc.), replace with:
```typescript
const workspace = getWorkspace(activeView);
const label = workspace.label;
```

- [ ] **Step 3: Replace getOpenFileDialogFilters()**

Remove the function and the per-workspace filter constants (LOG_FILE_DIALOG_FILTERS, INTUNE_FILE_DIALOG_FILTERS, etc.). Replace with:
```typescript
const workspace = getWorkspace(activeView);
const filters = workspace.fileFilters ?? [
  { name: "Log Files", extensions: ["log", "txt", "csv", "json", "xml", "evtx"] },
  { name: "All Files", extensions: ["*"] },
];
```

Keep a default fallback for workspaces that don't define filters.

- [ ] **Step 4: Replace getOpenActionLabels()**

Remove the function. Replace with:
```typescript
const workspace = getWorkspace(activeView);
const actionLabels = workspace.actionLabels ?? {
  file: "Open File",
  folder: "Open Folder",
  placeholder: "Open...",
};
```

- [ ] **Step 5: Verify types compile**

Run: `npx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git add src/components/layout/Toolbar.tsx
git commit -m "refactor(toolbar): use workspace registry for labels and file filters"
```

---

### Task 6: Final verification

- [ ] **Step 1: Run `npx tsc --noEmit`** — must pass
- [ ] **Step 2: Run `npm run frontend:build`** — must pass
- [ ] **Step 3: Verify no workspace-specific if/else chains remain in the refactored sections**

Check that AppShell.renderWorkspace(), FileSidebar routing, WORKSPACE_PLATFORM_MAP, WORKSPACE_LABELS, getOpenFileDialogFilters(), getOpenActionLabels() are all gone.

Note: Some workspace-specific logic will remain in Toolbar.tsx (openSourceForWorkspace, analysis handlers, command state). These are deferred to Phase 3b or handled per-workspace during Phase 4 migration. The goal of Phase 3 is to eliminate the pure-data if/else chains, not to move all workspace behavior.

- [ ] **Step 4: Commit if cleanup needed**
