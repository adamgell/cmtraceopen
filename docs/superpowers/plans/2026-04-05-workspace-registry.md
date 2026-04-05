# Workspace Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a pluggable workspace registry that replaces 25+ scattered if/else chains with centralized, type-safe workspace definitions, starting with sysmon as the template workspace.

**Architecture:** Each workspace is a self-contained folder under `src/workspaces/` exporting a `WorkspaceDefinition` object. A central registry assembles all definitions into a `Map`. Consumers (AppShell, Toolbar, FileSidebar, ui-store) read from the registry instead of branching per workspace.

**Tech Stack:** React 19, TypeScript, Zustand, Tauri v2, Fluent UI, React.lazy/Suspense

---

## File Structure

**New files to create:**
- `src/workspaces/types.ts` — `WorkspaceDefinition` interface and related types
- `src/workspaces/registry.ts` — Central registry, `getWorkspace()`, `getAvailableWorkspaces()`
- `src/workspaces/sysmon/index.ts` — Sysmon workspace definition
- `src/workspaces/sysmon/types.ts` — Moved from `src/types/sysmon.ts`
- `src/workspaces/sysmon/sysmon-store.ts` — Moved from `src/stores/sysmon-store.ts`
- `src/workspaces/sysmon/SysmonWorkspace.tsx` — Moved from `src/components/sysmon/SysmonWorkspace.tsx`
- `src/workspaces/sysmon/SysmonEventTable.tsx` — Moved from `src/components/sysmon/SysmonEventTable.tsx`
- `src/workspaces/sysmon/SysmonDashboardView.tsx` — Moved from `src/components/sysmon/SysmonDashboardView.tsx`
- `src/workspaces/sysmon/SysmonSummaryView.tsx` — Moved from `src/components/sysmon/SysmonSummaryView.tsx`
- `src/workspaces/sysmon/SysmonConfigView.tsx` — Moved from `src/components/sysmon/SysmonConfigView.tsx`
- `src/workspaces/sysmon/DashboardMetricCards.tsx` — Moved from `src/components/sysmon/DashboardMetricCards.tsx`
- `src/workspaces/sysmon/DashboardTimeline.tsx` — Moved from `src/components/sysmon/DashboardTimeline.tsx`
- `src/workspaces/sysmon/DashboardEventTypeChart.tsx` — Moved from `src/components/sysmon/DashboardEventTypeChart.tsx`
- `src/workspaces/sysmon/DashboardSecurityAlerts.tsx` — Moved from `src/components/sysmon/DashboardSecurityAlerts.tsx`
- `src/workspaces/sysmon/DashboardTopList.tsx` — Moved from `src/components/sysmon/DashboardTopList.tsx`
- `src/workspaces/sysmon/SysmonSidebar.tsx` — Extracted from `src/components/layout/FileSidebar.tsx` (lines 817-855)
- `src/workspaces/sysmon/use-sysmon-analysis-progress.ts` — Moved from `src/hooks/use-sysmon-analysis-progress.ts`

**Files to modify:**
- `src/components/layout/FileSidebar.tsx` — Remove inline `SysmonSidebar()` function (lines 817-855), update sidebar routing to import from workspace
- `src/components/layout/Toolbar.tsx` — Update sysmon store import path
- `src/components/layout/StatusBar.tsx` — Update sysmon store import path
- `src/lib/commands.ts` — Update sysmon type import path

**Files to delete (after move):**
- `src/components/sysmon/` — Entire directory (10 files)
- `src/stores/sysmon-store.ts`
- `src/types/sysmon.ts`
- `src/hooks/use-sysmon-analysis-progress.ts`

---

### Task 1: Create WorkspaceDefinition types

**Files:**
- Create: `src/workspaces/types.ts`

- [ ] **Step 1: Create the types file**

```typescript
// src/workspaces/types.ts
import type { LazyExoticComponent, ComponentType } from "react";
import type { LogSource, PlatformKind, WorkspaceId } from "../types/log";

export interface DialogFilter {
  name: string;
  extensions: string[];
}

export interface WorkspaceActionLabels {
  file?: string;
  folder?: string;
  placeholder?: string;
}

export interface WorkspaceCapabilities {
  tabStrip?: boolean;
  findBar?: boolean;
  detailsPane?: boolean;
  infoPane?: boolean;
  footerBar?: boolean;
  multiFileDrop?: boolean;
  fontSizing?: boolean;
}

export interface WorkspaceDefinition {
  /** Unique workspace identifier. */
  id: WorkspaceId;
  /** Human-readable label shown in toolbar dropdown. */
  label: string;
  /** Platforms this workspace is available on. "all" means no restriction. */
  platforms: PlatformKind[] | "all";
  /** Lazy-loaded main workspace component. */
  component: LazyExoticComponent<ComponentType>;
  /** Lazy-loaded sidebar component. Omit for no sidebar. */
  sidebar?: LazyExoticComponent<ComponentType>;
  /** Boolean capability flags. All default to false if omitted. */
  capabilities?: WorkspaceCapabilities;
  /** File dialog filters for the "Open File" action. */
  fileFilters?: DialogFilter[];
  /** Labels for toolbar open-file/folder buttons. */
  actionLabels?: WorkspaceActionLabels;
  /** Handler for opening a source in this workspace. */
  onOpenSource?: (source: LogSource, trigger: string) => Promise<void>;
  /** Handler for opening a path directly (drag-and-drop, file association). */
  onOpenPath?: (path: string) => Promise<void>;
}
```

- [ ] **Step 2: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS (no errors from the new file)

- [ ] **Step 3: Commit**

```bash
git add src/workspaces/types.ts
git commit -m "feat(workspaces): add WorkspaceDefinition types"
```

---

### Task 2: Create the workspace registry

**Files:**
- Create: `src/workspaces/registry.ts`

- [ ] **Step 1: Create the registry file**

```typescript
// src/workspaces/registry.ts
import type { PlatformKind, WorkspaceId } from "../types/log";
import type { WorkspaceDefinition } from "./types";

const ALL_WORKSPACES: WorkspaceDefinition[] = [];

export const workspaceRegistry = new Map<WorkspaceId, WorkspaceDefinition>(
  ALL_WORKSPACES.map((ws) => [ws.id, ws]),
);

export function getWorkspace(id: WorkspaceId): WorkspaceDefinition {
  const ws = workspaceRegistry.get(id);
  if (!ws) throw new Error(`Unknown workspace: ${id}`);
  return ws;
}

export function getAvailableWorkspaces(
  platform: PlatformKind,
  enabledWorkspaces?: readonly WorkspaceId[] | null,
): WorkspaceDefinition[] {
  const enabled = enabledWorkspaces ? new Set(enabledWorkspaces) : null;
  return ALL_WORKSPACES.filter((ws) => {
    if (enabled && !enabled.has(ws.id)) return false;
    return ws.platforms === "all" || ws.platforms.includes(platform);
  });
}
```

- [ ] **Step 2: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/workspaces/registry.ts
git commit -m "feat(workspaces): add central workspace registry"
```

---

### Task 3: Move sysmon types

**Files:**
- Create: `src/workspaces/sysmon/types.ts` (moved from `src/types/sysmon.ts`)
- Modify: `src/stores/sysmon-store.ts` — update import path
- Modify: `src/lib/commands.ts:14` — update import path
- Modify: `src/components/sysmon/DashboardEventTypeChart.tsx:3` — update import path
- Modify: `src/components/sysmon/DashboardSecurityAlerts.tsx:2` — update import path
- Modify: `src/components/sysmon/DashboardTimeline.tsx:4` — update import path
- Modify: `src/components/sysmon/DashboardTopList.tsx:3` — update import path
- Modify: `src/components/sysmon/SysmonEventTable.tsx:8` — update import path
- Delete: `src/types/sysmon.ts`

- [ ] **Step 1: Copy the types file to its new location**

Copy `src/types/sysmon.ts` to `src/workspaces/sysmon/types.ts` with identical contents. The file contains all sysmon types: `SysmonEventType`, `SysmonSeverity`, `SysmonEvent`, `SysmonEventTypeCount`, `SysmonSummary`, `SysmonConfig`, `TimeBucket`, `RankedItem`, `SecuritySummary`, `SysmonDashboardData`, `SysmonAnalysisResult`.

- [ ] **Step 2: Update import in `src/stores/sysmon-store.ts`**

Change line 2-10:
```typescript
// OLD
import type {
  SysmonAnalysisResult,
  SysmonConfig,
  SysmonDashboardData,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
  SysmonSummary,
} from "../types/sysmon";

// NEW
import type {
  SysmonAnalysisResult,
  SysmonConfig,
  SysmonDashboardData,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
  SysmonSummary,
} from "../workspaces/sysmon/types";
```

- [ ] **Step 3: Update import in `src/lib/commands.ts`**

Change line 14:
```typescript
// OLD
import type { SysmonAnalysisResult } from "../types/sysmon";

// NEW
import type { SysmonAnalysisResult } from "../workspaces/sysmon/types";
```

- [ ] **Step 4: Update imports in sysmon components**

Update these files' type imports from `"../../types/sysmon"` to `"../../workspaces/sysmon/types"`:
- `src/components/sysmon/DashboardEventTypeChart.tsx` line 3
- `src/components/sysmon/DashboardSecurityAlerts.tsx` line 2
- `src/components/sysmon/DashboardTimeline.tsx` line 4
- `src/components/sysmon/DashboardTopList.tsx` line 3
- `src/components/sysmon/SysmonEventTable.tsx` line 8

Note: These components will move in Task 5, but we update them now so they compile at every step.

- [ ] **Step 5: Delete old types file**

```bash
rm src/types/sysmon.ts
```

- [ ] **Step 6: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/workspaces/sysmon/types.ts src/types/ src/stores/sysmon-store.ts src/lib/commands.ts src/components/sysmon/
git commit -m "refactor(sysmon): move sysmon types to src/workspaces/sysmon/"
```

---

### Task 4: Move sysmon store

**Files:**
- Create: `src/workspaces/sysmon/sysmon-store.ts` (moved from `src/stores/sysmon-store.ts`)
- Modify: `src/components/sysmon/SysmonConfigView.tsx:2` — update import path
- Modify: `src/components/sysmon/SysmonDashboardView.tsx:2` — update import path
- Modify: `src/components/sysmon/SysmonEventTable.tsx:5` — update import path
- Modify: `src/components/sysmon/SysmonSummaryView.tsx:2` — update import path
- Modify: `src/components/sysmon/SysmonWorkspace.tsx:2` — update import path
- Modify: `src/components/layout/FileSidebar.tsx:15` — update import path
- Modify: `src/components/layout/StatusBar.tsx:24` — update import path
- Modify: `src/components/layout/Toolbar.tsx:37` — update import path
- Modify: `src/hooks/use-sysmon-analysis-progress.ts:3` — update import path
- Delete: `src/stores/sysmon-store.ts`

- [ ] **Step 1: Copy store to new location**

Copy `src/stores/sysmon-store.ts` to `src/workspaces/sysmon/sysmon-store.ts`.

Update its internal import (line 2-10) to `"./types"` since the types now live in the same directory. After Task 3, this import was changed to `"../workspaces/sysmon/types"` — now simplify to a local relative path:

```typescript
// OLD (after Task 3)
import type {
  SysmonAnalysisResult,
  SysmonConfig,
  SysmonDashboardData,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
  SysmonSummary,
} from "../workspaces/sysmon/types";

// NEW
import type {
  SysmonAnalysisResult,
  SysmonConfig,
  SysmonDashboardData,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
  SysmonSummary,
} from "./types";
```

- [ ] **Step 2: Update imports in sysmon components**

Update store imports from `"../../stores/sysmon-store"` to `"../../workspaces/sysmon/sysmon-store"` in:
- `src/components/sysmon/SysmonConfigView.tsx` line 2
- `src/components/sysmon/SysmonDashboardView.tsx` line 2
- `src/components/sysmon/SysmonEventTable.tsx` line 5
- `src/components/sysmon/SysmonSummaryView.tsx` line 2
- `src/components/sysmon/SysmonWorkspace.tsx` line 2

Note: These components move in Task 5. We update them now so they compile at every step.

- [ ] **Step 3: Update imports in layout components**

Update store imports from `"../../stores/sysmon-store"` to `"../../workspaces/sysmon/sysmon-store"` in:
- `src/components/layout/FileSidebar.tsx` line 15
- `src/components/layout/StatusBar.tsx` line 24
- `src/components/layout/Toolbar.tsx` line 37

- [ ] **Step 4: Update import in hooks**

Update import in `src/hooks/use-sysmon-analysis-progress.ts` line 3:

```typescript
// OLD
import { useSysmonStore, type SysmonAnalysisProgress } from "../stores/sysmon-store";

// NEW
import { useSysmonStore, type SysmonAnalysisProgress } from "../workspaces/sysmon/sysmon-store";
```

- [ ] **Step 5: Delete old store file**

```bash
rm src/stores/sysmon-store.ts
```

- [ ] **Step 6: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/workspaces/sysmon/sysmon-store.ts src/stores/ src/components/sysmon/ src/components/layout/ src/hooks/
git commit -m "refactor(sysmon): move sysmon store to src/workspaces/sysmon/"
```

---

### Task 5: Move sysmon components

**Files:**
- Create: `src/workspaces/sysmon/SysmonWorkspace.tsx` (moved)
- Create: `src/workspaces/sysmon/SysmonEventTable.tsx` (moved)
- Create: `src/workspaces/sysmon/SysmonDashboardView.tsx` (moved)
- Create: `src/workspaces/sysmon/SysmonSummaryView.tsx` (moved)
- Create: `src/workspaces/sysmon/SysmonConfigView.tsx` (moved)
- Create: `src/workspaces/sysmon/DashboardMetricCards.tsx` (moved)
- Create: `src/workspaces/sysmon/DashboardTimeline.tsx` (moved)
- Create: `src/workspaces/sysmon/DashboardEventTypeChart.tsx` (moved)
- Create: `src/workspaces/sysmon/DashboardSecurityAlerts.tsx` (moved)
- Create: `src/workspaces/sysmon/DashboardTopList.tsx` (moved)
- Modify: `src/components/layout/AppShell.tsx` — update SysmonWorkspace import
- Delete: `src/components/sysmon/` — entire directory

- [ ] **Step 1: Copy all 10 component files**

Copy all files from `src/components/sysmon/` to `src/workspaces/sysmon/`:

```
DashboardEventTypeChart.tsx
DashboardMetricCards.tsx
DashboardSecurityAlerts.tsx
DashboardTimeline.tsx
DashboardTopList.tsx
SysmonConfigView.tsx
SysmonDashboardView.tsx
SysmonEventTable.tsx
SysmonSummaryView.tsx
SysmonWorkspace.tsx
```

- [ ] **Step 2: Update internal imports in moved components**

Since types and store already live in `src/workspaces/sysmon/`, update the relative imports in each moved file:

**All 5 dashboard sub-components** (`DashboardEventTypeChart.tsx`, `DashboardSecurityAlerts.tsx`, `DashboardTimeline.tsx`, `DashboardTopList.tsx`, `DashboardMetricCards.tsx`):
- Type imports: change `"../../types/sysmon"` → `"./types"` (already pointing to `../../workspaces/sysmon/types` from Task 3, now simplify to `./types`)

Note: After Task 3, these files import from `"../../workspaces/sysmon/types"`. Now that the components live in `src/workspaces/sysmon/`, update to `"./types"`.

**`SysmonConfigView.tsx`:**
- Store: `"../../workspaces/sysmon/sysmon-store"` → `"./sysmon-store"`
- Shared: `"../../lib/log-accessibility"` stays as `"../../lib/log-accessibility"`

**`SysmonDashboardView.tsx`:**
- Store: `"../../workspaces/sysmon/sysmon-store"` → `"./sysmon-store"`
- Internal imports (5 dashboard components): already `"./"` relative — no change needed

**`SysmonEventTable.tsx`:**
- Store: `"../../workspaces/sysmon/sysmon-store"` → `"./sysmon-store"`
- Types: `"../../workspaces/sysmon/types"` → `"./types"`
- Shared: `"../../lib/log-accessibility"`, `"../../stores/ui-store"`, `"../../lib/themes"` — no change needed, paths still valid from `src/workspaces/sysmon/`

**`SysmonSummaryView.tsx`:**
- Store: `"../../workspaces/sysmon/sysmon-store"` → `"./sysmon-store"`

**`SysmonWorkspace.tsx`:**
- Store: `"../../workspaces/sysmon/sysmon-store"` → `"./sysmon-store"`
- Toolbar: `"../layout/Toolbar"` → `"../../components/layout/Toolbar"`
- Internal: `"./SysmonEventTable"`, `"./SysmonSummaryView"`, `"./SysmonConfigView"`, `"./SysmonDashboardView"` — no change needed

- [ ] **Step 3: Update AppShell import**

Find the import of `SysmonWorkspace` in `src/components/layout/AppShell.tsx` and update:

```typescript
// OLD (find the exact line — search for "SysmonWorkspace")
import { SysmonWorkspace } from "../sysmon/SysmonWorkspace";

// NEW
import { SysmonWorkspace } from "../../workspaces/sysmon/SysmonWorkspace";
```

- [ ] **Step 4: Delete old component directory**

```bash
rm -rf src/components/sysmon/
```

- [ ] **Step 5: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/workspaces/sysmon/ src/components/ 
git commit -m "refactor(sysmon): move sysmon components to src/workspaces/sysmon/"
```

---

### Task 6: Move sysmon analysis progress hook

**Files:**
- Create: `src/workspaces/sysmon/use-sysmon-analysis-progress.ts` (moved from `src/hooks/use-sysmon-analysis-progress.ts`)
- Modify: any file that imports the hook — search for `use-sysmon-analysis-progress`
- Delete: `src/hooks/use-sysmon-analysis-progress.ts`

- [ ] **Step 1: Find all consumers of the hook**

Run: `grep -r "use-sysmon-analysis-progress" src/`

Identify every file that imports this hook.

- [ ] **Step 2: Copy the hook file**

Copy `src/hooks/use-sysmon-analysis-progress.ts` to `src/workspaces/sysmon/use-sysmon-analysis-progress.ts`.

Update its internal import:

```typescript
// OLD
import { useSysmonStore, type SysmonAnalysisProgress } from "../stores/sysmon-store";

// NEW (store is now in the same directory)
import { useSysmonStore, type SysmonAnalysisProgress } from "./sysmon-store";
```

- [ ] **Step 3: Update all consumer imports**

For each file found in Step 1, update the import path to point to `"../../workspaces/sysmon/use-sysmon-analysis-progress"` (adjust relative path based on the consumer's location).

- [ ] **Step 4: Delete old hook file**

```bash
rm src/hooks/use-sysmon-analysis-progress.ts
```

- [ ] **Step 5: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/workspaces/sysmon/use-sysmon-analysis-progress.ts src/hooks/
git commit -m "refactor(sysmon): move analysis progress hook to src/workspaces/sysmon/"
```

---

### Task 7: Extract SysmonSidebar from FileSidebar

**Files:**
- Create: `src/workspaces/sysmon/SysmonSidebar.tsx` (extracted from `src/components/layout/FileSidebar.tsx` lines 817-855)
- Modify: `src/components/layout/FileSidebar.tsx` — remove inline `SysmonSidebar()`, import from workspace

- [ ] **Step 1: Read FileSidebar.tsx to get exact SysmonSidebar code and its dependencies**

Read `src/components/layout/FileSidebar.tsx` lines 817-855. Note:
- The `SysmonSidebar` function uses `useSysmonStore`, `getBaseName()`, `SourceSummaryCard`, and `tokens`.
- `getBaseName()` and `SourceSummaryCard` are defined elsewhere in FileSidebar.tsx — check if they're exported or inline.

- [ ] **Step 2: Create the extracted SysmonSidebar component**

Create `src/workspaces/sysmon/SysmonSidebar.tsx`:

```typescript
import { tokens } from "@fluentui/react-components";
import { useSysmonStore } from "./sysmon-store";
import { SourceSummaryCard } from "../../components/layout/FileSidebar";

// Import or inline the getBaseName helper — check FileSidebar.tsx to see if it's exported.
// If not exported, either export it from FileSidebar or copy the helper inline:
function getBaseName(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || path;
}

export function SysmonSidebar() {
  const summary = useSysmonStore((s) => s.summary);
  const sourcePath = useSysmonStore((s) => s.sourcePath);
  const isAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const analysisError = useSysmonStore((s) => s.analysisError);
  const progressMessage = useSysmonStore((s) => s.progressMessage);

  const title = sourcePath ? getBaseName(sourcePath) : "Sysmon";
  const subtitle = sourcePath ?? "Open a folder containing Sysmon EVTX files to begin.";

  return (
    <>
      <SourceSummaryCard
        badge="sysmon"
        title={title}
        subtitle={subtitle}
        body={
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
            {isAnalyzing && <div>{progressMessage ?? "Analyzing..."}</div>}
            {analysisError && <div style={{ color: tokens.colorPaletteRedForeground2 }}>{analysisError}</div>}
            {summary && (
              <>
                <div>Events: {summary.totalEvents.toLocaleString()}</div>
                <div>Processes: {summary.uniqueProcesses.toLocaleString()}</div>
                <div>Files: {summary.sourceFiles.length}</div>
                {summary.parseErrors > 0 && (
                  <div style={{ color: tokens.colorPaletteRedForeground2 }}>
                    Parse errors: {summary.parseErrors}
                  </div>
                )}
              </>
            )}
            {!isAnalyzing && !analysisError && !summary && <div>Ready</div>}
          </div>
        }
      />
    </>
  );
}
```

**Important:** Before writing this file, check whether `SourceSummaryCard` and `getBaseName` are exported from FileSidebar.tsx. If `SourceSummaryCard` is not exported, you need to export it. If `getBaseName` is not exported, either export it from a shared utility or copy it into SysmonSidebar.tsx as shown above.

- [ ] **Step 3: Update FileSidebar.tsx**

1. Remove the inline `SysmonSidebar()` function (lines 817-855)
2. Add an import at the top: `import { SysmonSidebar } from "../../workspaces/sysmon/SysmonSidebar";`
3. The sidebar routing (line ~1063) already references `<SysmonSidebar />` — it should now use the imported version
4. Remove the `useSysmonStore` import from FileSidebar.tsx if no other code in the file uses it

- [ ] **Step 4: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/workspaces/sysmon/SysmonSidebar.tsx src/components/layout/FileSidebar.tsx
git commit -m "refactor(sysmon): extract SysmonSidebar to src/workspaces/sysmon/"
```

---

### Task 8: Create sysmon workspace definition and register it

**Files:**
- Create: `src/workspaces/sysmon/index.ts`
- Modify: `src/workspaces/registry.ts` — add sysmon import and registration

- [ ] **Step 1: Create the workspace definition**

```typescript
// src/workspaces/sysmon/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const sysmonWorkspace: WorkspaceDefinition = {
  id: "sysmon",
  label: "Sysmon",
  platforms: ["windows"],
  component: lazy(() =>
    import("./SysmonWorkspace").then((m) => ({ default: m.SysmonWorkspace }))
  ),
  sidebar: lazy(() =>
    import("./SysmonSidebar").then((m) => ({ default: m.SysmonSidebar }))
  ),
  capabilities: {},
  fileFilters: [
    { name: "EVTX Files", extensions: ["evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open EVTX File",
    folder: "Open EVTX Folder",
    placeholder: "Open Sysmon Source...",
  },
};
```

Note: `onOpenSource` is intentionally omitted here — it will be wired up when consumers are refactored to use the registry (Phase 3, a future plan). For now, the definition captures metadata only.

- [ ] **Step 2: Register sysmon in the registry**

Update `src/workspaces/registry.ts`:

```typescript
// src/workspaces/registry.ts
import type { PlatformKind, WorkspaceId } from "../types/log";
import type { WorkspaceDefinition } from "./types";
import { sysmonWorkspace } from "./sysmon";

const ALL_WORKSPACES: WorkspaceDefinition[] = [
  sysmonWorkspace,
];

export const workspaceRegistry = new Map<WorkspaceId, WorkspaceDefinition>(
  ALL_WORKSPACES.map((ws) => [ws.id, ws]),
);

export function getWorkspace(id: WorkspaceId): WorkspaceDefinition {
  const ws = workspaceRegistry.get(id);
  if (!ws) throw new Error(`Unknown workspace: ${id}`);
  return ws;
}

export function getAvailableWorkspaces(
  platform: PlatformKind,
  enabledWorkspaces?: readonly WorkspaceId[] | null,
): WorkspaceDefinition[] {
  const enabled = enabledWorkspaces ? new Set(enabledWorkspaces) : null;
  return ALL_WORKSPACES.filter((ws) => {
    if (enabled && !enabled.has(ws.id)) return false;
    return ws.platforms === "all" || ws.platforms.includes(platform);
  });
}
```

- [ ] **Step 3: Verify types compile**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/workspaces/sysmon/index.ts src/workspaces/registry.ts
git commit -m "feat(workspaces): register sysmon as first workspace definition"
```

---

### Task 9: Final verification and cleanup

**Files:**
- Verify: all files in `src/workspaces/sysmon/`
- Verify: no stale imports remain

- [ ] **Step 1: Verify no references to old paths remain**

Run these searches and confirm zero results:

```bash
# Old type path
grep -r "types/sysmon" src/ --include="*.ts" --include="*.tsx"

# Old store path
grep -r "stores/sysmon-store" src/ --include="*.ts" --include="*.tsx"

# Old component path
grep -r "components/sysmon/" src/ --include="*.ts" --include="*.tsx"

# Old hook path
grep -r "hooks/use-sysmon-analysis-progress" src/ --include="*.ts" --include="*.tsx"
```

Expected: No matches for any of these.

- [ ] **Step 2: Verify the old directories are clean**

```bash
# Should not exist
ls src/components/sysmon/ 2>&1  # expect: No such file or directory
ls src/types/sysmon.ts 2>&1     # expect: No such file or directory
ls src/stores/sysmon-store.ts 2>&1  # expect: No such file or directory
ls src/hooks/use-sysmon-analysis-progress.ts 2>&1  # expect: No such file or directory
```

- [ ] **Step 3: Verify the new workspace structure**

```bash
ls src/workspaces/sysmon/
```

Expected files:
```
DashboardEventTypeChart.tsx
DashboardMetricCards.tsx
DashboardSecurityAlerts.tsx
DashboardTimeline.tsx
DashboardTopList.tsx
SysmonConfigView.tsx
SysmonDashboardView.tsx
SysmonEventTable.tsx
SysmonSidebar.tsx
SysmonSummaryView.tsx
SysmonWorkspace.tsx
index.ts
sysmon-store.ts
types.ts
use-sysmon-analysis-progress.ts
```

- [ ] **Step 4: Full type check**

Run: `npx tsc --noEmit`
Expected: PASS with zero errors

- [ ] **Step 5: Verify app builds**

Run: `npm run frontend:build`
Expected: PASS — Vite build succeeds

- [ ] **Step 6: Commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore(sysmon): final cleanup of workspace migration"
```

Only commit if there were changes to make. If Steps 1-5 all pass with no changes needed, skip this step.
