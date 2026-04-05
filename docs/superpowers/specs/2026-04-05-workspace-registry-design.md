# Workspace Registry Design

## Problem

Adding a new workspace to CMTrace Open requires touching 8-10 files across multiple layers. There are 25+ workspace-specific branching points scattered across 8 frontend files (AppShell, Toolbar, FileSidebar, ui-store, StatusBar, EvidenceBundleDialog, use-keyboard, use-drag-drop). Each new workspace adds another branch to every chain, making the codebase harder to maintain and more error-prone.

## Goal

Replace scattered if/else chains with a centralized, type-safe workspace registry. Adding a new workspace should require creating one folder with a definition file and adding one import to the registry. Everything else — routing, labels, platform gating, file dialogs, sidebar rendering — derives from the registry.

## Scope

- **In scope:** Frontend workspace registration, component routing, consumer refactoring, file migration
- **Out of scope:** Rust backend changes (module structure, Cargo feature flags, command registration). The frontend design is compatible with a future Rust-side registry but does not require it.

## Design

### Core Type: `WorkspaceDefinition`

```typescript
// src/workspaces/types.ts

import type { LazyExoticComponent, ComponentType } from "react";
import type { WorkspaceId, PlatformId, LogSource } from "../types/log";

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
  /** Unique workspace identifier. Must match a value in the WorkspaceId union. */
  id: WorkspaceId;

  /** Human-readable label shown in toolbar dropdown and navigation. */
  label: string;

  /** Which platforms this workspace is available on. "all" means no restriction. */
  platforms: PlatformId[] | "all";

  /** Lazy-loaded main workspace component. */
  component: LazyExoticComponent<ComponentType>;

  /** Lazy-loaded sidebar component. Omit for no sidebar. */
  sidebar?: LazyExoticComponent<ComponentType>;

  /** Boolean capability flags. All default to false if omitted. */
  capabilities?: WorkspaceCapabilities;

  /** File dialog filters for the "Open File" action. Omit to use default log filters. */
  fileFilters?: DialogFilter[];

  /** Labels for open-file/folder toolbar buttons. */
  actionLabels?: WorkspaceActionLabels;

  /**
   * Handler for opening a source (file, folder, or known source) in this workspace.
   * If omitted, the default log workspace source loader is used.
   */
  onOpenSource?: (source: LogSource, trigger: string) => Promise<void>;

  /**
   * Handler for opening a path directly (e.g., from drag-and-drop or file association).
   * If omitted, falls through to onOpenSource with a file source.
   */
  onOpenPath?: (path: string) => Promise<void>;
}
```

All fields beyond `id`, `label`, `platforms`, and `component` are optional. This keeps simple workspaces simple while allowing complex ones to declare their full surface area. New optional fields can be added without breaking existing definitions.

### Directory Structure

```
src/workspaces/
├── types.ts                    # WorkspaceDefinition, WorkspaceCapabilities, helpers
├── registry.ts                 # Central registry — imports definitions, builds Map
├── sysmon/
│   ├── index.ts                # exports sysmonWorkspace: WorkspaceDefinition
│   ├── SysmonWorkspace.tsx     # from src/components/sysmon/
│   ├── SysmonEventTable.tsx    # from src/components/sysmon/
│   ├── SysmonDashboardView.tsx # from src/components/sysmon/
│   ├── SysmonSummaryView.tsx   # from src/components/sysmon/
│   ├── SysmonConfigView.tsx    # from src/components/sysmon/
│   ├── SysmonSidebar.tsx       # from src/components/sysmon/ (or FileSidebar)
│   ├── sysmon-store.ts         # from src/stores/sysmon-store.ts
│   └── types.ts                # from src/types/sysmon.ts
├── dsregcmd/
│   ├── index.ts
│   ├── ...components
│   ├── dsregcmd-store.ts
│   └── types.ts
├── intune/
│   ├── index.ts
│   ├── ...components
│   ├── intune-store.ts
│   └── types.ts
├── new-intune/
│   ├── index.ts
│   └── ...components (may share intune store)
├── log/
│   ├── index.ts
│   ├── ...components
│   ├── log-store.ts
│   ├── filter-store.ts
│   └── types.ts
├── deployment/
│   ├── index.ts
│   ├── ...components
│   ├── deployment-store.ts
│   └── types.ts
├── event-log/
│   ├── index.ts
│   └── ...components
├── macos-diag/
│   ├── index.ts
│   └── ...components
```

Each workspace folder is self-contained: definition, components, store, types. Shared utilities (layout shell, common hooks, shared types like `LogEntry`) remain in their current locations.

### Registry

```typescript
// src/workspaces/registry.ts
import { sysmonWorkspace } from "./sysmon";
import { dsregcmdWorkspace } from "./dsregcmd";
import { intuneWorkspace } from "./intune";
import { newIntuneWorkspace } from "./new-intune";
import { logWorkspace } from "./log";
import { deploymentWorkspace } from "./deployment";
import { eventLogWorkspace } from "./event-log";
import { macosDiagWorkspace } from "./macos-diag";

import type { WorkspaceDefinition } from "./types";

const ALL_WORKSPACES: WorkspaceDefinition[] = [
  logWorkspace,
  intuneWorkspace,
  newIntuneWorkspace,
  dsregcmdWorkspace,
  sysmonWorkspace,
  deploymentWorkspace,
  eventLogWorkspace,
  macosDiagWorkspace,
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
  platform: PlatformId,
  enabledWorkspaces?: readonly WorkspaceId[] | null,
): WorkspaceDefinition[] {
  const enabled = enabledWorkspaces ? new Set(enabledWorkspaces) : null;
  return ALL_WORKSPACES.filter((ws) => {
    if (enabled && !enabled.has(ws.id)) return false;
    return ws.platforms === "all" || ws.platforms.includes(platform);
  });
}
```

### Consumer Changes

**AppShell.tsx** — `renderWorkspace()` becomes a registry lookup:

```typescript
const workspace = getWorkspace(activeView);
const Component = workspace.component;
return (
  <Suspense fallback={<WorkspaceLoading />}>
    <Component />
  </Suspense>
);

// Capability-gated UI:
{workspace.capabilities?.tabStrip && <TabStrip />}
{workspace.capabilities?.findBar && showFindBar && <FindBar />}
```

**Toolbar.tsx** — labels, filters, and source routing become lookups:

```typescript
const workspace = getWorkspace(activeView);
const label = workspace.label;
const filters = workspace.fileFilters ?? defaultLogFilters;
const actionLabels = workspace.actionLabels ?? defaultActionLabels;

// Source opening:
if (workspace.onOpenSource) {
  await workspace.onOpenSource(source, trigger);
} else {
  await loadLogWorkspaceSource(source, trigger);
}
```

**FileSidebar.tsx** — sidebar routing:

```typescript
const workspace = getWorkspace(activeView);
const Sidebar = workspace.sidebar;
return Sidebar ? (
  <Suspense fallback={null}><Sidebar /></Suspense>
) : null;
```

**ui-store.ts** — platform gating uses `getAvailableWorkspaces()` from registry. `WORKSPACE_PLATFORM_MAP` is removed.

**use-drag-drop.ts, use-keyboard.ts** — capability checks replace workspace ID checks:

```typescript
const workspace = getWorkspace(activeView);
if (workspace.capabilities?.multiFileDrop) { ... }
if (workspace.capabilities?.fontSizing) { ... }
```

## Migration Strategy

### Phase 1: Foundation
- Create `src/workspaces/types.ts` with `WorkspaceDefinition` and related types
- Create `src/workspaces/registry.ts` with empty registry and helper functions
- No behavior changes

### Phase 2: Migrate sysmon (template workspace)
- Move `src/components/sysmon/*` to `src/workspaces/sysmon/`
- Move `src/stores/sysmon-store.ts` to `src/workspaces/sysmon/`
- Move `src/types/sysmon.ts` to `src/workspaces/sysmon/`
- Create `src/workspaces/sysmon/index.ts` with `WorkspaceDefinition`
- Register in `registry.ts`
- Update all imports referencing old paths
- App still uses if/else chains — sysmon just lives in a new location

### Phase 3: Wire consumers to the registry
- Create shim `WorkspaceDefinition` entries for non-migrated workspaces (pointing to current component locations)
- Refactor AppShell, Toolbar, FileSidebar, ui-store to use registry lookups
- Remove if/else chains, `WORKSPACE_PLATFORM_MAP`, `WORKSPACE_LABELS`, `getOpenFileDialogFilters()`, and `openSourceForWorkspace()` branching
- All workspaces work via the registry

### Phase 4: Migrate remaining workspaces (one by one, smallest first)
1. dsregcmd (9 components, small store)
2. event-log
3. macos-diag
4. deployment
5. intune / new-intune (largest — 21 components, 34KB store)
6. log (most complex — deeply integrated)

Each migration: move files into `src/workspaces/{id}/`, replace the shim definition with a real one, update imports.

### Phase 5: Cleanup
- Remove empty `src/components/{workspace}/` directories
- Remove workspace exports from `src/stores/` if barrel files exist
- Remove `src/types/{workspace}.ts` files
- Verify no stale imports remain

## Testing

- After each phase: `npx tsc --noEmit` must pass
- After Phase 2: verify sysmon workspace loads and analyzes EVTX files correctly
- After Phase 3: verify all workspaces still work (manual smoke test of each)
- After each Phase 4 migration: verify that workspace loads and its core workflow works
- Existing Rust tests (`cargo test`) are unaffected since backend is untouched

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Import path breakage during file moves | Run `npx tsc --noEmit` after every move. Use IDE-assisted renames where possible. |
| Circular dependencies between workspace and shared code | Workspaces import from shared code, never the reverse. Registry is the only shared-to-workspace bridge. |
| `React.lazy` Suspense boundaries missing | Wrap all lazy components in `<Suspense>` with appropriate fallbacks in AppShell and FileSidebar. |
| Phase 3 (consumer rewire) is the riskiest single phase | Create shim definitions first so all workspaces work via registry before removing old code. Never remove old branching until the registry path is verified working. |
| new-intune and intune share state | Both can import from `src/workspaces/intune/intune-store.ts`. Cross-workspace imports within the `workspaces/` tree are acceptable for genuinely shared state. |

## Future Extensions

These are explicitly out of scope but the design supports them:

- **Status bar formatters**: Add optional `getStatusText()` to `WorkspaceDefinition`
- **Keyboard shortcuts per workspace**: Add optional `shortcuts` field
- **Evidence bundle support**: Add optional `evidenceBundle` capability
- **Rust-side registry**: Trait-based workspace registration with macro-generated command handlers
- **Dynamic workspace loading**: Workspaces loaded from plugins or external packages
