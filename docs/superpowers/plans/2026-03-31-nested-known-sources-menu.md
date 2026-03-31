# Nested Known Log Sources Menu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat Known Log Sources menu with nested family > group > source submenus, and add ConfigMgr client log sources.

**Architecture:** Add a `KnownSourceToolbarFamily` type that wraps the existing `KnownSourceToolbarGroup`. Rewrite the grouping function to produce a 3-level hierarchy. Update the Toolbar to render nested Fluent UI `<Menu>` components. Add ConfigMgr sources to the Rust catalog.

**Tech Stack:** React, Fluent UI v9 (nested `<Menu>`), Zustand, Rust/Tauri

**Spec:** `docs/superpowers/specs/2026-03-31-nested-known-sources-menu-design.md`

---

### Task 1: Add ConfigMgr sources to the Rust catalog

**Files:**
- Modify: `src-tauri/src/commands/known_sources.rs:237` (insert after DMClient entry, before Panther)

- [ ] **Step 1: Add ConfigMgr sources**

Insert these entries after the `windows-dmclient-logs` entry (line 237) and before the `windows-panther-setupact-log` entry (line 238):

```rust
        // ── ConfigMgr ──
        windows_known_source(
            "windows-configmgr-ccm-logs",
            "CCM Logs Folder",
            "ConfigMgr client operational logs (policy, inventory, software distribution).",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\CCM\\Logs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-configmgr-ccmsetup-logs",
            "ccmsetup Logs Folder",
            "ConfigMgr client installation and setup logs.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\ccmsetup\\Logs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 20,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-configmgr-setup-temp-logs",
            "CCM Client Setup Logs (Temp)",
            "Temporary ConfigMgr client setup logs written during installation.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\Temp\\CCMSetup\\Logs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 30,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-configmgr-swmtr",
            "Software Metering Logs",
            "ConfigMgr software metering usage reporting data.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\System32\\SWMTRReporting",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 40,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
```

- [ ] **Step 2: Verify Rust compiles**

Run: `cargo check` from `src-tauri/`
Expected: Compiles with no errors.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/commands/known_sources.rs
git commit -m "feat: add ConfigMgr known log sources (CCM, ccmsetup, temp, metering)"
```

---

### Task 2: Add `KnownSourceToolbarFamily` type and update grouping function

**Files:**
- Modify: `src/types/log.ts:113` (add new interface after `KnownSourceMetadata`)
- Modify: `src/stores/log-store.ts:76-81` (keep existing type, add new type)
- Modify: `src/stores/log-store.ts:426-477` (rewrite grouping function)
- Modify: `src/stores/log-store.ts:499` (change state field type)
- Modify: `src/stores/log-store.ts:668` (change initial state)
- Modify: `src/stores/log-store.ts:756` (change setter call)
- Modify: `src/stores/log-store.ts:842` (change reset value)

- [ ] **Step 1: Add `KnownSourceToolbarFamily` interface to types**

In `src/types/log.ts`, add after the `KnownSourceMetadata` interface (after line 113):

```typescript
export interface KnownSourceToolbarFamily {
  id: string;
  label: string;
  sortOrder: number;
  groups: KnownSourceToolbarGroup[];
}
```

Also add the `KnownSourceToolbarGroup` interface here (move from log-store.ts so both types live together):

```typescript
export interface KnownSourceToolbarGroup {
  id: string;
  label: string;
  sortOrder: number;
  sources: KnownSourceMetadata[];
}
```

- [ ] **Step 2: Update `src/stores/log-store.ts` imports and remove old interface**

Remove the `KnownSourceToolbarGroup` interface definition from `src/stores/log-store.ts` (lines 76-81).

Add to the imports from `../types/log`:

```typescript
import type {
  // ...existing imports...
  KnownSourceToolbarFamily,
  KnownSourceToolbarGroup,
} from "../types/log";
```

- [ ] **Step 3: Rewrite `buildToolbarKnownSourceGroups` to `buildToolbarKnownSourceFamilies`**

Replace the function at `src/stores/log-store.ts:426-477` with:

```typescript
function buildToolbarKnownSourceFamilies(
  sources: KnownSourceMetadata[]
): KnownSourceToolbarFamily[] {
  const families = new Map<string, KnownSourceToolbarFamily>();

  for (const source of sources) {
    const grouping = source.grouping;
    const familyId = grouping?.familyId ?? UNGROUPED_TOOLBAR_GROUP_ID;
    const familyLabel = grouping?.familyLabel ?? UNGROUPED_TOOLBAR_GROUP_LABEL;
    const groupId = grouping
      ? `${grouping.familyId}:${grouping.groupId}`
      : UNGROUPED_TOOLBAR_GROUP_ID;
    const groupLabel = grouping?.groupLabel ?? UNGROUPED_TOOLBAR_GROUP_LABEL;
    const groupOrder = grouping?.groupOrder ?? LAST_SORT_ORDER;
    const familySortOrder = grouping?.groupOrder ?? LAST_SORT_ORDER;

    let family = families.get(familyId);
    if (!family) {
      family = {
        id: familyId,
        label: familyLabel,
        sortOrder: familySortOrder,
        groups: [],
      };
      families.set(familyId, family);
    }

    // Use the lowest group_order in the family as the family sort order
    if (familySortOrder < family.sortOrder) {
      family.sortOrder = familySortOrder;
    }

    let group = family.groups.find((g) => g.id === groupId);
    if (!group) {
      group = {
        id: groupId,
        label: groupLabel,
        sortOrder: groupOrder,
        sources: [],
      };
      family.groups.push(group);
    }

    group.sources.push(source);
  }

  // Sort sources within each group, groups within each family, then families
  return Array.from(families.values())
    .map((family) => ({
      ...family,
      groups: family.groups
        .map((group) => ({
          ...group,
          sources: [...group.sources].sort((a, b) => {
            const aOrder = a.grouping?.sourceOrder ?? LAST_SORT_ORDER;
            const bOrder = b.grouping?.sourceOrder ?? LAST_SORT_ORDER;
            return aOrder !== bOrder
              ? aOrder - bOrder
              : a.label.localeCompare(b.label);
          }),
        }))
        .sort((a, b) =>
          a.sortOrder !== b.sortOrder
            ? a.sortOrder - b.sortOrder
            : a.label.localeCompare(b.label)
        ),
    }))
    .sort((a, b) =>
      a.sortOrder !== b.sortOrder
        ? a.sortOrder - b.sortOrder
        : a.label.localeCompare(b.label)
    );
}
```

- [ ] **Step 4: Update state interface and references**

In the `LogState` interface (`src/stores/log-store.ts:499`), change:

```typescript
  knownSourceToolbarFamilies: KnownSourceToolbarFamily[];
```

In the initial state (~line 668), change:

```typescript
  knownSourceToolbarFamilies: [],
```

In the `setKnownSources` setter (~line 753-757), change:

```typescript
  setKnownSources: (sources) =>
    set({
      knownSources: sources,
      knownSourceToolbarFamilies: buildToolbarKnownSourceFamilies(sources),
    }),
```

In the reset/clear function (~line 842), change:

```typescript
  knownSourceToolbarFamilies: [],
```

- [ ] **Step 5: Verify TypeScript compiles (expect Toolbar errors)**

Run: `npx tsc --noEmit`
Expected: Errors in `Toolbar.tsx` referencing the old `knownSourceToolbarGroups` field. This is expected and will be fixed in Task 3.

- [ ] **Step 6: Commit**

```bash
git add src/types/log.ts src/stores/log-store.ts
git commit -m "refactor: restructure known sources to family > group > source hierarchy"
```

---

### Task 3: Update Toolbar to render nested submenus

**Files:**
- Modify: `src/components/layout/Toolbar.tsx:765` (update state selector)
- Modify: `src/components/layout/Toolbar.tsx:879-921` (rewrite menu rendering)

- [ ] **Step 1: Update the state selector**

At line 765, change:

```typescript
  const knownSourceToolbarFamilies = useLogStore((s) => s.knownSourceToolbarFamilies);
```

- [ ] **Step 2: Update the disabled check and button text**

At lines 883-895, update all references from `knownSourceToolbarGroups` to `knownSourceToolbarFamilies`:

```typescript
            disabled={
              !commandState.canOpenKnownSources ||
              knownSourceToolbarFamilies.length === 0
            }
            title="Open a known log source"
          >
            {commandState.canOpenKnownSources
              ? knownSourceToolbarFamilies.length > 0
                ? isIntuneWorkspace(activeView)
                  ? "Open Known Intune Source..."
                  : "Open Known Log Source..."
                : "No Known Log Sources"
              : "Known Sources Unavailable"}
```

- [ ] **Step 3: Replace flat menu rendering with nested submenus**

Replace the `MenuList` content (lines 900-918) with nested menus:

```tsx
          <MenuList>
            {knownSourceToolbarFamilies.map((family) => (
              <Menu key={family.id}>
                <MenuTrigger disableButtonEnhancement>
                  <MenuItem>{family.label}</MenuItem>
                </MenuTrigger>
                <MenuPopover>
                  <MenuList>
                    {family.groups.map((group) => (
                      <Menu key={group.id}>
                        <MenuTrigger disableButtonEnhancement>
                          <MenuItem>{group.label}</MenuItem>
                        </MenuTrigger>
                        <MenuPopover>
                          <MenuList>
                            {group.sources.map((source) => (
                              <MenuItem
                                key={source.id}
                                title={source.description}
                                onClick={() =>
                                  void openKnownSourceCatalogAction({
                                    sourceId: source.id,
                                    trigger: "toolbar.known-source-select",
                                  }).catch((err) =>
                                    console.error(
                                      "Failed to open known source catalog action",
                                      err
                                    )
                                  )
                                }
                              >
                                {source.label}
                              </MenuItem>
                            ))}
                          </MenuList>
                        </MenuPopover>
                      </Menu>
                    ))}
                  </MenuList>
                </MenuPopover>
              </Menu>
            ))}
          </MenuList>
```

- [ ] **Step 4: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add src/components/layout/Toolbar.tsx
git commit -m "feat: render known sources as nested family > group > source submenus"
```

---

### Task 4: Update frontend tests

**Files:**
- Modify: `src/stores/log-store.test.ts` (if tests reference `knownSourceToolbarGroups`)

- [ ] **Step 1: Check for existing tests that reference the old field**

Run: `grep -n "knownSourceToolbarGroups" src/stores/log-store.test.ts`

If matches exist, update the field name to `knownSourceToolbarFamilies` and adjust assertions to match the new 3-level structure (families containing groups containing sources).

If no matches, skip to step 2.

- [ ] **Step 2: Run all frontend tests**

Run: `npm run test`
Expected: All tests pass.

- [ ] **Step 3: Run Rust tests**

Run: `cargo test` from `src-tauri/`
Expected: All tests pass.

- [ ] **Step 4: Commit (if any test changes)**

```bash
git add -A
git commit -m "test: update tests for nested known source menu structure"
```
