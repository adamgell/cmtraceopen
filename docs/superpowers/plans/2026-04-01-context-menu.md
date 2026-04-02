# Right-Click Context Menu — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a native OS context menu to log rows with quick filter, clipboard, error lookup, and file actions.

**Architecture:** Build the menu entirely from the frontend using Tauri v2's JS Menu API (`@tauri-apps/api/menu`). A new hook (`use-context-menu.ts`) constructs `MenuItem` instances with action callbacks, then calls `menu.popup()` on right-click. No Rust backend command needed — the menu API is part of Tauri core. Filter actions use a new `addQuickFilter()` convenience in the filter store that appends a clause and triggers the existing auto-apply effect.

**Tech Stack:** Tauri v2 Menu API (JS), React, Zustand, `@tauri-apps/plugin-clipboard-manager`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/hooks/use-context-menu.ts` | Create | Hook: builds native menu, shows popup, dispatches actions |
| `src/components/log-view/LogRow.tsx` | Modify | Attach `onContextMenu` handler from hook |
| `src/stores/filter-store.ts` | Modify | Add `addQuickFilter()` action |
| `src/components/dialogs/FilterDialog.tsx` | Modify | Export `FilterClause` type (already exported), ensure `emptyClause()` is exported |

---

### Task 1: Add `addQuickFilter` to filter store

**Files:**
- Modify: `src/stores/filter-store.ts`
- Modify: `src/components/dialogs/FilterDialog.tsx:44-46`

- [ ] **Step 1: Export `emptyClause` from FilterDialog**

In `src/components/dialogs/FilterDialog.tsx`, change line 44 from:

```typescript
function emptyClause(): FilterClause {
```

to:

```typescript
export function emptyClause(): FilterClause {
```

- [ ] **Step 2: Add `addQuickFilter` to FilterState interface**

In `src/stores/filter-store.ts`, add to the `FilterState` interface (after `clearFilter`):

```typescript
  addQuickFilter: (field: FilterField, value: string, op: FilterOp) => void;
```

Add the import for `FilterField` and `FilterOp` at the top:

```typescript
import type { FilterClause, FilterField, FilterOp } from "../components/dialogs/FilterDialog";
```

(Replace the existing import that only imports `FilterClause`.)

- [ ] **Step 3: Implement `addQuickFilter`**

In the `create<FilterState>` block, add after `clearFilter`:

```typescript
  addQuickFilter: (field, value, op) =>
    set((state) => ({
      clauses: [...state.clauses, { field, value, op }],
    })),
```

This appends a new clause. The existing `useEffect` in `AppShell.tsx` (line 195) watches `filterClauses` and auto-runs the filter whenever clauses change.

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/stores/filter-store.ts src/components/dialogs/FilterDialog.tsx
git commit -m "feat: add addQuickFilter action to filter store"
```

---

### Task 2: Create context menu hook

**Files:**
- Create: `src/hooks/use-context-menu.ts`

- [ ] **Step 1: Create the hook file**

Create `src/hooks/use-context-menu.ts`:

```typescript
import { useCallback } from "react";
import { Menu, MenuItem, PredefinedMenuItem } from "@tauri-apps/api/menu";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useFilterStore } from "../stores/filter-store";
import { useUiStore } from "../stores/ui-store";
import type { LogEntry } from "../types/log";

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + "…" : text;
}

function findErrorCode(entry: LogEntry): string | null {
  if (entry.errorCodeSpans && entry.errorCodeSpans.length > 0) {
    const span = entry.errorCodeSpans[0];
    return entry.message.slice(span.start, span.end);
  }
  return null;
}

function formatLine(entry: LogEntry): string {
  const parts: string[] = [];
  if (entry.timestampDisplay) parts.push(entry.timestampDisplay);
  if (entry.component) parts.push(entry.component);
  if (entry.threadDisplay) parts.push(entry.threadDisplay);
  parts.push(entry.message);
  return parts.join("\t");
}

export function useContextMenu() {
  const addQuickFilter = useFilterStore((s) => s.addQuickFilter);

  const showContextMenu = useCallback(
    async (entry: LogEntry, event: React.MouseEvent) => {
      event.preventDefault();

      const errorCode = findErrorCode(entry);
      const messagePreview = truncate(entry.message, 40);

      const items = [
        await MenuItem.new({
          id: "copy-line",
          text: "Copy Line",
          action: () => {
            writeText(formatLine(entry));
          },
        }),
        await MenuItem.new({
          id: "copy-message",
          text: "Copy Message",
          action: () => {
            writeText(entry.message);
          },
        }),
      ];

      if (entry.timestampDisplay) {
        items.push(
          await MenuItem.new({
            id: "copy-timestamp",
            text: "Copy Timestamp",
            action: () => {
              writeText(entry.timestampDisplay!);
            },
          })
        );
      }

      items.push(
        await PredefinedMenuItem.new({ item: "Separator" })
      );

      items.push(
        await MenuItem.new({
          id: "include-filter",
          text: `Include: "${messagePreview}"`,
          action: () => {
            addQuickFilter("Message", entry.message, "Contains");
          },
        }),
        await MenuItem.new({
          id: "exclude-filter",
          text: `Exclude: "${messagePreview}"`,
          action: () => {
            addQuickFilter("Message", entry.message, "NotContains");
          },
        })
      );

      items.push(
        await PredefinedMenuItem.new({ item: "Separator" })
      );

      if (errorCode) {
        items.push(
          await MenuItem.new({
            id: "error-lookup",
            text: `Error Lookup: ${errorCode}`,
            action: () => {
              const uiState = useUiStore.getState();
              uiState.lookupErrorCode(errorCode);
            },
          })
        );
      }

      if (entry.sourceFile) {
        items.push(
          await MenuItem.new({
            id: "open-source-file",
            text: `Open Source File`,
            action: () => {
              writeText(entry.sourceFile!);
            },
          })
        );
      }

      const menu = await Menu.new({ items });
      await menu.popup();
    },
    [addQuickFilter]
  );

  return { showContextMenu };
}
```

- [ ] **Step 2: Verify `lookupErrorCode` exists in ui-store**

Check that `useUiStore` has a `lookupErrorCode` action. Search for it:

Run: `grep -n "lookupErrorCode" src/stores/ui-store.ts`

If it doesn't exist, the error lookup action should instead set `focusedErrorCode` and open the dialog:

```typescript
action: () => {
  const uiState = useUiStore.getState();
  uiState.setShowErrorLookupDialog(true);
  // The error code will need to be passed via store state
},
```

Adjust the hook based on what the ui-store exposes.

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/hooks/use-context-menu.ts
git commit -m "feat: add context menu hook with native Tauri menu popup"
```

---

### Task 3: Attach context menu to LogRow

**Files:**
- Modify: `src/components/log-view/LogRow.tsx`

- [ ] **Step 1: Add onContextMenu prop to LogRowProps**

In `src/components/log-view/LogRow.tsx`, add to the `LogRowProps` interface:

```typescript
  onContextMenu: (entry: LogEntry, event: React.MouseEvent) => void;
```

- [ ] **Step 2: Attach the handler to the row div**

In the `LogRow` component's returned JSX, find the outermost `<div>` that represents the row (the one with `onClick`). Add:

```typescript
onContextMenu={(e) => onContextMenu(entry, e)}
```

- [ ] **Step 3: Pass the handler from the parent**

Find where `LogRow` is rendered (likely in `src/components/log-view/LogList.tsx` or similar). Import and use the hook:

```typescript
import { useContextMenu } from "../../hooks/use-context-menu";

// Inside the component:
const { showContextMenu } = useContextMenu();

// In the LogRow render:
<LogRow
  // ... existing props
  onContextMenu={showContextMenu}
/>
```

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/components/log-view/LogRow.tsx src/components/log-view/LogList.tsx
git commit -m "feat: attach native context menu to log rows"
```

---

### Task 4: Final verification

- [ ] **Step 1: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 2: Run frontend build**

Run: `npm run frontend:build`
Expected: PASS

- [ ] **Step 3: Manual testing**

Run: `npm run frontend:dev`
Test in browser:
1. Open a log file
2. Right-click a log row → native context menu appears
3. Click "Copy Line" → verify clipboard contains full line text
4. Click "Copy Message" → verify clipboard contains message only
5. Click "Include Filter" → verify filter bar appears with the clause active
6. Click "Exclude Filter" → verify negative filter applied
7. Right-click a row with an error code → "Error Lookup" item appears
8. Right-click a row without error code → "Error Lookup" not shown

Note: Full native menu only works in the Tauri app (`npm run app:dev`). In browser-only mode (`frontend:dev`), the Tauri menu API may not be available — wrap calls in a try/catch for graceful degradation.
