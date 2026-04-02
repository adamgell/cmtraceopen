# Tab Close Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the bug where closing the last tab leaves stale log content in the view.

**Architecture:** Handle cleanup directly in the `closeTab` action in `ui-store.ts`. When the last tab is closed (`newTabs.length === 0`), immediately call `clearActiveFile()` on the log store and `clearFilter()` on the filter store. This is synchronous, deterministic, and doesn't rely on reactive `useEffect` timing.

**Tech Stack:** Zustand

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/stores/ui-store.ts` | Modify | Clear log and filter state in `closeTab` when no tabs remain |

---

### Task 1: Fix tab close cleanup in closeTab action

**Files:**
- Modify: `src/stores/ui-store.ts:516-534`

- [ ] **Step 1: Add cleanup to closeTab**

In `src/stores/ui-store.ts`, modify the `closeTab` action (lines 516-534). Add log store and filter store cleanup when the last tab is closed:

```typescript
      closeTab: (index) => {
        const { openTabs, activeTabIndex } = get();
        if (index < 0 || index >= openTabs.length) {
          console.warn("[ui-store] closeTab: invalid index", { index, tabCount: openTabs.length });
          return;
        }
        // Evict parsed entry cache for the closed tab
        clearCachedTabSnapshot(openTabs[index].filePath);
        const newTabs = openTabs.filter((_, i) => i !== index);
        let newActive = activeTabIndex;
        if (newTabs.length === 0) {
          newActive = -1;
          // Clear stale log content and filters when all tabs are closed
          useLogStore.getState().clearActiveFile();
          useFilterStore.getState().clearFilter();
        } else if (index === activeTabIndex) {
          newActive = index > 0 ? index - 1 : 0;
        } else if (index < activeTabIndex) {
          newActive = activeTabIndex - 1;
        }
        set({ openTabs: newTabs, activeTabIndex: newActive });
      },
```

Add the imports at the top of the file (if not already present):

```typescript
import { useLogStore } from "./log-store";
import { useFilterStore } from "./filter-store";
```

Check for circular imports — `log-store` and `filter-store` should not import `ui-store` at the module level. Since Zustand stores are accessed via `.getState()` at call time (not at import time), this is safe.

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 3: Manual verification**

Run: `npm run frontend:dev`
Test in browser:
1. Open a log from Known Sources → content appears
2. Close the tab → log view clears completely (no stale content)
3. Open a new file → loads correctly
4. Open two files, close one → other file's content stays visible
5. Close the last tab → view clears

- [ ] **Step 4: Commit**

```bash
git add src/stores/ui-store.ts
git commit -m "fix: clear log content and filters when last tab is closed (#55)"
```
