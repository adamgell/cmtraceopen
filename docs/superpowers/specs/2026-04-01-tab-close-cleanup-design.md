# Tab Close Cleanup — Design Spec

**Issue:** #55 — Tabs & content view — cleaning up on tab close
**Date:** 2026-04-01

## Problem

When closing a tab (especially the last tab), the log content view continues showing stale log entries. The log store is never cleared because `AppShell.tsx`'s tab-switch effect early-returns when `activeTabIndex === -1`.

## Root Cause

**File:** `src/components/layout/AppShell.tsx` lines 221-232

The `useEffect` watching `activeTabIndex` has a guard:
```typescript
if (activeTabIndex < 0 || activeTabIndex >= tabs.length) return;
```

When the last tab closes, `activeTabIndex` becomes `-1`, the guard triggers, and `clearActiveFile()` is never called. The log store retains stale `entries`, `openFilePath`, `selectedId`, etc.

## Fix

In the same `useEffect`, before the guard, add a branch that clears the log store when no tabs remain:

```typescript
if (activeTabIndex === -1 && tabs.length === 0) {
  useLogStore.getState().clearActiveFile();
  return;
}
```

`clearActiveFile()` already exists in the log store and correctly resets all relevant state.

## Files Modified

| File | Change |
|------|--------|
| `src/components/layout/AppShell.tsx` | Add no-tabs cleanup branch in tab-switch effect |

## Verification

1. Open a log file (creates a tab)
2. Close the tab
3. Verify the log view is empty (no stale content)
4. Open a new file — verify it loads correctly
5. Open multiple files, close them one by one — verify content updates correctly on each close
