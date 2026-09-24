import { beforeEach, describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";
import { useQuickStats } from "./use-quick-stats";
import { useLogStore } from "../stores/log-store";
import { useFilterStore } from "../stores/filter-store";

type Entry = ReturnType<typeof useLogStore.getState>["entries"][number];

// Only the fields the hook reads: id, severity, timestamp.
function entry(id: number, severity: string, timestamp: number): Entry {
  return {
    id,
    severity,
    timestamp,
    message: `line ${id}`,
  } as unknown as Entry;
}

const ENTRIES = [
  entry(1, "Error", 1_000),
  entry(2, "Error", 2_000),
  entry(3, "Warning", 3_000),
  entry(4, "Info", 4_000),
];

describe("useQuickStats", () => {
  beforeEach(() => {
    useLogStore.setState({ entries: ENTRIES, totalLines: ENTRIES.length });
    useFilterStore.setState({ filteredIds: null });
  });

  it("counts every entry when nothing is filtered", () => {
    const { result } = renderHook(() => useQuickStats());
    expect(result.current.totalLines).toBe(4);
    expect(result.current.filteredLineCount).toBe(4);
    expect(result.current.bySeverity).toEqual({
      error: 2,
      warning: 1,
      info: 1,
      success: 0,
    });
    expect(result.current.earliestTimestamp).toBe(1_000);
    expect(result.current.latestTimestamp).toBe(4_000);
  });

  it("counts only visible entries when filtered, and keeps the total unfiltered", () => {
    useFilterStore.setState({ filteredIds: new Set([1, 3]) as Set<number> });

    const { result } = renderHook(() => useQuickStats());

    // This distinction is what the panel renders as "N total (M filtered)".
    expect(result.current.totalLines).toBe(4);
    expect(result.current.filteredLineCount).toBe(2);
    expect(result.current.bySeverity).toEqual({
      error: 1,
      warning: 1,
      info: 0,
      success: 0,
    });
  });

  it("derives the time range from visible entries, not the whole file", () => {
    useFilterStore.setState({ filteredIds: new Set([2, 3]) as Set<number> });

    const { result } = renderHook(() => useQuickStats());

    // Entries 1 (1000) and 4 (4000) are hidden. A range that still spanned them
    // would describe rows the user cannot see.
    expect(result.current.earliestTimestamp).toBe(2_000);
    expect(result.current.latestTimestamp).toBe(3_000);
  });
});
