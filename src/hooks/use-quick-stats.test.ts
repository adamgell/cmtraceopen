import { beforeEach, describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";
import { useLogStore } from "../stores/log-store";
import { useFilterStore } from "../stores/filter-store";
import type { ErrorCodeOutcome, ErrorCodeSpan, LogEntry } from "../types/log";
import { useQuickStats } from "./use-quick-stats";

function span(codeHex: string, outcome: ErrorCodeOutcome): ErrorCodeSpan {
  return {
    start: 0,
    end: codeHex.length,
    codeHex,
    codeDecimal: "0",
    description: `${codeHex} fixture`,
    category: "Windows",
    outcome,
  };
}

function entry(id: number, errorCodeSpans: ErrorCodeSpan[]): LogEntry {
  return {
    id,
    lineNumber: id,
    message: `message ${id}`,
    component: "CBS",
    timestamp: null,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped",
    filePath: "/Windows/Logs/CBS/CBS.log",
    timezoneOffset: null,
    errorCodeSpans,
  };
}

describe("useQuickStats error codes", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
    useFilterStore.getState().clearFilter();
  });

  it("counts failures and action-required codes but not completed operations", () => {
    // #657: CBS.log writes [HRESULT = 0x00000000] on successful steps, so the
    // table counted S_OK and made a healthy log look broken.
    useLogStore.setState({
      entries: [
        entry(1, [span("0x80070005", "failure"), span("0x00000000", "success")]),
        entry(2, [span("0x00000000", "success")]),
        entry(3, [span("0x3010", "successRequiresAction")]),
      ],
      totalLines: 3,
    });

    const { result } = renderHook(() => useQuickStats());

    expect(result.current.errorCodes.map((code) => code.hex)).toEqual([
      "0x80070005",
      "0x3010",
    ]);
  });

  it("still counts a repeat failure once per occurrence", () => {
    useLogStore.setState({
      entries: [
        entry(1, [span("0x80070005", "failure")]),
        entry(2, [span("0x80070005", "failure")]),
      ],
      totalLines: 2,
    });

    const { result } = renderHook(() => useQuickStats());

    expect(result.current.errorCodes).toEqual([
      {
        hex: "0x80070005",
        description: "0x80070005 fixture",
        category: "Windows",
        count: 2,
      },
    ]);
  });
});

type Entry = ReturnType<typeof useLogStore.getState>["entries"][number];

// Only the fields the hook reads: id, severity, timestamp.
function logEntry(id: number, severity: string, timestamp: number): Entry {
  return {
    id,
    severity,
    timestamp,
    message: `line ${id}`,
  } as unknown as Entry;
}

const ENTRIES = [
  logEntry(1, "Error", 1_000),
  logEntry(2, "Error", 2_000),
  logEntry(3, "Warning", 3_000),
  logEntry(4, "Info", 4_000),
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
