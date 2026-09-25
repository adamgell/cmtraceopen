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
