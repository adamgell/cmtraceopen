import { describe, expect, it } from "vitest";
import { findAdjacentSeverityEntryId } from "./error-navigation";
import type { LogEntry, Severity } from "../types/log";

function makeEntry(id: number, severity: Severity): LogEntry {
  return {
    id,
    lineNumber: id,
    message: `message ${id}`,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity,
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath: "/test.log",
    timezoneOffset: null,
  };
}

describe("findAdjacentSeverityEntryId", () => {
  const entries = [
    makeEntry(1, "Info"),
    makeEntry(2, "Error"),
    makeEntry(3, "Warning"),
    makeEntry(4, "Error"),
  ];

  it("finds the next matching severity after the selected entry", () => {
    expect(findAdjacentSeverityEntryId(entries, 2, "Error", "next")).toBe(4);
  });

  it("finds the previous matching severity before the selected entry", () => {
    expect(findAdjacentSeverityEntryId(entries, 4, "Error", "previous")).toBe(2);
  });

  it("wraps when navigating past the last matching severity", () => {
    expect(findAdjacentSeverityEntryId(entries, 4, "Error", "next")).toBe(2);
  });

  it("starts at the first or last matching severity when no entry is selected", () => {
    expect(findAdjacentSeverityEntryId(entries, null, "Error", "next")).toBe(2);
    expect(findAdjacentSeverityEntryId(entries, null, "Error", "previous")).toBe(4);
  });

  it("returns null when the severity is not present", () => {
    expect(findAdjacentSeverityEntryId([makeEntry(1, "Info")], 1, "Error", "next")).toBeNull();
  });
});
