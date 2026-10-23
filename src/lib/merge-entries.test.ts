import { describe, expect, it } from "vitest";

import { findCorrelatedEntries, maxEntryEndLine, mergeEntries, replaceFileInMerge } from "./merge-entries";
import type { LogEntry } from "../types/log";

const entry = (filePath: string, lineNumber: number, timestamp: number | null): LogEntry =>
  ({ filePath, lineNumber, timestamp, message: `${filePath}:${lineNumber}` } as LogEntry);

describe("mergeEntries", () => {
  it("retains missing-timestamp entries for unified timeline unplaced coverage", () => {
    const merged = mergeEntries({
      first: [entry("C:\\logs\\first.log", 1, null)],
      second: [entry("D:\\logs\\second.log", 1, 2)],
    });

    expect(merged).toHaveLength(2);
    expect(merged.map((item) => item.timestamp)).toEqual([2, null]);
    expect(merged.map((item) => item.id)).toEqual([0, 1]);
  });
});

describe("mergeEntries continuation lines", () => {
  // Generic timestamped text logs (e.g. .NET stack traces) emit physical lines
  // with no timestamp of their own between timestamped records. In a merged
  // view they must stay with the record they continue, not sink to the end.
  it("keeps an untimestamped line directly after the timestamped line before it in the same file", () => {
    const merged = mergeEntries({
      app: [
        entry("C:\\logs\\app.log", 1, 1_000),
        entry("C:\\logs\\app.log", 2, null), // "   at Foo.Bar()" stack frame
        entry("C:\\logs\\app.log", 3, 3_000),
      ],
      ime: [entry("C:\\logs\\ime.log", 1, 2_000)],
    });

    expect(merged.map((item) => item.message)).toEqual([
      "C:\\logs\\app.log:1",
      "C:\\logs\\app.log:2",
      "C:\\logs\\ime.log:1",
      "C:\\logs\\app.log:3",
    ]);
  });

  it("places lines before a file's first timestamp just ahead of that first record", () => {
    const merged = mergeEntries({
      app: [
        entry("C:\\logs\\app.log", 1, null), // banner line
        entry("C:\\logs\\app.log", 2, 3_000),
      ],
      ime: [entry("C:\\logs\\ime.log", 1, 1_000), entry("C:\\logs\\ime.log", 2, 5_000)],
    });

    expect(merged.map((item) => item.message)).toEqual([
      "C:\\logs\\ime.log:1",
      "C:\\logs\\app.log:1",
      "C:\\logs\\app.log:2",
      "C:\\logs\\ime.log:2",
    ]);
  });

  it("leaves the displayed timestamp of a continuation line empty", () => {
    const merged = mergeEntries({
      app: [entry("C:\\logs\\app.log", 1, 1_000), entry("C:\\logs\\app.log", 2, null)],
    });

    expect(merged.map((item) => item.timestamp)).toEqual([1_000, null]);
    expect(merged.map((item) => item.mergeTimestamp)).toEqual([1_000, 1_000]);
  });

  it("still finds correlated entries across continuation lines in the middle of the merge", () => {
    const merged = mergeEntries({
      app: [
        entry("C:\\logs\\app.log", 1, 1_000),
        // A stack trace long enough that the binary search lands inside it.
        ...[2, 3, 4, 5, 6].map((line) => entry("C:\\logs\\app.log", line, null)),
        entry("C:\\logs\\app.log", 7, 9_000),
      ],
      ime: [entry("C:\\logs\\ime.log", 1, 1_200), entry("C:\\logs\\ime.log", 2, 8_900)],
      plain: [entry("C:\\logs\\notes.txt", 1, null)],
    });
    const target = merged.find((item) => item.message === "C:\\logs\\app.log:7");
    if (!target) throw new Error("fixture row app.log:7 is missing from the merge");

    const correlated = findCorrelatedEntries(merged, target, 500, {});

    expect(correlated.map((item) => item.entry.message)).toEqual(["C:\\logs\\ime.log:2"]);
    expect(correlated[0].deltaMs).toBe(-100);
  });
});

describe("replaceFileInMerge", () => {
  it("slots one file's new lines into the merge and leaves other rows untouched", () => {
    const merged = mergeEntries({
      app: [entry("C:\\logs\\app.log", 1, 1_000)],
      ime: [entry("C:\\logs\\ime.log", 1, 2_000), entry("C:\\logs\\ime.log", 2, 4_000)],
    });
    const appRows = merged.filter((item) => item.filePath === "C:\\logs\\app.log");

    const next = replaceFileInMerge(merged, "C:\\logs\\app.log", [
      ...appRows,
      { ...entry("C:\\logs\\app.log", 2, 3_000), id: 10 },
      { ...entry("C:\\logs\\app.log", 3, null), id: 11 },
    ]);

    expect(next.map((item) => item.message)).toEqual([
      "C:\\logs\\app.log:1",
      "C:\\logs\\ime.log:1",
      "C:\\logs\\app.log:2",
      "C:\\logs\\app.log:3",
      "C:\\logs\\ime.log:2",
    ]);
    expect(next[1]).toBe(merged[1]);
    expect(next[4]).toBe(merged[2]);
  });
});

describe("maxEntryEndLine", () => {
  it("returns the highest covered line, including multi-line records, never below the floor", () => {
    const rows = [
      { ...entry("C:\\logs\\app.log", 3, 1_000), message: "first\nsecond\nthird" },
      entry("C:\\logs\\app.log", 4, 2_000),
    ];

    expect(maxEntryEndLine(rows, 0)).toBe(5);
    expect(maxEntryEndLine(rows, 9)).toBe(9);
    expect(maxEntryEndLine([], 2)).toBe(2);
  });

  it("handles a batch larger than the engine's function-argument limit", () => {
    const rows = Array.from({ length: 300_000 }, (_, index) => entry("C:\\logs\\app.log", index + 1, index));

    expect(maxEntryEndLine(rows, 0)).toBe(300_000);
  });
});
