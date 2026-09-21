import { describe, expect, it } from "vitest";

import { mergeEntries } from "./merge-entries";
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
