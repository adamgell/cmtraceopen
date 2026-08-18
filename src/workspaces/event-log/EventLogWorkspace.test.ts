import { describe, expect, it } from "vitest";

import { scopeLogEntries } from "./unified-timeline";
import type { LogEntry } from "../../types/log";

const entry = (filePath: string, message: string): LogEntry =>
  ({ filePath, message } as LogEntry);

describe("scopeLogEntries", () => {
  it("keeps every source entry in a merged tab even when active source is stale", () => {
    const entries = [
      entry("C:\\logs\\first.log", "first source"),
      entry("D:\\logs\\second.log", "second source"),
    ];

    expect(
      scopeLogEntries(entries, { kind: "file", path: "C:\\logs\\first.log" }, "merged")
    ).toEqual(entries);
  });

  it("scopes non-merged entries to the active source", () => {
    const entries = [
      entry("C:/logs/first.log", "first source"),
      entry("D:\\logs\\second.log", "second source"),
    ];

    expect(
      scopeLogEntries(entries, { kind: "file", path: "C:\\logs\\first.log" }, "single-file")
    ).toEqual([entries[0]]);
  });

  it("keeps aggregate entries when unrelated Windows volumes yield a root scope", () => {
    const entries = [
      entry("C:\\logs\\first.log", "first source"),
      entry("D:/logs/second.log", "second source"),
    ];

    expect(scopeLogEntries(entries, { kind: "folder", path: "/" }, "aggregate-folder")).toEqual(
      entries
    );
  });
});
