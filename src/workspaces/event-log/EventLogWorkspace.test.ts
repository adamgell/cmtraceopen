import { describe, expect, it } from "vitest";

import { normalizeLogPath, scopeLogEntries } from "./unified-timeline";
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
      scopeLogEntries(
        entries,
        { kind: "file", path: "C:\\logs\\first.log" },
        "merged",
        "windows",
      ),
    ).toEqual(entries);
  });

  it("scopes non-merged entries to the active source", () => {
    const entries = [
      entry("C:/logs/first.log", "first source"),
      entry("D:\\logs\\second.log", "second source"),
    ];

    expect(
      scopeLogEntries(
        entries,
        { kind: "file", path: "C:\\logs\\first.log" },
        "single-file",
        "windows",
      ),
    ).toEqual([entries[0]]);
  });

  it("matches case-insensitively on Windows", () => {
    const entries = [entry("C:\\Logs\\first.log", "matching source")];

    expect(
      scopeLogEntries(
        entries,
        { kind: "file", path: "c:\\logs\\first.log" },
        "single-file",
        "windows",
      ),
    ).toEqual(entries);
  });

  it.each(["macos", "linux"] as const)(
    "does not mix case-distinct sources on %s",
    (platform) => {
      const entries = [
        entry("/logs/first.log", "lowercase source"),
        entry("/Logs/first.log", "uppercase source"),
      ];

      expect(
        scopeLogEntries(
          entries,
          { kind: "file", path: "/logs/first.log" },
          "single-file",
          platform,
        ),
      ).toEqual([entries[0]]);
    },
  );

  it.each(["macos", "linux"] as const)(
    "does not treat a backslash in a %s file name as a separator",
    (platform) => {
      const entries = [
        entry("/logs/a\\b.log", "backslash file name"),
        entry("/logs/a/b.log", "nested file"),
      ];

      expect(
        scopeLogEntries(
          entries,
          { kind: "file", path: "/logs/a\\b.log" },
          "single-file",
          platform,
        ),
      ).toEqual([entries[0]]);
    },
  );

  it.each(["macos", "linux"] as const)(
    "does not treat a backslash in a %s folder name as a separator",
    (platform) => {
      const entries = [
        entry("/logs/a\\b/inside.log", "backslash folder name"),
        entry("/logs/a/b/inside.log", "nested folder"),
      ];

      expect(
        scopeLogEntries(
          entries,
          { kind: "folder", path: "/logs/a\\b" },
          "aggregate-folder",
          platform,
        ),
      ).toEqual([entries[0]]);
    },
  );

  it("keeps aggregate entries when unrelated Windows volumes yield a root scope", () => {
    const entries = [
      entry("C:\\logs\\first.log", "first source"),
      entry("D:/logs/second.log", "second source"),
    ];

    expect(
      scopeLogEntries(
        entries,
        { kind: "folder", path: "/" },
        "aggregate-folder",
        "windows",
      ),
    ).toEqual(entries);
  });
});

describe("normalizeLogPath", () => {
  it("takes either separator, collapses runs and ignores case and a trailing slash on Windows", () => {
    expect(normalizeLogPath("C:\\Logs\\\\Sub/A.LOG", "windows")).toBe("c:/logs/sub/a.log");
    expect(normalizeLogPath("C:\\Logs\\", "windows")).toBe("c:/logs");
  });

  it.each(["macos", "linux"] as const)(
    "keeps case, and treats a backslash as part of the name, on %s",
    (platform) => {
      expect(normalizeLogPath("/Logs//Sub/A.LOG/", platform)).toBe("/Logs/Sub/A.LOG");
      expect(normalizeLogPath("/logs/A.log", platform)).not.toBe(normalizeLogPath("/logs/a.log", platform));
      expect(normalizeLogPath("/logs/a\\b.log", platform)).toBe("/logs/a\\b.log");
    },
  );
});
