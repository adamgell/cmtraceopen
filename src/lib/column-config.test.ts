import { describe, expect, it } from "vitest";

import {
  getAutoExpandedColumnWidth,
  getAvailableColumnWidth,
  getColumnDef,
  getColumnsForParser,
} from "./column-config";
import type { LogEntry } from "../types/log";

function makeEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: 1,
    lineNumber: 1,
    message: "GET /default.htm → 200",
    component: null,
    timestamp: 0,
    timestampDisplay: "2026-03-29 18:48:23",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped",
    filePath: "C:/inetpub/logs/LogFiles/W3SVC1/u_ex260329.log",
    timezoneOffset: null,
    ...overrides,
  };
}

describe("column-config", () => {
  it("returns the IIS W3C default column set", () => {
    expect(getColumnsForParser("iisW3c")).toEqual([
      "severity",
      "dateTime",
      "message",
      "httpMethod",
      "uri",
      "statusCode",
      "clientIp",
      "timeTakenMs",
      "serverIp",
      "userAgent",
    ]);
  });

  it("builds the URI column from stem and query", () => {
    const uriColumn = getColumnDef("uri");
    expect(uriColumn).toBeDefined();

    expect(
      uriColumn?.accessor(
        makeEntry({
          uriStem: "/api/devices",
          uriQuery: "id=42",
        })
      )
    ).toBe("/api/devices?id=42");

    expect(
      uriColumn?.accessor(
        makeEntry({
          uriStem: "/healthz",
          uriQuery: null,
        })
      )
    ).toBe("/healthz");
  });

  it("auto-expands the message column only when auto-sizing still owns it", () => {
    // First auto-expansion grows beyond the default width.
    expect(getAutoExpandedColumnWidth(undefined, 920, 600, null)).toBe(920);
    // Smaller content should not shrink the default width.
    expect(getAutoExpandedColumnWidth(undefined, 520, 600, null)).toBeNull();
    // Once auto-sizing owns the column, wider content can grow it again.
    expect(getAutoExpandedColumnWidth(920, 1080, 600, 920)).toBe(1080);
    // A user resize after auto-sizing should block further automatic changes.
    expect(getAutoExpandedColumnWidth(760, 1080, 600, 920)).toBeNull();
    // Narrower content should not shrink an already auto-sized column.
    expect(getAutoExpandedColumnWidth(920, 880, 600, 920)).toBeNull();
    // Existing persisted/manual widths are treated as user-owned from the start.
    expect(getAutoExpandedColumnWidth(920, 1080, 600, null)).toBeNull();
  });
});

describe("fit-to-window clamping (#254)", () => {
  const columns = getColumnsForParser("simple").map((id) => getColumnDef(id)!);

  it("reports the width left for message after the other columns", () => {
    const total = columns
      .filter((col) => col.id !== "message")
      .reduce((sum, col) => sum + col.defaultWidth, 0);

    expect(getAvailableColumnWidth(columns, "message", total + 500)).toBe(500);
  });

  it("subtracts overridden widths rather than defaults", () => {
    const messageDef = getColumnDef("message")!;
    const other = columns.find((col) => col.id !== "message")!;
    const baseline = getAvailableColumnWidth(columns, "message", 2000)!;
    const widened = getAvailableColumnWidth(columns, "message", 2000, {
      [other.id]: other.defaultWidth + 100,
    })!;

    expect(widened).toBe(baseline - 100);
    expect(messageDef.id).toBe("message");
  });

  it("returns null when the container is unmeasured or the column is absent", () => {
    // 0 during first paint and in jsdom, which has no layout.
    expect(getAvailableColumnWidth(columns, "message", 0)).toBeNull();
    expect(getAvailableColumnWidth(columns, "message", Number.NaN)).toBeNull();
    expect(getAvailableColumnWidth(columns, "lineNumber", 2000)).toBeNull();
  });

  it("caps auto-expansion at the available width instead of the content width", () => {
    // Content wants 1100px but only 800px remains: take 800, not 1100.
    expect(
      getAutoExpandedColumnWidth(undefined, 1100, 600, null, {
        available: 800,
        minWidth: 100,
      })
    ).toBe(800);
  });

  it("shrinks below the default when the row would otherwise overflow", () => {
    // The real case from #254: 528px of fixed columns plus a 600px message
    // column needs 1128px, but the list is ~1000px wide. Capping growth alone
    // leaves the overflow, so the column must give up width too.
    expect(
      getAutoExpandedColumnWidth(undefined, 1100, 600, null, {
        available: 472,
        minWidth: 100,
      })
    ).toBe(472);
  });

  it("never shrinks past the column minimum", () => {
    // Below the floor a scrollbar is unavoidable; legibility wins.
    expect(
      getAutoExpandedColumnWidth(undefined, 1100, 600, null, {
        available: 40,
        minWidth: 100,
      })
    ).toBe(100);
    expect(
      getAutoExpandedColumnWidth(undefined, 1100, 600, null, {
        available: -50,
        minWidth: 100,
      })
    ).toBe(100);
  });

  it("still uses the content width when it is narrower than the space available", () => {
    expect(
      getAutoExpandedColumnWidth(undefined, 900, 600, null, {
        available: 1500,
        minWidth: 100,
      })
    ).toBe(900);
  });

  it("reports no change when the clamped target already matches", () => {
    expect(
      getAutoExpandedColumnWidth(600, 1100, 600, 600, {
        available: 600,
        minWidth: 100,
      })
    ).toBeNull();
  });

  it("keeps the unclamped grow-only behaviour when no bounds are supplied", () => {
    expect(getAutoExpandedColumnWidth(undefined, 1100, 600, null)).toBe(1100);
    expect(getAutoExpandedColumnWidth(undefined, 1100, 600, null, null)).toBe(1100);
    expect(getAutoExpandedColumnWidth(undefined, 520, 600, null, null)).toBeNull();
  });

  it("does not override a user-owned width even when space is available", () => {
    expect(
      getAutoExpandedColumnWidth(920, 1080, 600, null, {
        available: 2000,
        minWidth: 100,
      })
    ).toBeNull();
  });
});
