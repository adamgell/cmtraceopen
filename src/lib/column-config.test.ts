import { describe, expect, it } from "vitest";

import { getColumnDef, getColumnsForParser } from "./column-config";
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
});
