import { describe, expect, it } from "vitest";
import {
  EVTX_EXPORT_FORMATS,
  exportPayload,
  isValidExportByteCount,
} from "./evtx-export";
import type { EvtxRecord } from "./types";

const record = (partial: Partial<EvtxRecord> = {}): EvtxRecord => ({
  id: 1,
  eventRecordId: 2,
  timestamp: "2026-08-09T12:00:00Z",
  timestampEpoch: 0,
  provider: "Provider",
  channel: "Application",
  eventId: 326,
  level: "Error",
  computer: "HOST",
  message: "event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "events.evtx",
  ...partial,
});

describe("event export invocation", () => {
  it("offers every backend format, including HTML and raw XML", () => {
    expect(EVTX_EXPORT_FORMATS.map((format) => format.value)).toEqual([
      "csv",
      "tsv",
      "json",
      "xml",
      "html",
      "rawXml",
    ]);
  });

  it("omits payload-heavy fields only for formats that do not serialize them", () => {
    const input = [record()];
    expect(exportPayload("csv", input)[0]).not.toHaveProperty("rawXml");
    expect(exportPayload("csv", input)[0]).not.toHaveProperty("eventData");
    expect(exportPayload("html", input)[0]).toHaveProperty("rawXml");
    expect(exportPayload("rawXml", input)[0]).toHaveProperty("rawXml");
  });

  it("rejects malformed IPC byte counts instead of claiming success", () => {
    expect(isValidExportByteCount(0)).toBe(true);
    expect(isValidExportByteCount(Number.MAX_SAFE_INTEGER)).toBe(true);
    expect(isValidExportByteCount(Number.NaN)).toBe(false);
    expect(isValidExportByteCount(-1)).toBe(false);
    expect(isValidExportByteCount("1024")).toBe(false);
  });
});
