import { describe, expect, it } from "vitest";
import type { EvtxRecord } from "./types";
import {
  DEFAULT_EVTX_QUICK_FILTER,
  evtxMarkerFileKey,
  evtxMarkerKey,
  evtxMarkerLineId,
  evtxQuickFilterTerms,
} from "./evtx-marker-adapter";

function record(overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 42,
    timestamp: "2026-08-18 12:00:00",
    timestampEpoch: 1_000,
    provider: "Provider",
    channel: "Application",
    eventId: 100,
    level: "Error",
    computer: "PC01",
    message: "A setup failure happened",
    eventData: [{ name: "App", value: "setup.exe" }],
    rawXml: "<Event />",
    sourceLabel: "C:/Windows/System32/winevt/Logs/Application.evtx",
    ...overrides,
  };
}

describe("EVTX marker identity adapter", () => {
  it("uses source and provider record identity, never the mutable row id", () => {
    const original = record({ id: 1 });
    const reordered = record({ id: 999 });

    expect(evtxMarkerKey(original)).toBe(evtxMarkerKey(reordered));
    expect(evtxMarkerLineId(original)).toBe(evtxMarkerLineId(reordered));
    expect(evtxMarkerFileKey(original.sourceLabel)).toContain("event-log:");
  });

  it("separates equal record IDs from different source labels and channels", () => {
    const base = record({ eventRecordId: 7 });
    expect(evtxMarkerKey(base)).not.toBe(
      evtxMarkerKey(record({ eventRecordId: 7, sourceLabel: "System.evtx" }))
    );
    expect(evtxMarkerKey(base)).not.toBe(
      evtxMarkerKey(record({ eventRecordId: 7, channel: "System" }))
    );
  });
  it("derives display terms without changing the centralized match predicate", () => {
    const quickFilter = {
      ...DEFAULT_EVTX_QUICK_FILTER,
      mode: "allWords" as const,
      query: "setup failure",
      highlight: true,
    };
    expect(evtxQuickFilterTerms(quickFilter)).toEqual(["setup", "failure"]);
  });
});
