import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxRecord } from "./types";
import { DEFAULT_CATEGORIES, type Marker } from "../../types/markers";
import {
  DEFAULT_EVTX_QUICK_FILTER,
  evtxMarkerFileKey,
  evtxMarkerKey,
  evtxMarkerLineId,
  isEvtxMarkerAddressable,
  evtxQuickFilterTerms,
  getEvtxMarker,
  toggleEvtxBookmark,
  toggleEvtxTag,
} from "./evtx-marker-adapter";
import { useMarkerStore } from "../../stores/marker-store";

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
  beforeEach(() => {
    useMarkerStore.setState({
      markersByFile: new Map(),
      categories: [...DEFAULT_CATEGORIES],
      activeCategory: "bug",
      loadingFiles: new Set(),
      clearRevisions: new Map(),
      createdTimestamps: new Map(),
      saveMarkers: vi.fn().mockResolvedValue(undefined),
    });
  });
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
  it("keeps missing-ID records distinct across sources and raw XML occurrences", () => {
    const missingId = record({
      eventRecordId: 0,
      eventRecordIdText: "0",
      rawXml: "<Event><EventData><Data Name=\"App\">first.exe</Data></EventData></Event>",
    });
    const differentOccurrence = record({
      eventRecordId: 0,
      eventRecordIdText: "0",
      rawXml: "<Event><EventData><Data Name=\"App\">second.exe</Data></EventData></Event>",
    });
    const differentSource = record({
      eventRecordId: 0,
      eventRecordIdText: "0",
      sourceLabel: "System.evtx",
      rawXml: missingId.rawXml,
    });

    expect(evtxMarkerKey(missingId)).not.toBe(evtxMarkerKey(differentOccurrence));
    expect(evtxMarkerLineId(missingId)).not.toBe(evtxMarkerLineId(differentOccurrence));
    expect(evtxMarkerKey(missingId)).not.toBe(evtxMarkerKey(differentSource));
    expect(evtxMarkerLineId(missingId)).not.toBe(evtxMarkerLineId(differentSource));
  });

  it("keeps unaddressable render keys bounded and omits event payloads", () => {
    const secret = "sensitive-payload".repeat(10_000);
    const missingId = record({
      eventRecordId: 0,
      eventRecordIdText: "0",
      message: secret,
      rawXml: `<Event>${secret}</Event>`,
    });

    const key = evtxMarkerKey(missingId);

    expect(key.length).toBeLessThan(256);
    expect(key).not.toContain("sensitive-payload");
  });

  it("fails closed for byte-identical records without a producer ID", () => {
    const missing = record({ eventRecordId: 0, eventRecordIdText: "0" });
    const duplicate = { ...missing };
    const malformed = record({ eventRecordId: -1, eventRecordIdText: null });
    const saved: Marker = {
      lineId: evtxMarkerLineId(missing),
      identity: evtxMarkerKey(missing),
      category: "bug",
      color: "#ef4444",
      added: "2026-08-18T12:00:00Z",
    };
    const markers = new Map([
      [evtxMarkerFileKey(missing.sourceLabel), new Map([[saved.lineId, saved]])],
    ]);

    expect(isEvtxMarkerAddressable(missing)).toBe(false);
    expect(isEvtxMarkerAddressable(duplicate)).toBe(false);
    expect(isEvtxMarkerAddressable(malformed)).toBe(false);
    expect(getEvtxMarker(missing, markers)).toBeNull();
    expect(getEvtxMarker(duplicate, markers)).toBeNull();
  });

  it("uses lossless text IDs instead of a rounded numeric collision", () => {
    const first = record({
      eventRecordId: Number.MAX_SAFE_INTEGER,
      eventRecordIdText: "9007199254740993",
    });
    const second = record({
      eventRecordId: Number.MAX_SAFE_INTEGER,
      eventRecordIdText: "9007199254740995",
    });

    expect(evtxMarkerKey(first)).not.toBe(evtxMarkerKey(second));
    expect(evtxMarkerLineId(first)).not.toBe(evtxMarkerLineId(second));
  });

  it("normalizes equivalent numeric and lossless textual IDs across refetches", () => {
    const numeric = record({ eventRecordId: 42, eventRecordIdText: undefined });
    const textual = record({ eventRecordId: 42, eventRecordIdText: "00042" });

    expect(evtxMarkerKey(numeric)).toBe(evtxMarkerKey(textual));
  });

  it("does not resolve a colliding identity-bearing hash to another event", () => {
    const first = record({ eventRecordId: 10 });
    const other = record({ eventRecordId: 11 });
    const marker: Marker = {
      lineId: evtxMarkerLineId(first),
      identity: evtxMarkerKey(other),
      category: "bug",
      color: "#ef4444",
      added: "2026-08-18T12:00:00Z",
    };

    expect(
      getEvtxMarker(
        first,
        new Map([[evtxMarkerFileKey(first.sourceLabel), new Map([[marker.lineId, marker]])]])
      )
    ).toBeNull();
  });

  it("allocates a free storage key when creating through a colliding hash", () => {
    const first = record({ eventRecordId: 10 });
    const other = record({ eventRecordId: 11 });
    const occupied: Marker = {
      lineId: evtxMarkerLineId(first),
      identity: evtxMarkerKey(other),
      category: "bug",
      color: "#ef4444",
      added: "2026-08-18T12:00:00Z",
    };
    const fileKey = evtxMarkerFileKey(first.sourceLabel);
    useMarkerStore.setState({
      markersByFile: new Map([[fileKey, new Map([[occupied.lineId, occupied]])]]),
    });

    toggleEvtxTag(first);

    const markers = useMarkerStore.getState().markersByFile.get(fileKey);
    expect(markers?.size).toBe(2);
    expect(markers?.get(occupied.lineId)?.identity).toBe(occupied.identity);
    const created = [...(markers?.values() ?? [])].find(
      (item) => item.identity === evtxMarkerKey(first)
    );
    expect(created?.lineId).not.toBe(occupied.lineId);
  });

  it("keeps a marker attached when source records are reordered", () => {
    const first = record({ id: 1, eventRecordId: 7 });
    const reordered = record({ id: 99, eventRecordId: 7 });
    const saved: Marker = {
      lineId: evtxMarkerLineId(first),
      identity: evtxMarkerKey(first),
      category: "bug",
      color: "#ef4444",
      added: "2026-08-18T12:00:00Z",
    };

    expect(evtxMarkerKey(first)).toBe(evtxMarkerKey(reordered));
    expect(
      getEvtxMarker(
        reordered,
        new Map([[evtxMarkerFileKey(reordered.sourceLabel), new Map([[saved.lineId, saved]])]])
      )
    ).toEqual(saved);
  });

  it("keeps exact structured identity when mutating an addressable marker", () => {
    const current = record({ eventRecordId: 42 });
    const lineId = evtxMarkerLineId(current);
    const identity = evtxMarkerKey(current);
    const saved: Marker = {
      lineId,
      identity,
      category: "bookmark",
      color: "#8b5cf6",
      added: "2026-08-18T12:00:00Z",
    };
    useMarkerStore.setState({
      markersByFile: new Map([
        [evtxMarkerFileKey(current.sourceLabel), new Map([[lineId, saved]])],
      ]),
      activeCategory: "bug",
      saveMarkers: vi.fn().mockResolvedValue(undefined),
    });

    toggleEvtxTag(current);

    expect(
      useMarkerStore
        .getState()
        .markersByFile.get(evtxMarkerFileKey(current.sourceLabel))
        ?.get(lineId)
    ).toMatchObject({ category: "bug", identity });
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
