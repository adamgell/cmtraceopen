import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxRecord } from "./types";
import {
  DEFAULT_CATEGORIES,
  type Marker,
  type MarkerFile,
} from "../../types/markers";
import { deferred } from "../../test-utils/deferred";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  DEFAULT_EVTX_QUICK_FILTER,
  evtxMarkerFileKey,
  evtxMarkerKey,
  evtxMarkerLineId,
  isEvtxMarkerAddressable,
  evtxQuickFilterTerms,
  getEvtxMarker,
  loadEvtxMarkers,
  toggleEvtxTag,
} from "./evtx-marker-adapter";
import { useMarkerStore } from "../../stores/marker-store";

const productionLoadMarkers = useMarkerStore.getState().loadMarkers;
const productionSaveMarkers = useMarkerStore.getState().saveMarkers;

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

function markerFile(sourceLabel: string, markers: Marker[]): MarkerFile {
  return {
    version: 1,
    sourcePath: evtxMarkerFileKey(sourceLabel),
    sourceSize: 0,
    created: "2026-08-18T10:00:00.000Z",
    modified: "2026-08-18T11:00:00.000Z",
    markers,
    categories: [...DEFAULT_CATEGORIES],
  };
}

describe("EVTX marker identity adapter", () => {
  beforeEach(() => {
    invoke.mockReset();
    useMarkerStore.setState({
      markersByFile: new Map(),
      categories: [...DEFAULT_CATEGORIES],
      activeCategory: "bug",
      loadingFiles: new Set(),
      clearRevisions: new Map(),
      createdTimestamps: new Map(),
      markerPersistenceByFile: new Map(),
      loadMarkers: vi.fn().mockResolvedValue("missing"),
      saveMarkers: vi.fn().mockResolvedValue("saved"),
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
      saveMarkers: vi.fn().mockResolvedValue("saved"),
    });

    toggleEvtxTag(current);

    expect(
      useMarkerStore
        .getState()
        .markersByFile.get(evtxMarkerFileKey(current.sourceLabel))
        ?.get(lineId)
    ).toMatchObject({ category: "bug", identity });
  });

  it("persists loaded disk markers together with an edit made while loading", async () => {
    const sourceLabel = "marker-load-save-race.evtx";
    const diskRecord = record({ sourceLabel, eventRecordId: 41 });
    const editedRecord = record({ sourceLabel, eventRecordId: 42 });
    const diskMarker: Marker = {
      lineId: evtxMarkerLineId(diskRecord),
      identity: evtxMarkerKey(diskRecord),
      category: "confirmed",
      color: "#22c55e",
      added: "2026-08-18T11:00:00Z",
    };
    const pendingLoad = deferred<MarkerFile | null>();
    const persistedSnapshots: Marker[][] = [];

    useMarkerStore.setState({
      loadMarkers: productionLoadMarkers,
      saveMarkers: productionSaveMarkers,
    });
    invoke.mockImplementation(
      (command: string, args?: { markerFile?: MarkerFile }) => {
        if (command === "load_markers") return pendingLoad.promise;
        if (command === "save_markers" && args?.markerFile) {
          persistedSnapshots.push(args.markerFile.markers);
          return Promise.resolve(undefined);
        }
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      },
    );

    loadEvtxMarkers([sourceLabel]);
    toggleEvtxTag(editedRecord);

    await Promise.resolve();
    expect(persistedSnapshots).toEqual([]);

    pendingLoad.resolve(markerFile(sourceLabel, [diskMarker]));
    await vi.waitFor(() => expect(persistedSnapshots).toHaveLength(1));

    expect(persistedSnapshots[0].map((marker) => marker.identity)).toEqual([
      evtxMarkerKey(diskRecord),
      evtxMarkerKey(editedRecord),
    ]);
  });

  it("blocks writes after load failure and flushes the dirty edit after retry", async () => {
    const sourceLabel = "failed-load-retry.evtx";
    const fileKey = evtxMarkerFileKey(sourceLabel);
    const diskRecord = record({ sourceLabel, eventRecordId: 41 });
    const editedRecord = record({ sourceLabel, eventRecordId: 42 });
    const diskMarker: Marker = {
      lineId: evtxMarkerLineId(diskRecord),
      identity: evtxMarkerKey(diskRecord),
      category: "confirmed",
      color: "#22c55e",
      added: "2026-08-18T10:00:00.000Z",
    };
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    useMarkerStore.setState({
      loadMarkers: productionLoadMarkers,
      saveMarkers: productionSaveMarkers,
    });
    invoke.mockRejectedValueOnce(new Error("marker file is unreadable"));

    loadEvtxMarkers([sourceLabel]);
    toggleEvtxTag(editedRecord);

    await vi.waitFor(() =>
      expect(
        invoke.mock.calls.some(([command]) => command === "load_markers"),
      ).toBe(true),
    );
    await vi.waitFor(() =>
      expect(useMarkerStore.getState().loadingFiles.has(fileKey)).toBe(false),
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(
      invoke.mock.calls.filter(
        ([command]) =>
          command === "save_markers" || command === "delete_markers",
      ),
    ).toEqual([]);
    expect(
      [
        ...(
          useMarkerStore.getState().markersByFile.get(fileKey) ?? new Map()
        ).values(),
      ].map((marker) => marker.identity),
    ).toEqual([evtxMarkerKey(editedRecord)]);

    invoke
      .mockResolvedValueOnce(markerFile(sourceLabel, [diskMarker]))
      .mockResolvedValueOnce(undefined);
    loadEvtxMarkers([sourceLabel]);

    await vi.waitFor(() =>
      expect(
        invoke.mock.calls.filter(([command]) => command === "save_markers"),
      ).toHaveLength(1),
    );

    const saveCall = invoke.mock.calls.find(
      ([command]) => command === "save_markers",
    );
    expect(
      (saveCall?.[1] as { markerFile: MarkerFile }).markerFile.markers.map(
        (marker) => marker.identity,
      ),
    ).toEqual([evtxMarkerKey(diskRecord), evtxMarkerKey(editedRecord)]);
    expect(
      invoke.mock.calls.filter(([command]) => command === "delete_markers"),
    ).toEqual([]);
    consoleError.mockRestore();
  });

  it("loads before persisting when mutation precedes the load effect", async () => {
    const sourceLabel = "persist-before-effect.evtx";
    const editedRecord = record({ sourceLabel, eventRecordId: 51 });
    useMarkerStore.setState({
      loadMarkers: productionLoadMarkers,
      saveMarkers: productionSaveMarkers,
    });
    invoke.mockResolvedValueOnce(null).mockResolvedValueOnce(undefined);

    toggleEvtxTag(editedRecord);

    await vi.waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));
    expect(invoke.mock.calls.map(([command]) => command)).toEqual([
      "load_markers",
      "save_markers",
    ]);
    expect(
      (
        invoke.mock.calls[1][1] as { markerFile: MarkerFile }
      ).markerFile.markers.map((marker) => marker.identity),
    ).toEqual([evtxMarkerKey(editedRecord)]);
  });

  it("persists a newer mutation after an older save settles", async () => {
    const sourceLabel = "marker-save-version.evtx";
    const firstRecord = record({ sourceLabel, eventRecordId: 61 });
    const secondRecord = record({ sourceLabel, eventRecordId: 62 });
    const firstSave = deferred<void>();
    const persistedSnapshots: MarkerFile[] = [];
    useMarkerStore.setState({
      loadMarkers: productionLoadMarkers,
      saveMarkers: productionSaveMarkers,
    });
    invoke.mockImplementation(
      (command: string, args?: { markerFile?: MarkerFile }) => {
        if (command === "load_markers") return Promise.resolve(null);
        if (command === "save_markers" && args?.markerFile) {
          persistedSnapshots.push(args.markerFile);
          return persistedSnapshots.length === 1
            ? firstSave.promise
            : Promise.resolve(undefined);
        }
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      },
    );

    toggleEvtxTag(firstRecord);
    await vi.waitFor(() => expect(persistedSnapshots).toHaveLength(1));
    toggleEvtxTag(secondRecord);

    expect(persistedSnapshots).toHaveLength(1);
    firstSave.resolve();
    await vi.waitFor(() => expect(persistedSnapshots).toHaveLength(2));

    expect(
      persistedSnapshots.map((snapshot) =>
        snapshot.markers.map((marker) => marker.identity),
      ),
    ).toEqual([
      [evtxMarkerKey(firstRecord)],
      [evtxMarkerKey(firstRecord), evtxMarkerKey(secondRecord)],
    ]);
  });

  it("retains a dirty marker after save failure and retries it on the next load request", async () => {
    const sourceLabel = "failed-save-retry.evtx";
    const editedRecord = record({ sourceLabel, eventRecordId: 71 });
    let saveAttempts = 0;
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    useMarkerStore.setState({
      loadMarkers: productionLoadMarkers,
      saveMarkers: productionSaveMarkers,
    });
    invoke.mockImplementation((command: string) => {
      if (command === "load_markers") return Promise.resolve(null);
      if (command === "save_markers") {
        saveAttempts += 1;
        return saveAttempts === 1
          ? Promise.reject(new Error("marker write failed"))
          : Promise.resolve(undefined);
      }
      return Promise.reject(new Error(`Unexpected marker command: ${command}`));
    });

    toggleEvtxTag(editedRecord);
    await vi.waitFor(() => expect(saveAttempts).toBe(1));
    loadEvtxMarkers([sourceLabel]);
    await vi.waitFor(() => expect(saveAttempts).toBe(2));

    expect(
      useMarkerStore.getState().markersByFile.get(evtxMarkerFileKey(sourceLabel))
        ?.size,
    ).toBe(1);
    expect(consoleError).toHaveBeenCalledOnce();
    consoleError.mockRestore();
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

  it.each(["Boot\rcompleted", "Boot\r\ncompleted"])(
    "derives highlight terms from carriage-return string separators: %j",
    (query) => {
      expect(
        evtxQuickFilterTerms({
          ...DEFAULT_EVTX_QUICK_FILTER,
          mode: "allStrings",
          query,
          highlight: true,
        }),
      ).toEqual(["Boot", "completed"]);
    },
  );
});
