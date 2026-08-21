import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_CATEGORIES, type Marker } from "../types/markers";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
import { mergeLoadedFileMarkers, useMarkerStore } from "./marker-store";

function marker(lineId: number, category = "bug", identity?: string): Marker {
  return {
    lineId,
    ...(identity === undefined ? {} : { identity }),
    category,
    color: "#ef4444",
    added: "2026-08-19T00:00:00.000Z",
  };
}

describe("marker load merge", () => {
  beforeEach(() => {
    invoke.mockReset();
    useMarkerStore.setState({
      markersByFile: new Map(),
      categories: [...DEFAULT_CATEGORIES],
      activeCategory: "bug",
      loadingFiles: new Set(),
      clearRevisions: new Map(),
      createdTimestamps: new Map(),
    });
  });
  it("preserves edits made while a file load is in flight", () => {
    const loaded = new Map([[1, marker(1, "confirmed")]]);
    const initial = new Map([
      [1, marker(1)],
      [2, marker(2)],
    ]);
    const current = new Map([
      [1, marker(1, "investigate")],
      [3, marker(3)],
    ]);

    const merged = mergeLoadedFileMarkers(loaded, initial, current);

    expect([...merged.values()]).toEqual([marker(1, "investigate"), marker(3)]);
    expect(merged.has(2)).toBe(false);
  });

  it("preserves loaded and local markers when defined identities share a line hash", () => {
    const loaded = new Map([[42, marker(42, "bug", "identity-from-disk")]]);
    const initial = new Map([[42, marker(42, "bug", "identity-before")]]);
    const current = new Map([[42, marker(42, "bug", "identity-after")]]);

    const merged = mergeLoadedFileMarkers(loaded, initial, current);

    expect(merged.size).toBe(2);
    expect([...merged.values()].map((item) => item.identity)).toEqual([
      "identity-from-disk",
      "identity-after",
    ]);
    expect([...merged.keys()]).toEqual([42, 43]);
  });

  it("retains an unchanged local identity beside a loaded collision", () => {
    const loaded = new Map([[42, marker(42, "bug", "identity-from-disk")]]);
    const initial = new Map([[42, marker(42, "bug", "identity-local")]]);
    const current = new Map([[42, marker(42, "bug", "identity-local")]]);

    const merged = mergeLoadedFileMarkers(loaded, initial, current);

    expect(merged.size).toBe(2);
    expect([...merged.values()].map((item) => item.identity)).toEqual([
      "identity-from-disk",
      "identity-local",
    ]);
    expect([...merged.keys()]).toEqual([42, 43]);
  });
  it("rejects malformed backend payloads without replacing existing markers", async () => {
    const existing = new Map([[1, marker(1)]]);
    useMarkerStore.setState({
      markersByFile: new Map([["file.evtx", existing]]),
      loadingFiles: new Set(),
    });
    invoke.mockResolvedValue({ version: "invalid" });

    await useMarkerStore.getState().loadMarkers("file.evtx");

    expect(useMarkerStore.getState().markersByFile.get("file.evtx")).toBe(
      existing,
    );
    expect(useMarkerStore.getState().loadingFiles.has("file.evtx")).toBe(false);
  });
  it("rejects impossible calendar dates at the marker IPC boundary", async () => {
    const existing = new Map([[1, marker(1)]]);
    useMarkerStore.setState({
      markersByFile: new Map([["invalid-date.evtx", existing]]),
      loadingFiles: new Set(),
    });
    invoke.mockResolvedValue({
      version: 1,
      sourcePath: "invalid-date.evtx",
      sourceSize: 0,
      created: "2026-02-30T00:00:00.000Z",
      modified: "2026-02-28T00:00:00.000Z",
      markers: [],
      categories: [],
    });

    await useMarkerStore.getState().loadMarkers("invalid-date.evtx");

    expect(
      useMarkerStore.getState().markersByFile.get("invalid-date.evtx"),
    ).toBe(existing);
  });
  it("does not resurrect markers cleared while a load is pending", async () => {
    let resolveLoad: (value: unknown) => void = () => undefined;
    invoke.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLoad = resolve;
        }),
    );
    useMarkerStore.setState({
      markersByFile: new Map([["clear-race.evtx", new Map([[1, marker(1)]])]]),
      loadingFiles: new Set(),
      clearRevisions: new Map(),
    });
    const pending = useMarkerStore.getState().loadMarkers("clear-race.evtx");
    useMarkerStore.getState().clearMarkersForFile("clear-race.evtx");
    resolveLoad({
      version: 1,
      sourcePath: "clear-race.evtx",
      sourceSize: 0,
      created: "2026-08-19T00:00:00.000Z",
      modified: "2026-08-19T00:00:00.000Z",
      markers: [marker(2)],
      categories: [{ id: "bug", label: "Bug", color: "#ef4444" }],
    });
    await pending;
    expect(useMarkerStore.getState().markersByFile.has("clear-race.evtx")).toBe(
      false,
    );
  });
  it("preserves categories added while a load is pending", async () => {
    let resolveLoad: (value: unknown) => void = () => undefined;
    invoke.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLoad = resolve;
        }),
    );
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(),
      clearRevisions: new Map(),
    });

    const pending = useMarkerStore.getState().loadMarkers("category-race.evtx");
    useMarkerStore.getState().addCategory({
      id: "during-load",
      label: "During load",
      color: "#123456",
    });
    resolveLoad({
      version: 1,
      sourcePath: "category-race.evtx",
      sourceSize: 0,
      created: "2026-08-19T00:00:00.000Z",
      modified: "2026-08-19T00:00:00.000Z",
      markers: [],
      categories: [{ id: "bug", label: "Bug", color: "#ef4444" }],
    });

    await pending;

    expect(useMarkerStore.getState().categories).toEqual(
      expect.arrayContaining([
        { id: "bug", label: "Bug", color: "#ef4444" },
        { id: "during-load", label: "During load", color: "#123456" },
      ]),
    );
  });
  it("upgrades a legacy line marker when an EVTX identity is supplied", () => {
    const filePath = "event-log:legacy.evtx";
    useMarkerStore.setState({
      markersByFile: new Map([[filePath, new Map([[42, marker(42)]])]]),
    });

    useMarkerStore
      .getState()
      .setMarkerCategory(filePath, 42, "confirmed", "identity-a");

    const upgraded = useMarkerStore
      .getState()
      .markersByFile.get(filePath)
      ?.get(42);
    expect(upgraded).toMatchObject({
      identity: "identity-a",
      category: "confirmed",
    });
  });

  it("keeps colliding EVTX hashes separate by exact identity", () => {
    useMarkerStore.setState({
      markersByFile: new Map(),
      activeCategory: "bug",
    });
    const store = useMarkerStore.getState();
    store.toggleMarker("event-log:collision.evtx", 42, "identity-a");
    store.toggleMarker("event-log:collision.evtx", 42, "identity-b");

    const markers = useMarkerStore
      .getState()
      .markersByFile.get("event-log:collision.evtx");
    expect(markers?.size).toBe(2);
    expect([...markers!.values()].map((item) => item.identity)).toEqual([
      "identity-a",
      "identity-b",
    ]);

    useMarkerStore
      .getState()
      .toggleMarker("event-log:collision.evtx", 42, "identity-a");
    expect(
      useMarkerStore.getState().markersByFile.get("event-log:collision.evtx")
        ?.size,
    ).toBe(1);
    expect(
      [
        ...useMarkerStore
          .getState()
          .markersByFile.get("event-log:collision.evtx")!
          .values(),
      ][0].identity,
    ).toBe("identity-b");
  });
  it("retains duplicate persisted line hashes by allocating a distinct storage key", async () => {
    const filePath = "event-log:persisted-collision.evtx";
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(),
      clearRevisions: new Map(),
      createdTimestamps: new Map(),
    });
    invoke.mockResolvedValueOnce({
      version: 1,
      sourcePath: filePath,
      sourceSize: 0,
      created: "2026-08-19T00:00:00.000Z",
      modified: "2026-08-19T00:00:00.000Z",
      markers: [
        marker(42, "bug", "identity-a"),
        marker(42, "bug", "identity-b"),
      ],
      categories: [{ id: "bug", label: "Bug", color: "#ef4444" }],
    });
    await useMarkerStore.getState().loadMarkers(filePath);

    const loaded = useMarkerStore.getState().markersByFile.get(filePath);
    expect(loaded?.size).toBe(2);
    expect([...loaded!.values()].map((item) => item.identity)).toEqual([
      "identity-a",
      "identity-b",
    ]);
  });
  it("discards identity-less persisted collisions instead of hiding them", async () => {
    const filePath = "event-log:persisted-identity-collision.evtx";
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(),
      clearRevisions: new Map(),
      createdTimestamps: new Map(),
    });
    invoke.mockResolvedValueOnce({
      version: 1,
      sourcePath: filePath,
      sourceSize: 0,
      created: "2026-08-19T00:00:00.000Z",
      modified: "2026-08-19T00:00:00.000Z",
      markers: [marker(42, "bug", "identity-a"), marker(42, "confirmed")],
      categories: [{ id: "bug", label: "Bug", color: "#ef4444" }],
    });

    await useMarkerStore.getState().loadMarkers(filePath);

    const loaded = useMarkerStore.getState().markersByFile.get(filePath);
    expect(loaded?.size).toBe(1);
    expect(loaded?.get(42)).toMatchObject({
      identity: "identity-a",
      category: "bug",
    });
  });

  it("uses last-wins semantics for duplicate identity-less persisted markers", async () => {
    const filePath = "event-log:persisted-legacy-collision.evtx";
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(),
      clearRevisions: new Map(),
      createdTimestamps: new Map(),
    });
    invoke.mockResolvedValueOnce({
      version: 1,
      sourcePath: filePath,
      sourceSize: 0,
      created: "2026-08-19T00:00:00.000Z",
      modified: "2026-08-19T00:00:00.000Z",
      markers: [marker(42, "bug"), marker(42, "confirmed")],
      categories: [{ id: "bug", label: "Bug", color: "#ef4444" }],
    });

    await useMarkerStore.getState().loadMarkers(filePath);

    const loaded = useMarkerStore.getState().markersByFile.get(filePath);
    expect(loaded?.size).toBe(1);
    expect(loaded?.get(42)?.category).toBe("confirmed");
  });
});
