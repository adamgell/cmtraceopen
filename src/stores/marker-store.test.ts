import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_CATEGORIES,
  type Marker,
  type MarkerFile,
} from "../types/markers";
import { deferred } from "../test-utils/deferred";

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

function markerFile(filePath: string, markers: Marker[]): MarkerFile {
  return {
    version: 1,
    sourcePath: filePath,
    sourceSize: 0,
    created: "2026-08-19T00:00:00.000Z",
    modified: "2026-08-19T00:00:00.000Z",
    markers,
    categories: [...DEFAULT_CATEGORIES],
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
      markerPersistenceByFile: new Map(),
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

    const outcome = await useMarkerStore.getState().loadMarkers("file.evtx");

    expect(outcome).toBe("failed");
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

    const outcome = await useMarkerStore
      .getState()
      .loadMarkers("invalid-date.evtx");

    expect(outcome).toBe("failed");
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
    const outcome = await pending;
    expect(outcome).toBe("superseded");
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

  it("reports a missing marker file as a successful load outcome", async () => {
    invoke.mockResolvedValue(null);

    const outcome = await useMarkerStore
      .getState()
      .loadMarkers("missing.evtx");

    expect(outcome).toBe("missing");
  });

  it("caches a successful marker read for repeated requests in one persistence session", async () => {
    const filePath = "cached-load.log";
    invoke.mockResolvedValue(null);

    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "missing",
    );
    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "missing",
    );
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("reloads a marker file after its persistence session state is replaced", async () => {
    const filePath = "fresh-persistence-session.log";
    invoke
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(markerFile(filePath, [marker(1)]));

    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "missing",
    );
    useMarkerStore.setState({ markerPersistenceByFile: new Map() });
    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "loaded",
    );
    expect(invoke).toHaveBeenCalledTimes(2);
  });

  it("reports backend load rejection as a failed outcome", async () => {
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    invoke.mockRejectedValue(new Error("marker file is unreadable"));

    const outcome = await useMarkerStore
      .getState()
      .loadMarkers("unreadable.evtx");

    expect(outcome).toBe("failed");
    expect(consoleError).toHaveBeenCalledOnce();
    consoleError.mockRestore();
  });

  it("reports successful and failed marker persistence outcomes", async () => {
    const filePath = "save-outcome.evtx";
    useMarkerStore.setState({
      markersByFile: new Map([[filePath, new Map([[1, marker(1)]])]]),
    });
    invoke.mockResolvedValueOnce(null).mockResolvedValueOnce(undefined);

    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "saved",
    );

    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    invoke.mockRejectedValueOnce(new Error("marker write failed"));
    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "failed",
    );
    expect(consoleError).toHaveBeenCalledOnce();
    consoleError.mockRestore();
  });

  it("reports successful and failed marker deletion outcomes", async () => {
    const filePath = "delete-outcome.evtx";
    invoke.mockResolvedValueOnce(null).mockResolvedValueOnce(undefined);

    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "deleted",
    );

    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    invoke.mockRejectedValueOnce(new Error("marker delete failed"));
    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "failed",
    );
    expect(consoleError).toHaveBeenCalledOnce();
    consoleError.mockRestore();
  });

  it("blocks a generic save after read failure until a successful retry merges the dirty marker", async () => {
    const filePath = "generic-failed-load.log";
    const diskMarker = marker(1, "confirmed", "disk-marker");
    const localMarker = marker(2, "bug", "local-marker");
    let loadAttempts = 0;
    const writes: MarkerFile[] = [];
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    invoke.mockImplementation(
      (command: string, args?: { markerFile?: MarkerFile }) => {
        if (command === "load_markers") {
          loadAttempts += 1;
          return loadAttempts === 1
            ? Promise.reject(new Error("marker file is unreadable"))
            : Promise.resolve(markerFile(filePath, [diskMarker]));
        }
        if (command === "save_markers" && args?.markerFile) {
          writes.push(args.markerFile);
          return Promise.resolve(undefined);
        }
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      },
    );

    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "failed",
    );
    useMarkerStore
      .getState()
      .toggleMarker(filePath, localMarker.lineId, localMarker.identity);

    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "failed",
    );
    expect(loadAttempts).toBe(1);
    expect(writes).toEqual([]);

    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "loaded",
    );
    expect(writes).toHaveLength(1);
    expect(writes[0].markers.map((item) => item.identity)).toEqual([
      "disk-marker",
      "local-marker",
    ]);
    consoleError.mockRestore();
  });

  it("preserves a same-identity category edit made before the first marker read", async () => {
    const filePath = "generic-preload-category.log";
    const writes: MarkerFile[] = [];
    invoke.mockImplementation(
      (command: string, args?: { markerFile?: MarkerFile }) => {
        if (command === "load_markers") {
          return Promise.resolve(
            markerFile(filePath, [marker(1, "confirmed", "same-record")]),
          );
        }
        if (command === "save_markers" && args?.markerFile) {
          writes.push(args.markerFile);
          return Promise.resolve(undefined);
        }
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      },
    );

    useMarkerStore.getState().toggleMarker(filePath, 1, "same-record");
    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe("saved");

    expect(writes).toHaveLength(1);
    expect(writes[0].markers).toMatchObject([
      { identity: "same-record", category: "bug" },
    ]);
  });

  it("preserves a same-identity removal made before the first marker read", async () => {
    const filePath = "generic-preload-removal.log";
    const residentMarker = marker(1, "confirmed", "same-record");
    const commands: string[] = [];
    useMarkerStore.setState({
      markersByFile: new Map([
        [filePath, new Map([[residentMarker.lineId, residentMarker]])],
      ]),
    });
    invoke.mockImplementation((command: string) => {
      commands.push(command);
      if (command === "load_markers") {
        return Promise.resolve(markerFile(filePath, [residentMarker]));
      }
      if (command === "delete_markers") return Promise.resolve(undefined);
      if (command === "save_markers") return Promise.resolve(undefined);
      return Promise.reject(new Error(`Unexpected marker command: ${command}`));
    });

    useMarkerStore.getState().removeMarker(filePath, 1, "same-record");
    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "deleted",
    );

    expect(commands).toEqual(["load_markers", "delete_markers"]);
    expect(useMarkerStore.getState().markersByFile.get(filePath)?.size).toBe(0);
  });

  it("does not restore disk markers after a clear made before the first marker read", async () => {
    const filePath = "generic-preload-clear.log";
    const commands: string[] = [];
    invoke.mockImplementation((command: string) => {
      commands.push(command);
      if (command === "load_markers") {
        return Promise.resolve(
          markerFile(filePath, [marker(1, "confirmed", "disk-record")]),
        );
      }
      if (command === "delete_markers") return Promise.resolve(undefined);
      if (command === "save_markers") return Promise.resolve(undefined);
      return Promise.reject(new Error(`Unexpected marker command: ${command}`));
    });

    useMarkerStore.getState().clearMarkersForFile(filePath);
    expect(await useMarkerStore.getState().saveMarkers(filePath)).toBe(
      "deleted",
    );

    expect(commands).toEqual(["load_markers", "delete_markers"]);
    expect(useMarkerStore.getState().markersByFile.get(filePath)?.size).toBe(0);
  });

  it("lets the first disk read replace clean resident state", async () => {
    const filePath = "generic-preload-clean.log";
    useMarkerStore.setState({
      markersByFile: new Map([
        [filePath, new Map([[1, marker(1, "bug", "same-record")]])],
      ]),
    });
    invoke.mockResolvedValue(
      markerFile(filePath, [marker(1, "confirmed", "same-record")]),
    );

    expect(await useMarkerStore.getState().loadMarkers(filePath)).toBe(
      "loaded",
    );
    expect(
      useMarkerStore.getState().markersByFile.get(filePath)?.get(1)?.category,
    ).toBe("confirmed");
  });

  it("serializes direct generic save requests so an older snapshot cannot finish last", async () => {
    const filePath = "generic-save-order.log";
    const firstWrite = deferred<void>();
    const writes: MarkerFile[] = [];
    invoke.mockImplementation(
      (command: string, args?: { markerFile?: MarkerFile }) => {
        if (command === "load_markers") return Promise.resolve(null);
        if (command === "save_markers" && args?.markerFile) {
          writes.push(args.markerFile);
          return writes.length === 1
            ? firstWrite.promise
            : Promise.resolve(undefined);
        }
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      },
    );
    await useMarkerStore.getState().loadMarkers(filePath);
    useMarkerStore.getState().toggleMarker(filePath, 1, "first");

    const firstSave = useMarkerStore.getState().saveMarkers(filePath);
    await vi.waitFor(() => expect(writes).toHaveLength(1));
    useMarkerStore.getState().toggleMarker(filePath, 2, "second");
    const secondSave = useMarkerStore.getState().saveMarkers(filePath);

    await Promise.resolve();
    expect(writes).toHaveLength(1);
    firstWrite.resolve();
    await Promise.all([firstSave, secondSave]);

    expect(
      writes.map((item) => item.markers.map((entry) => entry.identity)),
    ).toEqual([["first"], ["first", "second"]]);
  });

  it("persists a trailing snapshot when a marker changes during a generic save", async () => {
    const filePath = "generic-save-mutation.log";
    const firstWrite = deferred<void>();
    const writes: MarkerFile[] = [];
    invoke.mockImplementation(
      (command: string, args?: { markerFile?: MarkerFile }) => {
        if (command === "load_markers") return Promise.resolve(null);
        if (command === "save_markers" && args?.markerFile) {
          writes.push(args.markerFile);
          return writes.length === 1
            ? firstWrite.promise
            : Promise.resolve(undefined);
        }
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      },
    );
    await useMarkerStore.getState().loadMarkers(filePath);
    useMarkerStore.getState().toggleMarker(filePath, 1, "first");

    const saving = useMarkerStore.getState().saveMarkers(filePath);
    await vi.waitFor(() => expect(writes).toHaveLength(1));
    useMarkerStore.getState().toggleMarker(filePath, 2, "second");
    firstWrite.resolve();
    await saving;

    expect(
      writes.map((item) => item.markers.map((entry) => entry.identity)),
    ).toEqual([["first"], ["first", "second"]]);
  });

  it("honors a load retry requested while the previous load is still in flight", async () => {
    const filePath = "generic-inflight-load-retry.log";
    const firstLoad = deferred<MarkerFile | null>();
    let loadAttempts = 0;
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    invoke.mockImplementation((command: string) => {
      if (command !== "load_markers") {
        return Promise.reject(
          new Error(`Unexpected marker command: ${command}`),
        );
      }
      loadAttempts += 1;
      return loadAttempts === 1
        ? firstLoad.promise
        : Promise.resolve(markerFile(filePath, [marker(7)]));
    });

    const firstRequest = useMarkerStore.getState().loadMarkers(filePath);
    const retryRequest = useMarkerStore.getState().loadMarkers(filePath);
    firstLoad.reject(new Error("transient marker read failure"));

    expect(await firstRequest).toBe("failed");
    expect(await retryRequest).toBe("loaded");
    expect(loadAttempts).toBe(2);
    expect(useMarkerStore.getState().markersByFile.get(filePath)?.size).toBe(1);
    consoleError.mockRestore();
  });

  it("retries a failed delete when a load request arrives during the delete", async () => {
    const filePath = "generic-delete-retry.log";
    const firstDelete = deferred<void>();
    let deleteAttempts = 0;
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    invoke.mockImplementation((command: string) => {
      if (command === "load_markers") {
        return Promise.resolve(markerFile(filePath, [marker(1)]));
      }
      if (command === "delete_markers") {
        deleteAttempts += 1;
        return deleteAttempts === 1
          ? firstDelete.promise
          : Promise.resolve(undefined);
      }
      return Promise.reject(new Error(`Unexpected marker command: ${command}`));
    });
    await useMarkerStore.getState().loadMarkers(filePath);
    useMarkerStore.getState().removeMarker(filePath, 1);

    const deleting = useMarkerStore.getState().saveMarkers(filePath);
    await vi.waitFor(() => expect(deleteAttempts).toBe(1));
    const retrying = useMarkerStore.getState().loadMarkers(filePath);
    firstDelete.reject(new Error("transient marker delete failure"));

    expect(await deleting).toBe("failed");
    expect(await retrying).toBe("loaded");
    expect(deleteAttempts).toBe(2);
    expect(useMarkerStore.getState().markersByFile.get(filePath)?.size).toBe(0);
    expect(consoleError).toHaveBeenCalledOnce();
    consoleError.mockRestore();
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
    const outcome = await useMarkerStore.getState().loadMarkers(filePath);

    expect(outcome).toBe("loaded");
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
