import { describe, expect, it, vi } from "vitest";
import type { Marker } from "../types/markers";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { mergeLoadedFileMarkers, useMarkerStore } from "./marker-store";

function marker(lineId: number, category = "bug"): Marker {
  return { lineId, category, color: "#ef4444", added: "2026-08-19T00:00:00.000Z" };
}

describe("marker load merge", () => {
  it("preserves edits made while a file load is in flight", () => {
    const loaded = new Map([[1, marker(1, "confirmed")]]);
    const initial = new Map([[1, marker(1)], [2, marker(2)] ]);
    const current = new Map([[1, marker(1, "investigate")], [3, marker(3)] ]);

    const merged = mergeLoadedFileMarkers(loaded, initial, current);

    expect([...merged.values()]).toEqual([
      marker(1, "investigate"),
      marker(3),
    ]);
    expect(merged.has(2)).toBe(false);
  });

  it("rejects malformed backend payloads without replacing existing markers", async () => {
    const existing = new Map([[1, marker(1)]]);
    useMarkerStore.setState({
      markersByFile: new Map([["file.evtx", existing]]),
      loadingFiles: new Set(),
    });
    invoke.mockResolvedValue({ version: "invalid" });

    await useMarkerStore.getState().loadMarkers("file.evtx");

    expect(useMarkerStore.getState().markersByFile.get("file.evtx")).toBe(existing);
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

    expect(useMarkerStore.getState().markersByFile.get("invalid-date.evtx")).toBe(existing);
  });
  it("does not resurrect markers cleared while a load is pending", async () => {
    let resolveLoad: (value: unknown) => void = () => undefined;
    invoke.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLoad = resolve;
        })
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
    expect(useMarkerStore.getState().markersByFile.has("clear-race.evtx")).toBe(false);
  });
  it("preserves categories added while a load is pending", async () => {
    let resolveLoad: (value: unknown) => void = () => undefined;
    invoke.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLoad = resolve;
        })
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
      ])
    );
  });
});