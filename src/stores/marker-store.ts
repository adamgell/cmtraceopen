import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { loadMarkerFile } from "../lib/commands";
import {
  type Marker,
  type MarkerCategory,
  type MarkerFile,
  DEFAULT_CATEGORIES,
} from "../types/markers";

// ── State shape ───────────────────────────────────────────────────────────────

interface MarkerState {
  /** Markers keyed by file path, then by line ID. */
  markersByFile: Map<string, Map<number, Marker>>;
  /** Shared categories across all files. */
  categories: MarkerCategory[];
  /** Category ID used when toggling a new marker on. */
  activeCategory: string;
  /** File paths currently being loaded from the backend. */
  loadingFiles: Set<string>;
  /** Per-file tombstones prevent in-flight loads from resurrecting a cleared file. */
  clearRevisions: Map<string, number>;
  /** Preserved `created` timestamps per file path (from loaded marker files). */
  createdTimestamps: Map<string, string>;

  // ── Async backend actions ─────────────────────────────────────────────────
  loadMarkers: (filePath: string) => Promise<void>;
  saveMarkers: (filePath: string) => Promise<void>;

  // ── Marker mutation actions ───────────────────────────────────────────────
  toggleMarker: (filePath: string, lineId: number) => void;
  setMarkerCategory: (filePath: string, lineId: number, category: string) => void;
  removeMarker: (filePath: string, lineId: number) => void;
  clearMarkersForFile: (filePath: string) => void;

  // ── Category actions ──────────────────────────────────────────────────────
  setActiveCategory: (category: string) => void;
  addCategory: (category: MarkerCategory) => void;

  // ── Selectors ─────────────────────────────────────────────────────────────
  getMarkersForFile: (filePath: string) => Map<number, Marker>;
  getMarkedLineIds: (filePath: string, category?: string) => number[];
}
function markersEqual(left: Marker | undefined, right: Marker | undefined): boolean {
  return (
    left?.lineId === right?.lineId &&
    left?.category === right?.category &&
    left?.color === right?.color &&
    left?.added === right?.added
  );
}


export function mergeLoadedFileMarkers(
  loaded: Map<number, Marker>,
  initial: ReadonlyMap<number, Marker>,
  current: ReadonlyMap<number, Marker> | undefined
): Map<number, Marker> {
  const merged = new Map(loaded);
  const ids = new Set([...initial.keys(), ...(current?.keys() ?? [])]);
  for (const lineId of ids) {
    const before = initial.get(lineId);
    const after = current?.get(lineId);
    if (markersEqual(before, after)) continue;
    if (after) merged.set(lineId, after);
    else merged.delete(lineId);
  }
  return merged;
}

// ── Store implementation ──────────────────────────────────────────────────────

export const useMarkerStore = create<MarkerState>((set, get) => ({
  markersByFile: new Map(),
  categories: [...DEFAULT_CATEGORIES],
  activeCategory: "bug",
  loadingFiles: new Set(),
  clearRevisions: new Map(),
  createdTimestamps: new Map(),

  // ── loadMarkers ─────────────────────────────────────────────────────────
  loadMarkers: async (filePath) => {
    const { loadingFiles, markersByFile, clearRevisions, categories } = get();

    // Guard against duplicate in-flight loads.
    if (loadingFiles.has(filePath)) {
      return;
    }
    // Edits made after this snapshot but before the backend responds must win over stale disk
    // state, including edits made when the file had no map yet.
    const initialFileMap = new Map(markersByFile.get(filePath) ?? []);
    const initialCategories = [...categories];
    const clearRevision = clearRevisions.get(filePath) ?? 0;

    set((state) => ({
      loadingFiles: new Set([...state.loadingFiles, filePath]),
    }));

    try {
      const result = await loadMarkerFile(filePath);
      const loadedFileMap = new Map<number, Marker>();
      if (result) {
        for (const marker of result.markers) {
          loadedFileMap.set(marker.lineId, marker);
        }
      }

      set((state) => {
        if ((state.clearRevisions.get(filePath) ?? 0) !== clearRevision) {
          return {};
        }
        const next = new Map(state.markersByFile);
        next.set(
          filePath,
          mergeLoadedFileMarkers(
            loadedFileMap,
            initialFileMap,
            state.markersByFile.get(filePath)
          )
        );

        // Preserve the original created timestamp for later saves.
        const nextCreated = new Map(state.createdTimestamps);
        if (result?.created) {
          nextCreated.set(filePath, result.created);
        }
        // Restore saved categories while preserving categories added during the load.
        const nextCategories = (() => {
          if (!result?.categories || result.categories.length === 0) return state.categories;
          const loadedIds = new Set(result.categories.map((category) => category.id));
          const addedDuringLoad = state.categories.filter(
            (category) =>
              !initialCategories.some((initial) => initial.id === category.id) &&
              !loadedIds.has(category.id)
          );
          return [...result.categories, ...addedDuringLoad];
        })();

        return {
          markersByFile: next,
          createdTimestamps: nextCreated,
          categories: nextCategories,
        };
      });
    } catch (err) {
      console.error("[marker-store] loadMarkers failed", { filePath, err });
    } finally {
      set((state) => {
        const next = new Set(state.loadingFiles);
        next.delete(filePath);
        return { loadingFiles: next };
      });
    }
  },

  // ── saveMarkers ─────────────────────────────────────────────────────────

  saveMarkers: async (filePath) => {
    const { markersByFile, categories, createdTimestamps } = get();
    const fileMap = markersByFile.get(filePath);

    if (!fileMap || fileMap.size === 0) {
      // No markers remaining — delete any persisted file.
      try {
        await invoke<void>("delete_markers", { filePath });
      } catch (err) {
        console.error("[marker-store] delete_markers failed", { filePath, err });
      }
      return;
    }

    const now = new Date().toISOString();
    const created = createdTimestamps.get(filePath) ?? now;
    const markerFile: MarkerFile = {
      version: 1,
      sourcePath: filePath,
      sourceSize: 0,
      created,
      modified: now,
      markers: Array.from(fileMap.values()),
      categories,
    };

    try {
      await invoke<void>("save_markers", { filePath, markerFile });
    } catch (err) {
      console.error("[marker-store] save_markers failed", { filePath, err });
    }
  },

  // ── toggleMarker ────────────────────────────────────────────────────────

  toggleMarker: (filePath, lineId) => {
    const { activeCategory, categories } = get();

    set((state) => {
      const next = new Map(state.markersByFile);
      const fileMap = new Map(next.get(filePath) ?? []);

      if (fileMap.has(lineId)) {
        // Toggle off — remove the marker.
        fileMap.delete(lineId);
      } else {
        // Toggle on — add a new marker using the active category.
        const categoryDef = categories.find((c) => c.id === activeCategory);
        const color = categoryDef?.color ?? "#60a5fa";
        const marker: Marker = {
          lineId,
          category: activeCategory,
          color,
          added: new Date().toISOString(),
        };
        fileMap.set(lineId, marker);
      }

      next.set(filePath, fileMap);
      return { markersByFile: next };
    });
  },

  // ── setMarkerCategory ───────────────────────────────────────────────────

  setMarkerCategory: (filePath, lineId, category) => {
    set((state) => {
      const next = new Map(state.markersByFile);
      const fileMap = new Map(next.get(filePath) ?? []);
      const existing = fileMap.get(lineId);

      if (!existing) {
        return {};
      }

      const categoryDef = state.categories.find((c) => c.id === category);
      const color = categoryDef?.color ?? existing.color;

      fileMap.set(lineId, { ...existing, category, color });
      next.set(filePath, fileMap);
      return { markersByFile: next };
    });
  },

  // ── removeMarker ────────────────────────────────────────────────────────

  removeMarker: (filePath, lineId) => {
    set((state) => {
      const next = new Map(state.markersByFile);
      const fileMap = new Map(next.get(filePath) ?? []);
      fileMap.delete(lineId);
      next.set(filePath, fileMap);
      return { markersByFile: next };
    });
  },

  // ── clearMarkersForFile ─────────────────────────────────────────────────

  clearMarkersForFile: (filePath) => {
    set((state) => {
      const next = new Map(state.markersByFile);
      next.delete(filePath);
      const clearRevisions = new Map(state.clearRevisions);
      clearRevisions.set(filePath, (clearRevisions.get(filePath) ?? 0) + 1);
      return { markersByFile: next, clearRevisions };
    });
  },

  // ── setActiveCategory ───────────────────────────────────────────────────

  setActiveCategory: (category) => set({ activeCategory: category }),

  // ── addCategory ─────────────────────────────────────────────────────────

  addCategory: (category) => {
    set((state) => ({
      categories: [...state.categories, category],
    }));
  },

  // ── getMarkersForFile (selector) ────────────────────────────────────────

  getMarkersForFile: (filePath) => {
    return get().markersByFile.get(filePath) ?? new Map<number, Marker>();
  },

  // ── getMarkedLineIds (selector) ─────────────────────────────────────────

  getMarkedLineIds: (filePath, category) => {
    const fileMap = get().markersByFile.get(filePath);
    if (!fileMap) return [];

    const ids: number[] = [];
    for (const [lineId, marker] of fileMap) {
      if (category === undefined || marker.category === category) {
        ids.push(lineId);
      }
    }
    return ids;
  },
}));
