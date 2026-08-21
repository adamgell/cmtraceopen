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
  toggleMarker: (filePath: string, lineId: number, identity?: string) => void;
  setMarkerCategory: (
    filePath: string,
    lineId: number,
    category: string,
    identity?: string,
  ) => void;
  removeMarker: (filePath: string, lineId: number, identity?: string) => void;
  clearMarkersForFile: (filePath: string) => void;

  // ── Category actions ──────────────────────────────────────────────────────
  setActiveCategory: (category: string) => void;
  addCategory: (category: MarkerCategory) => void;

  // ── Selectors ─────────────────────────────────────────────────────────────
  getMarkersForFile: (filePath: string) => Map<number, Marker>;
  getMarkedLineIds: (filePath: string, category?: string) => number[];
}
function markersEqual(
  left: Marker | undefined,
  right: Marker | undefined,
): boolean {
  return (
    left?.lineId === right?.lineId &&
    left?.identity === right?.identity &&
    left?.category === right?.category &&
    left?.color === right?.color &&
    left?.added === right?.added
  );
}
type MarkerIdentityIndex = Map<string, [number, Marker]>;

function buildMarkerIdentityIndex(fileMap: ReadonlyMap<number, Marker>): MarkerIdentityIndex {
  const index: MarkerIdentityIndex = new Map();
  for (const entry of fileMap) {
    if (entry[1].identity !== undefined && !index.has(entry[1].identity)) {
      index.set(entry[1].identity, entry);
    }
  }
  return index;
}

function updateMarkerIdentityIndex(
  index: MarkerIdentityIndex,
  entry: [number, Marker]
): void {
  if (entry[1].identity !== undefined) index.set(entry[1].identity, entry);
}

function removeMarkerIdentityIndex(
  index: MarkerIdentityIndex,
  fileMap: ReadonlyMap<number, Marker>,
  entry: [number, Marker]
): void {
  if (entry[1].identity === undefined || index.get(entry[1].identity)?.[0] !== entry[0]) {
    return;
  }
  index.delete(entry[1].identity);
  for (const candidate of fileMap) {
    if (candidate[1].identity === entry[1].identity) {
      index.set(entry[1].identity, candidate);
      break;
    }
  }
}

export function mergeLoadedFileMarkers(
  loaded: Map<number, Marker>,
  initial: ReadonlyMap<number, Marker>,
  current: ReadonlyMap<number, Marker> | undefined,
): Map<number, Marker> {
  const merged = new Map(loaded);
  const mergedIdentityIndex = buildMarkerIdentityIndex(merged);
  const currentMap = current ?? new Map<number, Marker>();
  const currentIdentityIndex = buildMarkerIdentityIndex(currentMap);
  const matchedCurrentKeys = new Set<number>();
  const changedPairs: Array<{
    initialKey: number;
    initialMarker: Marker;
    currentMarker: Marker;
  }> = [];

  // Identity-bearing markers may share a legacy line hash. Match those by their
  // identity first, falling back to an identity-less marker at the requested key
  // so a legacy marker can be upgraded in place.
  for (const [initialKey, initialMarker] of initial) {
    const currentEntry = findMergeMarkerEntry(
      currentMap,
      initialKey,
      initialMarker,
      currentIdentityIndex,
    );
    if (!currentEntry) {
      const loadedEntry = findMergeMarkerEntry(
        merged,
        initialKey,
        initialMarker,
        mergedIdentityIndex,
      );
      if (loadedEntry) {
        merged.delete(loadedEntry[0]);
        removeMarkerIdentityIndex(mergedIdentityIndex, merged, loadedEntry);
      }
      continue;
    }
    matchedCurrentKeys.add(currentEntry[0]);
    if (markersEqual(initialMarker, currentEntry[1])) {
      if (!findMergeMarkerEntry(merged, initialKey, initialMarker, mergedIdentityIndex)) {
        addMergedMarker(merged, currentEntry[1], currentEntry[0], mergedIdentityIndex);
      }
      continue;
    }
    changedPairs.push({
      initialKey,
      initialMarker,
      currentMarker: currentEntry[1],
    });
  }

  for (const { initialKey, initialMarker, currentMarker } of changedPairs) {
    const loadedEntry = findMergeMarkerEntry(
      merged,
      initialKey,
      initialMarker,
      mergedIdentityIndex,
    );
    if (loadedEntry) {
      const updatedEntry: [number, Marker] = [
        loadedEntry[0],
        { ...currentMarker, lineId: loadedEntry[0] },
      ];
      merged.set(updatedEntry[0], updatedEntry[1]);
      updateMarkerIdentityIndex(mergedIdentityIndex, updatedEntry);
    } else {
      addMergedMarker(merged, currentMarker, currentMarker.lineId, mergedIdentityIndex);
    }
  }

  // Markers added while loading must not overwrite a loaded marker that happens
  // to use the same line ID. Allocate a free storage key instead.
  for (const [currentKey, currentMarker] of currentMap) {
    if (matchedCurrentKeys.has(currentKey)) continue;
    addMergedMarker(merged, currentMarker, currentKey, mergedIdentityIndex);
  }

  return merged;
}

function findMergeMarkerEntry(
  fileMap: ReadonlyMap<number, Marker>,
  lineId: number,
  marker: Marker,
  identityIndex?: MarkerIdentityIndex,
): [number, Marker] | undefined {
  if (marker.identity !== undefined) {
    return findMarkerEntry(fileMap, lineId, marker.identity, identityIndex);
  }
  const candidate = fileMap.get(lineId);
  return candidate !== undefined && candidate.identity === undefined
    ? [lineId, candidate]
    : undefined;
}

function addMergedMarker(
  merged: Map<number, Marker>,
  marker: Marker,
  preferredLineId = marker.lineId,
  identityIndex?: MarkerIdentityIndex,
): void {
  const existing = findMergeMarkerEntry(merged, preferredLineId, marker, identityIndex);
  if (existing) {
    const updatedEntry: [number, Marker] = [existing[0], { ...marker, lineId: existing[0] }];
    merged.set(updatedEntry[0], updatedEntry[1]);
    if (identityIndex) updateMarkerIdentityIndex(identityIndex, updatedEntry);
    return;
  }
  if (
    marker.identity === undefined &&
    merged.get(preferredLineId)?.identity !== undefined
  ) {
    return;
  }

  let storageLineId = preferredLineId;
  while (merged.has(storageLineId)) {
    storageLineId = (storageLineId + 1) >>> 0;
  }
  const storedEntry: [number, Marker] = [
    storageLineId,
    { ...marker, lineId: storageLineId },
  ];
  merged.set(storedEntry[0], storedEntry[1]);
  if (identityIndex) updateMarkerIdentityIndex(identityIndex, storedEntry);
}
function findMarkerEntry(
  fileMap: ReadonlyMap<number, Marker>,
  lineId: number,
  identity?: string,
  identityIndex?: MarkerIdentityIndex,
): [number, Marker] | undefined {
  if (identity !== undefined) {
    const indexed = identityIndex?.get(identity);
    if (indexed) return indexed;
    if (!identityIndex) {
      for (const entry of fileMap) {
        if (entry[1].identity === identity) return entry;
      }
    }
  }
  const candidate = fileMap.get(lineId);
  if (
    !candidate ||
    (identity !== undefined && candidate.identity !== undefined)
  )
    return undefined;
  return [lineId, candidate];
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
          const existing = loadedFileMap.get(marker.lineId);
          if (
            !existing ||
            (existing.identity === undefined &&
              marker.identity === undefined) ||
            (existing.identity !== undefined &&
              existing.identity === marker.identity)
          ) {
            loadedFileMap.set(marker.lineId, marker);
            continue;
          }
          if (
            existing.identity !== undefined &&
            marker.identity === undefined
          ) {
            continue;
          }
          let storedLineId = marker.lineId;
          while (loadedFileMap.has(storedLineId)) {
            storedLineId = (storedLineId + 1) >>> 0;
          }
          loadedFileMap.set(storedLineId, { ...marker, lineId: storedLineId });
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
            state.markersByFile.get(filePath),
          ),
        );

        // Preserve the original created timestamp for later saves.
        const nextCreated = new Map(state.createdTimestamps);
        if (result?.created) {
          nextCreated.set(filePath, result.created);
        }
        // Restore saved categories while preserving categories added during the load.
        const nextCategories = (() => {
          if (!result?.categories || result.categories.length === 0)
            return state.categories;
          const loadedIds = new Set(
            result.categories.map((category) => category.id),
          );
          const addedDuringLoad = state.categories.filter(
            (category) =>
              !initialCategories.some(
                (initial) => initial.id === category.id,
              ) && !loadedIds.has(category.id),
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
        console.error("[marker-store] delete_markers failed", {
          filePath,
          err,
        });
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

  toggleMarker: (filePath, lineId, identity) => {
    const { activeCategory, categories } = get();

    set((state) => {
      const next = new Map(state.markersByFile);
      const fileMap = new Map(next.get(filePath) ?? []);
      const existingEntry = findMarkerEntry(fileMap, lineId, identity);

      if (existingEntry) {
        fileMap.delete(existingEntry[0]);
      } else {
        const categoryDef = categories.find((c) => c.id === activeCategory);
        const color = categoryDef?.color ?? "#60a5fa";
        let storedLineId = lineId;
        while (fileMap.has(storedLineId))
          storedLineId = (storedLineId + 1) >>> 0;
        const marker: Marker = {
          lineId: storedLineId,
          ...(identity === undefined ? {} : { identity }),
          category: activeCategory,
          color,
          added: new Date().toISOString(),
        };
        fileMap.set(storedLineId, marker);
      }

      next.set(filePath, fileMap);
      return { markersByFile: next };
    });
  },

  // ── setMarkerCategory ───────────────────────────────────────────────────
  setMarkerCategory: (filePath, lineId, category, identity) => {
    set((state) => {
      const next = new Map(state.markersByFile);
      const fileMap = new Map(next.get(filePath) ?? []);
      const existingEntry = findMarkerEntry(fileMap, lineId, identity);
      if (!existingEntry) return {};

      const categoryDef = state.categories.find((item) => item.id === category);
      const color = categoryDef?.color ?? existingEntry[1].color;
      fileMap.set(existingEntry[0], {
        ...existingEntry[1],
        ...(identity === undefined ? {} : { identity }),
        category,
        color,
      });
      next.set(filePath, fileMap);
      return { markersByFile: next };
    });
  },

  // ── removeMarker ─────────────────────────────────────────────────────────

  removeMarker: (filePath, lineId, identity) => {
    set((state) => {
      const next = new Map(state.markersByFile);
      const fileMap = new Map(next.get(filePath) ?? []);
      const existingEntry = findMarkerEntry(fileMap, lineId, identity);
      if (existingEntry) fileMap.delete(existingEntry[0]);
      next.set(filePath, fileMap);
      return { markersByFile: next };
    });
  },

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
