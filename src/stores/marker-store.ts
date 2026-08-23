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
  /** Per-file I/O ordering and durability state for the current store session. */
  markerPersistenceByFile: Map<string, MarkerFilePersistenceState>;

  // ── Async backend actions ─────────────────────────────────────────────────
  loadMarkers: (filePath: string) => Promise<MarkerLoadOutcome>;
  saveMarkers: (filePath: string) => Promise<MarkerSaveOutcome>;

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
export type MarkerLoadOutcome =
  | "loaded"
  | "missing"
  | "failed"
  | "superseded";
export type MarkerSaveOutcome = "saved" | "deleted" | "failed";

type SuccessfulMarkerLoadOutcome = Extract<
  MarkerLoadOutcome,
  "loaded" | "missing"
>;
type SuccessfulMarkerSaveOutcome = Extract<
  MarkerSaveOutcome,
  "saved" | "deleted"
>;
type MarkerFileLoadState = "unknown" | "ready" | "failed";
type QueuedMarkerOperation = () => Promise<void>;

interface MarkerFilePersistenceState {
  loadState: MarkerFileLoadState;
  lastLoadOutcome: SuccessfulMarkerLoadOutcome | null;
  mutationVersion: number;
  requestedMutationVersion: number;
  savedMutationVersion: number;
  saveIntentVersion: number;
  completedSaveIntentVersion: number;
  lastSaveOutcome: SuccessfulMarkerSaveOutcome | null;
  operationRunning: boolean;
  operations: QueuedMarkerOperation[];
}

function createMarkerFilePersistenceState(): MarkerFilePersistenceState {
  return {
    loadState: "unknown",
    lastLoadOutcome: null,
    mutationVersion: 0,
    requestedMutationVersion: 0,
    savedMutationVersion: 0,
    saveIntentVersion: 0,
    completedSaveIntentVersion: 0,
    lastSaveOutcome: null,
    operationRunning: false,
    operations: [],
  };
}

function runNextMarkerOperation(persistence: MarkerFilePersistenceState): void {
  if (persistence.operationRunning) return;
  const operation = persistence.operations.shift();
  if (!operation) return;

  persistence.operationRunning = true;
  const settle = () => {
    persistence.operationRunning = false;
    runNextMarkerOperation(persistence);
  };
  void operation().then(settle, settle);
}

function enqueueMarkerOperation<T>(
  persistence: MarkerFilePersistenceState,
  operation: () => Promise<T>,
): Promise<T> {
  const result = new Promise<T>((resolve, reject) => {
    persistence.operations.push(async () => {
      try {
        resolve(await operation());
      } catch (error) {
        reject(error);
      }
    });
  });
  runNextMarkerOperation(persistence);
  return result;
}

function hasPendingMarkerSave(
  persistence: MarkerFilePersistenceState,
): boolean {
  return (
    persistence.completedSaveIntentVersion < persistence.saveIntentVersion ||
    persistence.savedMutationVersion < persistence.requestedMutationVersion
  );
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

export const useMarkerStore = create<MarkerState>((set, get) => {
  const getPersistence = (filePath: string): MarkerFilePersistenceState => {
    const persistenceByFile = get().markerPersistenceByFile;
    const existing = persistenceByFile.get(filePath);
    if (existing) return existing;
    const created = createMarkerFilePersistenceState();
    persistenceByFile.set(filePath, created);
    return created;
  };

  const noteMarkerMutation = (filePath: string): void => {
    const persistence = getPersistence(filePath);
    persistence.mutationVersion += 1;
    if (hasPendingMarkerSave(persistence)) {
      persistence.requestedMutationVersion = persistence.mutationVersion;
    }
  };

  const loadMarkerFileIntoStore = async (
    filePath: string,
    persistence: MarkerFilePersistenceState,
  ): Promise<MarkerLoadOutcome> => {
    const { markersByFile, clearRevisions, categories } = get();
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
      const loadOutcome: SuccessfulMarkerLoadOutcome = result
        ? "loaded"
        : "missing";
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

      persistence.loadState = "ready";
      persistence.lastLoadOutcome = loadOutcome;
      if ((get().clearRevisions.get(filePath) ?? 0) !== clearRevision) {
        return "superseded";
      }

      set((state) => {
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
      return loadOutcome;
    } catch (err) {
      persistence.loadState = "failed";
      console.error("[marker-store] loadMarkers failed", { filePath, err });
      return "failed";
    } finally {
      set((state) => {
        const next = new Set(state.loadingFiles);
        next.delete(filePath);
        return { loadingFiles: next };
      });
    }
  };

  const saveMarkerFileSnapshot = async (
    filePath: string,
  ): Promise<MarkerSaveOutcome> => {
    const { markersByFile, categories, createdTimestamps } = get();
    const fileMap = markersByFile.get(filePath);

    if (!fileMap || fileMap.size === 0) {
      // No markers remaining — delete any persisted file.
      try {
        await invoke<void>("delete_markers", { filePath });
        return "deleted";
      } catch (err) {
        console.error("[marker-store] delete_markers failed", {
          filePath,
          err,
        });
        return "failed";
      }
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
      return "saved";
    } catch (err) {
      console.error("[marker-store] save_markers failed", { filePath, err });
      return "failed";
    }
  };

  const flushPendingMarkerSave = async (
    filePath: string,
    persistence: MarkerFilePersistenceState,
  ): Promise<MarkerSaveOutcome | null> => {
    let lastOutcome: MarkerSaveOutcome | null = null;
    while (hasPendingMarkerSave(persistence)) {
      const savingMutationVersion = persistence.mutationVersion;
      const savingIntentVersion = persistence.saveIntentVersion;
      const outcome = await saveMarkerFileSnapshot(filePath);
      lastOutcome = outcome;
      if (outcome === "failed") return outcome;

      persistence.savedMutationVersion = Math.max(
        persistence.savedMutationVersion,
        savingMutationVersion,
      );
      persistence.completedSaveIntentVersion = Math.max(
        persistence.completedSaveIntentVersion,
        savingIntentVersion,
      );
      persistence.lastSaveOutcome = outcome;
    }
    return lastOutcome;
  };

  const performMarkerLoadRequest = async (
    filePath: string,
    persistence: MarkerFilePersistenceState,
  ): Promise<MarkerLoadOutcome> => {
    // Marker maps remain resident for one store session. Reuse a successful read so repeated
    // Event Log render/effect requests cannot race a newer in-memory mutation back to disk.
    const outcome =
      persistence.loadState === "ready"
        ? (persistence.lastLoadOutcome ?? "missing")
        : await loadMarkerFileIntoStore(filePath, persistence);
    if (
      persistence.loadState === "ready" &&
      hasPendingMarkerSave(persistence)
    ) {
      await flushPendingMarkerSave(filePath, persistence);
    }
    return outcome;
  };

  const performMarkerSaveRequest = async (
    filePath: string,
    persistence: MarkerFilePersistenceState,
  ): Promise<MarkerSaveOutcome> => {
    if (persistence.loadState === "unknown") {
      await loadMarkerFileIntoStore(filePath, persistence);
    }
    if (persistence.loadState !== "ready") return "failed";

    const outcome = await flushPendingMarkerSave(filePath, persistence);
    return outcome ?? persistence.lastSaveOutcome ?? "failed";
  };

  return {
    markersByFile: new Map(),
    categories: [...DEFAULT_CATEGORIES],
    activeCategory: "bug",
    loadingFiles: new Set(),
    clearRevisions: new Map(),
    createdTimestamps: new Map(),
    markerPersistenceByFile: new Map(),

    // ── loadMarkers ───────────────────────────────────────────────────────
    loadMarkers: (filePath) => {
      const persistence = getPersistence(filePath);
      return enqueueMarkerOperation(persistence, () =>
        performMarkerLoadRequest(filePath, persistence),
      );
    },

    // ── saveMarkers ───────────────────────────────────────────────────────
    saveMarkers: (filePath) => {
      const persistence = getPersistence(filePath);
      persistence.saveIntentVersion += 1;
      persistence.requestedMutationVersion = Math.max(
        persistence.requestedMutationVersion,
        persistence.mutationVersion,
      );
      return enqueueMarkerOperation(persistence, () =>
        performMarkerSaveRequest(filePath, persistence),
      );
    },

    // ── toggleMarker ──────────────────────────────────────────────────────

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
      noteMarkerMutation(filePath);
    },

    // ── setMarkerCategory ─────────────────────────────────────────────────
    setMarkerCategory: (filePath, lineId, category, identity) => {
      let changed = false;
      set((state) => {
        const next = new Map(state.markersByFile);
        const fileMap = new Map(next.get(filePath) ?? []);
        const existingEntry = findMarkerEntry(fileMap, lineId, identity);
        if (!existingEntry) return {};

        const categoryDef = state.categories.find(
          (item) => item.id === category,
        );
        const color = categoryDef?.color ?? existingEntry[1].color;
        fileMap.set(existingEntry[0], {
          ...existingEntry[1],
          ...(identity === undefined ? {} : { identity }),
          category,
          color,
        });
        next.set(filePath, fileMap);
        changed = true;
        return { markersByFile: next };
      });
      if (changed) noteMarkerMutation(filePath);
    },

    // ── removeMarker ───────────────────────────────────────────────────────

    removeMarker: (filePath, lineId, identity) => {
      let changed = false;
      set((state) => {
        const next = new Map(state.markersByFile);
        const fileMap = new Map(next.get(filePath) ?? []);
        const existingEntry = findMarkerEntry(fileMap, lineId, identity);
        if (existingEntry) {
          fileMap.delete(existingEntry[0]);
          changed = true;
        }
        next.set(filePath, fileMap);
        return { markersByFile: next };
      });
      if (changed) noteMarkerMutation(filePath);
    },

    clearMarkersForFile: (filePath) => {
      set((state) => {
        const next = new Map(state.markersByFile);
        next.delete(filePath);
        const clearRevisions = new Map(state.clearRevisions);
        clearRevisions.set(filePath, (clearRevisions.get(filePath) ?? 0) + 1);
        return { markersByFile: next, clearRevisions };
      });
      noteMarkerMutation(filePath);
    },

    // ── setActiveCategory ─────────────────────────────────────────────────

    setActiveCategory: (category) => set({ activeCategory: category }),

    // ── addCategory ───────────────────────────────────────────────────────

    addCategory: (category) => {
      set((state) => ({
        categories: [...state.categories, category],
      }));
    },

    // ── getMarkersForFile (selector) ──────────────────────────────────────

    getMarkersForFile: (filePath) => {
      return get().markersByFile.get(filePath) ?? new Map<number, Marker>();
    },

    // ── getMarkedLineIds (selector) ───────────────────────────────────────

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
  };
});
