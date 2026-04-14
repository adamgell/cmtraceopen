import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
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

// ── Store implementation ──────────────────────────────────────────────────────

export const useMarkerStore = create<MarkerState>((set, get) => ({
  markersByFile: new Map(),
  categories: [...DEFAULT_CATEGORIES],
  activeCategory: "bug",
  loadingFiles: new Set(),
  createdTimestamps: new Map(),

  // ── loadMarkers ─────────────────────────────────────────────────────────

  loadMarkers: async (filePath) => {
    const { loadingFiles, markersByFile } = get();

    // Guard against duplicate in-flight loads.
    if (loadingFiles.has(filePath)) {
      return;
    }

    set((state) => ({
      loadingFiles: new Set([...state.loadingFiles, filePath]),
    }));

    try {
      const result = await invoke<MarkerFile | null>("load_markers", { filePath });

      if (result) {
        const fileMap = new Map<number, Marker>();
        for (const marker of result.markers) {
          fileMap.set(marker.lineId, marker);
        }

        set((state) => {
          const next = new Map(state.markersByFile);
          next.set(filePath, fileMap);

          // Preserve the original created timestamp for later saves
          const nextCreated = new Map(state.createdTimestamps);
          if (result.created) {
            nextCreated.set(filePath, result.created);
          }

          // Restore saved categories if the file provided them
          const nextCategories =
            result.categories && result.categories.length > 0
              ? result.categories
              : state.categories;

          return {
            markersByFile: next,
            createdTimestamps: nextCreated,
            categories: nextCategories,
          };
        });
      } else {
        // Ensure the file has an empty map so callers can safely query it.
        if (!markersByFile.has(filePath)) {
          set((state) => {
            const next = new Map(state.markersByFile);
            next.set(filePath, new Map());
            return { markersByFile: next };
          });
        }
      }
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
      return { markersByFile: next };
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
