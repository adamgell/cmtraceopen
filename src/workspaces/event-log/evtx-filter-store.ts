/**
 * Persisted store for the saved filter library.
 *
 * Deliberately separate from `evtx-store`, which holds loaded records. Those are large, derived,
 * and machine-specific, so persisting that store would write megabytes of event data into local
 * storage. This one holds only the criteria an operator chose to keep.
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";

import {
  mergeFilters,
  orderFilters,
  sanitizeSavedFilter,
  type EvtxFilterCriteria,
  type EvtxSavedFilter,
} from "./evtx-saved-filters";

interface SavedFilterState {
  savedFilters: EvtxSavedFilter[];
  /** Returns the stored filter, or null when the name is empty once trimmed. */
  save: (name: string, criteria: EvtxFilterCriteria) => EvtxSavedFilter | null;
  remove: (id: string) => void;
  toggleFavorite: (id: string) => void;
  markUsed: (id: string) => void;
  importFilters: (imported: EvtxSavedFilter[]) => void;
  ordered: () => EvtxSavedFilter[];
}
export function migratePersistedSavedFilters(
  persisted: unknown,
  version: number | undefined
): { savedFilters: EvtxSavedFilter[] } {
  if (version == null || version < 2) return { savedFilters: [] };
  if (version > 2) {
    throw new Error(`Unsupported saved-filter schema version ${version}`);
  }
  const raw = persisted as { savedFilters?: unknown } | undefined;
  if (!raw || !Array.isArray(raw.savedFilters)) {
    throw new Error("Malformed saved-filter storage envelope");
  }
  const list = raw.savedFilters;
  const savedFilters = list
    .map((entry, index) => sanitizeSavedFilter(entry, `restored-${index}`))
    .filter((filter): filter is EvtxSavedFilter => filter !== null);
  return { savedFilters };
}


function newId(): string {
  // crypto.randomUUID is unavailable in some webviews, so fall back rather than throwing.
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `filter-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export const useSavedFilterStore = create<SavedFilterState>()(
  persist(
    (set, get) => ({
      savedFilters: [],

      save: (name, criteria) => {
        const trimmed = name.trim();
        // A whitespace-only name is refused rather than stored. sanitizeSavedFilter drops it on
        // rehydration, so it would save, appear in the list, and then vanish on restart, which
        // reads as the app losing the operator's filter.
        if (!trimmed) return null;
        const existing = get().savedFilters.find(
          (filter) => filter.name.toLowerCase() === trimmed.toLowerCase()
        );
        // Saving under an existing name updates it rather than creating a second entry, which is
        // what "save" means when the name already exists in the list the operator is looking at.
        const filter: EvtxSavedFilter = {
          id: existing?.id ?? newId(),
          name: trimmed,
          favorite: existing?.favorite ?? false,
          tags: existing?.tags ?? [],
          criteria,
          lastUsed: Date.now(),
        };
        set({ savedFilters: mergeFilters(get().savedFilters, [filter]) });
        return filter;
      },

      remove: (id) =>
        set({ savedFilters: get().savedFilters.filter((filter) => filter.id !== id) }),

      toggleFavorite: (id) =>
        set({
          savedFilters: get().savedFilters.map((filter) =>
            filter.id === id ? { ...filter, favorite: !filter.favorite } : filter
          ),
        }),

      markUsed: (id) =>
        set({
          savedFilters: get().savedFilters.map((filter) =>
            filter.id === id ? { ...filter, lastUsed: Date.now() } : filter
          ),
        }),

      importFilters: (imported) =>
        set({ savedFilters: mergeFilters(get().savedFilters, imported) }),

      ordered: () => orderFilters(get().savedFilters),
    }),
    {
      name: "cmtraceopen-evtx-saved-filters",
      version: 2,
      migrate: (persisted, version) => migratePersistedSavedFilters(persisted, version),
      // Zustand only calls migrate when the stored version differs. Current-version data still
      // crosses an untrusted localStorage boundary, so validate it before merging state too.
      merge: (persisted, current) => ({
        ...current,
        ...migratePersistedSavedFilters(persisted, 2),
      }),
    }
  )
);
