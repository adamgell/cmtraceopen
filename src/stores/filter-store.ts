import { create } from "zustand";
import type { FilterClause, FilterField, FilterOp } from "../components/dialogs/FilterDialog";
import { useLogStore } from "./log-store";

export interface FilterStatusSnapshot {
  tone: "idle" | "active" | "busy" | "error";
  label: string;
}

export function getFilterStatusSnapshot(
  clauseCount: number,
  filteredCount: number | null,
  isFiltering: boolean,
  filterError: string | null
): FilterStatusSnapshot {
  if (isFiltering) {
    return {
      tone: "busy",
      label: "Filter applying",
    };
  }

  if (filterError) {
    return {
      tone: "error",
      label: "Filter error",
    };
  }

  if (clauseCount > 0) {
    const countText = filteredCount === null ? "" : ` • ${filteredCount} shown`;
    return {
      tone: "active",
      label: `Filter active (${clauseCount} clause${clauseCount === 1 ? "" : "s"}${countText})`,
    };
  }

  return {
    tone: "idle",
    label: "Filter clear",
  };
}

function reconcileSelectionWithFilter(ids: Set<number> | null): void {
  if (!ids) {
    return;
  }

  const logState = useLogStore.getState();
  const currentSelectedId = logState.selectedId;

  if (currentSelectedId === null || ids.has(currentSelectedId)) {
    return;
  }

  const { entries } = logState;
  const selectedIndex = entries.findIndex((entry) => entry.id === currentSelectedId);

  for (let index = selectedIndex + 1; index < entries.length; index += 1) {
    const candidateId = entries[index]?.id;
    if (candidateId !== undefined && ids.has(candidateId)) {
      logState.selectEntry(candidateId);
      return;
    }
  }

  for (let index = selectedIndex - 1; index >= 0; index -= 1) {
    const candidateId = entries[index]?.id;
    if (candidateId !== undefined && ids.has(candidateId)) {
      logState.selectEntry(candidateId);
      return;
    }
  }

  logState.selectEntry(null);
}

export type WhatIfFilter = "all" | "whatif-only" | "real-only";

interface FilterState {
  /** Active filter clauses */
  clauses: FilterClause[];
  /** Set of entry IDs that pass the filter (null = no filter active) */
  filteredIds: Set<number> | null;
  /** Whether a filter is currently being applied */
  isFiltering: boolean;
  /** Most recent filter application error */
  filterError: string | null;
  /** WhatIf display filter */
  whatIfFilter: WhatIfFilter;

  hasActiveFilter: () => boolean;
  addQuickFilter: (field: FilterField, value: string, op: FilterOp) => void;
  setClauses: (clauses: FilterClause[]) => void;
  setFilteredIds: (ids: Set<number> | null) => void;
  setIsFiltering: (filtering: boolean) => void;
  setFilterError: (error: string | null) => void;
  setWhatIfFilter: (filter: WhatIfFilter) => void;
  clearFilter: () => void;
}

export const useFilterStore = create<FilterState>((set, get) => ({
  clauses: [],
  filteredIds: null,
  isFiltering: false,
  filterError: null,
  whatIfFilter: "all",

  hasActiveFilter: () => get().clauses.length > 0,
  addQuickFilter: (field, value, op) =>
    set((state) => ({ clauses: [...state.clauses, { field, value, op }] })),
  setClauses: (clauses) => set({ clauses }),
  setFilteredIds: (ids) => {
    set({ filteredIds: ids });
    reconcileSelectionWithFilter(ids);
  },
  setIsFiltering: (filtering) => set({ isFiltering: filtering }),
  setFilterError: (error) => set({ filterError: error }),
  setWhatIfFilter: (filter) => set({ whatIfFilter: filter }),
  clearFilter: () =>
    set({
      clauses: [],
      filteredIds: null,
      isFiltering: false,
      filterError: null,
      whatIfFilter: "all",
    }),
}));