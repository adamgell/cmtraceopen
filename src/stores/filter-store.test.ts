import { describe, it, expect, beforeEach } from "vitest";
import { useFilterStore, getFilterStatusSnapshot } from "./filter-store";
import type { FilterClause } from "../components/dialogs/FilterDialog";

describe("filter-store", () => {
  beforeEach(() => {
    useFilterStore.getState().clearFilter();
  });

  describe("initial state", () => {
    it("starts with no active filter", () => {
      const state = useFilterStore.getState();
      expect(state.clauses).toHaveLength(0);
      expect(state.filteredIds).toBeNull();
      expect(state.isFiltering).toBe(false);
      expect(state.filterError).toBeNull();
      expect(state.hasActiveFilter()).toBe(false);
    });
  });

  describe("setClauses", () => {
    it("sets filter clauses", () => {
      const clauses: FilterClause[] = [
        { field: "Message", op: "Contains", value: "error" },
      ];
      useFilterStore.getState().setClauses(clauses);

      expect(useFilterStore.getState().clauses).toHaveLength(1);
      expect(useFilterStore.getState().hasActiveFilter()).toBe(true);
    });

    it("replaces existing clauses", () => {
      useFilterStore.getState().setClauses([
        { field: "Message", op: "Contains", value: "first" },
      ]);
      useFilterStore.getState().setClauses([
        { field: "Component", op: "Equals", value: "second" },
      ]);

      expect(useFilterStore.getState().clauses).toHaveLength(1);
      expect(useFilterStore.getState().clauses[0].value).toBe("second");
    });
  });

  describe("setFilteredIds", () => {
    it("sets the filtered entry ID set", () => {
      const ids = new Set([1, 3, 5]);
      useFilterStore.getState().setFilteredIds(ids);

      expect(useFilterStore.getState().filteredIds).toEqual(ids);
    });

    it("accepts null to clear filter results", () => {
      useFilterStore.getState().setFilteredIds(new Set([1]));
      useFilterStore.getState().setFilteredIds(null);

      expect(useFilterStore.getState().filteredIds).toBeNull();
    });
  });

  describe("setIsFiltering / setFilterError", () => {
    it("tracks filtering state", () => {
      useFilterStore.getState().setIsFiltering(true);
      expect(useFilterStore.getState().isFiltering).toBe(true);

      useFilterStore.getState().setIsFiltering(false);
      expect(useFilterStore.getState().isFiltering).toBe(false);
    });

    it("tracks filter errors", () => {
      useFilterStore.getState().setFilterError("Something went wrong");
      expect(useFilterStore.getState().filterError).toBe("Something went wrong");

      useFilterStore.getState().setFilterError(null);
      expect(useFilterStore.getState().filterError).toBeNull();
    });
  });

  describe("clearFilter", () => {
    it("resets all filter state", () => {
      useFilterStore.getState().setClauses([
        { field: "Message", op: "Contains", value: "test" },
      ]);
      useFilterStore.getState().setFilteredIds(new Set([1, 2]));
      useFilterStore.getState().setIsFiltering(true);
      useFilterStore.getState().setFilterError("err");

      useFilterStore.getState().clearFilter();

      const state = useFilterStore.getState();
      expect(state.clauses).toHaveLength(0);
      expect(state.filteredIds).toBeNull();
      expect(state.isFiltering).toBe(false);
      expect(state.filterError).toBeNull();
    });
  });
});

describe("getFilterStatusSnapshot", () => {
  it("returns idle when no clauses", () => {
    const snapshot = getFilterStatusSnapshot(0, null, false, null);
    expect(snapshot.tone).toBe("idle");
  });

  it("returns busy when filtering", () => {
    const snapshot = getFilterStatusSnapshot(1, null, true, null);
    expect(snapshot.tone).toBe("busy");
  });

  it("returns error when filter has error", () => {
    const snapshot = getFilterStatusSnapshot(1, null, false, "parse error");
    expect(snapshot.tone).toBe("error");
  });

  it("returns active with clause count and filtered count", () => {
    const snapshot = getFilterStatusSnapshot(2, 50, false, null);
    expect(snapshot.tone).toBe("active");
    expect(snapshot.label).toContain("2 clauses");
    expect(snapshot.label).toContain("50 shown");
  });

  it("singular clause label", () => {
    const snapshot = getFilterStatusSnapshot(1, 10, false, null);
    expect(snapshot.label).toContain("1 clause");
    expect(snapshot.label).not.toContain("clauses");
  });
});
