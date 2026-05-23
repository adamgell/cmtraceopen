import { invoke } from "@tauri-apps/api/core";
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  applyBackendFilter,
  getFilterStatusSnapshot,
  mergeFilteredIds,
  useFilterStore,
} from "./filter-store";
import type { FilterClause } from "../components/dialogs/FilterDialog";
import type { LogEntry } from "../types/log";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

function createEntry(id: number): LogEntry {
  return {
    id,
    lineNumber: id + 1,
    message: `message ${id}`,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath: `/logs/${id}.log`,
    timezoneOffset: null,
  };
}

describe("filter-store", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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

  describe("mergeFilteredIds", () => {
    it("merges matching appended IDs into the existing filtered ID set", () => {
      const merged = mergeFilteredIds(new Set([1, 3]), [5, 3, 8]);

      expect(Array.from(merged)).toEqual([1, 3, 5, 8]);
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

  describe("applyBackendFilter", () => {
    const clauses: FilterClause[] = [
      { field: "Message", op: "Contains", value: "error" },
    ];
    const entries = [createEntry(1), createEntry(2)];

    it("uses backend session keyed filtering when session metadata exists", async () => {
      vi.mocked(invoke).mockResolvedValue([2]);

      const ids = await applyBackendFilter(clauses, entries, {
        backendSessionKey: "session-123",
      });

      expect(ids).toEqual([2]);
      expect(invoke).toHaveBeenCalledTimes(1);
      expect(invoke).toHaveBeenCalledWith("apply_filter", {
        clauses,
        sessionKey: "session-123",
      });
    });

    it("falls back to raw-entry filtering when the backend session key is stale", async () => {
      vi.mocked(invoke)
        .mockRejectedValueOnce(new Error("Unknown parsed entries session key stale-session."))
        .mockResolvedValueOnce([1]);

      const ids = await applyBackendFilter(clauses, entries, {
        backendSessionKey: "stale-session",
      });

      expect(ids).toEqual([1]);
      expect(invoke).toHaveBeenCalledTimes(2);
      expect(vi.mocked(invoke).mock.calls).toEqual([
        ["apply_filter", { clauses, sessionKey: "stale-session" }],
        ["apply_filter", { clauses, entries }],
      ]);
    });

    it("uses raw-entry filtering for frontend-only views or missing session metadata", async () => {
      vi.mocked(invoke).mockResolvedValue([1, 2]);

      const ids = await applyBackendFilter(clauses, entries, {
        backendSessionKey: null,
      });

      expect(ids).toEqual([1, 2]);
      expect(invoke).toHaveBeenCalledTimes(1);
      expect(invoke).toHaveBeenCalledWith("apply_filter", {
        clauses,
        entries,
      });
    });

    it("uses raw-entry filtering for incremental live-tail batches even when a backend session exists", async () => {
      vi.mocked(invoke).mockResolvedValue([2]);

      const ids = await applyBackendFilter(clauses, entries, {
        backendSessionKey: "session-123",
        forceRawEntries: true,
      });

      expect(ids).toEqual([2]);
      expect(invoke).toHaveBeenCalledTimes(1);
      expect(invoke).toHaveBeenCalledWith("apply_filter", {
        clauses,
        entries,
      });
    });

    it("rethrows non-session backend errors so the existing error state flow remains visible", async () => {
      vi.mocked(invoke).mockRejectedValue(new Error("Invalid timestamp filter value"));

      await expect(applyBackendFilter(clauses, entries, {
        backendSessionKey: "session-123",
      })).rejects.toThrow("Invalid timestamp filter value");
      expect(invoke).toHaveBeenCalledTimes(1);
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
