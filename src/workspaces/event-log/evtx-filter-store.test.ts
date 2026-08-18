import { beforeEach, describe, expect, it } from "vitest";
import {
  migratePersistedSavedFilters,
  useSavedFilterStore,
} from "./evtx-filter-store";
import { sanitizeCriteria } from "./evtx-saved-filters";

const criteria = () =>
  sanitizeCriteria({ beforeLoad: { levels: ["Error"] }, onLoad: { search: "boot" } });

/** save() returns null for an empty name; every call here uses a real one, so assert that. */
function saveNamed(name: string) {
  const saved = useSavedFilterStore.getState().save(name, criteria());
  if (!saved) throw new Error(`save refused the name ${JSON.stringify(name)}`);
  return saved;
}

beforeEach(() => {
  useSavedFilterStore.setState({ savedFilters: [] });
  localStorage.clear();
});

describe("useSavedFilterStore", () => {
  it("saves a filter and stamps it as used", () => {
    const saved = saveNamed("Boot errors");
    expect(saved.name).toBe("Boot errors");
    expect(saved.lastUsed).not.toBeNull();
    expect(useSavedFilterStore.getState().savedFilters).toHaveLength(1);
  });
  it("rejects persisted v1 and unknown versions while accepting layered v2", () => {
    const layered = {
      savedFilters: [
        {
          id: "v2",
          name: "Layered",
          criteria: {
            beforeLoad: { levels: ["Error"], eventIds: "", timeWindow: "24h" },
            onLoad: { search: "", quickFilter: { mode: "oneString", query: "", scope: "allColumns", action: "show", caseSensitive: false, highlight: true } },
            afterLoad: { groupBy: [] },
          },
        },
      ],
    };
    expect(migratePersistedSavedFilters(layered, 1).savedFilters).toEqual([]);
    expect(migratePersistedSavedFilters(layered, 0).savedFilters).toEqual([]);
    expect(() => migratePersistedSavedFilters(layered, 99)).toThrow(/Unsupported/);
    expect(migratePersistedSavedFilters(layered, 2).savedFilters).toHaveLength(1);
  });
  it("rejects absent and malformed current-schema envelopes", () => {
    expect(() => migratePersistedSavedFilters(undefined, 2)).toThrow(/Malformed/);
    expect(() => migratePersistedSavedFilters({ savedFilters: "bad" }, 2)).toThrow(/Malformed/);
  });
  it("persists every quick-filter mode and grouping criterion", () => {
    const saved = useSavedFilterStore.getState().save(
      "Triage",
      sanitizeCriteria({
        afterLoad: { groupBy: ["provider", "eventId"] },
        onLoad: {
          quickFilter: {
            mode: "allStrings",
            query: "boot,failed",
            scope: "visibleColumns",
            action: "hide",
            caseSensitive: true,
            highlight: false,
          },
        },
      })
    );
    expect(saved?.criteria.afterLoad.groupBy).toEqual(["provider", "eventId"]);
    expect(saved?.criteria.onLoad.quickFilter).toEqual({
      mode: "allStrings",
      query: "boot,failed",
      scope: "visibleColumns",
      action: "hide",
      caseSensitive: true,
      highlight: false,
    });
  });

  it("saving under an existing name updates rather than duplicating", () => {
    const first = saveNamed("Boot");
    const second = useSavedFilterStore
      .getState()
      .save("boot", sanitizeCriteria({ onLoad: { search: "changed" } }));
    if (!second) throw new Error("save refused a valid name");

    expect(useSavedFilterStore.getState().savedFilters).toHaveLength(1);
    expect(second.id).toBe(first.id);
    expect(useSavedFilterStore.getState().savedFilters[0].criteria.onLoad.search).toBe("changed");
  });

  it("preserves the favorite flag when re-saving", () => {
    const saved = saveNamed("Boot");
    useSavedFilterStore.getState().toggleFavorite(saved.id);
    useSavedFilterStore.getState().save("Boot", sanitizeCriteria({ search: "again" }));
    expect(useSavedFilterStore.getState().savedFilters[0].favorite).toBe(true);
  });

  it("removes by id", () => {
    const saved = saveNamed("Boot");
    useSavedFilterStore.getState().remove(saved.id);
    expect(useSavedFilterStore.getState().savedFilters).toEqual([]);
  });

  it("orders favorites first", () => {
    // Favourite the one that loses on every other rule. Favouriting "Alpha" proved nothing: both
    // saves stamp lastUsed from the same clock tick, so the ordering fell through to the name
    // comparison and "Alpha" came first whether or not toggleFavorite did anything at all.
    const zulu = saveNamed("Zulu");
    saveNamed("Alpha");

    expect(useSavedFilterStore.getState().ordered()[0].name).toBe("Alpha");

    useSavedFilterStore.getState().toggleFavorite(zulu.id);
    expect(useSavedFilterStore.getState().ordered()[0].name).toBe("Zulu");
  });

  it("drops persisted entries that no longer validate rather than repairing them", () => {
    // Persisted data outlives the build that wrote it. Repairing a filter into something the
    // operator never chose would be worse than losing it.
    const merged = (
      useSavedFilterStore.persist.getOptions().merge as (
        persisted: unknown,
        current: unknown
      ) => { savedFilters: unknown[] }
    )(
      { savedFilters: [{ name: "Good" }, { noName: true }, "nonsense"] },
      { savedFilters: [] }
    );
    expect(merged.savedFilters).toHaveLength(1);
  });

  it("refuses a whitespace-only name instead of storing one that vanishes", () => {
    // sanitizeSavedFilter drops an empty name on rehydration, so storing it would show the filter
    // in the list and then lose it on restart, which reads as the app losing the operator's work.
    expect(useSavedFilterStore.getState().save("   ", criteria())).toBeNull();
    expect(useSavedFilterStore.getState().savedFilters).toHaveLength(0);
  });
});
