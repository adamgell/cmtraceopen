import { beforeEach, describe, expect, it } from "vitest";
import { useSavedFilterStore } from "./evtx-filter-store";
import { sanitizeCriteria } from "./evtx-saved-filters";

const criteria = () => sanitizeCriteria({ levels: ["Error"], search: "boot" });

beforeEach(() => {
  useSavedFilterStore.setState({ savedFilters: [] });
  localStorage.clear();
});

describe("useSavedFilterStore", () => {
  it("saves a filter and stamps it as used", () => {
    const saved = useSavedFilterStore.getState().save("Boot errors", criteria());
    expect(saved.name).toBe("Boot errors");
    expect(saved.lastUsed).not.toBeNull();
    expect(useSavedFilterStore.getState().savedFilters).toHaveLength(1);
  });

  it("saving under an existing name updates rather than duplicating", () => {
    const store = useSavedFilterStore.getState();
    const first = store.save("Boot", criteria());
    const second = useSavedFilterStore
      .getState()
      .save("boot", sanitizeCriteria({ search: "changed" }));

    expect(useSavedFilterStore.getState().savedFilters).toHaveLength(1);
    expect(second.id).toBe(first.id);
    expect(useSavedFilterStore.getState().savedFilters[0].criteria.search).toBe("changed");
  });

  it("preserves the favorite flag when re-saving", () => {
    const saved = useSavedFilterStore.getState().save("Boot", criteria());
    useSavedFilterStore.getState().toggleFavorite(saved.id);
    useSavedFilterStore.getState().save("Boot", sanitizeCriteria({ search: "again" }));
    expect(useSavedFilterStore.getState().savedFilters[0].favorite).toBe(true);
  });

  it("removes by id", () => {
    const saved = useSavedFilterStore.getState().save("Boot", criteria());
    useSavedFilterStore.getState().remove(saved.id);
    expect(useSavedFilterStore.getState().savedFilters).toEqual([]);
  });

  it("orders favorites first", () => {
    const store = useSavedFilterStore.getState();
    store.save("Zulu", criteria());
    const alpha = useSavedFilterStore.getState().save("Alpha", criteria());
    useSavedFilterStore.getState().toggleFavorite(alpha.id);
    expect(useSavedFilterStore.getState().ordered()[0].name).toBe("Alpha");
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
});
