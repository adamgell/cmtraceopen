import { describe, expect, it } from "vitest";
import {
  buildFilterExport,
  mergeFilters,
  orderFilters,
  parseFilterExport,
  SAVED_FILTER_SCHEMA,
  ALL_LEVELS,
  sanitizeCriteria,
  sanitizeSavedFilter,
  type EvtxSavedFilter,
} from "./evtx-saved-filters";

function filter(partial: Partial<EvtxSavedFilter>): EvtxSavedFilter {
  return {
    id: "id",
    name: "name",
    favorite: false,
    tags: [],
    lastUsed: null,
    criteria: sanitizeCriteria({}),
    ...partial,
  };
}

describe("sanitizeCriteria", () => {
  it("keeps recognised values", () => {
    const criteria = sanitizeCriteria({
      beforeLoad: {
        levels: ["Error", "Warning"],
        eventIds: "4624,4625",
        timeWindow: "7d",
      },
      onLoad: {
        search: "logon",
        quickFilter: {
          mode: "allWords",
          query: "boot failed",
          scope: "visibleColumns",
          action: "hide",
          caseSensitive: true,
          highlight: false,
        },
      },
      afterLoad: { groupBy: ["level", "provider"] },
    });
    expect(criteria.beforeLoad.levels).toEqual(["Error", "Warning"]);
    expect(criteria.beforeLoad.timeWindow).toBe("7d");
    expect(criteria.afterLoad.groupBy).toEqual(["level", "provider"]);
    expect(criteria.onLoad.quickFilter).toEqual({
      mode: "allWords",
      query: "boot failed",
      scope: "visibleColumns",
      action: "hide",
      caseSensitive: true,
      highlight: false,
    });
  });

  it("drops unrecognised levels and group fields rather than trusting the file", () => {
    // Import files are hand-edited and shared; an unknown value must not widen a filter.
    const criteria = sanitizeCriteria({
      beforeLoad: { levels: ["Error", "Bogus"] },
      afterLoad: { groupBy: ["level", "nonsense"] },
    });
    expect(criteria.beforeLoad.levels).toEqual(["Error"]);
    expect(criteria.afterLoad.groupBy).toEqual(["level"]);
  });

  it("falls back to every level when none survive, rather than matching nothing", () => {
    const criteria = sanitizeCriteria({ beforeLoad: { levels: ["Bogus"] } });
    // Compared against the constant rather than its current size, so adding a level does not
    // report a length mismatch that says nothing about the cause.
    expect([...criteria.beforeLoad.levels].sort()).toEqual([...ALL_LEVELS].sort());
  });

  it("falls back to a known time window", () => {
    expect(sanitizeCriteria({ beforeLoad: { timeWindow: "forever" } }).beforeLoad.timeWindow).toBe("24h");
  });

  it("tolerates a completely wrong shape", () => {
    expect(sanitizeCriteria(null).beforeLoad.eventIds).toBe("");
    expect(sanitizeCriteria(42).onLoad.search).toBe("");
    expect(sanitizeCriteria(["a"]).beforeLoad.levels).toHaveLength(5);
  });
});

describe("sanitizeSavedFilter", () => {
  it("requires a name", () => {
    expect(sanitizeSavedFilter({ name: "   " }, "fallback")).toBeNull();
    expect(sanitizeSavedFilter({}, "fallback")).toBeNull();
  });

  it("supplies a fallback id and dedupes tags", () => {
    const saved = sanitizeSavedFilter(
      { name: "Logons", tags: ["auth", "auth", " auth ", ""] },
      "fallback"
    );
    expect(saved?.id).toBe("fallback");
    expect(saved?.tags).toEqual(["auth"]);
  });

  it("treats a non-boolean favorite as not favorite", () => {
    expect(sanitizeSavedFilter({ name: "x", favorite: "yes" }, "f")?.favorite).toBe(false);
  });
});

describe("parseFilterExport", () => {
  it("round-trips through buildFilterExport", () => {
    const original = [filter({ id: "a", name: "Errors", favorite: true })];
    const { filters, skipped } = parseFilterExport(buildFilterExport(original));
    expect(skipped).toBe(0);
    expect(filters[0].name).toBe("Errors");
    expect(filters[0].favorite).toBe(true);
  });

  it("skips individually invalid entries instead of failing the whole import", () => {
    const text = JSON.stringify({
      schema: 2,
      filters: [{ name: "Good" }, { noName: true }, { name: "Also good" }],
    });
    const { filters, skipped } = parseFilterExport(text);
    expect(filters.map((f) => f.name)).toEqual(["Good", "Also good"]);
    expect(skipped).toBe(1);
  });

  it("returns nothing for malformed json rather than throwing", () => {
    expect(parseFilterExport("{not json").filters).toEqual([]);
    expect(parseFilterExport("[]").filters).toEqual([]);
  });
});

describe("mergeFilters", () => {
  it("replaces a same-named filter and keeps the existing id", () => {
    // Ids are per machine, so matching on them would duplicate a filter shared twice.
    const existing = [filter({ id: "local", name: "Errors" })];
    const imported = [filter({ id: "remote", name: "errors", favorite: true })];
    const merged = mergeFilters(existing, imported);
    expect(merged).toHaveLength(1);
    expect(merged[0].id).toBe("local");
    expect(merged[0].favorite).toBe(true);
  });

  it("appends filters that do not collide", () => {
    const merged = mergeFilters(
      [filter({ id: "a", name: "A" })],
      [filter({ id: "b", name: "B" })]
    );
    expect(merged.map((f) => f.name)).toEqual(["A", "B"]);
  });
});

describe("orderFilters", () => {
  it("puts favorites first, then most recent, then alphabetical", () => {
    const ordered = orderFilters([
      filter({ name: "Zulu" }),
      filter({ name: "Alpha" }),
      filter({ name: "Recent", lastUsed: 100 }),
      filter({ name: "Starred", favorite: true }),
    ]);
    expect(ordered.map((f) => f.name)).toEqual(["Starred", "Recent", "Alpha", "Zulu"]);
  });

  it("does not mutate its input", () => {
    const input = [filter({ name: "B" }), filter({ name: "A" })];
    orderFilters(input);
    expect(input.map((f) => f.name)).toEqual(["B", "A"]);
  });
});

describe("hostile stored values", () => {
  it("rejects a non-finite lastUsed", () => {
    const parsed = parseFilterExport(
      '{"schema":2,"filters":[{"id":"a","name":"A","lastUsed":1e309}]}'
    );
    expect(parsed.filters).toHaveLength(1);
    expect(parsed.filters[0].lastUsed).toBeNull();
  });

  it("keeps a finite lastUsed", () => {
    const parsed = parseFilterExport(
      JSON.stringify({ schema: 2, filters: [{ id: "a", name: "A", lastUsed: 1700000000000 }] })
    );
    expect(parsed.filters[0].lastUsed).toBe(1700000000000);
  });

  it("refuses an export written by a newer or older schema", () => {
    for (const schema of [1, 99]) {
      const parsed = parseFilterExport(
        JSON.stringify({ schema, filters: [{ id: "a", name: "A" }] })
      );
      expect(parsed.filters).toHaveLength(0);
      expect(parsed.unsupportedSchema).toBe(true);
    }
  });

  it("still accepts the current schema", () => {
    const parsed = parseFilterExport(
      JSON.stringify({ schema: SAVED_FILTER_SCHEMA, filters: [{ id: "a", name: "A" }] })
    );
    expect(parsed.filters).toHaveLength(1);
    expect(parsed.unsupportedSchema).toBeUndefined();
  });

  it("rejects exports with a missing or non-numeric schema", () => {
    for (const payload of [
      { filters: [{ id: "a", name: "A" }] },
      { schema: "2", filters: [{ id: "a", name: "A" }] },
    ]) {
      const parsed = parseFilterExport(JSON.stringify(payload));
      expect(parsed.filters).toHaveLength(0);
      expect(parsed.unsupportedSchema).toBe(true);
    }
  });
});
