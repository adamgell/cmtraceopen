/**
 * `makeData` builds the shared correlation data as the hook stores it, so a test that asks for a
 * state gets that state and not a neighbour of it. The states of the unplaced list are the ones the
 * hook has: no run (null, with no counts), a run that counted none, and a run whose count is unknown.
 */
import { describe, expect, it } from "vitest";
import { fixtureEdges, makeData, type DataOptions } from "./evtx-correlation-test-fixtures";

const base: DataOptions = { items: [], edges: fixtureEdges("exactPair"), hasItems: false };

describe("makeData and the states of the unplaced list", () => {
  it("has no list and no counts for no run, as the hook has none without a session", () => {
    const data = makeData({ ...base, unplacedList: null });
    expect(data.unplacedList).toBeNull();
    expect(data.counts).toBeNull();
  });

  it("counts a default run as having none, in the data and in the counts alike", () => {
    const data = makeData({ ...base });
    expect(data.unplacedList).toEqual({ items: [], total: 0 });
    expect(data.counts?.unplacedList).toEqual({ items: [], total: 0 });
  });

  it("keeps a run whose count is unknown as unknown in both, never as 0", () => {
    const data = makeData({ ...base, unplacedList: { items: [], total: null } });
    expect(data.unplacedList).toEqual({ items: [], total: null });
    expect(data.counts?.unplacedList).toEqual({ items: [], total: null });
  });

  it("gives the counts the same list as the data", () => {
    const list = { items: [], total: 12 };
    const data = makeData({ ...base, unplacedList: list });
    expect(data.counts?.unplacedList).toBe(list);
  });

  it("uses the counts it is given, even for no run", () => {
    const given = makeData({ ...base }).counts;
    expect(makeData({ ...base, unplacedList: null, counts: given }).counts).toBe(given);
    expect(makeData({ ...base, counts: null }).counts).toBeNull();
  });
});
