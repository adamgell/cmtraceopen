/**
 * `makeData` builds the shared correlation data as the hook stores it, so a test that asks for a
 * state gets that state and not a neighbour of it. The states of the unplaced list are the ones the
 * hook has: no run (null, with no counts), a run that counted none, and a run whose count is unknown.
 */
import { describe, expect, it } from "vitest";
import { fixtureEdges, makeData, type DataOptions } from "./evtx-correlation-test-fixtures";
import { timelineOriginId } from "./unified-timeline";
import { UNAVAILABLE_CORRELATION } from "./useEvtxCorrelation";

const base: DataOptions = { items: [], edges: fixtureEdges("exactPair"), hasItems: false };

describe("makeData and the states of the unplaced list", () => {
  it("is the hook's unavailable shape for no run: no model, no counts, no list, no evidence", () => {
    const data = makeData({ ...base, unplacedList: null });
    expect(data.unplacedList).toBeNull();
    expect(data.counts).toBeNull();
    expect(data.model).toBeNull();
    expect(data.stage).toBe("unavailable");
    expect(data.hasItems).toBe(false);
    expect(data.unplaced).toBe(UNAVAILABLE_CORRELATION.unplaced);
    expect(data.edges).toBe(UNAVAILABLE_CORRELATION.edges);
  });

  it("keeps a pending no-run state pending, and any other stage unavailable", () => {
    expect(makeData({ ...base, unplacedList: null, stage: "pending" }).stage).toBe("pending");
    expect(makeData({ ...base, unplacedList: null, stage: "ready" }).stage).toBe("unavailable");
  });

  it("counts a default run as having none, in the data and in the counts alike", () => {
    const data = makeData({ ...base });
    expect(data.unplacedList).toEqual({ items: [], total: 0 });
    expect(data.counts?.unplacedList).toEqual({ items: [], total: 0 });
    expect(data.stage).toBe("ready");
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

  it("uses the counts it is given, null included, for a run", () => {
    const given = makeData({ ...base }).counts;
    expect(makeData({ ...base, counts: given }).counts).toBe(given);
    expect(makeData({ ...base, counts: null }).counts).toBeNull();
  });
});

describe("makeData derives the unplaced evidence from the list, as the hook does", () => {
  const item = (n: number) => ({
    reason: "missingTimestamp" as const,
    origin: {
      kind: "log" as const,
      file: `C:\\Logs\\a${n}.log`,
      component: null,
      line: n,
      source: "w.cpp",
      machine: null,
      bundle: null,
      recordId: n,
    },
  });
  const items = [item(1), item(2), item(3)];

  it("is complete only when the count is known and equals the items listed", () => {
    expect(makeData({ ...base, unplacedList: { items, total: 3 } }).unplaced.unplacedListComplete).toBe(true);
    expect(makeData({ ...base, unplacedList: { items, total: 8 } }).unplaced.unplacedListComplete).toBe(false);
    expect(makeData({ ...base, unplacedList: { items: [], total: 0 } }).unplaced.unplacedListComplete).toBe(true);
  });

  it("is not complete for an unknown count, even with nothing listed, where the hook says false", () => {
    expect(makeData({ ...base, unplacedList: { items: [], total: null } }).unplaced.unplacedListComplete).toBe(false);
    expect(makeData({ ...base, unplacedList: { items, total: null } }).unplaced.unplacedListComplete).toBe(false);
  });

  it("lists the ids of the items listed, and none for an empty list", () => {
    const data = makeData({ ...base, unplacedList: { items, total: 3 } });
    expect([...data.unplaced.unplacedIds].sort()).toEqual(items.map((entry) => timelineOriginId(entry.origin)).sort());
    expect(makeData({ ...base }).unplaced.unplacedIds.size).toBe(0);
  });

  it("lets a test state a contradiction on purpose, with `unplaced`", () => {
    const data = makeData({ ...base, unplacedList: { items, total: 3 }, unplaced: { unplacedListComplete: false } });
    expect(data.unplaced.unplacedListComplete).toBe(false);
    expect(data.unplaced.unplacedIds.size).toBe(3);
  });
});
