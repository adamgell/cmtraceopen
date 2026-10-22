/**
 * What the dock and the Details context both read first: which entry of a window is the selected
 * event, whether the counts belong to the window, and what may be shown (#842, #843). Both surfaces
 * call `readWindowFacts`, `dockCenterMs` and `compareByDistance`, so the ruled ladder has one
 * definition. `buildDockModel`'s own tests pin the same behaviour through the dock.
 */
import { describe, expect, it } from "vitest";
import {
  compareByDistance,
  readWindowFacts,
  dockCenterMs,
  type DockModelInput,
  type WindowRead,
} from "./evtx-correlation-dock-model";
import { fixtureEdges, eventItem, recordFor, rid, T0 } from "./evtx-correlation-test-fixtures";
import {
  countsFor,
  stoppedWindow,
  twinOf,
  unnumbered,
  windowAround,
} from "./evtx-detail-context-test-helpers";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

/** The facts of a read, failing the test for any early kind. */
function read(input: DockModelInput): WindowRead {
  const facts = readWindowFacts(input);
  if (facts.kind !== "read") throw new Error(`expected a read, got ${facts.kind}`);
  return facts;
}

/** Record 1 with its own entry and one 6 s later, an exact pair, counts of the same session. */
function scene(extra: Partial<DockModelInput> = {}): DockModelInput & { items: TimelineItem[] } {
  const record = recordFor(1);
  const items = [eventItem(1, record.timestampEpoch), eventItem(2, record.timestampEpoch + 6_000)];
  return {
    record,
    window: windowAround(record, items),
    counts: countsFor(fixtureEdges("exactPair")),
    unreadSources: false,
    items,
    ...extra,
  };
}

describe("dockCenterMs: the one definition of the instant a window is read around", () => {
  it("is null for no record", () => {
    expect(dockCenterMs(null)).toBeNull();
  });

  it("is the epoch of a record with a usable whole-millisecond timestamp", () => {
    expect(dockCenterMs(recordFor(1))).toBe(T0 + 1_000);
  });

  it.each([
    ["an epoch of 0", 0],
    ["a negative epoch", -5],
    ["an epoch that is not finite", Number.NaN],
    ["an infinite epoch", Number.POSITIVE_INFINITY],
    ["an epoch that is not a whole number of milliseconds", T0 + 0.5],
  ])("is null for %s", (_why, epoch) => {
    expect(dockCenterMs({ ...recordFor(1), timestampEpoch: epoch })).toBeNull();
  });
});

describe("compareByDistance: nearest first, then by id", () => {
  type Entry = { id: string; timestampMs: number };
  const at = (id: string, timestampMs: number): Entry => ({ id, timestampMs });
  const nearest = (center: number) => compareByDistance<Entry>(center, (entry) => entry.id);

  it("puts the nearer entry first, whichever side of the center it is on", () => {
    const order = [at("a", 1_000), at("b", 400), at("c", 1_900)].sort(nearest(1_000));
    expect(order.map((entry) => entry.id)).toEqual(["a", "b", "c"]);
    const before = [at("x", 1_500), at("y", 600)].sort(nearest(1_000));
    expect(before.map((entry) => entry.id)).toEqual(["y", "x"]);
  });

  it("breaks a tie on distance by id, so the order never depends on the input order", () => {
    const tied = [at("b", 1_100), at("c", 900), at("a", 1_100)];
    expect([...tied].sort(nearest(1_000)).map((entry) => entry.id)).toEqual(["a", "b", "c"]);
    expect([...tied].reverse().sort(nearest(1_000)).map((entry) => entry.id)).toEqual([
      "a",
      "b",
      "c",
    ]);
  });
});

describe("readWindowFacts: the states before there is anything to list", () => {
  it("has no selection without a record", () => {
    expect(readWindowFacts({ record: null, window: null, counts: null, unreadSources: false })).toEqual({
      kind: "noSelection",
    });
  });

  it("is untimed for a record with no usable timestamp, whatever window it is given", () => {
    const { window } = scene();
    const record = { ...recordFor(1), timestampEpoch: 0 };
    expect(readWindowFacts({ record, window, counts: null, unreadSources: false })).toEqual({ kind: "untimed" });
  });

  it("has nothing read before any window, and never pairs a record with another center's window", () => {
    const input = scene();
    expect(readWindowFacts({ ...input, window: null })).toEqual({ kind: "unread" });
    const other = { ...recordFor(1), timestampEpoch: input.record!.timestampEpoch + 1 };
    expect(readWindowFacts({ ...input, record: other })).toEqual({ kind: "unread" });
  });

  it("fails when the first reply never came, with the error, and never turns the count into 0", () => {
    const input = scene();
    const failed = windowAround(input.record!, [], { windowItems: null, omittedItems: null, complete: false, error: "down" });
    expect(readWindowFacts({ ...input, window: failed })).toEqual({ kind: "failed", error: "down" });
  });
});

describe("readWindowFacts: pairing the counts with the window, on the session key alone", () => {
  it("pairs counts of the window's own session", () => {
    const facts = read(scene());
    expect(facts.paired).toBe(true);
    expect(facts.pairedCounts).not.toBeNull();
    expect(facts.updating).toBe(false);
  });

  it("pairs nothing with counts of another session, and does not call that updating", () => {
    const facts = read(scene({ counts: countsFor(fixtureEdges("exactPair"), { builtFor: "session:2" }) }));
    expect(facts.paired).toBe(false);
    expect(facts.pairedCounts).toBeNull();
    expect(facts.updating).toBe(false);
    expect(facts.unplacedTotal).toBeNull();
    // Nothing can speak for a scope that is not paired.
    expect(facts.scopeNarrowed).toBe(true);
  });

  it("pairs nothing without counts", () => {
    const facts = read(scene({ counts: null }));
    expect(facts.paired).toBe(false);
    expect(facts.pairedCounts).toBeNull();
  });

  it("keeps an earlier session's pair, flagged updating, when the window is that session's own", () => {
    const facts = read(scene({ counts: countsFor(fixtureEdges("exactPair"), { updating: true }) }));
    expect(facts.paired).toBe(true);
    expect(facts.updating).toBe(true);
    // An earlier session's pair is `updating`, which is its own input to the absence rule, and is
    // not folded into the scope.
    expect(facts.scopeNarrowed).toBe(false);
  });

  it("reads the unplaced count from the paired counts only", () => {
    expect(read(scene({ counts: countsFor(fixtureEdges("exactPair"), { unplacedList: { items: [], total: 4 } }) })).unplacedTotal).toBe(4);
    expect(read(scene({ counts: countsFor(fixtureEdges("exactPair"), { unplacedList: { items: [], total: null } }) })).unplacedTotal).toBeNull();
    expect(read(scene()).unplacedTotal).toBe(0);
  });
});

describe("readWindowFacts: the scope is its own fact, and the three caveats are never folded into one", () => {
  it("is not narrowed when nothing is", () => {
    const facts = read(scene());
    expect(facts.scopeNarrowed).toBe(false);
    expect(facts.updating).toBe(false);
  });

  it("is narrowed when the session was built from fewer events than are loaded", () => {
    const facts = read(scene({ counts: countsFor(fixtureEdges("exactPair"), { scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } }) }));
    expect(facts.scopeNarrowed).toBe(true);
  });

  it("is narrowed when the scope is not known", () => {
    expect(read(scene({ counts: countsFor(fixtureEdges("exactPair"), { scope: null }) })).scopeNarrowed).toBe(true);
  });

  it("does not call an unread source a scope: it is the caller's own input to the absence rule", () => {
    const facts = read(scene({ unreadSources: true }));
    expect(facts.scopeNarrowed).toBe(false);
  });

  it("carries no field that stands for the scope, the unread sources and the rebuild together", () => {
    const facts = read(scene({ unreadSources: true, counts: countsFor(fixtureEdges("exactPair"), { updating: true }) }));
    expect(Object.keys(facts)).not.toContain("narrowed");
    expect(facts.scopeNarrowed).toBe(false);
    expect(facts.updating).toBe(true);
  });
});

describe("readWindowFacts: which entry is the selected event, and what may be shown", () => {
  it("finds the one entry that names the record, and shows every entry", () => {
    const input = scene();
    const facts = read(input);
    expect(facts.selected).toEqual({ status: "found", originId: rid(1) });
    expect(facts.originId).toBe(rid(1));
    expect(facts.identified).toBe(true);
    expect(facts.usable.map((item) => timelineOriginId(item.origin))).toEqual([rid(1), rid(2)]);
    expect(facts.items).toHaveLength(2);
    expect([...facts.naming]).toEqual([rid(1)]);
  });

  it("is ambiguous when several entries name it, and shows none of them", () => {
    const input = scene();
    const first = input.items[0]!;
    const twin = twinOf(first, rid(88));
    const facts = read({ ...input, window: windowAround(input.record!, [first, twin, eventItem(2, first.timestampMs + 6_000)]) });
    expect(facts.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(facts.originId).toBeNull();
    expect(facts.identified).toBe(false);
    expect(facts.usable.map((item) => timelineOriginId(item.origin))).toEqual([rid(2)]);
  });

  it("is unmatchable, from the record alone, and shows nothing", () => {
    const record = unnumbered(T0 + 1_000);
    const items = [eventItem(1, record.timestampEpoch), eventItem(2, record.timestampEpoch + 4_000)];
    const facts = read({ record, window: windowAround(record, items), counts: countsFor([]), unreadSources: false });
    expect(facts.selected).toEqual({ status: "unmatchable" });
    expect(facts.usable).toEqual([]);
    expect(facts.identified).toBe(false);
    expect(facts.items).toHaveLength(2);
  });

  it("is notInTimeline only for a window read whole, and then counts as identified", () => {
    const input = scene();
    const only = [eventItem(2, input.record!.timestampEpoch + 6_000)];
    const facts = read({ ...input, window: windowAround(input.record!, only) });
    expect(facts.selected).toEqual({ status: "notInTimeline" });
    expect(facts.identified).toBe(true);
    expect(facts.usable).toHaveLength(1);
  });

  it("is notRead, not notInTimeline, when a read that stopped holds no entry that names the event", () => {
    const input = scene();
    const early = [eventItem(5, input.record!.timestampEpoch - 20_000)];
    const facts = read({ ...input, window: stoppedWindow(input.record!, early, 2_500) });
    expect(facts.selected).toEqual({ status: "notRead" });
    expect(facts.identified).toBe(false);
  });
});
