/**
 * What the rail's Chains tab shows (spec 8.13, #841), decided as data: which rows, in what order and
 * cap, which are cards and which compact rows, the steps and their chips, the legend, the nearby group,
 * the Not placed card, the empty states and whether the actions may act. Pure: the shared correlation
 * data is built with the real chain model (`makeData`), as the view's tests do.
 */
import { describe, expect, it } from "vitest";
import modelSource from "./evtx-rail-chains-model.ts?raw";
import { CORRELATION_CHAIN_RENDER_LIMIT } from "./evtx-correlation-chains";
import {
  CHAIN_ENTRIES_BEING_READ_TEXT,
  CHAIN_STEPS_NOT_READ_TEXT,
  CONTAINS_SELECTED_EVENT_SUFFIX,
  NO_ANALYSIS_TEXT,
  NO_CHAINS_QUALIFIED_TEXT,
  NO_ENTRY_POSITION_TEXT,
  NO_LINKED_EVENTS_TEXT,
  NO_POSITION_TEXT,
  READING_EDGES_TEXT,
  SEQUENCE_ORDER_NOTE,
  UNREAD_SOURCES_CHAINS_NOTE,
  UPDATING_CORRELATION_TEXT,
  chainRowName,
  edgeInputNotice,
  moreText,
  noChainsFoundText,
  pastCapNotice,
  renderCapNotice,
  whyStatement,
} from "./evtx-correlation-copy";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import {
  T0,
  eventItem,
  fixtureEdges,
  idsOf,
  makeData,
  numberOf,
  recordFor,
  rid,
  synthetic,
  type DataOptions,
} from "./evtx-correlation-test-fixtures";
import { WAIT_FOR_UPDATE_REASON } from "./evtx-unplaced";
import { WAIT_FOR_ENTRIES_REASON } from "./evtx-correlation-copy";
import {
  RAIL_CHAIN_STEP_LIMIT,
  buildRailChains,
  selectedRecordRowId,
  type RailCardRow,
  type RailChainsReady,
  type RailCompactRow,
} from "./evtx-rail-chains-model";
import { TIME_RANGE_SEPARATOR } from "./evtx-time";
import { UNAVAILABLE_CORRELATION } from "./useEvtxCorrelation";
import { timelineOriginId, type TimelineItem, type UnplacedItem } from "./unified-timeline";

const NO_UNPROVEN_CLAIM = /not placed|no timeline position|without a timeline position|no timestamp/i;

function logItem(line: number, timestampMs: number, file = "C:\\Logs\\AppEnforce.log"): TimelineItem {
  return {
    timestampMs,
    severity: "warning",
    message: `log line ${line}`,
    origin: { kind: "log", file, component: null, line, source: file, machine: null, bundle: null, recordId: line },
  };
}

function itemsFor(edges: ReturnType<typeof fixtureEdges>): TimelineItem[] {
  return idsOf(edges).map((id) => eventItem(numberOf(id), T0 + numberOf(id) * 1_000));
}

/** An exact pair (1, 2), an ambiguous group of three (3 to 5), a candidate pair and a blocked pair. */
function mixed(extra: Partial<DataOptions> = {}) {
  const edges = [
    ...fixtureEdges("pairAndGroupDisjoint"),
    ...fixtureEdges("secondaryPair", 10),
    ...fixtureEdges("gappedPair", 20),
  ];
  return makeData({ items: itemsFor(edges), edges, ...extra });
}

function pair(extra: Partial<DataOptions> = {}) {
  return makeData({
    items: [eventItem(1, T0, "error", "first failed"), eventItem(2, T0 + 6_000, "info", "second ok")],
    edges: fixtureEdges("exactPair"),
    ...extra,
  });
}

function manyPairs(count: number, extra: Partial<DataOptions> = {}) {
  const edges = Array.from({ length: count }, (_, i) => synthetic(`e${i}`, rid(2 * i + 1), rid(2 * i + 2)));
  const items = Array.from({ length: count * 2 }, (_, i) => eventItem(i + 1, T0 + i * 1_000));
  return makeData({ items, edges, ...extra });
}

const base = { timeZoneMode: "utc" as const, unreadSources: false, selectedRowId: null, nearby: [] as TimelineItem[] };

function ready(data: ReturnType<typeof makeData>, overrides: Partial<Parameters<typeof buildRailChains>[0]> = {}): RailChainsReady {
  const model = buildRailChains({ data, ...base, ...overrides });
  if (model.kind !== "ready") throw new Error(`expected a ready model, got ${model.kind}`);
  return model;
}
const cards = (model: RailChainsReady) => model.rows.filter((row): row is RailCardRow => row.kind === "card");
const compacts = (model: RailChainsReady) => model.rows.filter((row): row is RailCompactRow => row.kind === "compact");

describe("without a model", () => {
  it("says there is no analysis when none exists and nothing is on the way, and claims nothing else", () => {
    expect(buildRailChains({ data: UNAVAILABLE_CORRELATION, ...base })).toEqual({ kind: "waiting", text: NO_ANALYSIS_TEXT });
  });

  it("says the edges are being read while a session is built, never that there is no analysis", () => {
    expect(buildRailChains({ data: { ...UNAVAILABLE_CORRELATION, stage: "pending" }, ...base })).toEqual({
      kind: "waiting",
      text: READING_EDGES_TEXT,
    });
  });

  it("shows a failure that is not a load result as a failure", () => {
    expect(
      buildRailChains({ data: { ...UNAVAILABLE_CORRELATION, stage: "pending", error: "boom" }, ...base }),
    ).toEqual({ kind: "failed", text: "Correlation could not be built: boom" });
  });
});

describe("the rows are the model's: its order, its cap, its rows", () => {
  it("lists every row of the model in the model's own order, strongest first, and does not re-sort", () => {
    const data = mixed();
    const model = ready(data);
    expect(model.rows.map((row) => row.chain.id)).toEqual(data.model!.chains.map((chain) => chain.id));
    expect(model.rows.map((row) => row.strength)).toEqual(data.model!.chains.map((chain) => chain.strength));
    expect(new Set(model.rows.map((row) => row.strength))).toEqual(new Set(["exact", "candidate", "ambiguous", "coverageBlocked"]));
  });

  it("makes a card of an exact or candidate chain and a compact row of the rest", () => {
    const model = ready(mixed());
    expect(model.rows.map((row) => [row.strength, row.kind])).toEqual([
      ["exact", "card"],
      ["candidate", "card"],
      ["ambiguous", "compact"],
      ["coverageBlocked", "compact"],
    ]);
  });

  it("caps at the render limit with the view's line, and lists the same rows the view would", () => {
    const data = manyPairs(CORRELATION_CHAIN_RENDER_LIMIT + 5);
    const model = ready(data);
    expect(model.rows).toHaveLength(CORRELATION_CHAIN_RENDER_LIMIT);
    expect(model.rows.map((row) => row.chain.id)).toEqual(data.model!.chains.map((chain) => chain.id));
    expect(model.notices).toContain(
      renderCapNotice({ shown: 100, totalCount: 105, omittedCount: 5 }),
    );
    expect(model.notices).toContain("Showing the first 100 of 105; 5 omitted.");
  });

  it("says nothing about the cap when nothing was dropped", () => {
    expect(ready(mixed()).notices.join(" ")).not.toMatch(/Showing the first|omitted/);
  });

  it("names each row as the view's option is named", () => {
    const data = mixed();
    const model = ready(data);
    expect(model.rows.map((row) => row.name)).toEqual(data.model!.chains.map((chain) => chainRowName(chain)));
  });

  it("shows a title, the span and the entries of every row, and the neutral fallbacks when there are none", () => {
    const model = ready(pair());
    const card = cards(model)[0]!;
    expect(card.title).toBe("101 \u00b7 first failed");
    expect(card.span).toBe(`10:20:00${TIME_RANGE_SEPARATOR}10:20:06`);
    expect(card.entries).toBe("2 entries");
    const counted = ready(pair({ hasItems: false, stage: "edgesOnly" }));
    expect(cards(counted)[0]!.title).toBe("Untitled chain");
    expect(cards(counted)[0]!.span).toBe(NO_POSITION_TEXT);
  });

  it("shows the first key, cut in the middle, with the whole value for a tooltip and the number of further keys", () => {
    const card = cards(ready(pair()))[0]!;
    expect(card.key).toEqual({ label: "key: ActivityId", shortValue: expect.any(String), fullValue: expect.any(String), more: 0 });
    expect(card.key!.fullValue.startsWith(card.key!.shortValue.slice(0, 2))).toBe(true);
  });
});

describe("the steps of a card", () => {
  it("lists the members in time order with a clock, the level, the message and the chip of the entry's kind", () => {
    const line = logItem(9, T0 + 3_000);
    const items = [eventItem(1, T0, "error", "first failed"), line, eventItem(3, T0 + 6_000, "info", "last ok")];
    const edges = [synthetic("e1", rid(1), timelineOriginId(line.origin)), synthetic("e2", timelineOriginId(line.origin), rid(3))];
    const card = cards(ready(makeData({ items, edges })))[0]!;
    expect(card.steps.map((step) => [step.timeText, step.level, step.chip, step.message])).toEqual([
      ["10:20:00", "Error", "EVT", "first failed"],
      ["10:20:03", "Warning", "LOG", "log line 9"],
      ["10:20:06", "Information", "EVT", "last ok"],
    ]);
    expect(card.more).toBeNull();
    expect(card.stepsText).toBeNull();
  });

  it("applies the time zone mode to the clock", () => {
    const card = cards(ready(pair(), { timeZoneMode: "local" }))[0]!;
    expect(card.steps[0]!.timeText).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });

  it(`stops at ${RAIL_CHAIN_STEP_LIMIT} steps and counts what it left out, exactly`, () => {
    const ids = Array.from({ length: 9 }, (_, i) => i + 1);
    const edges = ids.slice(1).map((n) => synthetic(`e${n}`, rid(n - 1), rid(n)));
    const items = ids.map((n) => eventItem(n, T0 + n * 1_000));
    const card = cards(ready(makeData({ items, edges })))[0]!;
    expect(RAIL_CHAIN_STEP_LIMIT).toBe(6);
    expect(card.steps).toHaveLength(6);
    expect(card.more).toBe(moreText(3, true));
    expect(card.more).toBe("+3 more");
  });

  it("marks an entry whose timestamp equals the one above, because time does not order the two", () => {
    const items = [eventItem(1, T0), eventItem(2, T0)];
    const card = cards(ready(makeData({ items, edges: fixtureEdges("exactPair") })))[0]!;
    expect(card.steps.map((step) => step.sameTimeAsPrevious)).toEqual([false, true]);
  });

  it("says the order is not evidence of cause once, above the cards, when a card has steps", () => {
    expect(ready(pair()).orderNote).toBe(SEQUENCE_ORDER_NOTE);
    expect(ready(pair({ hasItems: false, stage: "edgesOnly" })).orderNote).toBeNull();
    expect(ready(makeData({ items: [], edges: fixtureEdges("group3") })).orderNote).toBeNull();
  });

  it("lists no step for a compact row", () => {
    for (const row of compacts(ready(mixed()))) {
      expect(row).not.toHaveProperty("steps");
      expect(row.description).toBe(whyStatement(row.chain));
    }
  });

  it("says a chain none of whose entries has a loaded position has none to show", () => {
    const none = ready(makeData({ items: [], edges: fixtureEdges("exactPair"), hasItems: true }));
    expect(cards(none)[0]!.steps).toEqual([]);
    expect(cards(none)[0]!.stepsText).toBe(NO_ENTRY_POSITION_TEXT);
  });

  it("without the entries has no steps, and says they are being read or were not read", () => {
    const counts = pair({ hasItems: false, stage: "edgesOnly" });
    expect(cards(ready(counts))[0]!.steps).toEqual([]);
    expect(cards(ready(counts))[0]!.stepsText).toBe(CHAIN_STEPS_NOT_READ_TEXT);
    // Every member is unresolved before the entries are read: that is not a partial chain to explain.
    expect(cards(ready(counts))[0]!.partialNote).toBeNull();
    const reading = pair({ hasItems: false, stage: "scanning", nextScan: { state: "running", progress: null, stoppedBy: null, error: null } });
    expect(cards(ready(reading))[0]!.stepsText).toBe(CHAIN_ENTRIES_BEING_READ_TEXT);
    const scanning = pair({ hasItems: false, stage: "scanning" });
    expect(cards(ready(scanning))[0]!.stepsText).toBe(CHAIN_ENTRIES_BEING_READ_TEXT);
  });

  describe("members with no entry read", () => {
    const partialData = (unplaced: Partial<DataOptions["unplaced"]> = {}) =>
      makeData({ items: [eventItem(1, T0)], edges: fixtureEdges("exactPair"), unplaced });

    it("is said as a partial card, with the entries said for ALL members", () => {
      const card = cards(ready(partialData()))[0]!;
      expect(card.partial).toBe(true);
      expect(card.entries).toBe("2 entries");
      expect(card.steps).toHaveLength(1);
    });

    it("says no timestamp only when the engine's complete unplaced list proves it", () => {
      const proven = { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set([rid(2)]) };
      expect(cards(ready(partialData(proven)))[0]!.partialNote).toBe(
        "1 of 2 entries carry no timestamp, so they are not listed as steps.",
      );
      expect(cards(ready(partialData({ unplacedListComplete: false, unplacedIds: new Set([rid(2)]) })))[0]!.partialNote).toBe(
        "1 of 2 entries have no loaded timeline position, so they are not listed as steps.",
      );
    });

    it("has no note for a chain whose entries were all read", () => {
      expect(cards(ready(pair()))[0]!.partialNote).toBeNull();
      expect(cards(ready(pair()))[0]!.partial).toBe(false);
    });
  });
});

describe("the chain of the selected event", () => {
  it("marks the row the model is told, and only that row, and names it so", () => {
    const data = mixed();
    const target = data.model!.chains[1]!;
    const model = ready(data, { selectedRowId: target.id });
    expect(model.rows.filter((row) => row.selected).map((row) => row.chain.id)).toEqual([target.id]);
    expect(model.rows.find((row) => row.selected)!.name).toBe(`${chainRowName(target)}${CONTAINS_SELECTED_EVENT_SUFFIX}`);
    expect(ready(data).rows.some((row) => row.selected)).toBe(false);
  });

  it("marks a compact row too, when that is the strongest the event is in", () => {
    const data = mixed();
    const ambiguous = data.model!.chains.find((chain) => chain.strength === "ambiguous")!;
    const model = ready(data, { selectedRowId: ambiguous.id });
    expect(compacts(model).find((row) => row.selected)?.chain.id).toBe(ambiguous.id);
  });

  it("lists a row past the render cap after the capped rows, in its own form, and says why it is there", () => {
    const data = manyPairs(CORRELATION_CHAIN_RENDER_LIMIT + 30);
    const shown = new Set(data.model!.chains.map((chain) => chain.id));
    const past = [...data.model!.rowsByMember.values()].map((rows) => rows[0]!).find((row) => !shown.has(row.id))!;
    const model = ready(data, { selectedRowId: past.id });
    expect(model.rows).toHaveLength(CORRELATION_CHAIN_RENDER_LIMIT + 1);
    expect(model.rows.slice(0, CORRELATION_CHAIN_RENDER_LIMIT).map((row) => row.chain.id)).toEqual(
      data.model!.chains.map((chain) => chain.id),
    );
    expect(model.rows[model.rows.length - 1]).toMatchObject({ kind: "card", selected: true });
    expect(model.rows[model.rows.length - 1]!.chain.id).toBe(past.id);
    expect(model.notices).toContain(pastCapNotice(CORRELATION_CHAIN_RENDER_LIMIT));
  });

  it("keeps a row past the cap among compact rows in the model's order: rows are never regrouped", () => {
    const data = mixed();
    const model = ready(data, { selectedRowId: data.model!.chains[0]!.id });
    expect(model.rows.map((row) => row.chain.id)).toEqual(data.model!.chains.map((chain) => chain.id));
  });
});

describe("selectedRecordRowId", () => {
  const data = pair();
  const only = (id: number) => recordFor(id);

  it("is the row of the one entry that names the record", () => {
    expect(selectedRecordRowId(only(1), data)).toBe(data.model!.chains[0]!.id);
    expect(selectedRecordRowId(only(2), data)).toBe(data.model!.chains[0]!.id);
  });

  it("is the STRONGEST row the entry is in", () => {
    // Entry 2 is in an exact pair (1, 2) and in an ambiguous group (2, 3, 4).
    const edges = [synthetic("e1", rid(1), rid(2)), ...fixtureEdges("group3", 1)];
    const both = makeData({ items: itemsFor(edges), edges });
    expect(both.model!.rowsByMember.get(rid(2))!.map((row) => row.strength)).toEqual(["exact", "ambiguous"]);
    expect(selectedRecordRowId(recordFor(2), both)).toBe(both.model!.rowsByMember.get(rid(2))![0]!.id);
    expect(selectedRecordRowId(recordFor(3), both)).toBe(both.model!.rowsByMember.get(rid(3))![0]!.id);
    expect(both.model!.rowsByMember.get(rid(3))![0]!.strength).toBe("ambiguous");
  });

  it("is null for a record no row holds, and for no record", () => {
    expect(selectedRecordRowId(only(9), data)).toBeNull();
    expect(selectedRecordRowId(null, data)).toBeNull();
  });

  it("is null when several entries name the record: none is picked among them", () => {
    const twice = [
      eventItem(1, T0),
      { ...eventItem(1, T0), origin: { ...eventItem(1, T0).origin, stableId: "copy" } },
      eventItem(2, T0 + 1_000),
    ];
    const both = makeData({ items: twice, edges: fixtureEdges("exactPair") });
    expect(selectedRecordRowId(only(1), both)).toBeNull();
  });

  it("is null before the entries are read, even if some entries are at hand, and with no model", () => {
    expect(selectedRecordRowId(only(1), pair({ hasItems: false, stage: "edgesOnly" }))).toBeNull();
    expect(selectedRecordRowId(only(1), { ...pair(), hasItems: false })).toBeNull();
    expect(selectedRecordRowId(only(1), UNAVAILABLE_CORRELATION)).toBeNull();
  });
});

describe("what the model says about what it did not cover", () => {
  it("lists the view's notices from the one builder", () => {
    const model = ready(pair({ totalEdges: 40 }));
    expect(model.notices).toContain(edgeInputNotice({ edgeInputComplete: false, unloadedEdgeCount: 39 }));
  });

  it("says sources that were not fully read, and says nothing otherwise", () => {
    expect(ready(pair(), { unreadSources: true }).notices).toContain(UNREAD_SOURCES_CHAINS_NOTE);
    expect(ready(pair()).notices).not.toContain(UNREAD_SOURCES_CHAINS_NOTE);
  });

  it("says the update under way, the read in progress, a stopped read, and a retry for each failure", () => {
    const model = ready(pair({ updating: true, nextScan: { state: "running", progress: { scannedItems: 3, totalItems: 9, retainedItems: 1 }, stoppedBy: null, error: null } }));
    expect(model.statusText).toBe(UPDATING_CORRELATION_TEXT);
    expect(model.readingText).toBe("Reading 3 of 9 timeline items...");
    expect(ready(pair()).statusText).toBeNull();
    expect(ready(pair()).readingText).toBeNull();
    expect(ready(pair()).retry).toBe(false);
    expect(ready(pair({ scan: { state: "incomplete", stoppedBy: "budget", error: null } })).retry).toBe(true);
    expect(ready(pair({ edgeState: { error: "edges down" } })).retry).toBe(true);
  });

  it("shows a failure to update the model as such, with the model still on show", () => {
    expect(ready(pair({ error: "boom" })).error).toBe("Correlation could not be updated: boom");
    expect(ready(pair()).error).toBeNull();
  });
});

describe("the empty states", () => {
  const empty = (extra: Partial<DataOptions> = {}, overrides: Partial<Parameters<typeof buildRailChains>[0]> = {}) =>
    ready(makeData({ items: [], edges: [], ...extra }), overrides);

  it("says the spec's sentence when the session can speak for an absence", () => {
    expect(empty().emptyText).toBe(NO_LINKED_EVENTS_TEXT);
  });

  it.each([
    ["an edge that was never loaded", { totalEdges: 7 }, {}, noChainsFoundText(false)],
    ["a narrowed view", { scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } }, {}, NO_CHAINS_QUALIFIED_TEXT],
    ["a scope that is not known", { scope: null }, {}, NO_CHAINS_QUALIFIED_TEXT],
    ["a limit gap", { gaps: classifyCoverageGaps([{ source: "correlation", reason: "limit" }], 1) }, {}, NO_CHAINS_QUALIFIED_TEXT],
    ["a gap preview that is cut", { gaps: classifyCoverageGaps([], 4) }, {}, NO_CHAINS_QUALIFIED_TEXT],
    ["a rebuild under way", { updating: true }, {}, NO_CHAINS_QUALIFIED_TEXT],
    ["a source that was not fully read", {}, { unreadSources: true }, NO_CHAINS_QUALIFIED_TEXT],
  ] as const)("does not say there are no linked events under %s", (_why, extra, overrides, text) => {
    const model = empty(extra as Partial<DataOptions>, overrides);
    expect(model.emptyText).toBe(text);
    expect(model.emptyText).not.toBe(NO_LINKED_EVENTS_TEXT);
  });

  it("has no empty state when a row exists, even one that is not a link", () => {
    expect(ready(pair()).emptyText).toBeNull();
    expect(ready(makeData({ items: itemsFor(fixtureEdges("group3")), edges: fixtureEdges("group3") })).emptyText).toBeNull();
  });

  it("qualifies a line above rows that are not links, the same way", () => {
    const ambiguousOnly = makeData({ items: itemsFor(fixtureEdges("group3")), edges: fixtureEdges("group3") });
    expect(ready(ambiguousOnly).rowsLine).toBe("No exact or candidate chains were found.");
    expect(ready(ambiguousOnly, { unreadSources: true }).rowsLine).toBe(
      "No exact or candidate chains were found among what was loaded.",
    );
    expect(ready(pair()).rowsLine).toBeNull();
  });
});

describe("the legend", () => {
  it("is absent when there is nothing to key", () => {
    expect(ready(makeData({ items: [], edges: [] })).legend).toBeNull();
  });

  it("names exact and candidate in the spec's words, and no 'not linked' entry without a nearby entry", () => {
    const legend = ready(pair()).legend!;
    expect(legend).toEqual({ exact: "Exact match", candidate: "Candidate identity", notLinked: null });
  });
});

describe("the nearby group, which no producer feeds yet", () => {
  const stray = (n: number, offsetMs = 2_000) => eventItem(n, T0 + offsetMs);
  const withNearby = (items: TimelineItem[], extra: Partial<DataOptions> = {}, overrides: Partial<Parameters<typeof buildRailChains>[0]> = {}) =>
    ready(pair(extra), { nearby: items, ...overrides });

  it("is absent with no nearby entry, whatever the session", () => {
    expect(ready(pair()).nearby).toBeNull();
  });

  it("says 'Not linked', for entries in no row, only when the session can speak", () => {
    const model = withNearby([stray(8), stray(9, 3_000)]);
    expect(model.nearby!.heading).toBe("Nearby, not linked (2)");
    expect(model.legend!.notLinked).toBe("Not linked");
    expect(model.nearby!.rows.map((row) => row.reason)).toEqual(["time only, not linked", "time only, not linked"]);
  });

  it.each([
    ["edges not all loaded", { totalEdges: 12 }, {}],
    ["a narrowed view", { scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } }, {}],
    ["an unread source", {}, { unreadSources: true }],
    ["a rebuild under way", { updating: true }, {}],
  ] as const)("says 'No loaded link' and never 'not linked' under %s", (_why, extra, overrides) => {
    const model = withNearby([stray(8)], extra as Partial<DataOptions>, overrides);
    expect(model.nearby!.heading).toBe("Nearby, no loaded link (1)");
    expect(model.legend!.notLinked).toBe("No loaded link");
    expect(model.nearby!.rows[0]!.reason).toBe("time only, no loaded link");
    expect(JSON.stringify(model.nearby)).not.toMatch(/not linked/);
  });

  it("withdraws 'Not linked' for an entry a gap names, and so for the group", () => {
    const gaps = classifyCoverageGaps([{ source: rid(9), reason: "x" }], 1);
    const model = withNearby([stray(8), stray(9, 3_000)], { gaps });
    expect(model.nearby!.rows.map((row) => row.reason)).toEqual(["time only, not linked", "time only, no loaded link"]);
    expect(model.nearby!.heading).toBe("Nearby, no loaded link (2)");
  });

  it("hands the session's loaded partners to the rule: an entry with one is 'in another chain'", () => {
    // Every entry with a loaded partner is a member of a row, and so is listed there; this feeds the
    // rule an inconsistent snapshot on purpose, to see that the partners reach it.
    const data = { ...pair(), linkPartners: new Map([[rid(8), 1]]) };
    const model = ready(data, { nearby: [stray(8)] });
    expect(model.nearby!.rows[0]!.reason).toBe("time only; in another chain");
    expect(model.nearby!.heading).toBe("Nearby, not in this chain (1)");
    expect(model.legend!.notLinked).toBe("Not in this chain");
  });

  it("leaves out an entry that is a member of a row: it is listed there, not as context", () => {
    const model = withNearby([eventItem(1, T0), stray(8)]);
    expect(model.nearby!.rows.map((row) => row.id)).toEqual([timelineOriginId(stray(8).origin)]);
    expect(withNearby([eventItem(1, T0)]).nearby).toBeNull();
  });

  it("gives an entry no strength and no connector, and adds no row", () => {
    const model = withNearby([stray(8), stray(9, 3_000)]);
    expect(model.nearby!.rows[0]).not.toHaveProperty("strength");
    expect(model.nearby!.rows[0]).not.toHaveProperty("chain");
    expect(model.rows).toHaveLength(1);
  });

  it("orders the entries by time and names them by the lane they are in", () => {
    const model = withNearby([stray(9, 3_000), stray(8, 2_000)]);
    expect(model.nearby!.rows.map((row) => row.timeText)).toEqual(["10:20:02", "10:20:03"]);
    expect(model.nearby!.rows[0]!.entry).toBe("108 \u00b7 System");
  });
});

describe("the Not placed card", () => {
  const unplaced = (n: number): UnplacedItem => ({
    reason: "missingTimestamp",
    origin: logItem(n, 0).origin,
  });

  it("is absent when there is no run, and when the engine counted none", () => {
    expect(ready(pair({ unplacedList: { items: [], total: 0 } })).notPlaced).toBeNull();
  });

  it("states the count the engine gave, in the card's own words", () => {
    const model = ready(pair({ unplacedList: { items: [unplaced(1), unplaced(2)], total: 5 } }));
    expect(model.notPlaced).toEqual({
      heading: "Not placed (5)",
      body: "5 items carry no timestamp. Placing them would invent an order the evidence does not support.",
    });
  });

  it("says the count is unknown, never 0, when the engine's count was not trusted", () => {
    const model = ready(pair({ unplacedList: { items: [], total: null } }));
    expect(model.notPlaced!.heading).toBe("Not placed (count unknown)");
    expect(model.notPlaced!.body).toContain("not known");
    expect(JSON.stringify(model.notPlaced)).not.toMatch(/\(0\)/);
  });
});

describe("the actions", () => {
  it("may act on a chain whose entries were read, in a model that is not being rebuilt", () => {
    expect(ready(pair()).actions).toEqual({ canAct: true, reason: undefined });
  });

  it("waits for the update first, then for the entries", () => {
    expect(ready(pair({ updating: true })).actions).toEqual({ canAct: false, reason: WAIT_FOR_UPDATE_REASON });
    expect(ready(pair({ hasItems: false, stage: "edgesOnly" })).actions).toEqual({
      canAct: false,
      reason: WAIT_FOR_ENTRIES_REASON,
    });
  });
});

describe("no string claims an entry is unplaced without proof", () => {
  it("over every state the model can be in with weak evidence", () => {
    const weak = { scanComplete: false, unplacedListComplete: false, unplacedIds: new Set<string>() };
    const states = [
      ready(makeData({ items: [eventItem(1, T0)], edges: fixtureEdges("exactPair"), unplaced: weak })),
      ready(makeData({ items: [], edges: fixtureEdges("group3"), unplaced: weak })),
      ready(makeData({ items: [], edges: fixtureEdges("gappedPair"), unplaced: weak, hasItems: false, stage: "edgesOnly" })),
      ready(makeData({ items: [], edges: [], unplaced: weak, totalEdges: 3 }), { unreadSources: true }),
      ready(mixed({ unplaced: weak, updating: true })),
    ];
    for (const model of states) {
      const text = JSON.stringify(model, (key, value) => (key === "chain" ? undefined : value));
      expect(text).not.toMatch(NO_UNPROVEN_CLAIM);
    }
  });
});

describe("pure", () => {
  it("imports no React, store or IO", () => {
    expect(modelSource).not.toMatch(/from "react"|zustand|@tauri-apps|from "\.\/evtx-store"|from "\.\/evtx-layout-store"/);
  });

  it("has no color literal, no font size and no hard-coded sentence of the copy module's", () => {
    expect(modelSource).not.toMatch(/["'`]#[0-9a-fA-F]{3,8}["'`]|\brgba?\(|\d\s*px\b/);
  });
});
