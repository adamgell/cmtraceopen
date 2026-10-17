/**
 * What the correlation dock shows. The window and the counts are built the way the loader and the
 * hook build them (the real chain model over real edges), and the selected record is the loaded
 * record an origin names, field for field, so the origin join is the production one.
 */
import { describe, expect, it } from "vitest";
import modelSource from "./evtx-correlation-dock-model.ts?raw";
import windowSource from "./evtx-correlation-window.ts?raw";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  AMBIGUOUS_EVENT_NOTE,
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  UNREAD_SOURCES_NOTE,
} from "./evtx-correlation-copy";
import {
  DOCK_MAX_LANES,
  DOCK_NEARBY_LINE_CAP,
  DOCK_NEARBY_MARKER_CAP,
  DOCK_STEP_CAP,
  buildDockModel,
  chainInWindow,
  dockMarkerName,
  type DockModelInput,
  type DockReady,
} from "./evtx-correlation-dock-model";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import {
  T0,
  eventItem,
  fixtureEdges,
  makeCounts,
  recordFor,
  rid,
  synthetic,
  type DataOptions,
} from "./evtx-correlation-test-fixtures";
import {
  IN_ANOTHER_CHAIN_LABEL,
  NOT_LINKED_LABEL,
  NO_LOADED_LINK_LABEL,
} from "./evtx-correlation-view-model";
import type { LoadedCorrelationWindow } from "./evtx-correlation-window";
import type { EvtxRecord } from "./types";
import type { TimelineCorrelationEdge, TimelineItem } from "./unified-timeline";
import { timelineOriginId } from "./unified-timeline";

const HALF = 75_000;
const SESSION_KEY = "session:1";
/** What no string may say unless the entry is proven unplaced; the dock never proves it. */
const NO_UNPROVEN_CLAIM = /not placed|no timeline position|without a timeline position/i;

/** The window the loader would return for `record` over `items`: whole, unless overridden. */
function windowAround(
  record: EvtxRecord,
  items: TimelineItem[],
  overrides: Partial<LoadedCorrelationWindow> = {},
): LoadedCorrelationWindow {
  return {
    sessionKey: SESSION_KEY,
    centerMs: record.timestampEpoch,
    halfWidthMs: HALF,
    startMs: record.timestampEpoch - HALF,
    endMs: record.timestampEpoch + HALF,
    items,
    windowItems: items.length,
    omittedItems: 0,
    complete: true,
    stoppedBy: null,
    error: null,
    retainedBytes: 1_000,
    calls: 1,
    ...overrides,
  };
}

function counts(edges: TimelineCorrelationEdge[], extra: Partial<DataOptions> = {}) {
  return makeCounts({ items: [], edges, builtFor: SESSION_KEY, ...extra });
}

/** An event on `channel` at `timestampMs`, named by record `n`. */
function onChannel(n: number, timestampMs: number, channel: string, message?: string): TimelineItem {
  const item = eventItem(n, timestampMs, "info", message);
  return item.origin.kind === "event" ? { ...item, origin: { ...item.origin, channel } } : item;
}

function ready(input: DockModelInput): DockReady {
  const model = buildDockModel(input);
  if (model.kind !== "ready") throw new Error(`expected a ready dock, got ${model.kind}`);
  return model;
}

/** Record 1, an exact pair (1, 2) six seconds apart, with both in the window. */
function pairScene(extra: Partial<DockModelInput> = {}) {
  const record = recordFor(1);
  const items = [eventItem(1, record.timestampEpoch), eventItem(2, record.timestampEpoch + 6_000)];
  const edges = fixtureEdges("exactPair");
  const input: DockModelInput = {
    record,
    window: windowAround(record, items),
    counts: counts(edges),
    unreadSources: false,
    ...extra,
  };
  return { record, items, edges, input };
}

describe("which state the dock is in", () => {
  it("has no selection when there is no record", () => {
    expect(buildDockModel({ record: null, window: null, counts: null, unreadSources: false })).toEqual({
      kind: "noSelection",
    });
  });

  it.each([
    ["an epoch of 0", 0],
    ["a negative epoch", -5],
    ["an epoch that is not finite", Number.NaN],
    ["an epoch that is not a whole number of milliseconds", T0 + 0.5],
  ])("is untimed for %s, whatever window it is given", (_why, epoch) => {
    const record = { ...recordFor(1), timestampEpoch: epoch };
    const { input } = pairScene();
    expect(buildDockModel({ ...input, record })).toEqual({ kind: "untimed" });
  });

  it("has nothing read before any window, and never pairs a record with another center's window", () => {
    const { input, record } = pairScene();
    expect(buildDockModel({ ...input, window: null })).toEqual({ kind: "unread" });
    const other = recordFor(3);
    expect(other.timestampEpoch).not.toBe(record.timestampEpoch);
    expect(buildDockModel({ ...input, record: other })).toEqual({ kind: "unread" });
  });

  it("is failed, with the error and no count, when the first reply never came", () => {
    const { input, record } = pairScene();
    const window = windowAround(record, [], {
      windowItems: null,
      omittedItems: null,
      complete: false,
      stoppedBy: "error",
      error: "session was not found",
    });
    expect(buildDockModel({ ...input, window })).toEqual({ kind: "failed", error: "session was not found" });
  });

  it("is ready for a window that stopped early, with the items it has", () => {
    const { input, record } = pairScene();
    const window = windowAround(record, input.window!.items, {
      windowItems: 500,
      omittedItems: 498,
      complete: false,
      stoppedBy: "callLimit",
    });
    expect(buildDockModel({ ...input, window }).kind).toBe("ready");
  });
});

describe("chainInWindow (the adapter between a row and the plot)", () => {
  const t = recordFor(1).timestampEpoch;
  const mapOf = (...items: TimelineItem[]) => new Map(items.map((item) => [timelineOriginId(item.origin), item]));
  const row = (memberIds: string[], unresolvedMemberIds: string[] = []) => {
    const edges = [synthetic("e1", rid(1), rid(2)), synthetic("e2", rid(2), rid(3))];
    const model = buildCorrelationChains({ items: [], timelineEdges: edges, totalTimelineEdges: 2, findings: [] });
    const full = model.chains[0]!;
    return { ...full, memberIds, unresolvedMemberIds };
  };

  it("places the members that have an item, in time order, and lists the rest as having none", () => {
    const part = chainInWindow(row([], [rid(3), rid(1), rid(2)]), rid(1), mapOf(eventItem(1, t + 5_000), eventItem(3, t)));
    expect(part.memberIds).toEqual([rid(3), rid(1)]);
    expect(part.unresolvedMemberIds).toEqual([rid(2)]);
  });

  it("gives the same part for a counts-only row (every member unresolved) and a full row (members resolved)", () => {
    const items = mapOf(eventItem(1, t), eventItem(2, t + 1_000), eventItem(3, t + 2_000));
    const countsOnly = chainInWindow(row([], [rid(1), rid(2), rid(3)]), rid(1), items);
    const full = chainInWindow(row([rid(1), rid(2), rid(3)], []), rid(1), items);
    expect(full).toEqual(countsOnly);
    expect(full.memberIds).toEqual([rid(1), rid(2), rid(3)]);
    expect(full.unresolvedMemberIds).toEqual([]);
  });

  it("takes the span from the placed members only, never from members that have no item", () => {
    const part = chainInWindow(row([], [rid(1), rid(2), rid(3)]), rid(1), mapOf(eventItem(1, t + 4_000), eventItem(2, t + 9_000)));
    expect(part.startMs).toBe(t + 4_000);
    expect(part.endMs).toBe(t + 9_000);
    expect(part.unresolvedMemberIds).toEqual([rid(3)]);
  });

  it("breaks a tie on time by id, so the order does not depend on the row's own order", () => {
    const items = mapOf(eventItem(2, t), eventItem(1, t), eventItem(3, t));
    const forward = chainInWindow(row([], [rid(1), rid(2), rid(3)]), rid(1), items);
    const reversed = chainInWindow(row([], [rid(3), rid(2), rid(1)]), rid(1), items);
    expect(forward.memberIds).toEqual([rid(1), rid(2), rid(3)]);
    expect(reversed).toEqual(forward);
  });

  it("hands the row's edges and evidence over untouched, and does not change the row", () => {
    const given = row([], [rid(1), rid(2), rid(3)]);
    const before = JSON.stringify(given);
    const part = chainInWindow(given, rid(1), mapOf(eventItem(1, t)));
    expect(part.edges).toBe(given.edges);
    expect(part.evidence).toBe(given.evidence);
    expect(JSON.stringify(given)).toBe(before);
  });

  it("is the origin alone, with no edge, no evidence and nothing unresolved, when the event is in no row", () => {
    expect(chainInWindow(null, rid(1), mapOf(eventItem(1, t + 3_000), eventItem(2, t)))).toEqual({
      memberIds: [rid(1)],
      unresolvedMemberIds: [],
      edges: [],
      evidence: [],
      startMs: t + 3_000,
      endMs: t + 3_000,
    });
  });

  it("is empty, with no span, when there is no row and no origin, or the origin has no item", () => {
    const empty = { memberIds: [], unresolvedMemberIds: [], edges: [], evidence: [], startMs: null, endMs: null };
    expect(chainInWindow(null, null, mapOf(eventItem(1, t)))).toEqual(empty);
    expect(chainInWindow(null, rid(9), mapOf(eventItem(1, t)))).toEqual(empty);
  });

  it("lists every member as having no item, with no span, when none has one", () => {
    const part = chainInWindow(row([], [rid(1), rid(2)]), rid(1), new Map());
    expect(part.memberIds).toEqual([]);
    expect(part.unresolvedMemberIds).toEqual([rid(1), rid(2)]);
    expect(part.startMs).toBeNull();
    expect(part.endMs).toBeNull();
  });
});

describe("the selected event, found in the window", () => {
  it("finds the origin the record names, with the origin join's own matchers", () => {
    const model = ready(pairScene().input);
    expect(model.selected).toEqual({ status: "found", originId: rid(1) });
    expect(model.eventId).toBe(101);
    expect(model.plot.members.find((m) => m.id === rid(1))).toBeDefined();
  });

  it("does not take an entry for the record because the event ID matches", () => {
    const { input, record } = pairScene();
    // The same event ID and provider, but another record: it is not this event.
    const twin = eventItem(1, record.timestampEpoch + 1_000);
    const stray =
      twin.origin.kind === "event" ? { ...twin, origin: { ...twin.origin, stableId: rid(77), recordId: 77 } } : twin;
    const model = ready({ ...input, window: windowAround(record, [...input.window!.items, stray]) });
    expect(model.selected).toEqual({ status: "found", originId: rid(1) });
    expect(model.plot.members.map((m) => m.id)).not.toContain(rid(77));
  });

  it("says the event is not in the timeline when no entry of the window names it", () => {
    const { input, record } = pairScene();
    const model = ready({ ...input, window: windowAround(record, [eventItem(2, record.timestampEpoch + 6_000)]) });
    expect(model.selected).toEqual({ status: "notInTimeline" });
    expect(model.row).toBeNull();
    expect(model.notices).toContain(NOT_IN_TIMELINE_NOTE);
    expect(model.open).toEqual({ disabled: "notInTimeline" });
    expect(model.plot.members).toEqual([]);
  });

  it("is ambiguous, and links nothing, when two entries both name the record", () => {
    const { input, record } = pairScene();
    const first = input.window!.items[0]!;
    const second =
      first.origin.kind === "event" ? { ...first, origin: { ...first.origin, stableId: rid(88) } } : first;
    const model = ready({ ...input, window: windowAround(record, [first, second]) });
    expect(model.selected).toEqual({ status: "ambiguous" });
    expect(model.row).toBeNull();
    expect(model.notices).toContain(AMBIGUOUS_EVENT_NOTE);
    expect(model.open).toEqual({ disabled: "ambiguous" });
  });

  it("is found when two items share one origin: identical duplicates are one origin", () => {
    const { input, record } = pairScene();
    const items = [...input.window!.items, input.window!.items[0]!];
    expect(ready({ ...input, window: windowAround(record, items) }).selected).toEqual({
      status: "found",
      originId: rid(1),
    });
  });

  it("never takes a text-log line for the selected event", () => {
    const { input, record } = pairScene();
    const log: TimelineItem = {
      timestampMs: record.timestampEpoch,
      severity: "info",
      message: "line",
      origin: { kind: "log", file: "C:\\Logs\\a.log", component: null, line: 1, source: "w", machine: null, bundle: null, recordId: 1 },
    };
    const model = ready({ ...input, window: windowAround(record, [log]) });
    expect(model.selected).toEqual({ status: "notInTimeline" });
  });
});

describe("the row of the selected event", () => {
  it("is the strongest row of the uncapped index, with its title when every entry is in the window", () => {
    const model = ready(pairScene().input);
    expect(model.row).toMatchObject({
      strength: "exact",
      memberCount: 2,
      inWindow: 2,
      outsideWindow: 0,
      otherRows: 0,
    });
    // Both entries are Information, so the earlier one names the row (D19).
    expect(model.row?.title).toBe("101 · message 1");
    expect(model.row?.key?.kind).toBe("activityId");
    expect(model.open).toEqual({ rowId: model.row?.id });
  });

  it("finds a row the model's 100-row cap dropped", () => {
    const edges: TimelineCorrelationEdge[] = [];
    for (let i = 0; i < 130; i += 1) edges.push(synthetic(`e${i}`, rid(1 + i * 2), rid(2 + i * 2)));
    const probe = buildCorrelationChains({ items: [], timelineEdges: edges, totalTimelineEdges: 130, findings: [] });
    const shown = new Set(probe.chains.flatMap((row) => row.unresolvedMemberIds));
    const past = [...probe.rowsByMember.keys()].find((id) => !shown.has(id))!;
    const n = Number(/record(\d+)$/.exec(past)![1]);
    const record = recordFor(n);
    const items = [eventItem(n, record.timestampEpoch), eventItem(n % 2 === 1 ? n + 1 : n - 1, record.timestampEpoch + 1_000)];
    const model = ready({ record, window: windowAround(record, items), counts: counts(edges), unreadSources: false });
    expect(model.row).not.toBeNull();
    expect(model.row?.id).toBe(probe.rowsByMember.get(past)![0]!.id);
    expect(model.open).toEqual({ rowId: model.row?.id });
  });

  it("counts the entries the window does not hold, never places them, and claims no whole-chain title", () => {
    const { input, record } = pairScene();
    const model = ready({ ...input, window: windowAround(record, [eventItem(1, record.timestampEpoch)]) });
    expect(model.row).toMatchObject({ memberCount: 2, inWindow: 1, outsideWindow: 1 });
    expect(model.row?.title).toBe("Chain of 2 entries (1 in this window)");
    expect(model.notices).toContain("1 of 2 entries of this chain is outside this window, so it is not shown here.");
    expect(model.plot.connectors).toEqual([]);
    expect(model.plot.undrawnEdges.map((edge) => edge.reason)).toEqual(["endpointWithoutItem"]);
    expect(model.steps).toHaveLength(1);
  });

  it("draws a connector only between two entries that are both in the window, traced to evidence", () => {
    const model = ready(pairScene().input);
    expect(model.plot.connectors).toHaveLength(1);
    expect(model.plot.connectors[0]).toMatchObject({ strength: "exact" });
    expect(model.plot.connectors[0]!.evidence.length).toBeGreaterThan(0);
  });

  it("draws no connector for an ambiguous or coverage blocked row", () => {
    const record = recordFor(1);
    const items = [eventItem(1, record.timestampEpoch), eventItem(2, record.timestampEpoch + 2_000)];
    const blocked: TimelineCorrelationEdge = {
      ...synthetic("g", rid(1), rid(2)),
      coverage: { state: "gap", gap: { source: "Live", reason: "channel not collected" } },
    };
    for (const edge of [synthetic("a", rid(1), rid(2), "ambiguous"), blocked]) {
      const model = ready({ record, window: windowAround(record, items), counts: counts([edge]), unreadSources: false });
      expect(model.row?.strength).not.toMatch(/^(exact|candidate)$/);
      expect(model.plot.connectors).toEqual([]);
    }
  });

  it("names the other rows the event is in, and takes the strongest", () => {
    const record = recordFor(1);
    const items = [eventItem(1, record.timestampEpoch), eventItem(2, record.timestampEpoch + 2_000), eventItem(7, record.timestampEpoch + 3_000)];
    const edges = [synthetic("e1", rid(1), rid(2)), synthetic("a1", rid(1), rid(7), "ambiguous")];
    const model = ready({ record, window: windowAround(record, items), counts: counts(edges), unreadSources: false });
    expect(model.row?.strength).toBe("exact");
    expect(model.row?.otherRows).toBe(1);
  });

  it("is no row, with no connector, when the event is in none", () => {
    const record = recordFor(1);
    const items = [eventItem(1, record.timestampEpoch), eventItem(4, record.timestampEpoch + 2_000)];
    const model = ready({ record, window: windowAround(record, items), counts: counts([synthetic("e1", rid(8), rid(9))]), unreadSources: false });
    expect(model.row).toBeNull();
    expect(model.plot.connectors).toEqual([]);
    expect(model.steps).toHaveLength(1);
    expect(model.open).toEqual({ disabled: "notInChain" });
  });

  it("lists the steps in time order, four at most, and counts the rest", () => {
    const record = recordFor(1);
    const edges = [1, 2, 3, 4, 5, 6].slice(1).map((n) => synthetic(`e${n}`, rid(1), rid(n + 0)));
    const items = [1, 2, 3, 4, 5, 6].map((n) => eventItem(n, record.timestampEpoch + (6 - n) * 1_000));
    const model = ready({ record, window: windowAround(record, items), counts: counts(edges), unreadSources: false });
    expect(DOCK_STEP_CAP).toBe(4);
    expect(model.steps).toHaveLength(4);
    expect(model.steps.map((step) => step.timestampMs)).toEqual([...model.steps.map((s) => s.timestampMs)].sort((a, b) => a - b));
    expect(model.moreSteps).toBe(2);
    expect(model.steps[0]).toMatchObject({ entry: "106", message: "message 6" });
  });
});

describe("what a step and a marker say of an entry's message", () => {
  it("is the message head: its first non-empty line, cut at 80 characters, as a chain title is", () => {
    const record = recordFor(1);
    const long = `${"x".repeat(100)} tail`;
    const items = [
      eventItem(1, record.timestampEpoch, "info", `\n  first line of one\nsecond line`),
      eventItem(2, record.timestampEpoch + 1_000, "info", long),
    ];
    const model = ready({ record, window: windowAround(record, items), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
    expect(model.steps[0]?.message).toBe("first line of one");
    expect(model.steps[1]?.message).toBe(`${"x".repeat(77)}...`);
    const marker = model.plot.members.find((m) => m.id === rid(1))!;
    expect(dockMarkerName(model, marker, "utc")).toContain(", first line of one,");
  });
});

describe("the counts belong to the window's session, or nothing is called linked", () => {
  const states: [string, (input: DockModelInput) => DockModelInput][] = [
    ["not in yet", (input) => ({ ...input, counts: null })],
    ["another session's", (input) => ({ ...input, counts: counts(fixtureEdges("exactPair"), { builtFor: "session:2" }) })],
    ["an earlier session's, marked updating", (input) => ({ ...input, counts: counts(fixtureEdges("exactPair"), { updating: true }) })],
  ];

  it.each(states)("pairs nothing when the counts are %s", (_why, apply) => {
    const { input } = pairScene();
    const model = ready(apply(input));
    expect(model.paired).toBe(false);
    expect(model.row).toBeNull();
    expect(model.plot.connectors).toEqual([]);
    expect(model.notices).toContain(LINKS_LOADING_TEXT);
    expect(model.open).toEqual({ disabled: "loading" });
    for (const entry of model.nearby) expect(entry.reason).toBe("noLoadedLink");
  });

  it("never calls an entry not linked while the counts are not paired", () => {
    const { input, record } = pairScene();
    const items = [...input.window!.items, eventItem(9, record.timestampEpoch + 2_000)];
    const model = ready({ ...input, window: windowAround(record, items), counts: null });
    expect(model.plot.nearby.map((marker) => marker.linkLabel)).toEqual([NO_LOADED_LINK_LABEL, NO_LOADED_LINK_LABEL]);
    expect(model.plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
  });

  it("pairs when the counts are the window's session and current", () => {
    expect(ready(pairScene().input).paired).toBe(true);
  });
});

describe("context: the other entries of the window, by time and no more", () => {
  const record = recordFor(1);
  const t = record.timestampEpoch;
  const chainItems = [eventItem(1, t), eventItem(2, t + 6_000)];
  const exactPair = () => fixtureEdges("exactPair");
  const build = (context: TimelineItem[], extra: Partial<DockModelInput> = {}) =>
    ready({ record, window: windowAround(record, [...chainItems, ...context]), counts: counts(exactPair()), unreadSources: false, ...extra });

  it("draws every other entry as a dotted marker with no connector, no chain and no count", () => {
    const model = build([eventItem(9, t + 3_000), eventItem(8, t - 3_000)]);
    expect(model.plot.nearby.map((m) => m.id).sort()).toEqual([rid(8), rid(9)]);
    expect(model.plot.members.map((m) => m.id)).toEqual([rid(1), rid(2)]);
    expect(model.plot.connectors).toHaveLength(1);
    for (const connector of model.plot.connectors) expect([connector.left, connector.right]).not.toContain(rid(9));
    expect(model.row?.memberCount).toBe(2);
  });

  it("says 'time only, not linked' only when the session can speak for the entry", () => {
    const model = build([eventItem(9, t + 3_000)]);
    expect(model.nearby).toEqual([expect.objectContaining({ id: rid(9), reason: "notLinked" })]);
    expect(model.plot.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
  });

  it.each([
    ["an edge was never loaded", { totalEdges: 5 }],
    ["the view is narrowed", { scope: { visibleCount: 3, loadedCount: 10, textLogCount: 0 } }],
    ["the scope is not known", { scope: null }],
    ["the engine reported a correlation limit", { gaps: classifyCoverageGaps([{ source: "correlation", reason: "limit" }], 1) }],
    ["a gap names the entry", { gaps: classifyCoverageGaps([{ source: rid(9), reason: "x" }], 1) }],
    ["a gap names a member of the chain", { gaps: classifyCoverageGaps([{ source: rid(2), reason: "x" }], 1) }],
  ] as [string, Partial<DataOptions>][])("says 'time only, no loaded link' when %s", (_why, extra) => {
    const model = build([eventItem(9, t + 3_000)], { counts: counts(exactPair(), extra) });
    expect(model.nearby[0]?.reason).toBe("noLoadedLink");
    expect(model.plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
  });

  it("says 'in another chain' for an entry the edges give a partner, whatever else is incomplete", () => {
    const edges = [...exactPair(), synthetic("o", rid(9), rid(10))];
    const model = build([eventItem(9, t + 3_000), eventItem(10, t + 4_000), eventItem(11, t + 5_000)], {
      counts: counts(edges, { totalEdges: 99 }),
    });
    const reasons = Object.fromEntries(model.nearby.map((entry) => [entry.id, entry.reason]));
    expect(reasons[rid(9)]).toBe("inAnotherChain");
    expect(reasons[rid(10)]).toBe("inAnotherChain");
    expect(reasons[rid(11)]).toBe("noLoadedLink");
    expect(model.plot.nearby.find((m) => m.id === rid(9))?.linkLabel).toBe(IN_ANOTHER_CHAIN_LABEL);
  });

  it("names an entry that shares an ambiguous or coverage blocked row with the event", () => {
    const blocked: TimelineCorrelationEdge = {
      ...synthetic("g", rid(1), rid(10)),
      coverage: { state: "gap", gap: { source: "Live", reason: "channel not collected" } },
    };
    const edges = [...exactPair(), synthetic("a", rid(1), rid(9), "ambiguous"), blocked];
    const model = build([eventItem(9, t + 3_000), eventItem(10, t + 4_000), eventItem(11, t + 5_000)], {
      counts: counts(edges),
    });
    const reasons = Object.fromEntries(model.nearby.map((entry) => [entry.id, entry.reason]));
    expect(reasons[rid(9)]).toBe("ambiguousWithEvent");
    expect(reasons[rid(10)]).toBe("coverageBlockedWithEvent");
    expect(reasons[rid(11)]).toBe("notLinked");
  });

  it("names the nearest entries first, four at most, and counts the rest", () => {
    const context = [9, 10, 11, 12, 13, 14].map((n, i) => eventItem(n, t + 10_000 + i * 1_000));
    const model = build(context);
    expect(DOCK_NEARBY_LINE_CAP).toBe(4);
    expect(model.nearby.map((entry) => entry.id)).toEqual([rid(9), rid(10), rid(11), rid(12)]);
    expect(model.nearby.map((entry) => entry.deltaMs)).toEqual([10_000, 11_000, 12_000, 13_000]);
    expect(model.moreNearby).toBe(2);
  });

  it("measures distance on both sides of the event", () => {
    const model = build([eventItem(9, t - 4_000), eventItem(10, t + 3_000), eventItem(11, t - 9_000)]);
    expect(model.nearby.map((entry) => entry.id)).toEqual([rid(10), rid(9), rid(11)]);
    expect(model.nearby[1]?.deltaMs).toBe(-4_000);
  });

  it("draws the nearest sixty when there are more, and says how many it left out", () => {
    const context = Array.from({ length: 100 }, (_, i) => {
      const side = i % 2 === 0 ? 1 : -1;
      return eventItem(100 + i, t + side * (10_000 + i * 100));
    });
    const model = build(context);
    expect(DOCK_NEARBY_MARKER_CAP).toBe(60);
    expect(model.plot.nearby).toHaveLength(60);
    const drawn = new Set(model.plot.nearby.map((marker) => marker.id));
    const distance = (item: TimelineItem) => Math.abs(item.timestampMs - t);
    const farthestDrawn = Math.max(...context.filter((item) => drawn.has(timelineOriginId(item.origin))).map(distance));
    const nearestLeft = Math.min(...context.filter((item) => !drawn.has(timelineOriginId(item.origin))).map(distance));
    expect(farthestDrawn).toBeLessThan(nearestLeft);
    expect(model.notices).toContain("40 more nearby entries not drawn.");
  });

  it("draws a text-log line as context on its own lane, whose click selects no record", () => {
    const log: TimelineItem = {
      timestampMs: t + 2_000,
      severity: "warning",
      message: "log line 4",
      origin: { kind: "log", file: "C:\\Logs\\AppEnforce.log", component: null, line: 4, source: "writer.cpp", machine: null, bundle: null, recordId: 4 },
    };
    const model = build([log]);
    expect(model.plot.lanes.map((lane) => lane.label)).toEqual(["System", "AppEnforce.log"]);
    const marker = model.plot.nearby[0]!;
    expect(model.facts.get(marker.id)?.selectability).toBe("log");
    expect(dockMarkerName(model, marker, "utc")).toContain("a text-log line, not an event record, so activating it selects nothing");
  });

  it("dedupes entries that share an origin, keeping the first", () => {
    const first = eventItem(9, t + 3_000, "info", "first");
    const model = build([first, { ...first, message: "second" }]);
    expect(model.plot.nearby).toHaveLength(1);
    expect(model.plot.nearby[0]?.message).toBe("first");
  });
});

describe("the lanes: five at most, the event's first", () => {
  // The selected event is on the quietest channel of all; its record says so, or the join would not find it.
  const record = { ...recordFor(1), channel: "Zulu" };
  const t = record.timestampEpoch;
  const channels = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf"];
  const scene = () => {
    const own = onChannel(1, t, "Zulu", "the selected event");
    const partner = onChannel(2, t + 1_000, "Yankee");
    const others = channels.flatMap((channel, c) =>
      Array.from({ length: 7 - c }, (_, i) => onChannel(10 + c * 10 + i, t + 2_000 + c * 100 + i, channel)),
    );
    return { own, partner, others };
  };

  it("keeps the event's lane and its chain's lanes before busier lanes, and says what it left out", () => {
    const { own, partner, others } = scene();
    const items = [own, partner, ...others];
    const model = ready({
      record,
      window: windowAround(record, items),
      counts: counts(fixtureEdges("exactPair")),
      unreadSources: false,
    });
    expect(DOCK_MAX_LANES).toBe(5);
    const labels = model.plot.lanes.map((lane) => lane.label);
    expect(labels).toHaveLength(5);
    expect(labels).toContain("Zulu");
    expect(labels).toContain("Yankee");
    // The three busiest of the rest: Alpha (7), Bravo (6), Charlie (5).
    expect(labels).toEqual(expect.arrayContaining(["Alpha", "Bravo", "Charlie"]));
    expect(model.sourceCount).toBe(9);
    // Four lanes (Delta 4, Echo 3, Foxtrot 2, Golf 1) hold 10 entries.
    expect(model.notices).toContain("4 more sources not drawn (10 entries).");
    // The line names four of the 28 other entries; the entries in lanes that were not drawn count too.
    expect(model.nearby).toHaveLength(4);
    expect(model.moreNearby).toBe(24);
  });

  it("keeps the event's own lane when it is the quietest of all", () => {
    const { own, partner, others } = scene();
    const model = ready({
      record,
      window: windowAround(record, [own, partner, ...others]),
      counts: null,
      unreadSources: false,
    });
    expect(model.plot.lanes.map((lane) => lane.label)).toContain("Zulu");
  });

  it("draws every lane when there are five or fewer, and says nothing about omissions", () => {
    const { own, partner } = scene();
    const model = ready({
      record,
      window: windowAround(record, [own, partner, onChannel(5, t + 2_000, "Alpha")]),
      counts: counts(fixtureEdges("exactPair")),
      unreadSources: false,
    });
    expect(model.plot.lanes).toHaveLength(3);
    expect(model.notices.some((text) => /not drawn/.test(text))).toBe(false);
  });

  it("counts the sources exactly for a window read whole, and says at least for one that was not", () => {
    const { own, partner, others } = scene();
    const items = [own, partner, ...others];
    const whole = ready({ record, window: windowAround(record, items), counts: null, unreadSources: false });
    expect(whole.sources).toBe("9 sources");
    const cut = ready({
      record,
      window: windowAround(record, items, { complete: false, windowItems: 400, omittedItems: 300, stoppedBy: "callLimit" }),
      counts: null,
      unreadSources: false,
    });
    expect(cut.sources).toBe("at least 9 sources");
  });
});

describe("what the dock does not claim", () => {
  const record = recordFor(1);
  const t = record.timestampEpoch;
  const own = () => [eventItem(1, t)];

  it("says nothing about absence for a window that was not read whole", () => {
    const window = windowAround(record, own(), { complete: false, windowItems: 90, omittedItems: 89, stoppedBy: "budget" });
    const model = ready({ record, window, counts: counts([]), unreadSources: false });
    expect(model.empty).toBeNull();
    expect(model.notices[0]).toBe(
      "Showing 1 of 90 entries within \u00b175 s; reading stopped at its memory limit, so entries and sources may be missing.",
    );
  });

  it("makes the spec's absence claim only for a whole window, nothing narrowed and every source read", () => {
    const model = ready({ record, window: windowAround(record, own()), counts: counts([]), unreadSources: false });
    expect(model.empty).toEqual({ text: "No other sources have entries within \u00b175 s.", absolute: true });
  });

  it.each([
    ["the view is narrowed", { scope: { visibleCount: 1, loadedCount: 9, textLogCount: 0 } }, false, /Events hidden by the current filters/],
    ["the scope is not known", { scope: null }, false, /Events hidden by the current filters/],
    ["a source was not fully read", {}, true, /Some sources were not fully read/],
  ] as [string, Partial<DataOptions>, boolean, RegExp][])("qualifies the claim when %s", (_why, extra, unread, text) => {
    const model = ready({ record, window: windowAround(record, own()), counts: counts([], extra), unreadSources: unread });
    expect(model.empty?.absolute).toBe(false);
    expect(model.empty?.text).toMatch(text);
    expect(model.empty?.text).toMatch(/^No other visible sources/);
  });

  it("qualifies the claim while the counts are not paired, because the scope is then not known", () => {
    const model = ready({ record, window: windowAround(record, own()), counts: null, unreadSources: false });
    expect(model.empty?.absolute).toBe(false);
  });

  it("is not empty when another source has an entry, and is empty when only the event's own source does", () => {
    const sameSource = [eventItem(1, t), eventItem(5, t + 2_000)];
    expect(ready({ record, window: windowAround(record, sameSource), counts: counts([]), unreadSources: false }).empty).not.toBeNull();
    const other = [eventItem(1, t), onChannel(5, t + 2_000, "Application")];
    expect(ready({ record, window: windowAround(record, other), counts: counts([]), unreadSources: false }).empty).toBeNull();
  });

  it("says the window is empty when the record is not in it and nothing else is", () => {
    const model = ready({ record, window: windowAround(record, []), counts: counts([]), unreadSources: false });
    expect(model.selected).toEqual({ status: "notInTimeline" });
    expect(model.empty?.text).toMatch(/^No other (visible )?sources/);
    expect(model.sourceCount).toBe(0);
  });

  it("states an unread source, a narrowed scope and an incomplete edge input as notices, in order", () => {
    const scope = { visibleCount: 2, loadedCount: 9, textLogCount: 3 };
    const model = ready({
      record,
      window: windowAround(record, own()),
      counts: counts([synthetic("e", rid(8), rid(9))], { scope, totalEdges: 6 }),
      unreadSources: true,
    });
    expect(model.notices).toEqual([
      "Correlation details are paged and bounded: 5 correlation edges were not loaded, so chains may be incomplete.",
      "Links and strengths are computed over the 2 events visible. Events outside the view can make an Exact link ambiguous.",
      "Text logs are not scoped.",
      DOCK_SCOPE_NOTE,
      UNREAD_SOURCES_NOTE,
    ]);
  });

  it("never says an entry is unplaced, and never reads as cause", () => {
    const record1 = recordFor(1);
    const context = Array.from({ length: 70 }, (_, i) => onChannel(30 + i, record1.timestampEpoch + 1_000 + i * 50, `Chan${i % 7}`));
    const model = ready({
      record: record1,
      window: windowAround(record1, [eventItem(1, record1.timestampEpoch), ...context], { complete: false, windowItems: 900, omittedItems: 829, stoppedBy: "callLimit" }),
      counts: counts(fixtureEdges("exactPair"), { scope: null, totalEdges: 4 }),
      unreadSources: true,
    });
    const strings = [
      ...model.notices,
      model.sources,
      model.row?.title ?? "",
      ...model.nearby.map((entry) => entry.entry),
      ...model.plot.nearby.flatMap((marker) => [marker.linkLabel ?? "", dockMarkerName(model, marker, "utc")]),
    ];
    for (const text of strings) {
      expect(text).not.toMatch(NO_UNPROVEN_CLAIM);
      expect(text).not.toMatch(/caused|because of|as a result|led to|explains|due to/i);
    }
  });
});

describe("marker names", () => {
  const record = recordFor(1);
  const t = record.timestampEpoch;
  const items = [eventItem(1, t, "error", "the selected event failed"), eventItem(2, t + 6_000), eventItem(9, t + 3_000, "warning", "context"), eventItem(10, t + 4_000)];
  const edges = [...fixtureEdges("exactPair"), synthetic("o", rid(10), rid(11))];
  const model = ready({ record, window: windowAround(record, items), counts: counts(edges), unreadSources: false });
  const nameOf = (id: string, selectability?: Parameters<typeof dockMarkerName>[3]) => {
    const marker = [...model.plot.members, ...model.plot.nearby].find((m) => m.id === id)!;
    return dockMarkerName(model, marker, "utc", selectability);
  };

  it("names the selected event as such, with its link and what activating it does", () => {
    const name = nameOf(rid(1));
    expect(name).toBe(
      "System, 101 \u00b7 System, Error, 10:20:01, the selected event failed, exact link by ActivityId, the selected event",
    );
  });

  it("names a chain member by its row's strength and key", () => {
    expect(nameOf(rid(2))).toContain("exact link by ActivityId");
    expect(nameOf(rid(2))).toContain("activate to select this event");
  });

  it("names context by time only, with the one thing known of its links", () => {
    // Every edge is loaded, nothing is narrowed and no gap exists: the session can speak for rid(9).
    expect(nameOf(rid(9))).toContain("time only, not linked");
    expect(nameOf(rid(9))).not.toMatch(/exact|candidate/i);
    expect(nameOf(rid(10))).toContain("time only; in another chain");
  });

  it("never calls a context entry linked: 'linked' appears only inside 'not linked'", () => {
    for (const id of [rid(9), rid(10)]) {
      expect(nameOf(id)).not.toMatch(/(?<!not )\blinked\b/i);
    }
  });

  it("names context 'no loaded link', never 'not linked', when the session cannot speak for it", () => {
    const partial = ready({ record, window: windowAround(record, items), counts: counts(edges, { totalEdges: 50 }), unreadSources: false });
    const marker = partial.plot.nearby.find((m) => m.id === rid(9))!;
    const name = dockMarkerName(partial, marker, "utc");
    expect(name).toContain("time only, no loaded link");
    expect(name).not.toContain("not linked");
  });

  it("ends in what a click found when the caller says so", () => {
    expect(nameOf(rid(9), "ambiguous")).toMatch(/more than one loaded record matches, so activating it selects nothing$/);
    expect(nameOf(rid(9), "notLoaded")).toMatch(/no loaded record matches, so activating it selects nothing$/);
  });

  it("names a member of an ambiguous row as establishing no link", () => {
    const edge = synthetic("a", rid(1), rid(2), "ambiguous");
    const ambiguous = ready({ record, window: windowAround(record, items.slice(0, 2)), counts: counts([edge]), unreadSources: false });
    const marker = ambiguous.plot.members.find((m) => m.id === rid(2))!;
    expect(dockMarkerName(ambiguous, marker, "utc")).toContain("in an ambiguous row, which establishes no link");
    const blocked: TimelineCorrelationEdge = {
      ...synthetic("g", rid(1), rid(2)),
      coverage: { state: "gap", gap: { source: "Live", reason: "channel not collected" } },
    };
    const gapped = ready({ record, window: windowAround(record, items.slice(0, 2)), counts: counts([blocked]), unreadSources: false });
    const gappedMarker = gapped.plot.members.find((m) => m.id === rid(2))!;
    expect(dockMarkerName(gapped, gappedMarker, "utc")).toContain("in a coverage blocked row, which establishes no link");
  });
});

describe("the model is a function of its input", () => {
  it("is the same on every build, and does not change its input", () => {
    const { input } = pairScene();
    const before = JSON.stringify(input.window);
    expect(buildDockModel(input)).toEqual(buildDockModel(input));
    expect(JSON.stringify(input.window)).toBe(before);
  });

  it("builds a 6,000-entry window quickly", () => {
    const record = recordFor(1);
    const t = record.timestampEpoch;
    const items = [
      eventItem(1, t),
      ...Array.from({ length: 5_999 }, (_, i) => onChannel(1_000 + i, t - 70_000 + i * 23, `Chan${i % 40}`)),
    ];
    const started = performance.now();
    const model = ready({ record, window: windowAround(record, items), counts: counts([]), unreadSources: false });
    const elapsed = performance.now() - started;
    expect(model.plot.lanes).toHaveLength(5);
    expect(model.plot.nearby).toHaveLength(60);
    expect(elapsed).toBeLessThan(1_500);
  });
});

describe("what the model and the loader may import", () => {
  /** The modules a file imports at run time: `import type` is erased at build time and is not one. */
  const imports = (source: string) => [
    ...[...source.matchAll(/^import (?!type\b)[^;]*?from\s+"([^"]+)";/gms)].map((match) => match[1] as string),
    // A side-effect import has no `from`.
    ...[...source.matchAll(/^import\s+"([^"]+)";/gm)].map((match) => match[1] as string),
  ];
  const withoutComments = (source: string) => source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

  it("keeps the model pure: no React, no store, no IPC, and nothing from the lazy view", () => {
    for (const module of imports(modelSource)) {
      expect(module, module).not.toMatch(/^react|zustand|fluentui|tauri|evtx-store|ui-store|lib\/commands|EvtxCorrelationView|useEvtxCorrelation$/);
    }
    // The one hook module it names is a type import, erased at build time.
    expect(modelSource).toMatch(/import type \{ CorrelationCounts \} from "\.\/useEvtxCorrelation";/);
    expect(imports(modelSource)).not.toContain("./useEvtxCorrelation");
  });

  it("keeps the loader free of React and stores: its IO is injected", () => {
    for (const module of imports(windowSource)) {
      expect(module, module).not.toMatch(/^react|zustand|fluentui|evtx-store|ui-store|EvtxCorrelationView|useEvtxCorrelation/);
    }
  });

  it("holds no color literal, and no clock of its own", () => {
    for (const source of [modelSource, windowSource]) {
      const code = withoutComments(source);
      expect(code).not.toMatch(/["'`]#[0-9a-fA-F]{3,8}["'`]|rgba?\(|hsla?\(/);
      expect(code).not.toMatch(/Date\.now|new Date\(/);
    }
  });

  it("gives the model no timer at all; the loader's only one is its injectable default sleep", () => {
    expect(withoutComments(modelSource)).not.toMatch(/setTimeout|setInterval|requestAnimationFrame/);
    const timers = withoutComments(windowSource).match(/setTimeout|setInterval/g) ?? [];
    expect(timers).toEqual(["setTimeout"]);
  });
});
