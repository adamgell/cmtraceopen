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
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  NOT_READ_NOTE,
  UNREAD_SOURCES_NOTE,
  ambiguousEventNote,
  nearbyReason,
  notReadNote,
  outsideWindowNote,
  unmatchableNote,
} from "./evtx-correlation-copy";
import {
  DOCK_MAX_LANES,
  DOCK_NEARBY_LINE_CAP,
  DOCK_NEARBY_MARKER_CAP,
  DOCK_STEP_CAP,
  buildDockModel,
  chainInWindow,
  dockCenterMs,
  dockMarkerName,
  resolveMarkerClick,
  type DockModelInput,
  type DockReady,
} from "./evtx-correlation-dock-model";
import vectorDocument from "./__fixtures__/engine-compaction-vectors.json";
import { timelineReference } from "./evtx-engine-compaction-test-fixtures";
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
  LINK_TO_EVENT_UNKNOWN_LABEL,
  NOT_LINKED_LABEL,
  NO_LOADED_LINK_LABEL,
} from "./evtx-correlation-view-model";
import type { LoadedCorrelationWindow } from "./evtx-correlation-window";
import type { EvtxRecord } from "./types";
import type { TimelineCorrelationEdge, TimelineItem } from "./unified-timeline";
import { timelineOriginId } from "./unified-timeline";
import { buildEvidenceIndex } from "./evtx-insights-data";

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

/** What `makeCounts` accepts: counts exist only for a run, so an unplaced list is never null here. */
type CountsOptions = Partial<Omit<DataOptions, "unplacedList">> & {
  unplacedList?: NonNullable<DataOptions["unplacedList"]>;
};

function counts(edges: TimelineCorrelationEdge[], extra: CountsOptions = {}) {
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
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.row).toBeNull();
    expect(model.notices).toContain(ambiguousEventNote(2));
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

describe("which entry is the selected event: the statuses (#842, review A1)", () => {
  const LOG_FILE = "C:\\Logs\\AppEnforce.log";
  const logRow = (line: number, epoch: number, overrides: Partial<EvtxRecord> = {}): EvtxRecord => ({
    ...recordFor(line),
    originKind: "log",
    eventId: 0,
    sourceLabel: LOG_FILE,
    channel: LOG_FILE,
    provider: "CcmExec",
    computer: "",
    timestampEpoch: epoch,
    ...overrides,
  });
  /** The log item the engine builds from that row (`origin_of`, timeline.rs). */
  const logItemFor = (line: number, timestampMs: number, file = LOG_FILE): TimelineItem => ({
    timestampMs,
    severity: "info",
    message: `log line ${line}`,
    origin: { kind: "log", file, component: "CcmExec", line, source: file, machine: null, bundle: null, recordId: line },
  });
  /** A record the join can never name: an event the provider never numbered. */
  const unnumbered = (epoch: number): EvtxRecord => ({ ...recordFor(1), eventRecordId: 0, eventRecordIdText: null, timestampEpoch: epoch });
  const stopsEarly = (record: EvtxRecord, items: TimelineItem[]) =>
    windowAround(record, items, { complete: false, windowItems: 2_500, omittedItems: 2_500 - items.length, stoppedBy: "error", error: "timeline down" });

  describe("notRead: the read stopped before the event, so nothing is said about whether it is in the timeline", () => {
    const record = recordFor(1);
    const t = record.timestampEpoch;
    const early = () => [eventItem(5, t - 20_000), eventItem(6, t - 10_000)];

    it("is notRead, not notInTimeline, when a read that stopped holds no entry that names the event", () => {
      const model = ready({ record, window: stopsEarly(record, early()), counts: counts([]), unreadSources: false });
      expect(model.selected).toEqual({ status: "notRead" });
      expect(model.notices).toContain(NOT_READ_NOTE);
      expect(model.notices).not.toContain(NOT_IN_TIMELINE_NOTE);
      expect(model.open).toEqual({ disabled: "notRead" });
    });

    it("is notInTimeline for the same entries in a window that was read whole", () => {
      const model = ready({ record, window: windowAround(record, early()), counts: counts([]), unreadSources: false });
      expect(model.selected).toEqual({ status: "notInTimeline" });
      expect(model.notices).toContain(NOT_IN_TIMELINE_NOTE);
      expect(model.notices).not.toContain(NOT_READ_NOTE);
      expect(model.open).toEqual({ disabled: "notInTimeline" });
    });

    it("finds the event when the read that stopped did reach it", () => {
      const items = [eventItem(1, t), eventItem(2, t + 6_000)];
      const model = ready({ record, window: stopsEarly(record, items), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
      expect(model.selected).toEqual({ status: "found", originId: rid(1) });
      expect(model.open).toEqual({ rowId: model.row?.id });
    });

    it("does not call an entry that has a partner 'in another chain': its partner may be the event", () => {
      const edges = [synthetic("o", rid(5), rid(11))];
      const model = ready({ record, window: stopsEarly(record, early()), counts: counts(edges), unreadSources: false });
      const reasons = Object.fromEntries(model.nearby.map((entry) => [entry.id, entry.reason]));
      expect(reasons[rid(5)]).toBe("linkUnknownToEvent");
      expect(nearbyReason(reasons[rid(5)]!)).toBe("linked, but its link to this event is not known");
      // What the entry itself shows stands: no partner, every edge loaded, nothing narrowed.
      expect(reasons[rid(6)]).toBe("notLinked");
      expect(model.plot.nearby.find((m) => m.id === rid(5))?.linkLabel).toBe(LINK_TO_EVENT_UNKNOWN_LABEL);
    });

    it("keeps 'in another chain' when the event is known not to be in a window read whole", () => {
      const edges = [synthetic("o", rid(5), rid(11))];
      const model = ready({ record, window: windowAround(record, early()), counts: counts(edges), unreadSources: false });
      const reasons = Object.fromEntries(model.nearby.map((entry) => [entry.id, entry.reason]));
      expect(reasons[rid(5)]).toBe("inAnotherChain");
      expect(model.plot.nearby.find((m) => m.id === rid(5))?.linkLabel).toBe(IN_ANOTHER_CHAIN_LABEL);
    });
  });

  it("names what is known of the event before the links are in: the Open reason is the status, not 'loading'", () => {
    const record = recordFor(1);
    const t = record.timestampEpoch;
    const noCounts = { counts: null, unreadSources: false };
    const unmatchableRecord = unnumbered(t);
    expect(ready({ record: unmatchableRecord, window: windowAround(unmatchableRecord, []), ...noCounts }).open).toEqual({ disabled: "unmatchable" });
    expect(ready({ record, window: stopsEarly(record, []), ...noCounts }).open).toEqual({ disabled: "notRead" });
    expect(ready({ record, window: windowAround(record, []), ...noCounts }).open).toEqual({ disabled: "notInTimeline" });
    const first = eventItem(1, t);
    const twin = first.origin.kind === "event" ? { ...first, origin: { ...first.origin, stableId: rid(88) } } : first;
    expect(ready({ record, window: windowAround(record, [first, twin]), ...noCounts }).open).toEqual({ disabled: "ambiguous" });
    // An identified event waits for the links.
    expect(ready({ record, window: windowAround(record, [first]), ...noCounts }).open).toEqual({ disabled: "loading" });
  });

  describe("an archive text row (originKind log) is matchable", () => {
    const t = T0 + 5_000;
    const row = logRow(7, t);

    it("is found by the strict log matcher, and is the selected entry rather than context", () => {
      const items = [logItemFor(7, t), eventItem(2, t + 3_000)];
      const model = ready({ record: row, window: windowAround(row, items), counts: counts([]), unreadSources: false });
      expect(model.selected.status).toBe("found");
      expect(model.plot.members.map((m) => m.kind)).toEqual(["log"]);
      expect(model.plot.nearby.map((m) => m.id)).toEqual([rid(2)]);
      expect(model.nearby.map((entry) => entry.id)).toEqual([rid(2)]);
      expect(model.notices).not.toContain(NOT_IN_TIMELINE_NOTE);
    });

    it("is not unmatchable for lacking an event identity, even numbered 0", () => {
      const zero = logRow(0, t, { eventRecordId: 0, eventRecordIdText: null });
      const model = ready({ record: zero, window: windowAround(zero, [logItemFor(0, t)]), counts: counts([]), unreadSources: false });
      expect(model.selected.status).toBe("found");
    });

    it("is not found by an entry of another file, line or bundle, and is notInTimeline then (window whole)", () => {
      for (const item of [logItemFor(7, t, "C:\\Logs\\Other.log"), logItemFor(8, t)]) {
        const model = ready({ record: row, window: windowAround(row, [item]), counts: counts([]), unreadSources: false });
        expect(model.selected).toEqual({ status: "notInTimeline" });
      }
    });

    it("is notRead when the read stopped before it, and notInTimeline only when the window was whole", () => {
      const model = ready({ record: row, window: stopsEarly(row, [eventItem(2, t - 5_000)]), counts: counts([]), unreadSources: false });
      expect(model.selected).toEqual({ status: "notRead" });
    });

    it("is found by its own line among the other lines of the same file, which are context", () => {
      const items = [logItemFor(6, t - 1_000), logItemFor(7, t), logItemFor(8, t + 1_000)];
      const model = ready({ record: row, window: windowAround(row, items), counts: counts([]), unreadSources: false });
      expect(model.selected.status).toBe("found");
      expect(model.plot.members).toHaveLength(1);
      expect(model.plot.nearby).toHaveLength(2);
    });
  });

  describe("unmatchable: an event with no record identity cannot be told from the entries", () => {
    const record = unnumbered(recordFor(1).timestampEpoch);
    const t = record.timestampEpoch;
    const items = () => [eventItem(1, t), eventItem(2, t + 4_000), onChannel(3, t + 8_000, "Application")];

    it("is decided from the record alone, before any entry is looked at", () => {
      const model = ready({ record, window: windowAround(record, items()), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
      expect(model.selected).toEqual({ status: "unmatchable" });
      expect(model.open).toEqual({ disabled: "unmatchable" });
      // The same, with the window empty and with the read stopped: it never depends on the entries.
      expect(ready({ record, window: windowAround(record, []), counts: counts([]), unreadSources: false }).selected).toEqual({ status: "unmatchable" });
      expect(ready({ record, window: stopsEarly(record, []), counts: counts([]), unreadSources: false }).selected).toEqual({ status: "unmatchable" });
    });

    it("draws no labelled context: no marker, no 'Also nearby', no member, no connector", () => {
      const model = ready({ record, window: windowAround(record, items()), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
      expect(model.plot.members).toEqual([]);
      expect(model.plot.nearby).toEqual([]);
      expect(model.plot.lanes).toEqual([]);
      expect(model.plot.connectors).toEqual([]);
      expect(model.nearby).toEqual([]);
      expect(model.moreNearby).toBe(0);
      expect(model.steps).toEqual([]);
      expect(model.row).toBeNull();
      expect([...model.facts.keys()]).toEqual([]);
    });

    it("says why, with the window's exact entry count, and still counts the sources", () => {
      const model = ready({ record, window: windowAround(record, items()), counts: counts([]), unreadSources: false });
      expect(model.notices).toContain(unmatchableNote(3, 75_000));
      expect(model.notices).not.toContain(NOT_IN_TIMELINE_NOTE);
      expect(model.sourceCount).toBe(2);
      expect(model.sources).toBe("2 sources");
      const partial = ready({ record, window: stopsEarly(record, items()), counts: counts([]), unreadSources: false });
      expect(partial.notices).toContain(unmatchableNote(2_500, 75_000));
      expect(partial.sources).toBe("at least 2 sources");
    });

    it("is not claimed for an event record that has an identity, or for a log row", () => {
      const numbered = { ...record, eventRecordId: 1, eventRecordIdText: "1" };
      expect(ready({ record: numbered, window: windowAround(numbered, items()), counts: counts([]), unreadSources: false }).selected.status).not.toBe("unmatchable");
    });
  });

  describe("ambiguous: the entries that could each be the event are not context", () => {
    const record = recordFor(1);
    const t = record.timestampEpoch;
    const twinOf = (item: TimelineItem, stableId: string): TimelineItem =>
      item.origin.kind === "event" ? { ...item, origin: { ...item.origin, stableId } } : item;
    const first = eventItem(1, t);
    const scene = (extra: TimelineItem[] = []) => [first, twinOf(first, rid(88)), twinOf(first, rid(89)), ...extra];

    it("counts the entries that name the event and does not draw any of them", () => {
      const model = ready({ record, window: windowAround(record, scene([eventItem(9, t + 3_000)])), counts: counts([]), unreadSources: false });
      expect(model.selected).toEqual({ status: "ambiguous", candidates: 3 });
      expect(model.plot.nearby.map((m) => m.id)).toEqual([rid(9)]);
      expect(model.nearby.map((entry) => entry.id)).toEqual([rid(9)]);
      expect(model.moreNearby).toBe(0);
      expect(model.plot.members).toEqual([]);
      expect(model.notices).toContain(ambiguousEventNote(3));
    });

    it("never heads 'Also nearby' with the event itself at 0 ms", () => {
      const model = ready({ record, window: windowAround(record, scene()), counts: counts([]), unreadSources: false });
      expect(model.nearby).toEqual([]);
      expect(model.plot.nearby).toEqual([]);
    });

    it("does not call an entry with a partner 'time only' or 'in another chain'", () => {
      const edges = [synthetic("o", rid(9), rid(11))];
      const model = ready({ record, window: windowAround(record, scene([eventItem(9, t + 3_000), eventItem(10, t + 4_000)])), counts: counts(edges), unreadSources: false });
      const reasons = Object.fromEntries(model.nearby.map((entry) => [entry.id, entry.reason]));
      expect(reasons[rid(9)]).toBe("linkUnknownToEvent");
      expect(reasons[rid(10)]).toBe("notLinked");
    });

    it("still counts every source of the window, including the candidates' lane", () => {
      const model = ready({ record, window: windowAround(record, scene([onChannel(9, t + 3_000, "Application")])), counts: counts([]), unreadSources: false });
      expect(model.sourceCount).toBe(2);
    });
  });
});

describe("a record whose identity text the engine compacted is found, never 'not in the timeline' (#842, review A1 fv1)", () => {
  const vectorText = (name: string) =>
    (vectorDocument.timelineText.find((c) => c.name === name) as { input: string }).input;
  const LABELS: readonly (readonly [string, string])[] = [
    ["257 bytes", vectorText("ascii-257")],
    ["300 bytes with backslashes", vectorText("ascii-300-backslashes")],
    ["a collector bundle path of 276 bytes", vectorText("bundle-path-276")],
    ["3-byte characters past 256 bytes", vectorText("cjk-273")],
  ];
  const COLLECTOR_SEGMENT =
    "CMTRACE-20261017-101500-DESKTOP-7H2K9Q1-0f3c9a1b2d4e5f60718293a4b5c6d7e8.zip::CMTRACE-20261017-101500-DESKTOP-7H2K9Q1-0f3c9a1b2d4e5f60718293a4b5c6d7e8";

  /** An event entry whose origin text the engine compacted, in the engine's own form. */
  function compactedEvent(n: number, timestampMs: number, record: EvtxRecord): TimelineItem {
    const item = eventItem(n, timestampMs);
    if (item.origin.kind !== "event") throw new Error("an event origin");
    return {
      ...item,
      origin: {
        ...item.origin,
        source: timelineReference(record.sourceLabel),
        channel: timelineReference(record.channel),
        provider: timelineReference(record.provider),
      },
    };
  }

  it.each(LABELS)("finds an event record whose source label is %s", (_why, label) => {
    const record = { ...recordFor(1), sourceLabel: label };
    const t = record.timestampEpoch;
    const items = [compactedEvent(1, t, record), eventItem(2, t + 6_000), eventItem(9, t + 3_000)];
    expect(items[0]!.origin.kind === "event" && items[0]!.origin.source).not.toBe(label);
    const model = ready({ record, window: windowAround(record, items), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
    expect(model.selected).toEqual({ status: "found", originId: rid(1) });
    expect(model.notices).not.toContain(NOT_IN_TIMELINE_NOTE);
    expect(model.open).toEqual({ rowId: model.row?.id });
    // The entry is the selected event, drawn as a member, and is not its own context.
    expect(model.plot.members.map((m) => m.id)).toContain(rid(1));
    expect(model.plot.nearby.map((m) => m.id)).not.toContain(rid(1));
    expect(model.nearby.map((entry) => entry.id)).not.toContain(rid(1));
  });

  it.each(LABELS)("finds an event record whose channel and provider are %s", (_why, label) => {
    const record = { ...recordFor(1), channel: label, provider: label };
    const t = record.timestampEpoch;
    const model = ready({ record, window: windowAround(record, [compactedEvent(1, t, record)]), counts: counts([]), unreadSources: false });
    expect(model.selected).toEqual({ status: "found", originId: rid(1) });
  });

  it.each(LABELS)("finds an archive text row whose source label is %s", (_why, label) => {
    const t = T0 + 5_000;
    const row: EvtxRecord = {
      ...recordFor(7),
      originKind: "log",
      eventId: 0,
      sourceLabel: label,
      channel: label,
      provider: "CcmExec",
      computer: "",
      timestampEpoch: t,
    };
    const bundle = label === vectorText("bundle-path-276") ? COLLECTOR_SEGMENT : null;
    const item: TimelineItem = {
      timestampMs: t,
      severity: "info",
      message: "log line 7",
      origin: {
        kind: "log",
        file: timelineReference(label),
        component: "CcmExec",
        line: 7,
        source: timelineReference(label),
        machine: null,
        bundle,
        recordId: 7,
      },
    };
    const model = ready({ record: row, window: windowAround(row, [item, eventItem(2, t + 3_000)]), counts: counts([]), unreadSources: false });
    expect(model.selected.status).toBe("found");
    expect(model.notices).not.toContain(NOT_IN_TIMELINE_NOTE);
    expect(model.plot.members.map((m) => m.kind)).toEqual(["log"]);
    expect(model.plot.nearby.map((m) => m.id)).toEqual([rid(2)]);
  });

  describe("an archive text row's machine, component and bundle, read as the engine built them", () => {
    type LogOrigin = Extract<TimelineItem["origin"], { kind: "log" }>;
    const BUNDLE_SOURCE = `C:\\Cases\\${COLLECTOR_SEGMENT.split("::")[1]}\\evidence\\logs\\CcmExec.log`;
    const bundleOfBundleSource = COLLECTOR_SEGMENT.split("::")[1] as string;

    /** An archive row, and the entry the engine made for it, whose origin fields the case overrides. */
    function archive(rowFields: Partial<EvtxRecord>, originFields: Partial<LogOrigin>) {
      const t = T0 + 5_000;
      const row: EvtxRecord = {
        ...recordFor(7),
        originKind: "log",
        eventId: 0,
        sourceLabel: "C:\\Cases\\CcmExec.log",
        channel: "C:\\Cases\\CcmExec.log",
        provider: "CcmExec",
        computer: "",
        timestampEpoch: t,
        ...rowFields,
      };
      const item: TimelineItem = {
        timestampMs: t,
        severity: "info",
        message: "log line 7",
        origin: {
          kind: "log",
          file: row.sourceLabel,
          component: "CcmExec",
          line: 7,
          source: row.sourceLabel,
          machine: null,
          bundle: null,
          recordId: 7,
          ...originFields,
        },
      };
      return ready({ record: row, window: windowAround(row, [item, eventItem(2, t + 3_000)]), counts: counts([]), unreadSources: false });
    }

    it("finds a row whose machine and component the engine trimmed before it built the origin", () => {
      expect(archive({ computer: "  DESKTOP-01  ", provider: "  CcmExec  " }, { machine: "DESKTOP-01", component: "CcmExec" }).selected.status).toBe("found");
    });

    it("finds a row whose machine and component are placeholder words, which the engine leaves out", () => {
      expect(archive({ computer: " Unknown ", provider: "N/A" }, { machine: null, component: null }).selected.status).toBe("found");
    });

    it("does not find a row whose machine or component the entry names differently", () => {
      expect(archive({ computer: "DESKTOP-01" }, { machine: "DESKTOP-02" }).selected).toEqual({ status: "notInTimeline" });
      expect(archive({ provider: "CcmExec" }, { component: "Other" }).selected).toEqual({ status: "notInTimeline" });
    });

    it("finds a row inside a collector bundle by that bundle, and not by another", () => {
      expect(archive({ sourceLabel: BUNDLE_SOURCE, channel: BUNDLE_SOURCE }, { file: BUNDLE_SOURCE, source: BUNDLE_SOURCE, bundle: bundleOfBundleSource }).selected.status).toBe("found");
      expect(archive({ sourceLabel: BUNDLE_SOURCE, channel: BUNDLE_SOURCE }, { file: BUNDLE_SOURCE, source: BUNDLE_SOURCE, bundle: null }).selected).toEqual({ status: "notInTimeline" });
    });
  });

  it("finds a record whose machine is padded, as the engine trims it before it compacts it", () => {
    const record = { ...recordFor(1), computer: "  DESKTOP-01  " };
    const model = ready({ record, window: windowAround(record, [eventItem(1, record.timestampEpoch)]), counts: counts([]), unreadSources: false });
    expect(model.selected).toEqual({ status: "found", originId: rid(1) });
  });

  it("does not take the entry of a record with another long label, which shares only its prefix", () => {
    const label = vectorText("ascii-257");
    const record = { ...recordFor(1), sourceLabel: `${label}z` };
    const other = { ...recordFor(1), sourceLabel: label };
    const model = ready({
      record,
      window: windowAround(record, [compactedEvent(1, record.timestampEpoch, other)]),
      counts: counts([]),
      unreadSources: false,
    });
    expect(model.selected).toEqual({ status: "notInTimeline" });
  });

  describe("an identity the engine refused (the committed vectors)", () => {
    it("finds a record whose text conflicts with its number: the engine rewrote the origin to the number", () => {
      const record = { ...recordFor(1), eventRecordId: 9, eventRecordIdText: "5" };
      const item = eventItem(1, record.timestampEpoch);
      const rewritten =
        item.origin.kind === "event" ? { ...item, origin: { ...item.origin, recordId: 9, recordIdText: "9" } } : item;
      const model = ready({ record, window: windowAround(record, [rewritten]), counts: counts([]), unreadSources: false });
      expect(model.selected.status).toBe("found");
    });

    it("is unmatchable when the engine left the origin no identity, and says so rather than 'not in the timeline'", () => {
      const record = { ...recordFor(1), eventRecordId: 0, eventRecordIdText: "5" };
      const item = eventItem(1, record.timestampEpoch);
      const bare =
        item.origin.kind === "event" ? { ...item, origin: { ...item.origin, recordId: 0, recordIdText: null } } : item;
      const model = ready({ record, window: windowAround(record, [bare]), counts: counts([]), unreadSources: false });
      expect(model.selected).toEqual({ status: "unmatchable" });
      expect(model.notices).not.toContain(NOT_IN_TIMELINE_NOTE);
    });
  });
});

describe("the row of the selected event", () => {
  it("is the strongest row of the uncapped index, with its title when every entry is in the window", () => {
    const model = ready(pairScene().input);
    expect(model.row).toMatchObject({
      strength: "exact",
      memberCount: 2,
      read: 2,
      notShown: 0,
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
    expect(model.row).toMatchObject({ memberCount: 2, read: 1, notShown: 1, outsideWindow: 1 });
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

describe("a window that was not read whole makes no definite claim about the rest (#842, review A1)", () => {
  const record = recordFor(1);
  const t = record.timestampEpoch;
  const cut = (items: TimelineItem[]) =>
    windowAround(record, items, { complete: false, windowItems: 900, omittedItems: 900 - items.length, stoppedBy: "budget" });

  it("says a member of the row that was not read is not among the entries read, never 'outside this window'", () => {
    // The read stopped just after the event; its exact partner, 20 s later, is inside the window and unread.
    const model = ready({ record, window: cut([eventItem(1, t)]), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
    expect(model.row).toMatchObject({ memberCount: 2, read: 1, notShown: 1, outsideWindow: null });
    expect(model.notices).toContain(notReadNote(1, 2));
    expect(model.notices).not.toContain(outsideWindowNote(1, 2));
    expect(model.notices.some((text) => /outside this window/.test(text))).toBe(false);
    expect(model.row?.title).toBe("Chain of 2 entries (1 read)");
  });

  it("still says it is outside the window for a window read whole", () => {
    const model = ready({ record, window: windowAround(record, [eventItem(1, t)]), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
    expect(model.row).toMatchObject({ notShown: 1, outsideWindow: 1 });
    expect(model.notices).toContain(outsideWindowNote(1, 2));
    expect(model.notices.some((text) => /not among the entries read/.test(text))).toBe(false);
    expect(model.row?.title).toBe("Chain of 2 entries (1 in this window)");
  });

  it("keeps the whole-chain title when every member was read, even if the window was not read whole", () => {
    const items = [eventItem(1, t), eventItem(2, t + 6_000)];
    const model = ready({ record, window: cut(items), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
    expect(model.row).toMatchObject({ notShown: 0, outsideWindow: null });
    expect(model.row?.title).toBe("101 · message 1");
    expect(model.notices.some((text) => /not among the entries read|outside this window/.test(text))).toBe(false);
  });

  it("words the counts of what the lists leave out as lower bounds, and as exact ones for a window read whole", () => {
    const members = [1, 2, 3, 4, 5, 6];
    const edges = members.slice(1).map((n) => synthetic(`e${n}`, rid(1), rid(n)));
    const items = members.map((n) => eventItem(n, t + (6 - n) * 1_000));
    const context = [20, 21, 22, 23, 24, 25].map((n, i) => eventItem(n, t + 10_000 + i * 1_000));
    const whole = ready({ record, window: windowAround(record, [...items, ...context]), counts: counts(edges), unreadSources: false });
    expect(whole.complete).toBe(true);
    expect([whole.moreSteps, whole.moreStepsText]).toEqual([2, "+2 more"]);
    expect([whole.moreNearby, whole.moreNearbyText]).toEqual([2, "+2 more"]);
    const partial = ready({ record, window: cut([...items, ...context]), counts: counts(edges), unreadSources: false });
    expect(partial.complete).toBe(false);
    expect([partial.moreSteps, partial.moreStepsText]).toEqual([2, "at least 2 more"]);
    expect([partial.moreNearby, partial.moreNearbyText]).toEqual([2, "at least 2 more"]);
  });

  it("says nothing of 'more' when there is none to count", () => {
    const model = ready({ record, window: cut([eventItem(1, t), eventItem(2, t + 1_000)]), counts: counts(fixtureEdges("exactPair")), unreadSources: false });
    expect([model.moreStepsText, model.moreNearbyText]).toEqual([null, null]);
  });
});

describe("unread sources and an updating pair withdraw 'not linked' (#842, review A1)", () => {
  const record = recordFor(1);
  const t = record.timestampEpoch;
  const scene = (extra: Partial<DockModelInput>, counted: CountsOptions = {}) =>
    ready({
      record,
      window: windowAround(record, [eventItem(1, t), eventItem(2, t + 6_000), eventItem(9, t + 3_000)]),
      counts: counts(fixtureEdges("exactPair"), counted),
      unreadSources: false,
      ...extra,
    });

  it("says 'time only, not linked' on an otherwise clear session", () => {
    const model = scene({});
    expect(model.nearby.map((entry) => entry.reason)).toEqual(["notLinked"]);
    expect(model.plot.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
  });

  it("says 'no loaded link' instead when a source was not read: its records could carry the link", () => {
    const model = scene({ unreadSources: true });
    expect(model.nearby.map((entry) => entry.reason)).toEqual(["noLoadedLink"]);
    expect(model.plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
    expect(model.plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
    expect(model.notices).toContain(UNREAD_SOURCES_NOTE);
  });

  it("says 'no loaded link' while the pair is an earlier session's, which a newer one is replacing", () => {
    const model = scene({}, { updating: true });
    expect(model.updating).toBe(true);
    expect(model.nearby.map((entry) => entry.reason)).toEqual(["noLoadedLink"]);
    expect(model.plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
  });

  it("keeps an entry's loaded partner a fact whatever else is withdrawn", () => {
    const edges = [...fixtureEdges("exactPair"), synthetic("o", rid(9), rid(10))];
    const model = ready({
      record,
      window: windowAround(record, [eventItem(1, t), eventItem(2, t + 6_000), eventItem(9, t + 3_000)]),
      counts: counts(edges, { updating: true }),
      unreadSources: true,
    });
    expect(model.nearby.map((entry) => entry.reason)).toEqual(["inAnotherChain"]);
  });

  describe("the absence claim also waits for a pair that is not updating", () => {
    const own = () => [eventItem(1, t)];

    it("names only the reason that applies: an unread source or a rebuild is not 'hidden by the filters'", () => {
      const unread = ready({ record, window: windowAround(record, own()), counts: counts([]), unreadSources: true });
      expect(unread.empty?.text).toContain("Some sources were not fully read");
      expect(unread.empty?.text).not.toMatch(/hidden by the current filters|being rebuilt/);
      const rebuilding = ready({ record, window: windowAround(record, own()), counts: counts([], { updating: true }), unreadSources: false });
      expect(rebuilding.empty?.text).not.toMatch(/hidden by the current filters|not fully read/);
    });

    it("is absolute only when the pair is current", () => {
      const current = ready({ record, window: windowAround(record, own()), counts: counts([]), unreadSources: false });
      expect(current.empty).toEqual({ text: "No other sources have entries within \u00b175 s.", absolute: true });
      const updating = ready({ record, window: windowAround(record, own()), counts: counts([], { updating: true }), unreadSources: false });
      expect(updating.empty?.absolute).toBe(false);
      expect(updating.empty?.text).toContain("The timeline is being rebuilt, so this may change.");
      expect(updating.empty?.text).toMatch(/^No other visible sources/);
    });
  });
});

describe("the counts belong to the window's session, or nothing is called linked", () => {
  const states: [string, (input: DockModelInput) => DockModelInput][] = [
    ["not in yet", (input) => ({ ...input, counts: null })],
    ["another session's", (input) => ({ ...input, counts: counts(fixtureEdges("exactPair"), { builtFor: "session:2" }) })],
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

  it("pairs when the counts are the window's session", () => {
    const model = ready(pairScene().input);
    expect(model.paired).toBe(true);
    expect(model.updating).toBe(false);
  });

  it("keeps an earlier session's window and its own counts paired while a newer session loads, and says it is updating", () => {
    // The counts are marked updating because a newer session exists; the window is the SAME earlier
    // session's, so the two agree with each other and nothing newer is mixed in.
    const { input } = pairScene();
    const model = ready({ ...input, counts: counts(fixtureEdges("exactPair"), { updating: true }) });
    expect(model.paired).toBe(true);
    expect(model.updating).toBe(true);
    expect(model.row?.strength).toBe("exact");
    expect(model.plot.connectors).toHaveLength(1);
    expect(model.notices).not.toContain(LINKS_LOADING_TEXT);
  });

  it("never pairs a newer window with an earlier session's counts, nor an earlier window with newer counts", () => {
    const { input } = pairScene();
    const newerWindow = { ...input.window!, sessionKey: "session:2" };
    expect(ready({ ...input, window: newerWindow, counts: counts(fixtureEdges("exactPair"), { updating: true }) }).paired).toBe(false);
    expect(ready({ ...input, counts: counts(fixtureEdges("exactPair"), { builtFor: "session:2" }) }).paired).toBe(false);
  });

  it("is not updating when nothing is paired, even if the counts that are not the window's are", () => {
    const { input } = pairScene();
    expect(ready({ ...input, counts: null }).updating).toBe(false);
    const other = counts(fixtureEdges("exactPair"), { builtFor: "session:2", updating: true });
    expect(ready({ ...input, counts: other }).updating).toBe(false);
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
  ] as [string, CountsOptions][])("says 'time only, no loaded link' when %s", (_why, extra) => {
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
  ] as [string, CountsOptions, boolean, RegExp][])("qualifies the claim when %s", (_why, extra, unread, text) => {
    const model = ready({ record, window: windowAround(record, own()), counts: counts([], extra), unreadSources: unread });
    expect(model.empty?.absolute).toBe(false);
    expect(model.empty?.text).toMatch(text);
    expect(model.empty?.text).toMatch(/^No other visible sources/);
  });

  describe("entries the session could not place are in no window (#842, review A1)", () => {
    const own = () => [eventItem(1, t)];
    const withUnplaced = (unplacedList: { items: never[]; total: number | null }, extra: Partial<DockModelInput> = {}) =>
      ready({ record, window: windowAround(record, own()), counts: counts([], { unplacedList }), unreadSources: false, ...extra });

    it("makes the absence claim for a known count of zero, from the paired counts", () => {
      expect(withUnplaced({ items: [], total: 0 }).empty).toEqual({
        text: "No other sources have entries within \u00b175 s.",
        absolute: true,
      });
    });

    it("withdraws it for a positive count and names the count", () => {
      const model = withUnplaced({ items: [], total: 7 });
      expect(model.empty?.absolute).toBe(false);
      expect(model.empty?.text).toContain("7 entries have no usable time and appear in no window.");
    });

    it("withdraws it for an unknown count, which is not read as zero", () => {
      const model = withUnplaced({ items: [], total: null });
      expect(model.empty?.absolute).toBe(false);
      expect(model.empty?.text).toContain("How many entries have no usable time is not known");
    });

    it("reads the count from the counts that are paired with the window, never from other counts", () => {
      const other = counts([], { builtFor: "session:2", unplacedList: { items: [], total: 0 } });
      const model = ready({ record, window: windowAround(record, own()), counts: other, unreadSources: false });
      expect(model.paired).toBe(false);
      expect(model.empty?.absolute).toBe(false);
      expect(model.empty?.text).toContain("is not known");
    });

    it("is not an absence claim at all for a window that was not read whole, whatever the count", () => {
      const window = windowAround(record, own(), { complete: false, windowItems: 90, omittedItems: 89, stoppedBy: "budget" });
      expect(ready({ record, window, counts: counts([], { unplacedList: { items: [], total: 0 } }), unreadSources: false }).empty).toBeNull();
    });
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

  it("says an entry with no usable record identity selects nothing", () => {
    expect(nameOf(rid(9), "noIdentity")).toMatch(/it has no usable record identity, so activating it selects nothing$/);
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

  describe("what it costs grows with the window, not with its square", () => {
    const record = recordFor(1);
    const t = record.timestampEpoch;

    /**
     * `n` entries, the first the selected event and the rest spread over 40 channels across the
     * window, whose `timestampMs` and `origin` count every read. The lane mix is the same for any n.
     */
    function countedItems(n: number, reads: { count: number }): TimelineItem[] {
      const counted = (source: TimelineItem): TimelineItem => {
        const copy = { severity: source.severity, message: source.message } as TimelineItem;
        Object.defineProperty(copy, "timestampMs", {
          enumerable: true,
          get() {
            reads.count += 1;
            return source.timestampMs;
          },
        });
        Object.defineProperty(copy, "origin", {
          enumerable: true,
          get() {
            reads.count += 1;
            return source.origin;
          },
        });
        return copy;
      };
      return [
        counted(eventItem(1, t)),
        ...Array.from({ length: n - 1 }, (_, i) =>
          counted(onChannel(1_000 + i, t - 70_000 + Math.floor((i * 140_000) / n), `Chan${i % 40}`)),
        ),
      ];
    }

    function readsFor(n: number): number {
      const reads = { count: 0 };
      const items = countedItems(n, reads);
      reads.count = 0;
      const model = ready({ record, window: windowAround(record, items), counts: counts([]), unreadSources: false });
      expect(model.plot.lanes).toHaveLength(5);
      expect(model.plot.nearby).toHaveLength(60);
      return reads.count;
    }

    it("reads each entry a bounded number of times: doubling the window less than 2.6 times the reads", () => {
      const small = readsFor(3_000);
      const large = readsFor(6_000);
      // The counting works: every entry is read more than once, and the figure is not trivial.
      expect(small).toBeGreaterThan(3_000);
      // n log n doubles to about 2.2; an O(n squared) step anywhere would quadruple it. The limit is
      // a figure on reads of `timestampMs` and `origin` and nothing else: the counter sees only those
      // two properties of an entry (severity and message are plain values, and a read of the lane or
      // the window object is not an entry read). A pass that is quadratic in some other property, or
      // in the members it builds from the entries, is not seen by it; the 6,000-entry smoke test
      // below is the wall-clock net for that, and its limit is loose by design.
      expect(large / small, `${small} reads at 3,000 entries, ${large} at 6,000`).toBeLessThan(2.6);
    });

    it("counts a pass that is quadratic, so the guard can fail", () => {
      // A control for the guard itself: a deliberately quadratic pass over the same counted entries.
      const grown = (n: number) => {
        const reads = { count: 0 };
        const items = countedItems(n, reads);
        reads.count = 0;
        for (const a of items) for (const b of items) if (a.timestampMs === b.timestampMs) void 0;
        return reads.count;
      };
      expect(grown(600) / grown(300)).toBeGreaterThan(2.6);
    });

    it("smoke: builds a 6,000-entry window in well under ten seconds, and logs its figure", () => {
      const items = [
        eventItem(1, t),
        ...Array.from({ length: 5_999 }, (_, i) => onChannel(1_000 + i, t - 70_000 + i * 23, `Chan${i % 40}`)),
      ];
      const started = performance.now();
      const model = ready({ record, window: windowAround(record, items), counts: counts([]), unreadSources: false });
      const elapsed = performance.now() - started;
      console.info(`buildDockModel, 6,000 entries over 40 channels: ${elapsed.toFixed(1)} ms`);
      expect(model.plot.lanes).toHaveLength(5);
      expect(model.plot.nearby).toHaveLength(60);
      expect(elapsed).toBeLessThan(10_000);
    });
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

describe("what a click on a marker does (#842, A1 ruling 6)", () => {
  const origin = (n: number) => eventItem(n, T0).origin;

  it("selects the record when exactly one loaded record matches the entry", () => {
    const click = resolveMarkerClick(origin(1), buildEvidenceIndex([recordFor(1), recordFor(2)]));
    expect(click).toEqual({ kind: "select", recordId: recordFor(1).id });
  });

  it("selects nothing when no loaded record matches, and says so", () => {
    expect(resolveMarkerClick(origin(1), buildEvidenceIndex([recordFor(2)]))).toEqual({
      kind: "nothing",
      selectability: "notLoaded",
    });
    expect(resolveMarkerClick(origin(1), buildEvidenceIndex([]))).toEqual({ kind: "nothing", selectability: "notLoaded" });
  });

  it("selects nothing when several loaded records match, never the first of them", () => {
    const twin: EvtxRecord = { ...recordFor(1), id: recordFor(1).id + 1000 };
    expect(resolveMarkerClick(origin(1), buildEvidenceIndex([recordFor(1), twin]))).toEqual({
      kind: "nothing",
      selectability: "ambiguous",
    });
  });

  it("selects nothing for a text-log line, which is not an event record", () => {
    const line: TimelineItem = {
      timestampMs: T0,
      severity: "info",
      message: "log line",
      origin: { kind: "log", file: "C:\\Logs\\A.log", component: null, line: 3, source: "A.log", machine: null, bundle: null, recordId: 3 },
    };
    expect(resolveMarkerClick(line.origin, buildEvidenceIndex([recordFor(1)]))).toEqual({
      kind: "nothing",
      selectability: "log",
    });
  });

  it("selects nothing for an event entry the join can never name, and says it has no identity", () => {
    const item = eventItem(1, T0);
    if (item.origin.kind !== "event") throw new Error("an event origin");
    const bare = { ...item.origin, recordId: 0, recordIdText: null };
    expect(resolveMarkerClick(bare, buildEvidenceIndex([recordFor(1)]))).toEqual({
      kind: "nothing",
      selectability: "noIdentity",
    });
  });
});

describe("the instant the dock centers on", () => {
  it("is the selected event's timestamp, and nothing for no selection or an event with none", () => {
    const record = recordFor(1);
    expect(dockCenterMs(record)).toBe(record.timestampEpoch);
    expect(dockCenterMs(null)).toBeNull();
    for (const epoch of [0, -5, Number.NaN, Number.POSITIVE_INFINITY, 1.5]) {
      expect(dockCenterMs({ ...record, timestampEpoch: epoch }), String(epoch)).toBeNull();
    }
  });

  it("is what makes an event untimed in the model, so the reader and the model cannot disagree", () => {
    const untimed = { ...recordFor(1), timestampEpoch: 0 };
    expect(buildDockModel({ record: untimed, window: null, counts: null, unreadSources: false })).toEqual({ kind: "untimed" });
    expect(buildDockModel({ record: null, window: null, counts: null, unreadSources: false })).toEqual({ kind: "noSelection" });
  });
});
