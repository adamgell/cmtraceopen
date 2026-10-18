/**
 * What the Details "Context ±5 min" list shows for one selected event and one window read (spec 8.13
 * item 7, #843). The window and the counts are built the way the loader and the hook build them (the
 * real chain model over real and synthetic edges), and the selected record is the loaded record an
 * origin names, field for field, so the origin join is the production one.
 *
 * The two things this file protects most: a row with no edge to the selected event carries no
 * relationship words at all (the class test below runs every state), and "nearest" is said only
 * when it is proven.
 */
import { describe, expect, it } from "vitest";
import {
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  NOT_READ_NOTE,
  NO_SESSION_TEXT,
  READING_WINDOW_TEXT,
  UNREAD_SOURCES_NOTE,
  UNTIMED_TEXT,
  ambiguousEventNote,
  emptyWindowText,
  sharedOriginNote,
  unmatchableNote,
  windowFailureText,
  windowNotice,
} from "./evtx-correlation-copy";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import {
  fixtureEdges,
  eventItem,
  recordFor,
  rid,
  synthetic,
  T0,
} from "./evtx-correlation-test-fixtures";
import {
  BUILDING_TIMELINE_TEXT,
  DETAIL_CONTEXT_HALF_WIDTH_MS,
  DETAIL_CONTEXT_KINDS_LABEL,
  DETAIL_CONTEXT_ROW_CAP,
  DETAIL_CONTEXT_TITLE,
  LINKS_MAY_BE_MISSING_TEXT,
  LINK_LEGEND_TEXT,
  TIMELINE_UPDATING_NOTE,
  buildDetailContext,
  directLinks,
  type DetailContextInput,
  type DetailContextModel,
  type DetailContextReady,
} from "./evtx-detail-context-model";
import {
  FIVE_MIN,
  countsFor,
  logItem,
  onChannel,
  stoppedWindow,
  twinOf,
  unnumbered,
  windowAround,
} from "./evtx-detail-context-test-helpers";
import { timelineOriginId, type TimelineCorrelationEdge, type TimelineItem } from "./unified-timeline";

/** Record 20, with 41 entries one second apart named by records 1 to 41 (entry n is at T0 + n s). */
const record = recordFor(20);
const t = record.timestampEpoch;
const entries = (): TimelineItem[] =>
  Array.from({ length: 41 }, (_, index) => eventItem(index + 1, T0 + (index + 1) * 1_000));

function input(extra: Partial<DetailContextInput> = {}): DetailContextInput {
  return {
    record,
    window: windowAround(record, entries()),
    counts: countsFor([]),
    unreadSources: false,
    session: "available",
    ...extra,
  };
}

function ready(extra: Partial<DetailContextInput> = {}): DetailContextReady {
  const model = buildDetailContext(input(extra));
  if (model.kind !== "ready") throw new Error(`expected a ready list, got ${model.kind}`);
  return model;
}

const ids = (model: DetailContextReady) => model.rows.map((row) => row.id);
const numbers = (model: DetailContextReady) => ids(model).map((id) => Number(/record(\d+)$/.exec(id)?.[1]));

describe("which state the list is in", () => {
  it("has nothing without a selected record", () => {
    expect(buildDetailContext(input({ record: null }))).toEqual({ kind: "none" });
  });

  it.each([0, -5, Number.NaN, T0 + 0.5])("is untimed for an epoch of %s, whatever window it is given", (epoch) => {
    const untimed = { ...recordFor(20), timestampEpoch: epoch };
    expect(buildDetailContext(input({ record: untimed }))).toEqual({ kind: "untimed", text: UNTIMED_TEXT });
  });

  it.each([
    ["no session", "none", { kind: "noSession", text: NO_SESSION_TEXT }],
    ["a session being built", "building", { kind: "building", text: BUILDING_TIMELINE_TEXT }],
    ["a session whose window is being read", "available", { kind: "reading", text: READING_WINDOW_TEXT }],
  ] as const)("has nothing to list for %s before any window", (_why, session, expected) => {
    expect(buildDetailContext(input({ window: null, session }))).toEqual(expected);
  });

  it("says the analysis is being built, not that it is missing, while the session is pending", () => {
    expect(BUILDING_TIMELINE_TEXT).toBe(
      "The event analysis is being built, so the entries around this event are not available yet.",
    );
    expect(BUILDING_TIMELINE_TEXT).not.toBe(NO_SESSION_TEXT);
  });

  it("never lists another selection's window under this record", () => {
    const other = { ...record, timestampEpoch: t + 1 };
    expect(buildDetailContext(input({ window: windowAround(other, entries()) })).kind).toBe("reading");
  });

  it("never lists a window of another width, since the list says ±5 min", () => {
    expect(DETAIL_CONTEXT_HALF_WIDTH_MS).toBe(FIVE_MIN);
    expect(buildDetailContext(input({ window: windowAround(record, entries(), {}, 75_000) })).kind).toBe("reading");
  });

  it("keeps listing a window that answers the selection while the session is rebuilt", () => {
    expect(buildDetailContext(input({ session: "building" })).kind).toBe("ready");
    expect(buildDetailContext(input({ session: "none" })).kind).toBe("ready");
  });

  it("fails with the error when the first reply never came, and never counts the window as empty", () => {
    const failed = windowAround(record, [], { windowItems: null, omittedItems: null, complete: false, error: "session was not found" });
    expect(buildDetailContext(input({ window: failed }))).toEqual({
      kind: "failed",
      text: windowFailureText("session was not found"),
      error: "session was not found",
    });
  });
});

describe("the 12 nearest entries", () => {
  it("lists the selected event and its 11 nearest neighbours, in time order, not the first 12 by time", () => {
    const model = ready();
    expect(DETAIL_CONTEXT_ROW_CAP).toBe(12);
    expect(numbers(model)).toEqual([14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]);
    expect(DETAIL_CONTEXT_TITLE).toBe("Context ±5 min");
  });

  it("lists every entry when there are not more than 12", () => {
    const few = [eventItem(18, T0 + 18_000), eventItem(20, t), eventItem(23, T0 + 23_000)];
    const model = ready({ window: windowAround(record, few) });
    expect(numbers(model)).toEqual([18, 20, 23]);
  });

  it("breaks a tie on distance by id: records 14 and 26 are both 6 s away and only 14 is the 12th row", () => {
    const model = ready();
    expect(numbers(model)).toContain(14);
    expect(numbers(model)).not.toContain(26);
  });

  it("breaks a tie among entries of one instant by id, whatever order they were read in", () => {
    const sameInstant = Array.from({ length: 20 }, (_, index) => eventItem(100 + index, t + 1_000));
    const forward = ready({ window: windowAround(record, [eventItem(20, t), ...sameInstant]) });
    const reversed = ready({ window: windowAround(record, [eventItem(20, t), ...[...sameInstant].reverse()]) });
    expect(numbers(forward)).toEqual([20, ...Array.from({ length: 11 }, (_, index) => 100 + index)]);
    expect(ids(reversed)).toEqual(ids(forward));
  });

  it("keeps the selected event when 30 other entries share its millisecond and sort before it", () => {
    const crowd = Array.from({ length: 30 }, (_, index) => eventItem(100 + index, t));
    const model = ready({ window: windowAround(record, [...crowd, eventItem(20, t)]) });
    expect(model.rows).toHaveLength(12);
    expect(model.rows.filter((row) => row.isSelected).map((row) => row.id)).toEqual([rid(20)]);
  });

  it("marks one row as the selected event, found by its origin and not by its time", () => {
    const sameMillisecond = [eventItem(5, t), eventItem(20, t), eventItem(6, t)];
    const model = ready({ window: windowAround(record, sameMillisecond) });
    expect(model.rows.filter((row) => row.isSelected).map((row) => row.id)).toEqual([rid(20)]);
    expect(model.selected).toEqual({ status: "found", originId: rid(20) });
  });

  it("lists 12 other entries, with no selected row, when the event is not identified", () => {
    const without = entries().filter((item) => timelineOriginId(item.origin) !== rid(20));
    const model = ready({ window: windowAround(record, without) });
    expect(model.selected).toEqual({ status: "notInTimeline" });
    expect(model.rows).toHaveLength(12);
    expect(model.rows.some((row) => row.isSelected)).toBe(false);
    expect(numbers(model)).toEqual([14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26]);
  });

  it("leaves out the entries that could each be the event when several name it", () => {
    const twin = twinOf(eventItem(20, t), rid(88));
    const model = ready({ window: windowAround(record, [...entries(), twin]) });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(ids(model)).not.toContain(rid(20));
    expect(ids(model)).not.toContain(rid(88));
    expect(model.rows).toHaveLength(12);
    expect(model.rows.some((row) => row.isSelected)).toBe(false);
  });

  it("lists nothing when the event has no record identity, since any entry could be it", () => {
    const unmatchable = unnumbered(t);
    const model = ready({ record: unmatchable, window: windowAround(unmatchable, entries()) });
    expect(model.selected).toEqual({ status: "unmatchable" });
    expect(model.rows).toEqual([]);
    expect(model.caption).toBeNull();
    expect(model.notices).toContain(unmatchableNote(41, FIVE_MIN, "list"));
  });

  it("lists identical duplicates once", () => {
    const model = ready({ window: windowAround(record, [...entries(), eventItem(21, T0 + 21_000)]) });
    expect(ids(model).filter((id) => id === rid(21))).toHaveLength(1);
  });
});

describe("a row", () => {
  it("is an EVT or a LOG row by what the entry is", () => {
    const mixed = [eventItem(20, t), logItem(7, t + 2_000)];
    const model = ready({ window: windowAround(record, mixed) });
    expect(model.rows.map((row) => [row.kind, row.chip])).toEqual([
      ["event", "EVT"],
      ["log", "LOG"],
    ]);
  });

  it("says how far it is from the selected event, before or after", () => {
    const around = [
      eventItem(20, t),
      eventItem(21, t + 3_300),
      eventItem(19, t - 3_300),
      eventItem(23, t),
      eventItem(24, t + 125_000),
      eventItem(25, t - 850),
    ];
    const model = ready({ window: windowAround(record, around) });
    const text = Object.fromEntries(model.rows.map((row) => [Number(/record(\d+)$/.exec(row.id)?.[1]), row.offsetText]));
    expect(text).toEqual({ 19: "-3.3 s", 20: "this event", 21: "+3.3 s", 23: "same time", 24: "+2 min 5 s", 25: "-850 ms" });
    expect(model.rows.find((row) => row.id === rid(21))?.offsetMs).toBe(3_300);
    expect(model.rows.find((row) => row.id === rid(19))?.offsetMs).toBe(-3_300);
  });

  it("names its source as the entry label: the event and its channel, or the file and its line", () => {
    const mixed = [
      eventItem(20, t),
      onChannel(21, t + 1_000, "Microsoft-Windows-DeviceManagement/Admin"),
      logItem(7, t + 2_000),
    ];
    const model = ready({ window: windowAround(record, mixed) });
    expect(model.rows.map((row) => row.entry)).toEqual([
      "120 · System",
      "121 · Microsoft-Windows-DeviceManagement/Admin",
      "AgentExecutor.log · line 7",
    ]);
  });

  it("carries the entry's own message", () => {
    const model = ready({ window: windowAround(record, [eventItem(20, t), logItem(7, t + 2_000)]) });
    expect(model.rows.map((row) => row.message)).toEqual(["message 20", "Starting Powershell Execution"]);
  });

  it("is in the order of time, ties in the order of ids", () => {
    const model = ready();
    const times = model.rows.map((row) => row.timestampMs);
    expect(times).toEqual([...times].sort((a, b) => a - b));
  });
});

describe("the link icon marks a DIRECT Exact or Candidate edge between the entry and the selected event", () => {
  const exactTo = (n: number) => synthetic(`e${n}`, rid(20), rid(n));
  const linked = (edges: TimelineCorrelationEdge[], extra: Partial<DetailContextInput> = {}) =>
    ready({ counts: countsFor(edges), ...extra });
  const linkOf = (model: DetailContextReady, n: number) => model.rows.find((row) => row.id === rid(n))?.link;

  it("shows it for an exact partner, with the key", () => {
    const model = linked([exactTo(21)]);
    expect(linkOf(model, 21)).toEqual({ strength: "exact", name: "Exact link to this event by ActivityId" });
    expect(model.legend).toBe(LINK_LEGEND_TEXT);
  });

  it("names the strength of THIS edge, not of the chain", () => {
    const model = linked([exactTo(21), synthetic("c22", rid(20), rid(22), "candidate")]);
    expect(linkOf(model, 21)?.strength).toBe("exact");
    expect(linkOf(model, 22)).toEqual({ strength: "candidate", name: "Candidate link to this event by ActivityId" });
  });

  it("names the key of a real candidate edge the engine's reducer produced", () => {
    const model = linked(fixtureEdges("secondaryPair", 19));
    expect(linkOf(model, 21)).toEqual({ strength: "candidate", name: "Candidate link to this event by secondary identifier" });
  });

  it("names no key when the pair's edge carries keys of more than one kind", () => {
    const second: TimelineCorrelationEdge = { ...synthetic("s21", rid(20), rid(21)), key: { kind: "sessionId", value: "s" } };
    const model = linked([exactTo(21), second]);
    expect(linkOf(model, 21)).toEqual({ strength: "exact", name: "Exact link to this event" });
  });

  it("has no icon for a member of an Ambiguous row", () => {
    const model = linked([synthetic("a", rid(20), rid(21), "ambiguous")]);
    expect(linkOf(model, 21)).toBeNull();
    expect(model.legend).toBeNull();
  });

  it("has no icon for a member of a Coverage blocked row", () => {
    const blocked: TimelineCorrelationEdge = {
      ...exactTo(21),
      coverage: { state: "gap", gap: { source: "Live", reason: "channel not collected" } },
    };
    expect(linkOf(linked([blocked]), 21)).toBeNull();
  });

  it("has no icon for an entry that is linked elsewhere", () => {
    const model = linked([exactTo(21), synthetic("x", rid(16), rid(17))]);
    expect(linkOf(model, 21)?.strength).toBe("exact");
    expect(model.rows.map((row) => row.id)).toEqual(expect.arrayContaining([rid(16), rid(17)]));
    expect(linkOf(model, 16)).toBeNull();
    expect(linkOf(model, 17)).toBeNull();
  });

  it("has no icon for a transitive member of the event's chain, which has no direct edge to it", () => {
    const model = linked([exactTo(21), synthetic("t", rid(21), rid(22))]);
    expect(linkOf(model, 21)?.strength).toBe("exact");
    expect(linkOf(model, 22)).toBeNull();
  });

  it("has no icon on the selected event's own row", () => {
    const model = linked([exactTo(21)]);
    expect(linkOf(model, 20)).toBeNull();
    expect(model.rows.find((row) => row.isSelected)?.link).toBeNull();
  });

  it("has no icon when the counts belong to another session", () => {
    const model = linked([exactTo(21)], { counts: countsFor([exactTo(21)], { builtFor: "session:2" }) });
    expect(model.paired).toBe(false);
    expect(model.rows.every((row) => row.link === null)).toBe(true);
    expect(model.legend).toBeNull();
  });

  it("has no icon without counts", () => {
    const model = ready({ counts: null });
    expect(model.rows.every((row) => row.link === null)).toBe(true);
  });

  it.each([
    ["the read stopped before the event (notRead)", () => input({ window: stoppedWindow(record, entries().slice(0, 15), 500) }), "notRead"],
    ["several entries name the event (ambiguous)", () => input({ window: windowAround(record, [...entries(), twinOf(eventItem(20, t), rid(88))]) }), "ambiguous"],
    ["the event is not in the window (notInTimeline)", () => input({ window: windowAround(record, entries().filter((item) => timelineOriginId(item.origin) !== rid(20))) }), "notInTimeline"],
  ] as const)("has no icon when the event is not identified: %s", (_why, build, status) => {
    const edges = [exactTo(21), exactTo(14), exactTo(88)];
    const model = ready({ ...build(), counts: countsFor(edges) });
    expect(model.selected.status).toBe(status);
    expect(model.rows.length).toBeGreaterThan(0);
    expect(model.rows.every((row) => row.link === null)).toBe(true);
    expect(model.legend).toBeNull();
  });

  it("marks an earlier session's pair, which is shown while a newer one is read", () => {
    const model = linked([exactTo(21)], { counts: countsFor([exactTo(21)], { updating: true }) });
    expect(model.updating).toBe(true);
    expect(linkOf(model, 21)?.strength).toBe("exact");
    expect(model.notices).toContain(TIMELINE_UPDATING_NOTE);
  });

  it("finds the partners of an origin in every row that holds it, the weaker label when two disagree", () => {
    const edge = (right: string, strength: "exact" | "candidate" | "ambiguous", kind = "activityId") => ({
      left: rid(20),
      right,
      strength,
      keys: [{ kind: kind as "activityId", value: "k" }],
    });
    const rows = [
      { edges: [edge(rid(21), "exact"), edge(rid(23), "ambiguous"), { ...edge(rid(24), "exact"), right: null }] },
      { edges: [edge(rid(21), "candidate"), { ...edge(rid(22), "exact"), left: rid(22), right: rid(20) }] },
    ];
    const partners = directLinks(rows, rid(20));
    expect([...partners.keys()].sort()).toEqual([rid(21), rid(22)].sort());
    expect(partners.get(rid(21))?.strength).toBe("candidate");
    expect(partners.get(rid(22))?.strength).toBe("exact");
    expect(directLinks(rows, rid(30)).size).toBe(0);
    expect(directLinks([], rid(20)).size).toBe(0);
  });
});

describe("what is said about links that may be missing, instead of a word on a row", () => {
  const exact = [synthetic("e", rid(20), rid(21))];

  it("says nothing about missing links when the session can speak for their absence", () => {
    const model = ready({ counts: countsFor(exact) });
    expect(model.notices).not.toContain(LINKS_MAY_BE_MISSING_TEXT);
    expect(model.notices).toEqual([]);
  });

  it.each([
    ["an edge that was not loaded", { totalEdges: 9 }, false],
    ["a narrowed scope", { scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } }, false],
    ["an unknown scope", { scope: null }, false],
    ["a limit gap", { gaps: classifyCoverageGaps([{ source: "correlation", reason: "limit" }], 1) }, false],
    ["a cut gap preview", { gaps: classifyCoverageGaps([], 4) }, false],
    ["a gap that names the event", { gaps: classifyCoverageGaps([{ source: rid(20), reason: "x" }], 1) }, false],
    ["a gap that names a member of the event's row", { gaps: classifyCoverageGaps([{ source: rid(21), reason: "x" }], 1) }, false],
    ["a gap that names a listed entry", { gaps: classifyCoverageGaps([{ source: rid(17), reason: "x" }], 1) }, false],
    ["an unread source", {}, true],
    ["an earlier session's pair", { updating: true }, false],
  ] as const)("says links may be missing for %s", (_why, countsExtra, unread) => {
    const model = ready({ counts: countsFor(exact, countsExtra), unreadSources: unread });
    expect(model.notices).toContain(LINKS_MAY_BE_MISSING_TEXT);
  });

  it("does not let a gap that names an entry nobody lists withdraw the claim", () => {
    const model = ready({ counts: countsFor(exact, { gaps: classifyCoverageGaps([{ source: rid(40), reason: "x" }], 1) }) });
    expect(model.notices).not.toContain(LINKS_MAY_BE_MISSING_TEXT);
  });

  it("says it while the counts are not the window's, with the loading note", () => {
    const model = ready({ counts: countsFor(exact, { builtFor: "session:2" }) });
    expect(model.notices).toEqual([LINKS_LOADING_TEXT, LINKS_MAY_BE_MISSING_TEXT]);
    expect(ready({ counts: null }).notices).toEqual([LINKS_LOADING_TEXT, LINKS_MAY_BE_MISSING_TEXT]);
  });

  it("does not say it when no icon could have been shown, because the event is not identified", () => {
    const unfound = ready({ window: stoppedWindow(record, entries().slice(0, 15), 500), counts: countsFor(exact) });
    expect(unfound.notices).not.toContain(LINKS_MAY_BE_MISSING_TEXT);
  });

  it("states the specific notes the dock states, in order", () => {
    const scope = { visibleCount: 2, loadedCount: 9, textLogCount: 3 };
    const model = ready({ counts: countsFor([synthetic("e", rid(80), rid(81))], { scope, totalEdges: 6 }), unreadSources: true });
    expect(model.notices).toEqual([
      "Correlation details are paged and bounded: 5 correlation edges were not loaded, so chains may be incomplete.",
      "Links and strengths are computed over the 2 events visible. Events outside the view can make an Exact link ambiguous.",
      "Text logs are not scoped.",
      DOCK_SCOPE_NOTE,
      UNREAD_SOURCES_NOTE,
      LINKS_MAY_BE_MISSING_TEXT,
    ]);
  });

  it("states what is wrong with the event when it is not identified", () => {
    const stopped = stoppedWindow(record, entries().slice(0, 15), 500);
    expect(ready({ window: stopped }).notices).toEqual([windowNotice(stopped) as string, NOT_READ_NOTE]);
    const absent = ready({ window: windowAround(record, entries().filter((item) => timelineOriginId(item.origin) !== rid(20))) });
    expect(absent.notices).toEqual([NOT_IN_TIMELINE_NOTE]);
    const twin = ready({ window: windowAround(record, [...entries(), twinOf(eventItem(20, t), rid(88))]) });
    expect(twin.notices).toEqual([ambiguousEventNote(2, "list")]);
  });
});

describe("the caption: nearest is said only when it is proven", () => {
  it("counts a window read whole", () => {
    expect(ready().caption).toBe("12 nearest of 41 entries within ±5 min");
    expect(ready({ window: windowAround(record, [eventItem(18, T0 + 18_000), eventItem(20, t)]) }).caption).toBe("2 entries within ±5 min");
  });

  it("has no caption for the event alone", () => {
    expect(ready({ window: windowAround(record, [eventItem(20, t)]) }).caption).toBeNull();
  });

  const stoppedAt = (last: number) =>
    ready({ window: stoppedWindow(record, entries().slice(0, last), 500) });

  it("is proven for a read that stopped, when every row is nearer than anything unread can be", () => {
    // Read to entry 41 (21 s after the event); the farthest row is 6 s away.
    const model = stoppedAt(41);
    expect(model.complete).toBe(false);
    expect(model.nearestProven).toBe(true);
    expect(model.caption).toBe("12 nearest entries within ±5 min");
    expect(model.notices[0]).toMatch(/^Showing 41 of 500 entries/);
  });

  it("is not proven when the farthest row is as far as the last entry read, for an unread tie could be nearer", () => {
    // Read to entry 26: the last read is 6 s after the event and a row is exactly 6 s away.
    const model = stoppedAt(26);
    expect(model.nearestProven).toBe(false);
    expect(model.caption).toBe("12 nearest of the 26 entries read");
  });

  it("is not proven when a row is farther than the last entry read", () => {
    const model = stoppedAt(25);
    expect(model.nearestProven).toBe(false);
    expect(model.caption).toBe("12 nearest of the 25 entries read");
  });

  it("is not proven when the read never reached the event, whatever the rows", () => {
    const model = stoppedAt(15);
    expect(model.selected).toEqual({ status: "notRead" });
    expect(model.nearestProven).toBe(false);
    expect(model.caption).toBe("12 nearest of the 15 entries read");
  });

  it("is not proven when the last entry read is the event's own instant", () => {
    const model = stoppedAt(20);
    expect(model.nearestProven).toBe(false);
  });

  it("is not proven with fewer than 12 rows, and says only how many were read", () => {
    const few = ready({ window: stoppedWindow(record, [eventItem(19, T0 + 19_000), eventItem(20, t), eventItem(30, T0 + 30_000)], 500) });
    expect(few.nearestProven).toBe(false);
    expect(few.caption).toBe("3 entries read");
  });

  it("is not proven with fewer than 12 rows even when the entry read last is not one of them", () => {
    // Two entries name the event, so both are left out; the later one is the last entry read.
    const later = { ...twinOf(eventItem(20, t), rid(88)), timestampMs: t + 9_000 };
    const window = stoppedWindow(record, [eventItem(19, t - 1_000), eventItem(20, t), later], 500);
    const model = ready({ window });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.rows).toHaveLength(1);
    expect(model.nearestProven).toBe(false);
    // The three entries READ, as the card above says; the two that name the event are explained by
    // the ambiguous note, and the caption says that one of them is nearer than the row it lists.
    expect(model.caption).toBe("The nearest, apart from the 2 that may be this event, of the 3 entries read");
  });

  it("never says 'of' the window's count when the rows are not proven nearest", () => {
    for (const last of [15, 20, 25, 26]) {
      expect(stoppedAt(last).caption).not.toContain("of 500");
    }
  });
});

describe("the caption counts what the card counts, never the list that left entries out", () => {
  /** The number the card's "Showing {k} of {n} entries" line names, or null when it says nothing. */
  const cardRead = (model: DetailContextReady) => {
    const match = /^Showing ([\d,]+) of ([\d,]+) entries/.exec(model.notices[0] ?? "");
    return match === null ? null : { read: Number(match[1]?.replace(/,/g, "")), of: Number(match[2]?.replace(/,/g, "")) };
  };
  const captionRead = (model: DetailContextReady) => {
    const match = /of the ([\d,]+) entries read$/.exec(model.caption ?? "");
    return match === null ? null : Number(match[1]?.replace(/,/g, ""));
  };
  const later = { ...twinOf(eventItem(20, t), rid(88)), timestampMs: t + 9_000 };
  /** The loader hands the entries over in time order; a stable sort keeps a scene honest about it. */
  const byTime = (list: TimelineItem[]) => [...list].sort((a, b) => a.timestampMs - b.timestampMs);

  it("counts the entries read, not the entries left after the ones that name an ambiguous event", () => {
    const window = stoppedWindow(record, [eventItem(19, t - 1_000), eventItem(20, t), later], 500);
    const model = ready({ window });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.notices[0]).toBe("Showing 3 of 500 entries within \u00b15 min; reading stopped at its call limit, so entries and sources may be missing.");
    expect(model.caption).toBe("The nearest, apart from the 2 that may be this event, of the 3 entries read");
    expect(model.notices).toContain(ambiguousEventNote(2, "list"));
  });

  it("counts the entries of the window the engine counted, for a window read whole", () => {
    const window = windowAround(record, [...entries(), twinOf(eventItem(20, t), rid(88))]);
    expect(window.windowItems).toBe(42);
    const model = ready({ window });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.caption).toBe("The 12 nearest, apart from the 2 that may be this event, of 42 entries within \u00b15 min");
    expect(model.notices).toContain(ambiguousEventNote(2, "list"));
  });

  it("counts a duplicate as read, and says that it repeats another entry's origin", () => {
    const read = entries().slice(0, 25);
    const window = stoppedWindow(record, [...read, read[24] as TimelineItem], 500);
    const model = ready({ window });
    expect(model.selected.status).toBe("found");
    expect(model.notices[0]).toMatch(/^Showing 26 of 500 entries/);
    // The copy of entry 25 is 5 s from the event, nearer than row 14 (6 s), and has no row of its own.
    expect(model.caption).toBe("12 nearest, counting repeats once, of the 26 entries read");
    expect(model.notices).toContain(sharedOriginNote(1));
    expect(sharedOriginNote(1)).toBe("1 entry read repeats another entry's origin and is counted once.");
  });

  it("says nothing about shared origins when no entry shares one", () => {
    expect(ready().notices).toEqual([]);
    expect(ready({ window: stoppedWindow(record, entries().slice(0, 25), 500) }).notices.join(" ")).not.toContain("origin");
  });

  it("agrees with the card on how many entries were read, in every scene where the read stopped", () => {
    const dup = entries().slice(0, 25);
    const scenes: [string, ReturnType<typeof stoppedWindow>][] = [
      ["an ambiguous event", stoppedWindow(record, [eventItem(19, t - 1_000), eventItem(20, t), later], 500)],
      ["an event the read did not reach", stoppedWindow(record, entries().slice(0, 15), 500)],
      ["a read that ends just after the event", stoppedWindow(record, entries().slice(0, 25), 500)],
      ["a duplicate", stoppedWindow(record, [...dup, dup[24] as TimelineItem], 500)],
      ["two duplicates and an ambiguous event", stoppedWindow(record, byTime([...dup, dup[24] as TimelineItem, dup[23] as TimelineItem, twinOf(eventItem(20, t), rid(88))]), 800)],
    ];
    for (const [why, window] of scenes) {
      const model = ready({ window });
      const card = cardRead(model);
      expect(card, why).not.toBeNull();
      expect(card?.read, why).toBe(window.items.length);
      expect(card?.of, why).toBe(window.windowItems);
      if (captionRead(model) !== null) expect(captionRead(model), why).toBe(card?.read);
    }
  });

  it("agrees with the engine on the window's count, in every scene where the read was whole", () => {
    const scenes: [string, ReturnType<typeof windowAround>][] = [
      ["a clear window", windowAround(record, entries())],
      ["two entries naming the event", windowAround(record, [...entries(), twinOf(eventItem(20, t), rid(88))])],
      ["a shared origin", windowAround(record, byTime([...entries(), eventItem(30, T0 + 30_000)]))],
    ];
    for (const [why, window] of scenes) {
      const model = ready({ window });
      expect(model.caption, why).toMatch(
        new RegExp(`( |^)12 nearest.* of ${(window.windowItems as number).toLocaleString()} entries within \u00b15 min$`),
      );
    }
  });
});

describe("the note about an origin that was read more than once claims only what the count proves", () => {
  const SHARED = "1 entry read repeats another entry's origin and is counted once.";
  const byTime = (list: TimelineItem[]) => [...list].sort((a, b) => a.timestampMs - b.timestampMs);
  /** What the note must never say: that the entry is in the list, or that another entry exists. */
  const OVERCLAIM = /listed|in this window|another entry of/i;

  it("is worded for the count alone, singular and plural", () => {
    expect(sharedOriginNote(1)).toBe(SHARED);
    expect(sharedOriginNote(3)).toBe("3 entries read repeat another entry's origin and are counted once.");
    expect(sharedOriginNote(1)).not.toMatch(OVERCLAIM);
    expect(sharedOriginNote(3)).not.toMatch(OVERCLAIM);
  });

  it("sits beside the absolute 'No other entries' claim without contradicting it: the copy is the event's own entry", () => {
    const window = windowAround(record, [eventItem(20, t), eventItem(20, t)]);
    expect(window.windowItems).toBe(2);
    const model = ready({ window });
    expect(model.empty).toEqual({ text: "No other entries within \u00b15 min.", absolute: true });
    expect(model.notices).toEqual([SHARED]);
    expect(model.rows.map((row) => row.id)).toEqual([rid(20)]);
    for (const text of [...model.notices, model.empty?.text ?? "", model.caption ?? ""]) {
      expect(text).not.toMatch(OVERCLAIM);
    }
  });

  it("does not say the entry is listed when its origin is outside the 12 rows", () => {
    const window = windowAround(record, byTime([...entries(), eventItem(30, T0 + 30_000)]));
    expect(window.windowItems).toBe(42);
    const model = ready({ window });
    expect(model.rows.map((row) => row.id)).not.toContain(rid(30));
    expect(model.notices).toEqual([SHARED]);
    expect(model.caption).toBe("12 nearest of 42 entries within \u00b15 min");
    for (const text of [...model.notices, model.caption ?? ""]) expect(text).not.toMatch(OVERCLAIM);
  });

  it("does not say the entry is listed when the event is unmatchable and nothing is", () => {
    const unmatchable = unnumbered(t);
    const nine = Array.from({ length: 8 }, (_, index) => eventItem(40 + index, t - 4_000 + index * 1_000));
    const window = windowAround(unmatchable, byTime([...nine, nine[3] as TimelineItem]));
    expect(window.windowItems).toBe(9);
    const model = ready({ record: unmatchable, window });
    expect(model.rows).toEqual([]);
    expect(model.notices).toEqual([SHARED, unmatchableNote(9, FIVE_MIN, "list")]);
    expect(model.notices[0]).not.toMatch(OVERCLAIM);
  });

  it("is said in the same words when the read stopped, beside the card", () => {
    const read = entries().slice(0, 25);
    const model = ready({ window: stoppedWindow(record, [...read, read[24] as TimelineItem], 500) });
    expect(model.notices.slice(0, 2)).toEqual([windowNotice(stoppedWindow(record, [...read, read[24] as TimelineItem], 500)) as string, SHARED]);
  });
});

describe("'N nearest' is literally true: the caption says when an entry set aside is nearer than a row", () => {
  const twin = (timestampMs: number) => ({ ...twinOf(eventItem(20, t), rid(88)), timestampMs });
  const byTime = (list: TimelineItem[]) => [...list].sort((a, b) => a.timestampMs - b.timestampMs);
  /** Twelve entries 1 to 12 s after the event, none of which names it. */
  const near = () => Array.from({ length: 12 }, (_, index) => eventItem(101 + index, t + (index + 1) * 1_000));

  it("says so for a window read whole, where both entries that may be the event are nearer than the rows", () => {
    const model = ready({ window: windowAround(record, [...entries(), twinOf(eventItem(20, t), rid(88))]) });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.caption).toBe("The 12 nearest, apart from the 2 that may be this event, of 42 entries within \u00b15 min");
  });

  it("says so when only one of the entries that may be the event is nearer", () => {
    // Record 20's own entry is 1 s away (nearer than the 12th row, 12 s away); the copy is 200 s away.
    const window = windowAround(record, byTime([...near(), eventItem(20, t + 500), twin(t + 200_000)]));
    const model = ready({ window });
    expect(model.selected.status).toBe("ambiguous");
    expect(model.rows).toHaveLength(12);
    expect(model.caption).toBe("The 12 nearest, apart from the 2 that may be this event, of 14 entries within \u00b15 min");
  });

  it("keeps the plain caption when both entries that may be the event are farther than every row", () => {
    const window = windowAround(record, byTime([...near(), eventItem(20, t - 200_000), twin(t + 200_000)]));
    const model = ready({ window });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.caption).toBe("12 nearest of 14 entries within \u00b15 min");
    expect(model.notices).toContain(ambiguousEventNote(2, "list"));
  });

  it("keeps the plain caption when an entry that may be the event is exactly as far as the farthest row", () => {
    // The 12th row is 12 s away; the copy is also 12 s away, a tie the order settles, not a nearer entry.
    const window = windowAround(record, byTime([...near().slice(0, 11), eventItem(112, t + 12_000), eventItem(20, t - 200_000), twin(t - 12_000)]));
    const model = ready({ window });
    expect(model.selected.status).toBe("ambiguous");
    expect(model.caption).toBe("12 nearest of 14 entries within \u00b15 min");
  });

  it("says the nearest, once, for a single row, and keeps the plain caption when the entries set aside are farther", () => {
    const farther = [eventItem(19, t - 1_000), eventItem(20, t + 5_000), twin(t + 9_000)];
    const plain = ready({ window: stoppedWindow(record, farther, 500) });
    expect(plain.rows).toHaveLength(1);
    expect(plain.caption).toBe("1 nearest of the 3 entries read");
    const nearer = ready({ window: stoppedWindow(record, [eventItem(19, t - 1_000), eventItem(20, t), twin(t + 9_000)], 500) });
    expect(nearer.caption).toBe("The nearest, apart from the 2 that may be this event, of the 3 entries read");
  });

  it("says so in the words of a read that stopped, in both forms", () => {
    const stopped = byTime([...entries(), twinOf(eventItem(20, t), rid(88))]);
    const proven = ready({ window: stoppedWindow(record, stopped, 500) });
    expect(proven.nearestProven).toBe(true);
    expect(proven.caption).toBe("The 12 nearest entries, apart from the 2 that may be this event, within \u00b15 min");
    const unproven = ready({ window: stoppedWindow(record, stopped.slice(0, 25), 500) });
    expect(unproven.nearestProven).toBe(false);
    expect(unproven.caption).toBe("The 12 nearest, apart from the 2 that may be this event, of the 25 entries read");
  });

  it("never adds the clause for an event that is not ambiguous", () => {
    expect(ready().caption).toBe("12 nearest of 41 entries within \u00b15 min");
    const without = entries().filter((item) => timelineOriginId(item.origin) !== rid(20));
    expect(ready({ window: windowAround(record, without) }).caption).toBe("12 nearest of 40 entries within \u00b15 min");
    const unmatchable = unnumbered(t);
    expect(ready({ record: unmatchable, window: windowAround(unmatchable, entries()) }).caption).toBeNull();
    expect(ready({ window: stoppedWindow(record, entries().slice(0, 15), 500) }).caption).not.toContain("apart from");
  });

  it("counts the entries the engine and the card count, with or without the clause", () => {
    const window = stoppedWindow(record, byTime([...entries(), twinOf(eventItem(20, t), rid(88))]).slice(0, 25), 500);
    const model = ready({ window });
    expect(model.notices[0]).toMatch(/^Showing 25 of 500 entries/);
    expect(model.caption).toMatch(/of the 25 entries read$/);
  });
});

describe("'N nearest' counts repeats once, and says so when a repeat is nearer than a row", () => {
  const byTime = (list: TimelineItem[]) => [...list].sort((a, b) => a.timestampMs - b.timestampMs);
  /** A second entry of the origin of entry `n`, read again at `timestampMs`. */
  const copyOf = (n: number, timestampMs: number): TimelineItem => ({ ...eventItem(n, timestampMs) });

  it("says so for the reviewer's scene: a copy of entry 25 (5 s) is nearer than row 14 (6 s)", () => {
    const read = entries().slice(0, 25);
    const model = ready({ window: stoppedWindow(record, byTime([...read, copyOf(25, T0 + 25_000)]), 500) });
    expect(model.selected.status).toBe("found");
    expect(model.nearestProven).toBe(false);
    expect(numbers(model)).toEqual([14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]);
    expect(model.notices[0]).toMatch(/^Showing 26 of 500 entries/);
    expect(model.caption).toBe("12 nearest, counting repeats once, of the 26 entries read");
  });

  it("says so for a whole window with a nearer copy, counting the copy in N", () => {
    const window = windowAround(record, byTime([...entries(), copyOf(24, T0 + 24_000)]));
    expect(window.windowItems).toBe(42);
    const model = ready({ window });
    expect(model.caption).toBe("12 nearest, counting repeats once, of 42 entries within \u00b15 min");
    expect(model.notices).toContain(sharedOriginNote(1));
  });

  it("keeps the plain caption when the copy is farther than every row", () => {
    const window = windowAround(record, byTime([...entries(), copyOf(41, T0 + 41_000)]));
    const model = ready({ window });
    expect(model.caption).toBe("12 nearest of 42 entries within \u00b15 min");
    expect(model.notices).toContain(sharedOriginNote(1));
  });

  it("keeps the plain caption when the copy is exactly as far as the farthest row", () => {
    // Row 14 is 6 s before the event; a copy of entry 26 is 6 s after it: a tie, not a nearer entry.
    const window = windowAround(record, byTime([...entries(), copyOf(26, T0 + 26_000)]));
    expect(ready({ window }).caption).toBe("12 nearest of 42 entries within \u00b15 min");
  });

  it("judges a repeat by its own time, not the time of the entry it repeats", () => {
    // Entry 1 is first read 19 s before the event; its second reading is 2 s after it: nearer than
    // the farthest row, and it is the repeat, since the first reading came first.
    const window = windowAround(record, byTime([...entries(), copyOf(1, t + 2_000)]));
    expect(ready({ window }).caption).toBe("12 nearest, counting repeats once, of 42 entries within \u00b15 min");
    // And the reverse: the entry is near, its second reading is far.
    const far = windowAround(record, byTime([...entries(), copyOf(21, t + 100_000)]));
    expect(ready({ window: far }).caption).toBe("12 nearest of 42 entries within \u00b15 min");
  });

  it("says so for a copy of the event's own entry", () => {
    const window = windowAround(record, byTime([...entries(), copyOf(20, t)]));
    const model = ready({ window });
    expect(model.selected).toEqual({ status: "found", originId: rid(20) });
    expect(model.caption).toBe("12 nearest, counting repeats once, of 42 entries within \u00b15 min");
  });

  it("makes one sentence of the ambiguous clause and the repeat clause", () => {
    const window = windowAround(record, byTime([...entries(), twinOf(eventItem(20, t), rid(88)), copyOf(24, T0 + 24_000)]));
    expect(window.windowItems).toBe(43);
    const model = ready({ window });
    expect(model.selected).toEqual({ status: "ambiguous", candidates: 2 });
    expect(model.caption).toBe(
      "The 12 nearest, apart from the 2 that may be this event and counting repeats once, of 43 entries within \u00b15 min",
    );
  });

  it("keeps each clause alone when only that one applies", () => {
    const naming = byTime([...entries(), twinOf(eventItem(20, t), rid(88)), copyOf(41, T0 + 41_000)]);
    expect(ready({ window: windowAround(record, naming) }).caption).toBe(
      "The 12 nearest, apart from the 2 that may be this event, of 43 entries within \u00b15 min",
    );
    const far = byTime([...near12(), eventItem(20, t - 200_000), { ...twinOf(eventItem(20, t), rid(88)), timestampMs: t + 200_000 }, copyOf(101, t + 250_000)]);
    expect(ready({ window: windowAround(record, far) }).caption).toBe("12 nearest of 15 entries within \u00b15 min");
  });

  it("says so in the proven form of a read that stopped", () => {
    const stopped = byTime([...entries(), copyOf(24, T0 + 24_000)]);
    const model = ready({ window: stoppedWindow(record, stopped, 500) });
    expect(model.nearestProven).toBe(true);
    expect(model.caption).toBe("12 nearest entries, counting repeats once, within \u00b15 min");
    const both = byTime([...entries(), twinOf(eventItem(20, t), rid(88)), copyOf(24, T0 + 24_000)]);
    expect(ready({ window: stoppedWindow(record, both, 500) }).caption).toBe(
      "The 12 nearest entries, apart from the 2 that may be this event and counting repeats once, within \u00b15 min",
    );
  });

  it("says nothing of repeats when there are none, and counts the note's entries as the repeats", () => {
    expect(ready().caption).toBe("12 nearest of 41 entries within \u00b15 min");
    const model = ready({ window: windowAround(record, byTime([...entries(), copyOf(24, T0 + 24_000), copyOf(24, T0 + 24_000)])) });
    expect(model.notices).toContain(sharedOriginNote(2));
  });

  function near12() {
    return Array.from({ length: 12 }, (_, index) => eventItem(101 + index, t + (index + 1) * 1_000));
  }
});

/**
 * The class test for "N nearest": over many windows, every entry the caption counts that has no row
 * is accounted for. Each is a row, the first of an origin that is ranked after the rows, an entry
 * that may be an ambiguous event, or a repeat of an origin already read; and the caption's two
 * clauses are said exactly when one of the last two is nearer than the farthest row. If a third way
 * to leave an entry out existed, "a distinct entry with no row, nearer than the farthest row" would
 * turn up here.
 */
describe("every entry counted in the caption is a row, ranked after the rows, a naming entry or a repeat", () => {
  /** mulberry32, seeded: the same windows on every run, and no two nearby seeds alike. */
  function generator(seed: number) {
    let state = seed | 0;
    return () => {
      state = (state + 0x6d2b79f5) | 0;
      let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
      mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
      return ((mixed ^ (mixed >>> 14)) >>> 0) / 2 ** 32;
    };
  }

  function sceneFor(seed: number) {
    const rand = generator(seed);
    const jitter = (spread: number) => t + Math.round((rand() * 2 - 1) * spread);
    const items: TimelineItem[] = [];
    const distinct = 1 + Math.floor(rand() * 40);
    for (let index = 0; index < distinct; index += 1) {
      items.push(rand() < 0.3 ? { ...logItem(index + 1, jitter(40_000)) } : eventItem(100 + index, jitter(40_000)));
    }
    // The event's own entry is at its instant (the engine places it at the record's epoch); a second
    // entry that names it is another record with the same fields, anywhere in the window.
    const kind = rand() < 0.4 ? "found" : rand() < 0.5 ? "ambiguous" : "absent";
    if (kind !== "absent") items.push(eventItem(20, t));
    if (kind === "ambiguous") items.push({ ...twinOf(eventItem(20, t), rid(88)), timestampMs: jitter(30_000) });
    // A repeated entry is the same record read again, so it has the same time as the one it repeats.
    const originals = [...items];
    for (let copies = Math.floor(rand() * 6); copies > 0; copies -= 1) {
      items.push({ ...(originals[Math.floor(rand() * originals.length)] as TimelineItem) });
    }
    const sorted = [...items].sort((a, b) => a.timestampMs - b.timestampMs);
    if (rand() < 0.5) return { kind, window: windowAround(record, sorted) };
    const cut = 1 + Math.floor(rand() * sorted.length);
    return { kind, window: stoppedWindow(record, sorted.slice(0, cut), sorted.length + 1 + Math.floor(rand() * 200)) };
  }

  it("holds for 400 windows, and each clause is said exactly when it is true", () => {
    const tally = { plain: 0, apart: 0, repeats: 0, both: 0, withoutCaption: 0 };
    for (let seed = 1; seed <= 400; seed += 1) {
      const { window } = sceneFor(seed);
      const model = ready({ window });
      if (model.caption === null) {
        tally.withoutCaption += 1;
        continue;
      }
      const center = window.centerMs;
      const distance = (item: TimelineItem) => Math.abs(item.timestampMs - center);
      const rowIds = new Set(model.rows.map((row) => row.id));
      const farthest = Math.max(0, ...model.rows.map((row) => Math.abs(row.offsetMs)));
      const naming = model.selected.status === "ambiguous" ? new Set([rid(20), rid(88)]) : new Set<string>();
      const seen = new Set<string>();
      let nearerOther = false;
      let nearerNaming = false;
      let nearerRepeat = false;
      for (const item of window.items) {
        const id = timelineOriginId(item.origin);
        const first = !seen.has(id);
        seen.add(id);
        if (!first) {
          if (distance(item) < farthest) nearerRepeat = true;
        } else if (rowIds.has(id)) {
          // A row.
        } else if (naming.has(id)) {
          if (distance(item) < farthest) nearerNaming = true;
        } else if (distance(item) < farthest) {
          nearerOther = true;
        }
      }
      const label = `seed ${seed}: ${model.caption}`;
      expect(nearerOther, `no third way to leave an entry out; ${label}`).toBe(false);
      if (model.nearestProven || model.complete || /nearest/.test(model.caption)) {
        expect(/apart from the \d+ that may be this event/.test(model.caption), label).toBe(nearerNaming);
        expect(/counting repeats once/.test(model.caption), label).toBe(nearerRepeat);
      }
      if (nearerNaming && nearerRepeat) tally.both += 1;
      else if (nearerNaming) tally.apart += 1;
      else if (nearerRepeat) tally.repeats += 1;
      else tally.plain += 1;
    }
    console.info(`oracle tally over 400 windows: ${JSON.stringify(tally)}`);
    // The draw reaches every case, so the checks above are not vacuous.
    expect(tally.plain).toBeGreaterThan(20);
    expect(tally.apart).toBeGreaterThan(5);
    expect(tally.repeats).toBeGreaterThan(5);
    expect(tally.both).toBeGreaterThan(0);
  });
});

describe("an empty list, and the absence claim", () => {
  const alone = () => [eventItem(20, t)];
  const empty = (extra: Partial<DetailContextInput> = {}) =>
    ready({ window: windowAround(record, alone()), ...extra }).empty;

  it("says there are no other entries only under all five conditions", () => {
    expect(empty()).toEqual(
      emptyWindowText({ halfWidthMs: FIVE_MIN, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 0, subject: "entries" }),
    );
    expect(empty()).toEqual({ text: "No other entries within ±5 min.", absolute: true });
  });

  it.each([
    ["the scope is narrowed", { counts: countsFor([], { scope: { visibleCount: 1, loadedCount: 9, textLogCount: 0 } }) }],
    ["the scope is not known", { counts: countsFor([], { scope: null }) }],
    ["a source was not fully read", { unreadSources: true }],
    ["the pair is an earlier session's", { counts: countsFor([], { updating: true }) }],
    ["the unplaced count is positive", { counts: countsFor([], { unplacedList: { items: [], total: 3 } }) }],
    ["the unplaced count is not known", { counts: countsFor([], { unplacedList: { items: [], total: null } }) }],
    ["the counts are not the window's", { counts: countsFor([], { builtFor: "session:2" }) }],
    ["there are no counts", { counts: null }],
  ] as [string, Partial<DetailContextInput>][])("qualifies it when %s", (_why, extra) => {
    const said = empty(extra);
    expect(said?.absolute).toBe(false);
    expect(said?.text).toMatch(/^No other visible entries within ±5 min\./);
  });

  it("is no claim at all for a window that was not read whole", () => {
    const model = ready({ window: stoppedWindow(record, alone(), 500) });
    expect(model.empty).toBeNull();
    expect(model.rows).toHaveLength(1);
  });

  it("is no claim when other entries exist but cannot be listed, because they could each be the event", () => {
    const twin = twinOf(eventItem(20, t), rid(88));
    expect(ready({ window: windowAround(record, [eventItem(20, t), twin]) }).empty).toBeNull();
    const unmatchable = unnumbered(t);
    expect(ready({ record: unmatchable, window: windowAround(unmatchable, [eventItem(5, t)]) }).empty).toBeNull();
  });

  it("is said for a record that is not in a window that holds nothing", () => {
    const model = ready({ window: windowAround(record, []) });
    expect(model.selected).toEqual({ status: "notInTimeline" });
    expect(model.rows).toEqual([]);
    expect(model.empty?.text).toMatch(/^No other (visible )?entries within/);
  });

  it("is not said when another entry is listed", () => {
    expect(ready().empty).toBeNull();
    expect(ready({ window: windowAround(record, [eventItem(20, t), eventItem(21, t + 1_000)]) }).empty).toBeNull();
  });
});

describe("no row, caption or note claims a relationship the evidence does not give (the class test)", () => {
  /** Every word the dock uses for an entry's relation to the event that a row here must never carry. */
  const RELATIONSHIP_WORDS =
    /not linked|no loaded link|in another chain|not in this chain|link to this event not known|ambiguous with this event|coverage blocked with this event|linked, but its link|time only[,;]/i;
  /** What no string may say unless an entry is proven unplaced; the list never proves it. */
  const NOT_PLACED = /not placed|no timeline position|without a timeline position|no timestamp/i;

  const exact = [synthetic("e", rid(20), rid(21)), synthetic("a", rid(20), rid(22), "ambiguous"), synthetic("o", rid(16), rid(17))];
  const blocked: TimelineCorrelationEdge = {
    ...synthetic("g", rid(20), rid(23)),
    coverage: { state: "gap", gap: { source: "Live", reason: "channel not collected" } },
  };
  const cases: [string, DetailContextInput][] = [
    ["a clear session", input({ counts: countsFor(exact) })],
    ["a blocked row", input({ counts: countsFor([...exact, blocked]) })],
    ["counts of another session", input({ counts: countsFor(exact, { builtFor: "session:2" }) })],
    ["no counts", input({ counts: null })],
    ["an earlier session's pair", input({ counts: countsFor(exact, { updating: true }) })],
    ["a narrowed scope", input({ counts: countsFor(exact, { scope: { visibleCount: 2, loadedCount: 9, textLogCount: 4 } }) })],
    ["a limit gap", input({ counts: countsFor(exact, { gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1) }) })],
    ["a gap naming a listed entry", input({ counts: countsFor(exact, { gaps: classifyCoverageGaps([{ source: rid(22), reason: "x" }], 1) }) })],
    ["unread sources", input({ counts: countsFor(exact), unreadSources: true })],
    ["unloaded edges", input({ counts: countsFor(exact, { totalEdges: 30 }) })],
    ["a read that stopped", input({ counts: countsFor(exact), window: stoppedWindow(record, entries().slice(0, 30), 500) })],
    ["a read that stopped before the event", input({ counts: countsFor(exact), window: stoppedWindow(record, entries().slice(0, 12), 500) })],
    ["an ambiguous event", input({ counts: countsFor(exact), window: windowAround(record, [...entries(), twinOf(eventItem(20, t), rid(88))]) })],
    ["an unmatchable event", input({ record: unnumbered(t), window: windowAround(unnumbered(t), entries()), counts: countsFor(exact) })],
    ["an event that is not in the window", input({ counts: countsFor(exact), window: windowAround(record, entries().filter((item) => timelineOriginId(item.origin) !== rid(20))) })],
    ["an empty window", input({ counts: countsFor(exact), window: windowAround(record, []) })],
    ["the event alone", input({ counts: countsFor(exact), window: windowAround(record, [eventItem(20, t)]) })],
    ["text-log rows", input({ counts: countsFor(exact), window: windowAround(record, [eventItem(20, t), logItem(4, t + 1_000), logItem(5, t - 1_000)]) })],
    ["a session being rebuilt", input({ counts: countsFor(exact), session: "building" })],
  ];

  function wordsOf(model: DetailContextModel): { rows: string[]; section: string[] } {
    if (model.kind !== "ready") return { rows: [], section: [("text" in model ? model.text : "")] };
    return {
      rows: model.rows.flatMap((row) => [row.offsetText, row.entry, row.message]),
      section: [DETAIL_CONTEXT_TITLE, DETAIL_CONTEXT_KINDS_LABEL, model.caption ?? "", model.legend ?? "", ...model.notices, model.empty?.text ?? ""],
    };
  }

  it.each(cases)("uses none of those words, in rows or anywhere else: %s", (_why, scene) => {
    const { rows, section } = wordsOf(buildDetailContext(scene));
    for (const text of [...rows, ...section]) {
      expect(text).not.toMatch(RELATIONSHIP_WORDS);
      expect(text).not.toMatch(NOT_PLACED);
    }
  });

  it("gives a row that has no edge nothing but its time, its offset, its source and its message", () => {
    const model = ready({ counts: countsFor(exact) });
    for (const row of model.rows.filter((candidate) => candidate.link === null)) {
      expect(Object.keys(row).sort()).toEqual(
        ["chip", "entry", "id", "isSelected", "kind", "link", "message", "offsetMs", "offsetText", "timestampMs"].sort(),
      );
    }
    expect(model.rows.filter((row) => row.link !== null).map((row) => row.id)).toEqual([rid(21)]);
  });

  it("uses the words of the icon only for a row with an edge", () => {
    const model = ready({ counts: countsFor(exact) });
    const withWords = model.rows.filter((row) => row.link !== null);
    expect(withWords).toHaveLength(1);
    expect(withWords[0]?.link?.name).toBe("Exact link to this event by ActivityId");
  });

  it("says its legend only when an icon is shown", () => {
    expect(ready({ counts: countsFor(exact) }).legend).toBe(LINK_LEGEND_TEXT);
    expect(ready({ counts: countsFor([]) }).legend).toBeNull();
    expect(ready({ counts: countsFor([synthetic("a", rid(20), rid(22), "ambiguous")]) }).legend).toBeNull();
  });

  it("holds the words it adds to ASCII and the middle dot and plus-minus sign, with no dash", () => {
    for (const text of [
      BUILDING_TIMELINE_TEXT,
      LINK_LEGEND_TEXT,
      LINKS_MAY_BE_MISSING_TEXT,
      TIMELINE_UPDATING_NOTE,
      NO_SESSION_TEXT,
    ]) {
      expect(text).not.toMatch(/[‒-―−]/);
      expect(text).toMatch(/^[\x20-\x7e]+$/);
    }
  });
});

describe("the model is a function of its input", () => {
  it("is the same on every build, and does not change its input", () => {
    const scene = input({ counts: countsFor([synthetic("e", rid(20), rid(21))]) });
    const before = JSON.stringify(scene.window);
    expect(buildDetailContext(scene)).toEqual(buildDetailContext(scene));
    expect(JSON.stringify(scene.window)).toBe(before);
  });

  describe("what it costs grows with the window, not with its square", () => {
    /** `n` entries over 40 channels, whose `timestampMs` and `origin` count every read. */
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
        counted(eventItem(20, t)),
        ...Array.from({ length: n - 1 }, (_, i) =>
          counted(onChannel(1_000 + i, t - 140_000 + Math.floor((i * 280_000) / n), `Chan${i % 40}`)),
        ),
      ];
    }

    function readsFor(n: number): number {
      const reads = { count: 0 };
      const items = countedItems(n, reads);
      reads.count = 0;
      const model = ready({ window: windowAround(record, items) });
      expect(model.rows).toHaveLength(12);
      return reads.count;
    }

    it("reads each entry a bounded number of times: doubling the window less than 2.6 times the reads", () => {
      const small = readsFor(3_000);
      const large = readsFor(6_000);
      // The counting works: every entry is read more than once, and the figure is not trivial.
      expect(small).toBeGreaterThan(3_000);
      // n log n doubles to about 2.2; an O(n squared) step would quadruple it. The counter sees only
      // reads of `timestampMs` and `origin`; the smoke test below is the wall-clock net for the rest.
      expect(large / small, `${small} reads at 3,000 entries, ${large} at 6,000`).toBeLessThan(2.6);
    });

    it("smoke: builds a 6,000-entry window in well under ten seconds, and logs its figure", () => {
      const items = countedItems(6_000, { count: 0 });
      const started = performance.now();
      ready({ window: windowAround(record, items) });
      const elapsed = performance.now() - started;
      console.info(`buildDetailContext, 6,000 entries over 40 channels: ${elapsed.toFixed(1)} ms`);
      expect(elapsed).toBeLessThan(10_000);
    });
  });
});
