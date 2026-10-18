/**
 * What the lane plot and the tables draw. Real engine output (`__fixtures__/correlation-edges.json`,
 * the parser crate's own reducer) drives the shapes; synthetic edges cover what the engine cannot
 * yet produce (a log-line member, a mixed Exact and Candidate chain, an edge with no evidence).
 */
import { describe, expect, it, vi } from "vitest";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import {
  buildCorrelationChains,
  type CorrelationChain,
} from "./evtx-correlation-chains";
import {
  CORRELATION_AXIS_TICKS,
  CORRELATION_MARKER_CAP,
  CORRELATION_MIN_WINDOW_MS,
  axisTicks,
  buildChainPlot,
  chainSequence,
  chainTitle,
  defaultLaneWindow,
  describeLanes,
  entriesText,
  entryLabel,
  evidenceForEdge,
  formatDelta,
  isPartialChain,
  keyHeader,
  laneKeyOf,
  levelOfSeverity,
  memberLinkSummary,
  middleTruncate,
  placeInWindow,
  reconcileSelection,
  tickLabels,
  spanText,
  whyRows,
  IN_ANOTHER_CHAIN_LABEL,
  LINK_TO_EVENT_UNKNOWN_LABEL,
  NOT_IN_THIS_CHAIN_LABEL,
  NOT_LINKED_LABEL,
  NO_LOADED_LINK_LABEL,
  UNLOADED_ENTRY,
  UNPLACED_ENTRY,
  UNTITLED_CHAIN,
  chainAccessibleName,
  isProvenUnplaced,
  listedRows,
  partitionUnplaced,
  sessionSpeaksForAbsence,
} from "./evtx-correlation-view-model";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import { TIME_RANGE_SEPARATOR } from "./evtx-time";
import {
  assertUnifiedTimelineShape,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineItem,
  type TimelineOrigin,
  type TimelineSeverity,
} from "./unified-timeline";

const rid = (n: number) => `source4:Live|machine10:DESKTOP-01|channel6:System|record${n}`;
/** Edges complete, nothing narrowed, no coverage gap: the only state in which "Not linked" may be said. */
const VIEW = { edgeInputComplete: true, narrowed: false, gaps: classifyCoverageGaps([], 0) };
/** What no string may say unless the entry is proven unplaced (the scan finished, on a complete list). */
const NO_UNPROVEN_CLAIM = /not placed|no timeline position|without a timeline position|no timestamp/i;

function fixtureEdges(name: string): TimelineCorrelationEdge[] {
  const scenarios = fixtureDocument.scenarios as unknown as Record<
    string,
    { edges: unknown[]; coverageGaps: unknown[] }
  >;
  const scenario = scenarios[name];
  if (scenario === undefined) throw new Error(`no fixture scenario ${name}`);
  return assertUnifiedTimelineShape({
    items: [],
    unplaced: [],
    edges: scenario.edges,
    coverageGaps: scenario.coverageGaps,
  }).edges;
}

function eventItem(
  n: number,
  timestampMs: number,
  severity: TimelineSeverity = "info",
  overrides: { channel?: string; source?: string; eventId?: number; message?: string } = {},
): TimelineItem {
  return {
    timestampMs,
    severity,
    message: overrides.message ?? `message ${n}`,
    origin: {
      kind: "event",
      stableId: rid(n),
      source: overrides.source ?? "Live",
      machine: "DESKTOP-01",
      bundle: null,
      channel: overrides.channel ?? "System",
      provider: "P",
      processId: null,
      eventId: overrides.eventId ?? 100 + n,
      recordId: n,
    },
  };
}

function logItem(
  file: string,
  line: number,
  timestampMs: number,
  source = "writer.cpp",
  severity: TimelineSeverity = "info",
): TimelineItem {
  return {
    timestampMs,
    severity,
    message: `log line ${line}`,
    origin: {
      kind: "log",
      file,
      component: null,
      line,
      source,
      machine: null,
      bundle: null,
      recordId: line,
    },
  };
}

const mapOf = (items: TimelineItem[]) =>
  new Map(items.map((item) => [timelineOriginId(item.origin), item]));

function synthetic(
  id: string,
  fromId: string,
  toId: string,
  strength: TimelineCorrelationEdge["strength"] = "exact",
  overrides: Partial<TimelineCorrelationEdge> = {},
): TimelineCorrelationEdge {
  return {
    id,
    fromId,
    toId,
    key: { kind: "activityId", value: `key-${id}` },
    strength,
    confidence: "high",
    candidateIds: [],
    evidence: [
      { originId: fromId, field: "activityId", value: `key-${id}` },
      { originId: toId, field: "activityId", value: `key-${id}` },
    ],
    coverage: { state: "covered" },
    ...overrides,
  };
}

function chainOf(
  edges: TimelineCorrelationEdge[],
  items: TimelineItem[],
  index = 0,
): CorrelationChain {
  const model = buildCorrelationChains({
    items,
    timelineEdges: edges,
    totalTimelineEdges: edges.length,
    findings: [],
  });
  const chain = model.chains[index];
  if (chain === undefined) throw new Error("no chain");
  return chain;
}

describe("defaultLaneWindow (spec 8.11: padded 25% on each side, at least 10 s)", () => {
  it("pads the span by a quarter of it on each side", () => {
    expect(defaultLaneWindow(100_000, 200_000)).toEqual({ startMs: 75_000, endMs: 225_000 });
  });

  it("is 10 s wide and centred on a span that is shorter or a single instant", () => {
    expect(defaultLaneWindow(100_000, 102_000)).toEqual({ startMs: 96_000, endMs: 106_000 });
    expect(defaultLaneWindow(50_000, 50_000)).toEqual({ startMs: 45_000, endMs: 55_000 });
    const window = defaultLaneWindow(0, 1)!;
    expect(window.endMs - window.startMs).toBe(CORRELATION_MIN_WINDOW_MS);
  });

  it("stops padding to the minimum exactly where 25% each side reaches 10 s", () => {
    // A 6.667 s span padded to 10 s: just over is padded 25% a side, just under takes the minimum.
    const wide = defaultLaneWindow(0, 7_000)!;
    expect(wide.endMs - wide.startMs).toBe(10_500);
    const narrow = defaultLaneWindow(0, 6_000)!;
    expect(narrow.endMs - narrow.startMs).toBe(10_000);
  });

  it("is null with no placed member", () => {
    expect(defaultLaneWindow(null, null)).toBeNull();
    expect(defaultLaneWindow(5, null)).toBeNull();
  });
});

describe("placeInWindow", () => {
  const window = { startMs: 1_000, endMs: 11_000 };

  it("places a time inside across 0 to 1, the two edges included", () => {
    expect(placeInWindow(6_000, window)).toEqual({ x: 0.5, pinned: null, outsideMs: 0 });
    expect(placeInWindow(1_000, window)).toEqual({ x: 0, pinned: null, outsideMs: 0 });
    expect(placeInWindow(11_000, window)).toEqual({ x: 1, pinned: null, outsideMs: 0 });
  });

  it("pins a time outside to the nearer edge and says how far outside it is", () => {
    expect(placeInWindow(400, window)).toEqual({ x: 0, pinned: "before", outsideMs: 600 });
    expect(placeInWindow(11_001, window)).toEqual({ x: 1, pinned: "after", outsideMs: 1 });
  });
});

describe("axisTicks", () => {
  it("gives five evenly spaced ticks, the ends included", () => {
    expect(axisTicks({ startMs: 0, endMs: 8_000 })).toEqual([0, 2_000, 4_000, 6_000, 8_000]);
    expect(CORRELATION_AXIS_TICKS).toBe(5);
  });
});

describe("tickLabels (R9)", () => {
  const NOW = Date.UTC(2026, 9, 16, 12, 0, 0);
  const at = (day: number, h: number, m: number, sec = 0, year = 2026, month = 9) =>
    Date.UTC(year, month, day, h, m, sec);

  it("is the clock alone, with seconds, when the ticks are under a minute apart", () => {
    const labels = tickLabels(axisTicks({ startMs: at(6, 10, 20, 0), endMs: at(6, 10, 20, 10) }), "utc", { nowMs: NOW });
    expect(labels).toEqual(["10:20:00", "10:20:02", "10:20:05", "10:20:07", "10:20:10"]);
  });

  it("drops the seconds when the ticks are a minute or more apart, unless asked to keep them", () => {
    const ticks = axisTicks({ startMs: at(6, 10, 0), endMs: at(6, 12, 0) });
    expect(tickLabels(ticks, "utc", { nowMs: NOW })).toEqual(["10:00", "10:30", "11:00", "11:30", "12:00"]);
    expect(tickLabels(ticks, "utc", { nowMs: NOW, withSeconds: true })[1]).toBe("10:30:00");
    expect(tickLabels([at(6, 10, 0, 5), at(6, 10, 0, 35)], "utc", { nowMs: NOW, withSeconds: false })).toEqual([
      "10:00",
      "10:00",
    ]);
  });

  it("names the day on every tick once the ticks cross midnight", () => {
    const ticks = axisTicks({ startMs: at(6, 23, 59, 50), endMs: at(7, 0, 0, 10) });
    expect(tickLabels(ticks, "utc", { nowMs: NOW })).toEqual([
      "Oct 6 23:59:50",
      "Oct 6 23:59:55",
      "Oct 7 00:00:00",
      "Oct 7 00:00:05",
      "Oct 7 00:00:10",
    ]);
  });

  it("never gives two ticks of a multi-day window the same label", () => {
    const ticks = axisTicks({ startMs: at(6, 10, 0), endMs: at(8, 10, 0) });
    const labels = tickLabels(ticks, "utc", { nowMs: NOW });
    expect(labels).toEqual(["Oct 6 10:00", "Oct 6 22:00", "Oct 7 10:00", "Oct 7 22:00", "Oct 8 10:00"]);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("names the year when the ticks are not in the current year, even inside one day", () => {
    const ticks = axisTicks({ startMs: at(6, 10, 20, 0), endMs: at(6, 10, 20, 10) });
    expect(tickLabels(ticks, "utc", { nowMs: Date.UTC(2027, 1, 1) })[0]).toBe("Oct 6 2026 10:20:00");
  });

  it("names the year across a year boundary", () => {
    const ticks = axisTicks({ startMs: at(31, 23, 59, 50, 2026, 11), endMs: at(1, 0, 0, 10, 2027, 0) });
    expect(tickLabels(ticks, "utc", { nowMs: Date.UTC(2027, 0, 15) })).toEqual([
      "Dec 31 2026 23:59:50",
      "Dec 31 2026 23:59:55",
      "Jan 1 2027 00:00:00",
      "Jan 1 2027 00:00:05",
      "Jan 1 2027 00:00:10",
    ]);
  });

  it("reads the real clock for the year rule unless one is given", () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.UTC(2027, 1, 1));
      expect(tickLabels([at(6, 10, 20, 0), at(6, 10, 20, 10)], "utc")[0]).toBe("Oct 6 2026 10:20:00");
      vi.setSystemTime(Date.UTC(2026, 9, 16));
      expect(tickLabels([at(6, 10, 20, 0), at(6, 10, 20, 10)], "utc")[0]).toBe("10:20:00");
    } finally {
      vi.useRealTimers();
    }
  });

  it("has no label for no tick, and one clock for one tick", () => {
    expect(tickLabels([], "utc", { nowMs: NOW })).toEqual([]);
    expect(tickLabels([at(6, 10, 20, 5)], "utc", { nowMs: NOW })).toEqual(["10:20"]);
  });
});

describe("formatDelta", () => {
  it.each([
    [0, "0 ms"],
    [850, "850 ms"],
    [3_300, "3.3 s"],
    [5_000, "5 s"],
    [59_940, "59.9 s"],
    [60_000, "1 min"],
    [125_000, "2 min 5 s"],
    [3_600_000, "1 h"],
    [3_840_000, "1 h 4 min"],
    [86_400_000, "1 d"],
    [97_200_000, "1 d 3 h"],
    [-3_300, "3.3 s"],
  ])("formats %d ms as %s", (ms, text) => {
    expect(formatDelta(ms)).toBe(text);
  });
});

describe("spanText", () => {
  it("writes HH:mm:ss, the spec's separator, HH:mm:ss, in the chosen zone", () => {
    const start = Date.UTC(2026, 9, 6, 10, 20, 5);
    const end = Date.UTC(2026, 9, 6, 10, 20, 11);
    expect(spanText(start, end, "utc")).toBe(`10:20:05${TIME_RANGE_SEPARATOR}10:20:11`);
  });

  it("is null, not a made-up time, with no placed member", () => {
    expect(spanText(null, null, "utc")).toBeNull();
  });
});

describe("lanes", () => {
  const event = (channel: string, source = "Live") => eventItem(1, 0, "info", { channel, source }).origin;

  it("keys a log lane by FILE, never by source", () => {
    const sameSourceTwoFiles = [
      logItem("C:\\Logs\\a.log", 1, 0, "ccmutillib.cpp").origin,
      logItem("C:\\Logs\\b.log", 1, 0, "ccmutillib.cpp").origin,
    ];
    expect(describeLanes(sameSourceTwoFiles)).toHaveLength(2);
    const oneFileTwoSources = [
      logItem("C:\\Logs\\a.log", 1, 0, "one.cpp").origin,
      logItem("C:\\Logs\\a.log", 2, 0, "two.cpp").origin,
    ];
    expect(describeLanes(oneFileTwoSources)).toHaveLength(1);
    expect(laneKeyOf(oneFileTwoSources[0]!)).toBe(laneKeyOf(oneFileTwoSources[1]!));
  });

  it("keys an event lane by source and channel", () => {
    expect(laneKeyOf(event("System", "a.evtx"))).not.toBe(laneKeyOf(event("System", "b.evtx")));
    expect(laneKeyOf(event("System", "a.evtx"))).not.toBe(laneKeyOf(event("Application", "a.evtx")));
    expect(laneKeyOf(event("System", "a.evtx"))).toBe(laneKeyOf(event("System", "a.evtx")));
  });

  it("names an event lane by its channel and a log lane by the basename of its file", () => {
    const lanes = describeLanes([
      event("System"),
      logItem("C:\\Windows\\CCM\\Logs\\AppEnforce.log", 1, 0).origin,
    ]);
    expect(lanes.map((lane) => lane.label)).toEqual(["System", "AppEnforce.log"]);
    expect(lanes.map((lane) => lane.kind)).toEqual(["event", "log"]);
  });

  it("adds the source only when two event lanes share a channel, and the whole source when that is not enough", () => {
    const apart = describeLanes([event("System", "C:\\a\\x.evtx"), event("System", "C:\\b\\y.evtx")]);
    expect(apart.map((lane) => lane.label)).toEqual(["System (x.evtx)", "System (y.evtx)"]);
    const same = describeLanes([event("System", "C:\\a\\x.evtx"), event("System", "C:\\b\\x.evtx")]);
    expect(same.map((lane) => lane.label)).toEqual([
      "System (C:\\a\\x.evtx)",
      "System (C:\\b\\x.evtx)",
    ]);
    expect(describeLanes([event("System", "a"), event("Application", "a")]).map((l) => l.label)).toEqual([
      "Application",
      "System",
    ]);
  });

  it("adds the parent folder only when two log files share a basename, and the whole path when that is not enough", () => {
    const folders = describeLanes([
      logItem("C:\\One\\ime.log", 1, 0).origin,
      logItem("C:\\Two\\ime.log", 1, 0).origin,
    ]);
    expect(folders.map((lane) => lane.label)).toEqual(["One/ime.log", "Two/ime.log"]);
    const deep = describeLanes([
      logItem("C:\\a\\Logs\\ime.log", 1, 0).origin,
      logItem("C:\\b\\Logs\\ime.log", 1, 0).origin,
    ]);
    expect(deep.map((lane) => lane.label)).toEqual(["C:\\a\\Logs\\ime.log", "C:\\b\\Logs\\ime.log"]);
    expect(describeLanes([logItem("C:\\One\\ime.log", 1, 0).origin]).map((l) => l.label)).toEqual([
      "ime.log",
    ]);
  });

  it("orders event lanes by channel, then log lanes by path, whatever the input order", () => {
    const origins: TimelineOrigin[] = [
      logItem("C:\\z.log", 1, 0).origin,
      event("System"),
      logItem("C:\\a.log", 1, 0).origin,
      event("Application"),
    ];
    const forward = describeLanes(origins).map((lane) => lane.label);
    expect(forward).toEqual(["Application", "System", "a.log", "z.log"]);
    expect(describeLanes([...origins].reverse()).map((lane) => lane.label)).toEqual(forward);
  });

  it("carries the full name in the detail, not in the label", () => {
    const [lane] = describeLanes([logItem("C:\\Windows\\CCM\\Logs\\AppEnforce.log", 1, 0).origin]);
    expect(lane?.detail).toBe("C:\\Windows\\CCM\\Logs\\AppEnforce.log");
  });
});

describe("entryLabel", () => {
  it("reads {eventId} and the channel for an event", () => {
    expect(entryLabel(eventItem(1, 0, "info", { eventId: 76, channel: "Admin" }), undefined)).toBe(
      "76 · Admin",
    );
  });

  it("reads the file and line for a log line, not the source", () => {
    const item = logItem("C:\\Logs\\AppEnforce.log", 42, 0, "ccmutillib.cpp");
    const [lane] = describeLanes([item.origin]);
    expect(entryLabel(item, lane)).toBe("AppEnforce.log · line 42");
    expect(entryLabel(item, undefined)).toBe("AppEnforce.log · line 42");
  });
});

describe("levelOfSeverity", () => {
  it("maps all five severities to their level", () => {
    expect(
      (["verbose", "info", "warning", "error", "critical"] as const).map(levelOfSeverity),
    ).toEqual(["Verbose", "Information", "Warning", "Error", "Critical"]);
  });
});

describe("evidenceForEdge", () => {
  const evidence = [
    { originId: "a", field: "activityId", value: "x" },
    { originId: "b", field: "relatedActivityId", value: "x" },
    { originId: "b", field: "sessionId", value: "y" },
    { originId: "c", field: "sessionId", value: "y" },
    { originId: "z", field: "activityId", value: "x" },
    { originId: "a", field: "sessionId", value: "x" },
  ];

  it("takes the rows of the edge's two endpoints for a key the edge carries", () => {
    const rows = evidenceForEdge(
      { evidence },
      { left: "a", right: "b", keys: [{ kind: "activityId", value: "x" }] },
    );
    expect(rows).toEqual([evidence[0], evidence[1]]);
  });

  it("reads the related-activity alias as the activity id, as the engine does", () => {
    const rows = evidenceForEdge(
      { evidence: [evidence[1]!] },
      { left: "a", right: "b", keys: [{ kind: "activityId", value: "x" }] },
    );
    expect(rows).toHaveLength(1);
  });

  it("leaves out another edge's row on a shared endpoint, a third entry's row, and a different key kind with the same value", () => {
    const rows = evidenceForEdge(
      { evidence },
      { left: "a", right: "b", keys: [{ kind: "activityId", value: "x" }] },
    );
    expect(rows).not.toContain(evidence[2]); // b's sessionId=y belongs to the edge b-c
    expect(rows).not.toContain(evidence[4]); // z is no endpoint
    expect(rows).not.toContain(evidence[5]); // sessionId=x is not the activityId key
  });

  it("is empty for an edge with no second endpoint", () => {
    expect(
      evidenceForEdge({ evidence }, { left: "a", right: null, keys: [{ kind: "activityId", value: "x" }] }),
    ).toEqual([]);
  });
});

describe("buildChainPlot", () => {
  const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);

  it("draws a real exact pair as two markers on one lane joined by one exact connector backed by evidence", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.members.map((m) => m.id)).toEqual([rid(1), rid(2)]);
    expect(plot.lanes).toHaveLength(1);
    expect(plot.connectors).toHaveLength(1);
    const connector = plot.connectors[0]!;
    expect(connector).toMatchObject({ left: rid(1), right: rid(2), strength: "exact" });
    expect(connector.evidence.map((row) => row.originId).sort()).toEqual([rid(1), rid(2)]);
    expect(plot.undrawnEdges).toEqual([]);
    expect(plot.membersWithoutItem).toBe(0);
    expect(plot.showsNotLinkedLegend).toBe(false);
  });

  it("styles each connector by its own edge's strength, not the chain's", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000), eventItem(3, T0 + 2_000)];
    const edges = [
      synthetic("e1", rid(1), rid(2), "exact"),
      synthetic("e2", rid(2), rid(3), "candidate"),
    ];
    const chain = chainOf(edges, items);
    expect(chain.strength).toBe("candidate");
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.connectors.map((c) => `${c.left}>${c.right}:${c.strength}`)).toEqual([
      `${rid(1)}>${rid(2)}:exact`,
      `${rid(2)}>${rid(3)}:candidate`,
    ]);
  });

  it("draws a real candidate pair with a candidate connector", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000)];
    const chain = chainOf(fixtureEdges("secondaryPair"), items);
    expect(chain.strength).toBe("candidate");
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.connectors.map((c) => c.strength)).toEqual(["candidate"]);
    expect(plot.connectors[0]!.evidence.length).toBeGreaterThan(0);
  });

  it("never draws a connector for an ambiguous group, whatever its edges say", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000), eventItem(3, T0 + 2_000)];
    const chain = chainOf(fixtureEdges("group3"), items);
    expect(chain.strength).toBe("ambiguous");
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.members).toHaveLength(3);
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges).toEqual([]);
  });

  it("never draws a connector for a coverage blocked row", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000)];
    const chain = chainOf(fixtureEdges("gappedPair"), items);
    expect(chain.strength).toBe("coverageBlocked");
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.members).toHaveLength(2);
    expect(plot.connectors).toEqual([]);
  });

  it("does not draw an exact edge that has no evidence row, and says so", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000)];
    const chain = chainOf([synthetic("e1", rid(1), rid(2), "exact", { evidence: [] })], items);
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges).toEqual([
      { left: rid(1), right: rid(2), strength: "exact", reason: "noEvidence" },
    ]);
  });

  it("does not draw an edge whose only evidence is for a different key or another entry", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000), eventItem(3, T0 + 2_000)];
    const chain = chainOf(
      [
        synthetic("e1", rid(1), rid(2), "exact", {
          evidence: [
            { originId: rid(3), field: "activityId", value: "key-e1" },
            { originId: rid(1), field: "sessionId", value: "other" },
          ],
        }),
      ],
      items,
    );
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges[0]?.reason).toBe("noEvidence");
  });

  it("gives a member with no item no position and no connector, and counts it", () => {
    const items = [eventItem(1, T0)];
    const chain = chainOf([synthetic("e1", rid(1), rid(2), "exact")], items);
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    expect(plot.members.map((m) => m.id)).toEqual([rid(1)]);
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges).toEqual([
      { left: rid(1), right: rid(2), strength: "exact", reason: "endpointWithoutItem" },
    ]);
    expect(plot.membersWithoutItem).toBe(1);
  });

  it("draws an empty plot, with the members counted, when no member is placed", () => {
    const chain = chainOf(fixtureEdges("exactPair"), []);
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: new Map() });
    expect(plot.window).toBeNull();
    expect(plot.members).toEqual([]);
    expect(plot.lanes).toEqual([]);
    expect(plot.ticks).toEqual([]);
    expect(plot.membersWithoutItem).toBe(2);
    expect(plot.omittedMarkers).toBe(0);
  });

  it("pins a member outside the window to the edge with a label that says how far outside", () => {
    const items = [eventItem(1, T0, "info", { eventId: 76 }), eventItem(2, T0 + 60_000, "info", { eventId: 72 })];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const window = { startMs: T0 + 3_000, endMs: T0 + 50_000 };
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items), window });
    const [before, after] = plot.members;
    expect(before).toMatchObject({ id: rid(1) });
    expect(before!.placement).toEqual({ x: 0, pinned: "before", outsideMs: 3_000 });
    expect(before!.pinLabel).toBe("76 · 3 s earlier");
    expect(after!.placement).toEqual({ x: 1, pinned: "after", outsideMs: 10_000 });
    expect(after!.pinLabel).toBe("72 · 10 s later");
    // A pinned member is still a member and still joined: nothing is dropped for being outside.
    expect(plot.connectors).toHaveLength(1);
  });

  it("gives an inside member no pin label", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const plot = buildChainPlot({ ...VIEW, chain: chainOf(fixtureEdges("exactPair"), items), itemsById: mapOf(items) });
    for (const marker of plot.members) {
      expect(marker.pinLabel).toBeNull();
      expect(marker.placement.pinned).toBeNull();
    }
  });

  it("uses the default window and its five ticks", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 100_000)];
    const plot = buildChainPlot({ ...VIEW, chain: chainOf(fixtureEdges("exactPair"), items), itemsById: mapOf(items) });
    expect(plot.window).toEqual({ startMs: T0 - 25_000, endMs: T0 + 125_000 });
    expect(plot.ticks).toHaveLength(5);
    expect(plot.ticks[0]).toBe(T0 - 25_000);
    expect(plot.ticks[4]).toBe(T0 + 125_000);
  });

  describe("caps never hide a count", () => {
    const manyMembers = (count: number) => {
      const items = Array.from({ length: count }, (_, i) => eventItem(i + 1, T0 + i * 1_000));
      const edges = Array.from({ length: count - 1 }, (_, i) =>
        synthetic(`e${i}`, rid(i + 1), rid(i + 2), "exact"),
      );
      return { items, chain: chainOf(edges, items) };
    };

    it("draws the first markers in time order and counts the rest", () => {
      const { items, chain } = manyMembers(CORRELATION_MARKER_CAP + 30);
      const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
      expect(plot.members).toHaveLength(CORRELATION_MARKER_CAP);
      expect(plot.omittedMarkers).toBe(30);
      expect(plot.members.map((m) => m.sequenceIndex)).toEqual(
        Array.from({ length: CORRELATION_MARKER_CAP }, (_, i) => i),
      );
    });

    it("does not draw a connector to a marker the cap left out, and reports why", () => {
      const { items, chain } = manyMembers(5);
      const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items), markerCap: 3 });
      expect(plot.members).toHaveLength(3);
      expect(plot.connectors).toHaveLength(2);
      expect(plot.undrawnEdges.map((edge) => edge.reason)).toEqual(["beyondMarkerCap", "beyondMarkerCap"]);
    });

    it("counts the connectors the connector cap left out", () => {
      const { items, chain } = manyMembers(6);
      const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items), connectorCap: 2 });
      expect(plot.connectors).toHaveLength(2);
      expect(plot.omittedConnectors).toBe(3);
    });
  });

  describe("the not-linked seam (decision A on #838)", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const chain = () => chainOf(fixtureEdges("exactPair"), items);
    const stray = eventItem(9, T0 + 3_000, "warning");

    it("draws nothing extra when given none, which is what production passes", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [] });
      expect(plot.nearby).toEqual([]);
      expect(plot.showsNotLinkedLegend).toBe(false);
      expect(buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items) }).nearby).toEqual([]);
    });

    it("draws a context entry as a marker with no connector, kept apart from the members, and shows the legend", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray] });
      expect(plot.nearby).toHaveLength(1);
      expect(plot.nearby[0]).toMatchObject({ id: rid(9), role: "nearby", sequenceIndex: null });
      expect(plot.members.map((m) => m.role)).toEqual(["member", "member"]);
      expect(plot.members.some((m) => m.id === rid(9))).toBe(false);
      for (const connector of plot.connectors) {
        expect([connector.left, connector.right]).not.toContain(rid(9));
      }
      expect(plot.connectors).toHaveLength(1);
      expect(plot.showsNotLinkedLegend).toBe(true);
    });

    it("counts a context entry in no member, connector or chain figure", () => {
      const withContext = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray] });
      const without = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items) });
      expect(withContext.members).toEqual(without.members);
      expect(withContext.connectors).toEqual(without.connectors);
      expect(withContext.membersWithoutItem).toBe(without.membersWithoutItem);
    });

    it("never draws a member twice, and never marks one as not linked", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [items[0]!, stray] });
      expect(plot.nearby.map((m) => m.id)).toEqual([rid(9)]);
    });

    it("puts a context entry on its own lane and counts the ones past the cap", () => {
      const other = eventItem(8, T0 + 2_000, "info", { channel: "Application" });
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, other], markerCap: 1 });
      expect(plot.omittedNearby).toBe(1);
      const plotAll = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, other] });
      expect(plotAll.lanes.map((lane) => lane.label)).toEqual(["Application", "System"]);
    });

    it.each([
      ["edges and events are all there", { edgeInputComplete: true, narrowed: false }, NOT_LINKED_LABEL],
      ["edges were not all loaded", { edgeInputComplete: false, narrowed: false }, NO_LOADED_LINK_LABEL],
      ["the view is narrowed", { edgeInputComplete: true, narrowed: true }, NO_LOADED_LINK_LABEL],
      ["both", { edgeInputComplete: false, narrowed: true }, NO_LOADED_LINK_LABEL],
    ])("labels a context marker and the legend by what is known: %s", (_why, state, label) => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], ...state });
      expect(plot.nearby[0]?.linkLabel).toBe(label);
      expect(plot.notLinkedLabel).toBe(label);
      expect(plot.showsNotLinkedLegend).toBe(true);
      // The label changes the words and nothing else: still no connector, still not a member.
      expect(plot.connectors).toHaveLength(1);
      expect(plot.members.map((m) => m.linkLabel)).toEqual([null, null]);
    });

    describe("needs the engine's correlation gaps to allow it (J1)", () => {
      const gapped = (gaps: ReturnType<typeof classifyCoverageGaps>, nearby = [stray]) =>
        buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby, gaps });
      const originGap = (id: string) => ({
        source: id,
        reason: "exact UserId identity group exceeds the 256-member correlation limit",
      });

      it.each([
        ["the correlation input limit", [{ source: "timeline-correlation-projection", reason: "limit" }], 1],
        ["the reducer's truncation", [{ source: "correlation", reason: "edge budget" }], 1],
        [
          "the transport projection that omitted identity fields (L1)",
          [{ source: "timeline-transport-projection", reason: "omitted identity or derived fields may limit correlation" }],
          1,
        ],
        [
          "records whose malformed EventRecordID had every identity key stripped (L1)",
          [{ source: "event-record-identity", reason: "1 event record was excluded from diagnosis" }],
          1,
        ],
        ["a gap preview that does not show every gap", [originGap(rid(70))], 40],
        ["a gap count that is not known", [], null],
      ])("reads 'No loaded link' for every marker and the legend under %s", (_why, preview, total) => {
        const plot = gapped(classifyCoverageGaps(preview, total));
        expect(plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
        expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
        expect(plot.showsNotLinkedLegend).toBe(true);
      });

      it("withdraws 'Not linked' for the marker a gap names, and for the legend that stands for it", () => {
        const named = eventItem(8, T0 + 2_000);
        const plot = gapped(classifyCoverageGaps([originGap(rid(9))], 1), [stray, named]);
        expect(plot.nearby.map((m) => [m.id, m.linkLabel])).toEqual([
          [rid(8), NOT_LINKED_LABEL],
          [rid(9), NO_LOADED_LINK_LABEL],
        ]);
        expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
      });

      it("keeps 'Not linked' for a marker no gap names", () => {
        const plot = gapped(classifyCoverageGaps([originGap(rid(70))], 1));
        expect(plot.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
        expect(plot.notLinkedLabel).toBe(NOT_LINKED_LABEL);
      });

      describe("a gap that names a chain member (L2)", () => {
        // An identity alias conflict is about ONE observation: the engine pushes no ActivityId key
        // for that member, so the key it would share with a context entry was never computed.
        const aliasConflict = (id: string) => ({
          source: id,
          reason: "conflicting explicit identity aliases for ActivityId",
        });

        it("withdraws 'Not linked' for a context marker that has no gap of its own, and for the legend", () => {
          const plot = gapped(classifyCoverageGaps([aliasConflict(rid(1))], 1));
          expect(plot.nearby.map((m) => [m.id, m.linkLabel])).toEqual([[rid(9), NO_LOADED_LINK_LABEL]]);
          expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
          expect(plot.showsNotLinkedLegend).toBe(true);
        });

        it("withdraws it for every context marker, not only the first", () => {
          const other = eventItem(8, T0 + 2_000);
          const plot = gapped(classifyCoverageGaps([aliasConflict(rid(2))], 1), [stray, other]);
          expect(plot.nearby.map((m) => m.linkLabel)).toEqual([NO_LOADED_LINK_LABEL, NO_LOADED_LINK_LABEL]);
          expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
        });

        it("withdraws it for a member beyond the marker cap: the key is lost whether or not the member is drawn", () => {
          const plot = buildChainPlot({
            ...VIEW,
            chain: chain(),
            itemsById: mapOf(items),
            nearby: [stray],
            markerCap: 1,
            gaps: classifyCoverageGaps([aliasConflict(rid(2))], 1),
          });
          expect(plot.members.map((m) => m.id)).toEqual([rid(1)]);
          expect(plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
          expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
        });

        it("withdraws it for a member with no loaded item, which is never drawn", () => {
          const partial = chainOf(fixtureEdges("exactPair"), [items[0]!]);
          expect(partial.unresolvedMemberIds).toEqual([rid(2)]);
          const plot = buildChainPlot({
            ...VIEW,
            chain: partial,
            itemsById: mapOf([items[0]!]),
            nearby: [stray],
            gaps: classifyCoverageGaps([aliasConflict(rid(2))], 1),
          });
          expect(plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
          expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
        });

        it("gives the legend the same words when no member can be placed", () => {
          const bare = chainOf(fixtureEdges("exactPair"), []);
          const plot = buildChainPlot({
            ...VIEW,
            chain: bare,
            itemsById: new Map(),
            gaps: classifyCoverageGaps([aliasConflict(rid(1))], 1),
          });
          expect(plot.window).toBeNull();
          expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
        });

        it("leaves 'Not linked' alone when the gap names an origin that is neither a member nor a marker", () => {
          const plot = gapped(classifyCoverageGaps([aliasConflict(rid(70))], 1));
          expect(plot.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
          expect(plot.notLinkedLabel).toBe(NOT_LINKED_LABEL);
        });
      });

      it("lets list-view compaction gaps pass", () => {
        const plot = gapped(
          classifyCoverageGaps(
            [
              { source: "timeline-item-projection", reason: "a" },
              { source: "timeline-message-projection", reason: "b" },
            ],
            2,
          ),
        );
        expect(plot.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
      });

      it("gives the same words for a chain with no placed member, where nothing can be drawn", () => {
        const bare = chainOf(fixtureEdges("exactPair"), []);
        const clear = buildChainPlot({ ...VIEW, chain: bare, itemsById: new Map() });
        expect(clear.window).toBeNull();
        expect(clear.notLinkedLabel).toBe(NOT_LINKED_LABEL);
        const cut = buildChainPlot({
          ...VIEW,
          chain: bare,
          itemsById: new Map(),
          gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1),
        });
        expect(cut.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
      });

      it("takes the words from the legend even when no marker is drawn", () => {
        const none = gapped(classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1), []);
        expect(none.showsNotLinkedLegend).toBe(false);
        expect(none.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
      });
    });

    it("gives the legend its words even when no marker is drawn, and never reads Not linked on an unknown state", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), edgeInputComplete: false });
      expect(plot.showsNotLinkedLegend).toBe(false);
      expect(plot.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
      expect(NO_LOADED_LINK_LABEL).not.toBe(NOT_LINKED_LABEL);
    });

    it("draws the same whatever order the context entries arrive in", () => {
      const a = eventItem(8, T0 + 2_000);
      const forward = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [a, stray] });
      const reversed = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, a] });
      expect(forward).toEqual(reversed);
    });
  });

  describe("a context entry that is linked elsewhere (#842, ruling 2)", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const chain = () => chainOf(fixtureEdges("exactPair"), items);
    const stray = eventItem(9, T0 + 3_000, "warning");
    const plain = eventItem(8, T0 + 2_000);
    const partners = (...ids: [number, number][]) => new Map(ids.map(([n, count]) => [rid(n), count]));

    it("calls it In another chain, never Not linked, even when every edge is loaded and nothing is narrowed", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners([9, 1]) });
      expect(plot.nearby[0]?.linkLabel).toBe(IN_ANOTHER_CHAIN_LABEL);
      expect(plot.nearby[0]?.linkLabel).not.toBe(NOT_LINKED_LABEL);
    });

    it("says so whatever else is incomplete: a loaded partner is a fact", () => {
      for (const state of [
        { edgeInputComplete: false, narrowed: false },
        { edgeInputComplete: true, narrowed: true },
        { edgeInputComplete: false, narrowed: true, gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1) },
        { edgeInputComplete: true, narrowed: false, gaps: classifyCoverageGaps([{ source: rid(9), reason: "x" }], 1) },
      ]) {
        const plot = buildChainPlot({ ...VIEW, ...state, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners([9, 3]) });
        expect(plot.nearby[0]?.linkLabel).toBe(IN_ANOTHER_CHAIN_LABEL);
      }
    });

    it("leaves an entry with no partner on the old rule, and a count of 0 is no partner", () => {
      const clear = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [plain], linkPartners: partners([9, 1]) });
      expect(clear.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
      const zero = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners([9, 0]) });
      expect(zero.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
      const unknown = buildChainPlot({ ...VIEW, edgeInputComplete: false, chain: chain(), itemsById: mapOf(items), nearby: [plain], linkPartners: partners([9, 1]) });
      expect(unknown.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
    });

    it("is exactly the old behavior when no partner map is given", () => {
      const withNone = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, plain] });
      const withEmpty = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, plain], linkPartners: new Map() });
      expect(withEmpty).toEqual(withNone);
      expect(withNone.nearby.map((m) => m.linkLabel)).toEqual([NOT_LINKED_LABEL, NOT_LINKED_LABEL]);
    });

    it("keeps the dotted marker, no connector and no membership for it", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners([9, 2]) });
      expect(plot.nearby[0]).toMatchObject({ role: "nearby", sequenceIndex: null });
      expect(plot.connectors).toHaveLength(1);
      expect(plot.members.map((m) => m.id)).toEqual([rid(1), rid(2)]);
    });

    describe("the legend's one word for the dotted marker", () => {
      it("drops to Not in this chain when any marker is linked elsewhere, and says nothing stronger", () => {
        const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, plain], linkPartners: partners([9, 1]) });
        expect(plot.notLinkedLabel).toBe(NOT_IN_THIS_CHAIN_LABEL);
        expect(plot.showsNotLinkedLegend).toBe(true);
      });

      it("says Not in this chain also when the others are not known to be unlinked", () => {
        const plot = buildChainPlot({ ...VIEW, edgeInputComplete: false, chain: chain(), itemsById: mapOf(items), nearby: [stray, plain], linkPartners: partners([9, 1]) });
        expect(plot.notLinkedLabel).toBe(NOT_IN_THIS_CHAIN_LABEL);
      });

      it("still says Not linked only when every marker may be called that", () => {
        const clear = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [plain, stray], linkPartners: partners([5, 1]) });
        expect(clear.notLinkedLabel).toBe(NOT_LINKED_LABEL);
        const gap = classifyCoverageGaps([{ source: rid(9), reason: "x" }], 1);
        const mixed = buildChainPlot({ ...VIEW, gaps: gap, chain: chain(), itemsById: mapOf(items), nearby: [plain, stray] });
        expect(mixed.notLinkedLabel).toBe(NO_LOADED_LINK_LABEL);
      });

      it("is the three words, apart", () => {
        expect(new Set([NOT_LINKED_LABEL, NO_LOADED_LINK_LABEL, IN_ANOTHER_CHAIN_LABEL, NOT_IN_THIS_CHAIN_LABEL]).size).toBe(4);
      });
    });
  });

  describe("a selection that is not identified (#842, review A1)", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const chain = () => chainOf(fixtureEdges("exactPair"), items);
    const stray = eventItem(9, T0 + 3_000, "warning");
    const plain = eventItem(8, T0 + 2_000);
    const partners = new Map([[rid(9), 2]]);

    it("calls an entry with a partner 'Link to this event not known', never 'In another chain'", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners, selectionIdentified: false });
      expect(plot.nearby[0]?.linkLabel).toBe(LINK_TO_EVENT_UNKNOWN_LABEL);
      expect(plot.nearby[0]?.linkLabel).not.toBe(IN_ANOTHER_CHAIN_LABEL);
    });

    it("leaves what the entry itself shows alone: Not linked and No loaded link are facts about it", () => {
      const clear = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [plain], linkPartners: partners, selectionIdentified: false });
      expect(clear.nearby[0]?.linkLabel).toBe(NOT_LINKED_LABEL);
      const unknown = buildChainPlot({ ...VIEW, edgeInputComplete: false, chain: chain(), itemsById: mapOf(items), nearby: [plain], linkPartners: partners, selectionIdentified: false });
      expect(unknown.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
    });

    it("says it whatever else is incomplete, as a loaded partner does", () => {
      const plot = buildChainPlot({ ...VIEW, edgeInputComplete: false, narrowed: true, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners, selectionIdentified: false });
      expect(plot.nearby[0]?.linkLabel).toBe(LINK_TO_EVENT_UNKNOWN_LABEL);
    });

    it("gives the legend the same word when any marker has it, ahead of Not in this chain", () => {
      const plot = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, plain], linkPartners: partners, selectionIdentified: false });
      expect(plot.notLinkedLabel).toBe(LINK_TO_EVENT_UNKNOWN_LABEL);
      const identified = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray, plain], linkPartners: partners });
      expect(identified.notLinkedLabel).toBe(NOT_IN_THIS_CHAIN_LABEL);
    });

    it("is the identified behavior by default and when true", () => {
      const byDefault = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners });
      const explicit = buildChainPlot({ ...VIEW, chain: chain(), itemsById: mapOf(items), nearby: [stray], linkPartners: partners, selectionIdentified: true });
      expect(byDefault.nearby[0]?.linkLabel).toBe(IN_ANOTHER_CHAIN_LABEL);
      expect(explicit).toEqual(byDefault);
    });

    it("keeps the four words apart", () => {
      expect(new Set([NOT_LINKED_LABEL, NO_LOADED_LINK_LABEL, IN_ANOTHER_CHAIN_LABEL, NOT_IN_THIS_CHAIN_LABEL, LINK_TO_EVENT_UNKNOWN_LABEL]).size).toBe(5);
    });
  });

  describe("a row the plot is given in part (#842, ruling 1)", () => {
    const first = eventItem(1, T0);
    const second = eventItem(2, T0 + 6_000);
    const stray = eventItem(9, T0 + 3_000, "warning");
    const full = () => chainOf(fixtureEdges("exactPair"), [first, second]);

    it("draws the connector between two members that are both in the part it was given", () => {
      const row = full();
      const plot = buildChainPlot({ ...VIEW, chain: row, itemsById: mapOf([first, second]) });
      const part = { memberIds: row.memberIds, unresolvedMemberIds: [], edges: row.edges, evidence: row.evidence, startMs: row.startMs, endMs: row.endMs };
      expect(buildChainPlot({ ...VIEW, chain: part, itemsById: mapOf([first, second]) })).toEqual(plot);
      expect(plot.connectors).toHaveLength(1);
    });

    it("leaves an edge to a member that is not in the part undrawn, and counts that member as having no item", () => {
      const row = full();
      const part = { memberIds: [rid(1)], unresolvedMemberIds: [rid(2)], edges: row.edges, evidence: row.evidence, startMs: T0, endMs: T0 };
      const plot = buildChainPlot({ ...VIEW, chain: part, itemsById: mapOf([first]), window: { startMs: T0 - 5_000, endMs: T0 + 5_000 } });
      expect(plot.connectors).toEqual([]);
      expect(plot.undrawnEdges.map((edge) => edge.reason)).toEqual(["endpointWithoutItem"]);
      expect(plot.membersWithoutItem).toBe(1);
    });

    it("plots an entry that is in no row: one member, no connector, the rest as context", () => {
      const part = { memberIds: [rid(1)], unresolvedMemberIds: [], edges: [], evidence: [], startMs: T0, endMs: T0 };
      const plot = buildChainPlot({ ...VIEW, chain: part, itemsById: mapOf([first]), nearby: [stray], window: { startMs: T0 - 5_000, endMs: T0 + 5_000 } });
      expect(plot.members.map((m) => m.id)).toEqual([rid(1)]);
      expect(plot.nearby.map((m) => m.id)).toEqual([rid(9)]);
      expect(plot.connectors).toEqual([]);
      expect(plot.undrawnEdges).toEqual([]);
    });

    it("still withdraws Not linked when a member the part left out has a gap", () => {
      const part = { memberIds: [rid(1)], unresolvedMemberIds: [rid(2)], edges: [], evidence: [], startMs: T0, endMs: T0 };
      const gaps = classifyCoverageGaps([{ source: rid(2), reason: "x" }], 1);
      const plot = buildChainPlot({ ...VIEW, gaps, chain: part, itemsById: mapOf([first]), nearby: [stray], window: { startMs: T0 - 5_000, endMs: T0 + 5_000 } });
      expect(plot.nearby[0]?.linkLabel).toBe(NO_LOADED_LINK_LABEL);
    });
  });

  it("keys lanes by log FILE when a log line is a member, and names its marker by file and line", () => {
    const first = logItem("C:\\Logs\\AppEnforce.log", 10, T0, "ccmutillib.cpp");
    const second = logItem("C:\\Logs\\AppDiscovery.log", 4, T0 + 2_000, "ccmutillib.cpp");
    const items = [first, second];
    const ids = items.map((item) => timelineOriginId(item.origin));
    const chain = chainOf([synthetic("e1", ids[0]!, ids[1]!, "exact")], items);
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    // Two files, one shared source: two lanes.
    expect(plot.lanes.map((lane) => lane.label)).toEqual(["AppDiscovery.log", "AppEnforce.log"]);
    expect(plot.members.map((m) => m.entry)).toEqual([
      "AppEnforce.log · line 10",
      "AppDiscovery.log · line 4",
    ]);
    expect(plot.members.every((m) => m.kind === "log")).toBe(true);
  });

  it("is the same on every build of the same input", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000), eventItem(3, T0 + 7_000, "error")];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    expect(buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) })).toEqual(
      buildChainPlot({ ...VIEW, chain, itemsById: mapOf([...items].reverse()) }),
    );
  });
});

describe("whyRows", () => {
  const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);

  it("lists every evidence row by entry in the chain's time order", () => {
    const items = [eventItem(1, T0 + 6_000, "info", { eventId: 76 }), eventItem(2, T0, "info", { eventId: 72 })];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const rows = whyRows(chain, mapOf(items));
    expect(rows.map((row) => `${row.entry}|${row.field}|${row.value}`)).toEqual([
      "72 · System|activityId|x",
      "76 · System|activityId|x",
    ]);
    expect(rows.every((row) => row.placed)).toBe(true);
  });

  it("names an entry with no item by a neutral phrase and keeps its id, last", () => {
    const items = [eventItem(1, T0)];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const rows = whyRows(chain, mapOf(items));
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({ entry: UNLOADED_ENTRY, placed: false, originId: rid(2) });
    expect(UNLOADED_ENTRY).not.toMatch(NO_UNPROVEN_CLAIM);
  });

  it("calls an entry with no item 'without a timeline position' only when it is proven unplaced", () => {
    const items = [eventItem(1, T0)];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const proof = { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set([rid(2)]) };
    expect(whyRows(chain, mapOf(items), proof)[1]?.entry).toBe(UNPLACED_ENTRY);
    for (const weaker of [
      { ...proof, scanComplete: false },
      { ...proof, unplacedListComplete: false },
      { ...proof, unplacedIds: new Set<string>() },
    ]) {
      expect(whyRows(chain, mapOf(items), weaker)[1]?.entry).toBe(UNLOADED_ENTRY);
    }
  });

  it("covers every connector: each drawn edge has at least one row for each of its endpoints", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000), eventItem(3, T0 + 2_000)];
    const edges = [synthetic("e1", rid(1), rid(2), "exact"), synthetic("e2", rid(2), rid(3), "candidate")];
    const chain = chainOf(edges, items);
    const plot = buildChainPlot({ ...VIEW, chain, itemsById: mapOf(items) });
    const rows = whyRows(chain, mapOf(items));
    expect(plot.connectors.length).toBeGreaterThan(0);
    for (const connector of plot.connectors) {
      for (const endpoint of [connector.left, connector.right]) {
        expect(rows.some((row) => row.originId === endpoint)).toBe(true);
      }
      for (const row of connector.evidence) {
        expect(rows.some((r) => r.originId === row.originId && r.value === row.value)).toBe(true);
      }
    }
  });
});

describe("chainSequence", () => {
  const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);

  it("orders members by time with offsets from the first and marks the highest severity once", () => {
    const items = [
      eventItem(1, T0, "info"),
      eventItem(2, T0 + 3_300, "error"),
      eventItem(3, T0 + 9_000, "warning"),
    ];
    const edges = [synthetic("e1", rid(1), rid(2)), synthetic("e2", rid(2), rid(3))];
    const sequence = chainSequence(chainOf(edges, items), mapOf(items));
    expect(sequence.entries.map((e) => e.offsetMs)).toEqual([0, 3_300, 9_000]);
    expect(sequence.entries.map((e) => e.highestSeverity)).toEqual([false, true, false]);
    expect(sequence.entries.map((e) => e.level)).toEqual(["Information", "Error", "Warning"]);
    expect(sequence.itemlessIds).toEqual([]);
  });

  it("breaks a severity tie by the earliest time, as the title does", () => {
    const items = [eventItem(1, T0, "error"), eventItem(2, T0 + 1_000, "error")];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const sequence = chainSequence(chain, mapOf(items));
    expect(sequence.entries.map((e) => e.highestSeverity)).toEqual([true, false]);
    expect(chain.title).toContain(String(items[0]!.origin.kind === "event" ? items[0]!.origin.eventId : ""));
  });

  it("flags members that share a timestamp, because time does not order them", () => {
    const items = [eventItem(1, T0), eventItem(2, T0)];
    const sequence = chainSequence(chainOf(fixtureEdges("exactPair"), items), mapOf(items));
    expect(sequence.entries.map((e) => e.sameTimeAsPrevious)).toEqual([false, true]);
  });

  it("lists members with no item apart, sorted, and gives them no place in the order", () => {
    const items = [eventItem(1, T0)];
    const sequence = chainSequence(chainOf(fixtureEdges("exactPair"), items), mapOf(items));
    expect(sequence.entries).toHaveLength(1);
    expect(sequence.itemlessIds).toEqual([rid(2)]);
  });
});

describe("text helpers", () => {
  it("cuts a long value in the middle to 12 characters and leaves a short one alone", () => {
    expect(middleTruncate("short")).toBe("short");
    expect(middleTruncate("123456789012")).toBe("123456789012");
    const cut = middleTruncate("{3b7e9c1a-5d24-4f8e-a0c6-1e2b3d4f5a6b}");
    expect(Array.from(cut)).toHaveLength(12);
    expect(cut).toBe("{3b7e9\u20265a6b}");
    expect(middleTruncate("")).toBe("");
  });

  it("counts code points, so a cut never lands inside a surrogate pair", () => {
    const value = "\u{1F600}".repeat(20);
    const cut = middleTruncate(value);
    expect(Array.from(cut)).toHaveLength(12);
    expect(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(cut)).toBe(false);
  });

  it("shows the first key and how many more the row has", () => {
    expect(keyHeader([])).toBeNull();
    expect(
      keyHeader([
        { kind: "activityId", value: "x" },
        { kind: "sessionId", value: "y" },
        { kind: "userId", value: "z" },
      ]),
    ).toEqual({ kind: "activityId", value: "x", shortValue: "x", more: 2 });
  });

  it("counts all members in entriesText, singular for one", () => {
    expect(entriesText(1)).toBe("1 entry");
    expect(entriesText(2)).toBe("2 entries");
    expect(entriesText(0)).toBe("0 entries");
  });

  it("titles a row with no derived title by a neutral fallback that says nothing about positions", () => {
    expect(chainTitle({ title: null })).toBe("Untitled chain");
    expect(UNTITLED_CHAIN).toBe("Untitled chain");
    expect(UNTITLED_CHAIN).not.toMatch(NO_UNPROVEN_CLAIM);
    expect(chainTitle({ title: "76 · Failed" })).toBe("76 · Failed");
  });

  it("keeps the chain id in the accessible name of an untitled row, so two such rows differ", () => {
    expect(chainAccessibleName({ title: null, id: "chain|a" })).toBe("Untitled chain chain|a");
    expect(chainAccessibleName({ title: null, id: "chain|b" })).not.toBe(
      chainAccessibleName({ title: null, id: "chain|a" }),
    );
    expect(chainAccessibleName({ title: "76 · Failed", id: "chain|a" })).toBe("76 · Failed");
  });

  it("proves an entry unplaced only with the scan finished, a complete list, and the id on it", () => {
    const proof = { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set(["a"]) };
    expect(isProvenUnplaced("a", proof)).toBe(true);
    expect(isProvenUnplaced("b", proof)).toBe(false);
    expect(isProvenUnplaced("a", { ...proof, scanComplete: false })).toBe(false);
    expect(isProvenUnplaced("a", { ...proof, unplacedListComplete: false })).toBe(false);
    expect(partitionUnplaced(["a", "b", "a"], proof)).toEqual({ proven: ["a", "a"], unknown: ["b"] });
  });

  it("calls a chain partial whenever a member has no position", () => {
    expect(isPartialChain({ unresolvedMemberIds: [] })).toBe(false);
    expect(isPartialChain({ unresolvedMemberIds: ["a"] })).toBe(true);
  });
});

describe("reconcileSelection", () => {
  const chains = [{ id: "a" }, { id: "b" }];

  it("keeps a selection that still exists", () => {
    expect(reconcileSelection(chains, "b")).toEqual({ selectedId: "b", lost: false });
  });

  it("selects the first chain when nothing was selected, which is not a loss", () => {
    expect(reconcileSelection(chains, null)).toEqual({ selectedId: "a", lost: false });
  });

  it("falls back to the first chain and says the selection was lost when it is gone", () => {
    expect(reconcileSelection(chains, "gone")).toEqual({ selectedId: "a", lost: true });
  });

  it("selects nothing when there are no chains, and still reports a loss", () => {
    expect(reconcileSelection([], null)).toEqual({ selectedId: null, lost: false });
    expect(reconcileSelection([], "gone")).toEqual({ selectedId: null, lost: true });
  });
});

describe("listedRows (#842, ruling 3)", () => {
  const pairs = (count: number) =>
    Array.from({ length: count }, (_, i): TimelineCorrelationEdge => ({
      id: `e${i}`,
      fromId: `l${i}`,
      toId: `r${i}`,
      key: { kind: "activityId", value: `k${i}` },
      strength: "exact",
      confidence: "high",
      candidateIds: [],
      evidence: [{ originId: `l${i}`, field: "activityId", value: `k${i}` }],
      coverage: { state: "covered" },
    }));
  const model = buildCorrelationChains({
    items: [],
    timelineEdges: pairs(130),
    totalTimelineEdges: 130,
    findings: [],
  });
  const shown = new Set(model.chains.map((row) => row.id));
  const pastCap = [...model.rowsByMember.values()].map((rows) => rows[0] as CorrelationChain).find((row) => !shown.has(row.id)) as CorrelationChain;

  it("is the capped rows, untouched, when the selection is among them or there is none", () => {
    expect(listedRows(model, null)).toEqual({ rows: model.chains, pastCapId: null });
    const inside = model.chains[40] as CorrelationChain;
    expect(listedRows(model, inside.id).rows).toBe(model.chains);
    expect(listedRows(model, inside.id).pastCapId).toBeNull();
  });

  it("lists the selected row after the 100 when the cap dropped it, leaving the 100 where they were", () => {
    expect(pastCap).toBeDefined();
    const listed = listedRows(model, pastCap.id);
    expect(listed.pastCapId).toBe(pastCap.id);
    expect(listed.rows).toHaveLength(101);
    expect(listed.rows.slice(0, 100)).toEqual(model.chains);
    expect(listed.rows[100]).toBe(pastCap);
  });

  it("lists nothing extra for an id no row has, so the loss is still reported", () => {
    const listed = listedRows(model, "chain-that-never-was");
    expect(listed).toEqual({ rows: model.chains, pastCapId: null });
    expect(reconcileSelection(listed.rows, "chain-that-never-was").lost).toBe(true);
  });

  it("keeps a past-cap selection from reading as lost", () => {
    const listed = listedRows(model, pastCap.id);
    expect(reconcileSelection(listed.rows, pastCap.id)).toEqual({ selectedId: pastCap.id, lost: false });
    expect(reconcileSelection(model.chains, pastCap.id).lost).toBe(true);
  });
});

describe("memberLinkSummary", () => {
  it("counts distinct exact and candidate partners and ignores edges that are not links", () => {
    const summary = memberLinkSummary({
      edges: [
        { left: "a", right: "b", strength: "exact", keys: [] },
        { left: "a", right: "c", strength: "candidate", keys: [] },
        { left: "a", right: "d", strength: "ambiguous", keys: [] },
        { left: "b", right: "a", strength: "exact", keys: [] },
        { left: "e", right: null, strength: "exact", keys: [] },
      ],
    });
    expect(summary.get("a")).toEqual({ exact: 1, candidate: 1 });
    expect(summary.get("b")).toEqual({ exact: 1, candidate: 0 });
    expect(summary.get("c")).toEqual({ exact: 0, candidate: 1 });
    expect(summary.has("d")).toBe(false);
    expect(summary.has("e")).toBe(false);
  });
});

/**
 * "The session can speak for an absent link" is one predicate (#843): the plot's "Not linked" label
 * reads it, and so does the Details context list when it decides whether a missing link icon needs
 * a caveat. Each of the four conditions is pinned alone.
 */
describe("sessionSpeaksForAbsence", () => {
  const clear = classifyCoverageGaps([], 0);
  const speaks = {
    edgeInputComplete: true,
    narrowed: false,
    gaps: clear,
    memberIds: [rid(1), rid(2)],
  };

  it("holds when every edge is loaded, nothing is narrowed, no gap clears completeness and none names a member", () => {
    expect(sessionSpeaksForAbsence(speaks)).toBe(true);
    expect(sessionSpeaksForAbsence({ ...speaks, memberIds: [] })).toBe(true);
  });

  it("does not hold when an edge was not loaded", () => {
    expect(sessionSpeaksForAbsence({ ...speaks, edgeInputComplete: false })).toBe(false);
  });

  it("does not hold for a narrowed view", () => {
    expect(sessionSpeaksForAbsence({ ...speaks, narrowed: true })).toBe(false);
  });

  it("does not hold when a limit or truncation gap exists", () => {
    const limit = classifyCoverageGaps([{ source: "correlation", reason: "limit" }], 1);
    expect(limit.global).toBe(true);
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: limit })).toBe(false);
  });

  it("does not hold when the preview does not show every gap, or the gap count is not known", () => {
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: classifyCoverageGaps([], 3) })).toBe(false);
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: classifyCoverageGaps([], null) })).toBe(false);
  });

  it("does not hold when a gap names any member, placed or not, for every member's key may be lost", () => {
    const named = classifyCoverageGaps([{ source: rid(2), reason: "x" }], 1);
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: named })).toBe(false);
    // A gap that names an origin that is not a member does not bear on the members.
    const other = classifyCoverageGaps([{ source: rid(70), reason: "x" }], 1);
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: other })).toBe(true);
  });

  it("takes the members from any iterable", () => {
    const named = classifyCoverageGaps([{ source: rid(2), reason: "x" }], 1);
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: named, memberIds: new Set([rid(2)]) })).toBe(false);
    expect(sessionSpeaksForAbsence({ ...speaks, gaps: named, memberIds: new Set([rid(1)]) })).toBe(true);
  });

  it("is the rule the plot's 'Not linked' label follows", () => {
    const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const labelWith = (view: Partial<typeof VIEW>) =>
      buildChainPlot({ ...VIEW, ...view, chain, itemsById: mapOf(items), nearby: [eventItem(9, T0 + 3_000)] })
        .nearby[0]?.linkLabel;
    expect(labelWith({})).toBe(NOT_LINKED_LABEL);
    expect(labelWith({ edgeInputComplete: false })).toBe(NO_LOADED_LINK_LABEL);
    expect(labelWith({ narrowed: true })).toBe(NO_LOADED_LINK_LABEL);
    expect(labelWith({ gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1) })).toBe(NO_LOADED_LINK_LABEL);
    expect(labelWith({ gaps: classifyCoverageGaps([{ source: rid(2), reason: "x" }], 1) })).toBe(NO_LOADED_LINK_LABEL);
  });
});
