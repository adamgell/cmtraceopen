/**
 * What the lane plot and the tables draw. Real engine output (`__fixtures__/correlation-edges.json`,
 * the parser crate's own reducer) drives the shapes; synthetic edges cover what the engine cannot
 * yet produce (a log-line member, a mixed Exact and Candidate chain, an edge with no evidence).
 */
import { describe, expect, it } from "vitest";
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
  spanText,
  whyRows,
  UNTITLED_CHAIN,
} from "./evtx-correlation-view-model";
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
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.members.map((m) => m.id)).toEqual([rid(1), rid(2)]);
    expect(plot.lanes).toHaveLength(1);
    expect(plot.connectors).toHaveLength(1);
    const connector = plot.connectors[0]!;
    expect(connector).toMatchObject({ left: rid(1), right: rid(2), strength: "exact" });
    expect(connector.evidence.map((row) => row.originId).sort()).toEqual([rid(1), rid(2)]);
    expect(plot.undrawnEdges).toEqual([]);
    expect(plot.unplacedMembers).toBe(0);
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
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.connectors.map((c) => `${c.left}>${c.right}:${c.strength}`)).toEqual([
      `${rid(1)}>${rid(2)}:exact`,
      `${rid(2)}>${rid(3)}:candidate`,
    ]);
  });

  it("draws a real candidate pair with a candidate connector", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000)];
    const chain = chainOf(fixtureEdges("secondaryPair"), items);
    expect(chain.strength).toBe("candidate");
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.connectors.map((c) => c.strength)).toEqual(["candidate"]);
    expect(plot.connectors[0]!.evidence.length).toBeGreaterThan(0);
  });

  it("never draws a connector for an ambiguous group, whatever its edges say", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000), eventItem(3, T0 + 2_000)];
    const chain = chainOf(fixtureEdges("group3"), items);
    expect(chain.strength).toBe("ambiguous");
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.members).toHaveLength(3);
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges).toEqual([]);
  });

  it("never draws a connector for a coverage blocked row", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000)];
    const chain = chainOf(fixtureEdges("gappedPair"), items);
    expect(chain.strength).toBe("coverageBlocked");
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.members).toHaveLength(2);
    expect(plot.connectors).toEqual([]);
  });

  it("does not draw an exact edge that has no evidence row, and says so", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000)];
    const chain = chainOf([synthetic("e1", rid(1), rid(2), "exact", { evidence: [] })], items);
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
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
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges[0]?.reason).toBe("noEvidence");
  });

  it("gives a member with no item no position and no connector, and counts it", () => {
    const items = [eventItem(1, T0)];
    const chain = chainOf([synthetic("e1", rid(1), rid(2), "exact")], items);
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
    expect(plot.members.map((m) => m.id)).toEqual([rid(1)]);
    expect(plot.connectors).toEqual([]);
    expect(plot.undrawnEdges).toEqual([
      { left: rid(1), right: rid(2), strength: "exact", reason: "unplacedEndpoint" },
    ]);
    expect(plot.unplacedMembers).toBe(1);
  });

  it("draws an empty plot, with the members counted, when no member is placed", () => {
    const chain = chainOf(fixtureEdges("exactPair"), []);
    const plot = buildChainPlot({ chain, itemsById: new Map() });
    expect(plot.window).toBeNull();
    expect(plot.members).toEqual([]);
    expect(plot.lanes).toEqual([]);
    expect(plot.ticks).toEqual([]);
    expect(plot.unplacedMembers).toBe(2);
    expect(plot.omittedMarkers).toBe(0);
  });

  it("pins a member outside the window to the edge with a label that says how far outside", () => {
    const items = [eventItem(1, T0, "info", { eventId: 76 }), eventItem(2, T0 + 60_000, "info", { eventId: 72 })];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const window = { startMs: T0 + 3_000, endMs: T0 + 50_000 };
    const plot = buildChainPlot({ chain, itemsById: mapOf(items), window });
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
    const plot = buildChainPlot({ chain: chainOf(fixtureEdges("exactPair"), items), itemsById: mapOf(items) });
    for (const marker of plot.members) {
      expect(marker.pinLabel).toBeNull();
      expect(marker.placement.pinned).toBeNull();
    }
  });

  it("uses the default window and its five ticks", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 100_000)];
    const plot = buildChainPlot({ chain: chainOf(fixtureEdges("exactPair"), items), itemsById: mapOf(items) });
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
      const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
      expect(plot.members).toHaveLength(CORRELATION_MARKER_CAP);
      expect(plot.omittedMarkers).toBe(30);
      expect(plot.members.map((m) => m.sequenceIndex)).toEqual(
        Array.from({ length: CORRELATION_MARKER_CAP }, (_, i) => i),
      );
    });

    it("does not draw a connector to a marker the cap left out, and reports why", () => {
      const { items, chain } = manyMembers(5);
      const plot = buildChainPlot({ chain, itemsById: mapOf(items), markerCap: 3 });
      expect(plot.members).toHaveLength(3);
      expect(plot.connectors).toHaveLength(2);
      expect(plot.undrawnEdges.map((edge) => edge.reason)).toEqual(["beyondMarkerCap", "beyondMarkerCap"]);
    });

    it("counts the connectors the connector cap left out", () => {
      const { items, chain } = manyMembers(6);
      const plot = buildChainPlot({ chain, itemsById: mapOf(items), connectorCap: 2 });
      expect(plot.connectors).toHaveLength(2);
      expect(plot.omittedConnectors).toBe(3);
    });
  });

  describe("the not-linked seam (decision A on #838)", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];
    const chain = () => chainOf(fixtureEdges("exactPair"), items);
    const stray = eventItem(9, T0 + 3_000, "warning");

    it("draws nothing extra when given none, which is what production passes", () => {
      const plot = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [] });
      expect(plot.nearby).toEqual([]);
      expect(plot.showsNotLinkedLegend).toBe(false);
      expect(buildChainPlot({ chain: chain(), itemsById: mapOf(items) }).nearby).toEqual([]);
    });

    it("draws a context entry as a marker with no connector, kept apart from the members, and shows the legend", () => {
      const plot = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [stray] });
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
      const withContext = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [stray] });
      const without = buildChainPlot({ chain: chain(), itemsById: mapOf(items) });
      expect(withContext.members).toEqual(without.members);
      expect(withContext.connectors).toEqual(without.connectors);
      expect(withContext.unplacedMembers).toBe(without.unplacedMembers);
    });

    it("never draws a member twice, and never marks one as not linked", () => {
      const plot = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [items[0]!, stray] });
      expect(plot.nearby.map((m) => m.id)).toEqual([rid(9)]);
    });

    it("puts a context entry on its own lane and counts the ones past the cap", () => {
      const other = eventItem(8, T0 + 2_000, "info", { channel: "Application" });
      const plot = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [stray, other], markerCap: 1 });
      expect(plot.omittedNearby).toBe(1);
      const plotAll = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [stray, other] });
      expect(plotAll.lanes.map((lane) => lane.label)).toEqual(["Application", "System"]);
    });

    it("draws the same whatever order the context entries arrive in", () => {
      const a = eventItem(8, T0 + 2_000);
      const forward = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [a, stray] });
      const reversed = buildChainPlot({ chain: chain(), itemsById: mapOf(items), nearby: [stray, a] });
      expect(forward).toEqual(reversed);
    });
  });

  it("keys lanes by log FILE when a log line is a member, and names its marker by file and line", () => {
    const first = logItem("C:\\Logs\\AppEnforce.log", 10, T0, "ccmutillib.cpp");
    const second = logItem("C:\\Logs\\AppDiscovery.log", 4, T0 + 2_000, "ccmutillib.cpp");
    const items = [first, second];
    const ids = items.map((item) => timelineOriginId(item.origin));
    const chain = chainOf([synthetic("e1", ids[0]!, ids[1]!, "exact")], items);
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
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
    expect(buildChainPlot({ chain, itemsById: mapOf(items) })).toEqual(
      buildChainPlot({ chain, itemsById: mapOf([...items].reverse()) }),
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

  it("names an entry with no item by a fixed phrase and keeps its id, last", () => {
    const items = [eventItem(1, T0)];
    const chain = chainOf(fixtureEdges("exactPair"), items);
    const rows = whyRows(chain, mapOf(items));
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({
      entry: "Entry without a timeline position",
      placed: false,
      originId: rid(2),
    });
  });

  it("covers every connector: each drawn edge has at least one row for each of its endpoints", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 1_000), eventItem(3, T0 + 2_000)];
    const edges = [synthetic("e1", rid(1), rid(2), "exact"), synthetic("e2", rid(2), rid(3), "candidate")];
    const chain = chainOf(edges, items);
    const plot = buildChainPlot({ chain, itemsById: mapOf(items) });
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
    expect(sequence.unplacedIds).toEqual([]);
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
    expect(sequence.unplacedIds).toEqual([rid(2)]);
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

  it("titles a row with no placed member by a plain statement, not a made-up name", () => {
    expect(chainTitle({ title: null })).toBe(UNTITLED_CHAIN);
    expect(chainTitle({ title: "76 · Failed" })).toBe("76 · Failed");
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
