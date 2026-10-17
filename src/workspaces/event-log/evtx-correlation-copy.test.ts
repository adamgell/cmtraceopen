/**
 * The words the Correlation view says, and the copied text. The two things this file protects most
 * are that a narrowed or partial view says so, and that nothing here reads as cause.
 */
import { describe, expect, it } from "vitest";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import {
  buildCorrelationChains,
  type CorrelationChain,
  type CorrelationChainStrength,
} from "./evtx-correlation-chains";
import {
  STRENGTH_LABELS,
  chainCopyText,
  edgeInputNotice,
  keyKindLabel,
  plotOmissionNotice,
  renderCapNotice,
  scopeDisclosure,
  unresolvedNotice,
  whyHeading,
  whyStatement,
  type ChainCopyInput,
} from "./evtx-correlation-copy";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
import { getAllThemes } from "../../lib/themes";
import {
  assertUnifiedTimelineShape,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineItem,
  type TimelineSeverity,
} from "./unified-timeline";

const rid = (n: number) => `source4:Live|machine10:DESKTOP-01|channel6:System|record${n}`;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);

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
  message = `message ${n}`,
  eventId = 100 + n,
): TimelineItem {
  return {
    timestampMs,
    severity,
    message,
    origin: {
      kind: "event",
      stableId: rid(n),
      source: "Live",
      machine: "DESKTOP-01",
      bundle: null,
      channel: "System",
      provider: "P",
      processId: null,
      eventId,
      recordId: n,
    },
  };
}

function chainFor(name: string, items: TimelineItem[]): CorrelationChain {
  const edges = fixtureEdges(name);
  const model = buildCorrelationChains({
    items,
    timelineEdges: edges,
    totalTimelineEdges: edges.length,
    findings: [],
  });
  return model.chains[0]!;
}

const mapOf = (items: TimelineItem[]) =>
  new Map(items.map((item) => [timelineOriginId(item.origin), item]));

const COMPLETE = { edgeInputComplete: true, unloadedEdgeCount: 0 };
const PROVEN = { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set<string>() };

function copyInput(chain: CorrelationChain, items: TimelineItem[], overrides: Partial<ChainCopyInput> = {}): ChainCopyInput {
  return {
    chain,
    itemsById: mapOf(items),
    timeZoneMode: "utc",
    scope: null,
    edgeInput: COMPLETE,
    unplaced: PROVEN,
    ...overrides,
  };
}

describe("STRENGTH_LABELS", () => {
  it("equals the label the visual tokens give each strength, in every theme", () => {
    for (const theme of getAllThemes()) {
      const tokens = buildEvtxVisualTokens(theme);
      for (const strength of Object.keys(STRENGTH_LABELS) as CorrelationChainStrength[]) {
        expect(STRENGTH_LABELS[strength], `${theme.id} ${strength}`).toBe(tokens.strengths[strength].label);
      }
    }
  });
});

describe("scopeDisclosure (decision 10)", () => {
  it("is null while nothing is narrowed, because there is nothing events were left out of", () => {
    expect(scopeDisclosure({ visibleCount: 10, loadedCount: 10, textLogCount: 4 })).toBeNull();
    expect(scopeDisclosure({ visibleCount: 11, loadedCount: 10, textLogCount: 0 })).toBeNull();
  });

  it("says links and strengths are computed over the visible events and that others can make an Exact link ambiguous", () => {
    const disclosure = scopeDisclosure({ visibleCount: 12, loadedCount: 1_300, textLogCount: 0 });
    expect(disclosure?.strengthNote).toBe(
      "Links and strengths are computed over the 12 events visible. Events outside the view can make an Exact link ambiguous.",
    );
    expect(disclosure?.textLogNote).toBeNull();
  });

  it("uses the singular for one visible event", () => {
    expect(scopeDisclosure({ visibleCount: 1, loadedCount: 5, textLogCount: 0 })?.strengthNote).toContain(
      "the 1 event visible",
    );
  });

  it("adds the rail's sentence about text logs only when text logs were given to the session", () => {
    expect(scopeDisclosure({ visibleCount: 1, loadedCount: 5, textLogCount: 3 })?.textLogNote).toBe(
      "Text logs are not scoped.",
    );
    expect(scopeDisclosure({ visibleCount: 1, loadedCount: 5, textLogCount: 0 })?.textLogNote).toBeNull();
  });

  it("is narrowed by even one event", () => {
    expect(scopeDisclosure({ visibleCount: 4, loadedCount: 5, textLogCount: 0 })).not.toBeNull();
  });
});

describe("edgeInputNotice", () => {
  it("is silent only when every edge was loaded", () => {
    expect(edgeInputNotice(COMPLETE)).toBeNull();
  });

  it("says how many edges were left out when it knows", () => {
    expect(edgeInputNotice({ edgeInputComplete: false, unloadedEdgeCount: 40 })).toBe(
      "Correlation details are paged and bounded: 40 correlation edges were not loaded, so chains may be incomplete.",
    );
  });

  it("says the total is not known when it does not, and never claims zero were left out", () => {
    const notice = edgeInputNotice({ edgeInputComplete: false, unloadedEdgeCount: 0 });
    expect(notice).toContain("paged and bounded");
    expect(notice).toContain("not known");
    expect(notice).not.toMatch(/\b0\b/);
  });
});

describe("renderCapNotice", () => {
  it("uses the spec's sentence when rows were dropped", () => {
    expect(renderCapNotice({ shown: 100, totalCount: 120, omittedCount: 20 })).toBe(
      "Showing the first 100 of 120; 20 omitted.",
    );
  });

  it("is silent when nothing was dropped", () => {
    expect(renderCapNotice({ shown: 12, totalCount: 12, omittedCount: 0 })).toBeNull();
  });
});

describe("the render cap line and the paged-and-bounded notice are two different omissions", () => {
  it("never borrow each other's words, so edges never loaded are not read as rows dropped by the cap", () => {
    const cap = renderCapNotice({ shown: 100, totalCount: 120, omittedCount: 20 });
    expect(cap).not.toMatch(/paged|bounded|edges|loaded/);
    for (const state of [
      { edgeInputComplete: false, unloadedEdgeCount: 40 },
      { edgeInputComplete: false, unloadedEdgeCount: 0 },
    ]) {
      expect(edgeInputNotice(state)).not.toMatch(/Showing the first|omitted/);
    }
  });
});

describe("unresolvedNotice", () => {
  const chain = (ids: string[], memberCount = 5) => ({ unresolvedMemberIds: ids, memberCount });

  it("is silent when every member is placed", () => {
    expect(unresolvedNotice(chain([]), PROVEN)).toBeNull();
  });

  it("says no timestamp only when the scan finished, the unplaced list is complete, and every one is on it", () => {
    const evidence = { ...PROVEN, unplacedIds: new Set(["a", "b"]) };
    expect(unresolvedNotice(chain(["a", "b"]), evidence)).toBe(
      "2 of 5 entries carry no timestamp, so they are not placed on the plot.",
    );
  });

  it.each([
    ["the scan did not finish", { scanComplete: false, unplacedListComplete: true, unplacedIds: new Set(["a"]) }],
    ["the unplaced list is cut", { scanComplete: true, unplacedListComplete: false, unplacedIds: new Set(["a"]) }],
    ["one is not on the list", { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set<string>() }],
  ])("only says no position was loaded when %s", (_why, evidence) => {
    const text = unresolvedNotice(chain(["a"]), evidence);
    expect(text).toBe("1 of 5 entries have no loaded timeline position, so they are not placed on the plot.");
    expect(text).not.toContain("timestamp");
  });
});

describe("plotOmissionNotice", () => {
  it("is silent when no cap left anything out", () => {
    expect(plotOmissionNotice({ omittedMarkers: 0, omittedConnectors: 0 })).toBeNull();
  });

  it("names entries and connectors that were left out, singular and plural", () => {
    expect(plotOmissionNotice({ omittedMarkers: 1, omittedConnectors: 0 })).toBe(
      "1 entry is listed in Sequence but not drawn.",
    );
    expect(plotOmissionNotice({ omittedMarkers: 30, omittedConnectors: 3 })).toBe(
      "30 entries are listed in Sequence but not drawn; 3 connectors are not drawn.",
    );
  });
});

describe("whyHeading and whyStatement", () => {
  const items = [eventItem(1, T0), eventItem(2, T0 + 6_000)];

  it("heads an exact or candidate row as a link and an ambiguous or blocked row as not one", () => {
    expect(whyHeading("exact")).toBe("Why these are linked");
    expect(whyHeading("candidate")).toBe("Why these are linked");
    expect(whyHeading("ambiguous")).toBe("Why this is not a link");
    expect(whyHeading("coverageBlocked")).toBe("Why this is not a link");
  });

  it("states the spec's sentence for a real exact pair", () => {
    expect(whyStatement(chainFor("exactPair", items))).toBe(
      "One ActivityId value matches across 2 entries on one machine.",
    );
  });

  it("calls a candidate link a candidate, not a confirmed one", () => {
    const statement = whyStatement(chainFor("secondaryPair", items));
    expect(statement).toContain("candidate link, not a confirmed one");
  });

  it("says an ambiguous group establishes no single link", () => {
    const statement = whyStatement(chainFor("group3", [...items, eventItem(3, T0 + 7_000)]));
    expect(statement).toBe(
      "3 entries share ActivityId x, so no single link between two of them is established.",
    );
  });

  it("gives the engine's own gap reason for a coverage blocked row", () => {
    const statement = whyStatement(chainFor("gappedPair", items));
    expect(statement).toMatch(/^A coverage gap stops a link between these 2 entries: /);
    expect(statement.length).toBeGreaterThan(60);
  });

  it("caps the gap reasons it names and counts the rest", () => {
    const statement = whyStatement({
      strength: "coverageBlocked",
      keys: [],
      memberCount: 2,
      coverageGaps: ["a", "b", "c", "d", "e"].map((reason) => ({ source: "s", reason })),
    });
    expect(statement).toBe("A coverage gap stops a link between these 2 entries: a; b; c; and 2 more.");
  });

  it("describes several keys without naming one that is not the only one", () => {
    const statement = whyStatement({
      strength: "exact",
      keys: [
        { kind: "activityId", value: "x" },
        { kind: "sessionId", value: "y" },
      ],
      memberCount: 3,
      coverageGaps: [],
    });
    expect(statement).toBe("2 identifier values link these 3 entries; each connector is backed by the rows below.");
  });

  it("names every key kind in words, and an unknown kind as it is", () => {
    expect(keyKindLabel("providerChannelEventRecord")).toBe("provider, channel and record");
    expect(keyKindLabel("secondary")).toBe("secondary identifier");
    expect(keyKindLabel("somethingNew")).toBe("somethingNew");
  });
});

describe("chainCopyText", () => {
  const items = [
    eventItem(1, T0, "info", "Auto MDM Enroll: started", 72),
    eventItem(2, T0 + 6_000, "error", "Auto MDM Enroll: Failed\nstatus 0x80192ee7", 76),
  ];

  it("copies the title, keys, span, counts, sequence with offsets, and the evidence rows", () => {
    const chain = chainFor("exactPair", items);
    const text = chainCopyText(copyInput(chain, items));
    expect(text).toContain("Exact: 76 · Auto MDM Enroll: Failed");
    expect(text).toContain("Key: activityId x");
    expect(text).toContain("Time zone: UTC");
    expect(text).toContain("Span: 2026-10-06 10:20:00.000 to 2026-10-06 10:20:06.000");
    expect(text).toContain("Entries: 2 (2 placed, 0 not placed)");
    expect(text).toContain("1. 2026-10-06 10:20:00.000  Information  72 · System  [System]  Auto MDM Enroll: started");
    expect(text).toContain("2. +6 s  Error  76 · System  [System]  Auto MDM Enroll: Failed\n      status 0x80192ee7");
    expect(text).toContain("Why these are linked\nOne ActivityId value matches across 2 entries on one machine.");
    expect(text).toContain("  72 · System: activityId = x");
    expect(text).toContain("  76 · System: activityId = x");
  });

  it("says that order is by recorded time and never says one entry caused another", () => {
    const text = chainCopyText(copyInput(chainFor("exactPair", items), items));
    expect(text).toContain("ordered by recorded time; order is not evidence of cause");
    const withoutDisclaimer = text.replace("order is not evidence of cause", "");
    expect(withoutDisclaimer).not.toMatch(
      /\b(caused|causes|because|led to|leads to|triggered|resulted|due to|therefore|root cause)\b/i,
    );
  });

  it("carries the scope, text-log, paged-and-bounded and partial notices the screen shows", () => {
    const chain = chainFor("exactPair", [items[0]!]);
    const text = chainCopyText(
      copyInput(chain, [items[0]!], {
        scope: scopeDisclosure({ visibleCount: 2, loadedCount: 10, textLogCount: 1 }),
        edgeInput: { edgeInputComplete: false, unloadedEdgeCount: 7 },
        unplaced: { scanComplete: false, unplacedListComplete: false, unplacedIds: new Set() },
      }),
    );
    expect(text).toContain("Links and strengths are computed over the 2 events visible.");
    expect(text).toContain("Text logs are not scoped.");
    expect(text).toContain("Correlation details are paged and bounded: 7 correlation edges were not loaded");
    expect(text).toContain("1 of 2 entries have no loaded timeline position");
    expect(text).toContain("Entries: 2 (1 placed, 1 not placed)");
    expect(text).toContain("Entries without a timeline position:");
    expect(text).toContain(rid(2));
  });

  it("lists at most 20 unplaced ids and counts the rest", () => {
    const edges = Array.from({ length: 24 }, (_, i) => ({
      ...fixtureEdges("exactPair")[0]!,
      id: `e${i}`,
      fromId: rid(100),
      toId: rid(101 + i),
      evidence: [],
    }));
    const model = buildCorrelationChains({
      items: [],
      timelineEdges: edges,
      totalTimelineEdges: edges.length,
      findings: [],
    });
    const text = chainCopyText(copyInput(model.chains[0]!, []));
    expect(text.match(/source4:Live/g)?.length).toBe(20);
    expect(text).toContain("and 5 more");
  });

  it("heads an ambiguous row as not a link and keeps its strength word", () => {
    const three = [...items, eventItem(3, T0 + 7_000, "info", "third")];
    const text = chainCopyText(copyInput(chainFor("group3", three), three));
    expect(text.startsWith("Ambiguous: ")).toBe(true);
    expect(text).toContain("Why this is not a link");
    expect(text).not.toContain("Why these are linked");
  });

  it("flags entries with the same timestamp, because their order is not established", () => {
    const same = [eventItem(1, T0), eventItem(2, T0)];
    const text = chainCopyText(copyInput(chainFor("exactPair", same), same));
    expect(text).toContain("same timestamp as the entry above; their order is not established");
  });

  it("says plainly when no entry has a position, without inventing a span", () => {
    const text = chainCopyText(copyInput(chainFor("exactPair", []), []));
    expect(text).toContain("Span: not known, no entry of this chain has a timeline position");
    expect(text).toContain("No entry has a timeline position.");
    expect(text).toContain("Entries: 2 (0 placed, 2 not placed)");
  });
});
