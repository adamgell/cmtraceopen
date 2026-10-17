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
  type UnplacedEvidence,
} from "./evtx-correlation-copy";
import * as copyExports from "./evtx-correlation-copy";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import * as viewModelExports from "./evtx-correlation-view-model";
import {
  NOT_LINKED_LABEL,
  NO_LOADED_LINK_LABEL,
  UNLOADED_ENTRY,
  UNTITLED_CHAIN,
  buildChainPlot,
  chainAccessibleName,
  chainSequence,
  chainTitle,
  describeLanes,
  entriesText,
  entryLabel,
  formatDelta,
  keyHeader,
  middleTruncate,
  shortEntryId,
  spanText,
  whyRows,
} from "./evtx-correlation-view-model";
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
/** What no string may say unless the entry is proven unplaced (the scan finished, on a complete list). */
const NO_UNPROVEN_CLAIM = /not placed|no timeline position|without a timeline position|no timestamp/i;
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
    expect(text).toBe("1 of 5 entries have no loaded timeline position, so they are not drawn on the plot.");
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
    expect(text).toContain("Entries: 2 (2 placed)");
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
    // The scan did not finish, so nothing is proven unplaced: none of it may say so.
    expect(text).toContain("Entries: 2 (1 placed, 1 with no loaded position)");
    expect(text).toContain("Entries with no loaded timeline position:");
    expect(text).not.toMatch(NO_UNPROVEN_CLAIM);
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
    expect(text).toContain("Span: not known, no entry of this chain has a loaded timeline position");
    expect(text).toContain("No entry has a loaded timeline position.");
    expect(text).toContain("Entries: 2 (0 placed, 2 with no loaded position)");
    expect(text).not.toMatch(NO_UNPROVEN_CLAIM);
  });
});

/**
 * G2: no string may say an entry is not placed, has no timeline position or no timestamp unless the
 * scan finished and the id is on a complete unplaced list. Every string-producing export is run
 * over each way the proof can fail; the manifest below makes a new export fail this file until it
 * is classified, so a new string cannot slip past the audit.
 */
describe("no string claims an entry is unplaced without proof", () => {
  const STRING_EXPORTS = new Set([
    // evtx-correlation-copy.ts
    "STRENGTH_LABELS",
    "chainCopyText",
    "edgeInputNotice",
    "keyKindLabel",
    "plotOmissionNotice",
    "renderCapNotice",
    "scopeDisclosure",
    "unresolvedNotice",
    "whyHeading",
    "whyStatement",
    // evtx-correlation-view-model.ts
    "NOT_LINKED_LABEL",
    "NO_LOADED_LINK_LABEL",
    "UNLOADED_ENTRY",
    "UNPLACED_ENTRY",
    "UNTITLED_CHAIN",
    "buildChainPlot",
    "chainAccessibleName",
    "chainSequence",
    "chainTitle",
    "entriesText",
    "entryLabel",
    "formatDelta",
    "keyHeader",
    "middleTruncate",
    "shortEntryId",
    "spanText",
    "whyRows",
  ]);
  const NOT_STRINGS = new Set([
    "CORRELATION_AXIS_TICKS",
    "CORRELATION_CONNECTOR_CAP",
    "CORRELATION_MARKER_CAP",
    "CORRELATION_MIN_WINDOW_MS",
    "CORRELATION_SEQUENCE_INITIAL",
    "CORRELATION_WINDOW_PAD_RATIO",
    "KEY_VALUE_DISPLAY_CHARS",
    "axisTicks",
    "defaultLaneWindow",
    "describeLanes",
    "evidenceForEdge",
    "isPartialChain",
    "isProvenUnplaced",
    "laneKeyOf",
    "levelOfSeverity",
    "memberLinkSummary",
    "partitionUnplaced",
    "placeInWindow",
    "reconcileSelection",
  ]);

  it("classifies every runtime export of both modules, so a new string is audited", () => {
    const exported = [...Object.keys(copyExports), ...Object.keys(viewModelExports)];
    const unclassified = exported.filter((name) => !STRING_EXPORTS.has(name) && !NOT_STRINGS.has(name));
    expect(unclassified).toEqual([]);
  });

  const items = [eventItem(1, T0, "info", "started", 72), eventItem(2, T0 + 6_000, "error", "failed", 76)];
  const everyId = new Set([rid(1), rid(2), rid(3), "x"]);
  const weakEvidence: [string, UnplacedEvidence][] = [
    ["the scan did not finish", { scanComplete: false, unplacedListComplete: true, unplacedIds: everyId }],
    ["the unplaced list is cut", { scanComplete: true, unplacedListComplete: false, unplacedIds: everyId }],
    ["the id is not on the list", { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set() }],
    ["neither is known", { scanComplete: false, unplacedListComplete: false, unplacedIds: new Set() }],
  ];
  const shapes: [string, CorrelationChain, TimelineItem[]][] = [
    ["a pair with one item read", chainFor("exactPair", [items[0]!]), [items[0]!]],
    ["a pair with no item read", chainFor("exactPair", []), []],
    ["an ambiguous group with one item read", chainFor("group3", [items[0]!]), [items[0]!]],
    ["a coverage blocked pair with no item read", chainFor("gappedPair", []), []],
  ];

  function everyString(chain: CorrelationChain, read: TimelineItem[], evidence: UnplacedEvidence): string[] {
    const itemsById = mapOf(read);
    const narrowed = scopeDisclosure({ visibleCount: 2, loadedCount: 10, textLogCount: 3 });
    const incomplete = { edgeInputComplete: false, unloadedEdgeCount: 9 };
    const view = { edgeInputComplete: true, narrowed: false, gaps: classifyCoverageGaps([], 0) };
    const plot = buildChainPlot({ chain, itemsById, ...view });
    // An explicit window that leaves every member outside it, so the pinned labels are built.
    const pinned = buildChainPlot({ chain, itemsById, ...view, window: { startMs: T0 + 1, endMs: T0 + 2 } });
    const logLine: TimelineItem = {
      timestampMs: T0,
      severity: "warning",
      message: "line",
      origin: {
        kind: "log",
        file: "C:\\Logs\\AppEnforce.log",
        component: null,
        line: 9,
        source: "writer.cpp",
        machine: null,
        bundle: null,
        recordId: 9,
      },
    };
    const lane = describeLanes([logLine.origin, ...read.map((item) => item.origin)])[0];
    return [
      unresolvedNotice(chain, evidence) ?? "",
      chainCopyText({
        chain,
        itemsById,
        timeZoneMode: "utc",
        scope: narrowed,
        edgeInput: incomplete,
        unplaced: evidence,
      }),
      ...whyRows(chain, itemsById, evidence).map((row) => row.entry),
      ...whyRows(chain, itemsById).map((row) => row.entry),
      chainTitle(chain),
      chainAccessibleName(chain),
      UNTITLED_CHAIN,
      UNLOADED_ENTRY,
      NOT_LINKED_LABEL,
      NO_LOADED_LINK_LABEL,
      entriesText(chain.memberCount),
      whyHeading(chain.strength),
      whyStatement(chain),
      STRENGTH_LABELS[chain.strength],
      edgeInputNotice(incomplete) ?? "",
      edgeInputNotice({ edgeInputComplete: false, unloadedEdgeCount: 0 }) ?? "",
      renderCapNotice({ shown: 100, totalCount: 120, omittedCount: 20 }) ?? "",
      plotOmissionNotice({ omittedMarkers: 4, omittedConnectors: 2 }) ?? "",
      narrowed?.strengthNote ?? "",
      narrowed?.textLogNote ?? "",
      keyKindLabel("activityId"),
      keyHeader(chain.keys)?.shortValue ?? "",
      ...plot.members.flatMap((marker) => [marker.entry, marker.pinLabel ?? ""]),
      ...pinned.members.flatMap((marker) => [marker.entry, marker.pinLabel ?? ""]),
      ...read.flatMap((item) => [shortEntryId(item, undefined), entryLabel(item, undefined)]),
      shortEntryId(logLine, lane),
      entryLabel(logLine, lane),
      spanText(chain.startMs, chain.endMs, "utc") ?? "",
      spanText(null, null, "utc") ?? "",
      spanText(null, null, "local") ?? "",
      ...[0, 1, 850, 3_300, 60_000, 125_000, 3_840_000, 97_200_000, -5_000].map(formatDelta),
      middleTruncate("{3b7e9c1a-5d24-4f8e-a0c6-1e2b3d4f5a6b}"),
      ...chainSequence(chain, itemsById).entries.flatMap((entry) => [entry.entry, entry.laneLabel]),
    ];
  }

  it("builds pinned labels for the audit, so shortEntryId and the pin text are really run", () => {
    const view = { edgeInputComplete: true, narrowed: false, gaps: classifyCoverageGaps([], 0) };
    const chain = chainFor("exactPair", items);
    const pinned = buildChainPlot({
      chain,
      itemsById: mapOf(items),
      ...view,
      window: { startMs: T0 + 1, endMs: T0 + 2 },
    });
    expect(pinned.members.map((marker) => marker.pinLabel)).toEqual(["72 \u00b7 1 ms earlier", "76 \u00b7 6 s later"]);
  });

  it("calls every string-producing export of the view model, by name, in the helper", () => {
    // The manifest proves each export is classified; this proves the ones classified as producing
    // text are really called by the audit, so an edit to one of them is audited too.
    const called = everyString.toString();
    for (const name of [
      "spanText",
      "formatDelta",
      "shortEntryId",
      "entryLabel",
      "middleTruncate",
      "keyHeader",
      "whyRows",
      "chainSequence",
      "chainTitle",
      "chainAccessibleName",
      "entriesText",
      "buildChainPlot",
      "unresolvedNotice",
      "chainCopyText",
      "edgeInputNotice",
      "renderCapNotice",
      "plotOmissionNotice",
      "scopeDisclosure",
      "whyHeading",
      "whyStatement",
      "keyKindLabel",
    ]) {
      expect(called, name).toContain(name);
    }
  });

  for (const [shapeName, chain, read] of shapes) {
    it.each(weakEvidence)(`says nothing unproven for ${shapeName} when %s`, (_why, evidence) => {
      for (const text of everyString(chain, read, evidence)) {
        expect(text).not.toMatch(NO_UNPROVEN_CLAIM);
      }
    });
  }

  it("still says it, in the places that may, once the proof holds", () => {
    const chain = chainFor("exactPair", [items[0]!]);
    const proof: UnplacedEvidence = {
      scanComplete: true,
      unplacedListComplete: true,
      unplacedIds: new Set([rid(2)]),
    };
    expect(unresolvedNotice(chain, proof)).toBe(
      "1 of 2 entries carry no timestamp, so they are not placed on the plot.",
    );
    const text = chainCopyText({
      chain,
      itemsById: mapOf([items[0]!]),
      timeZoneMode: "utc",
      scope: null,
      edgeInput: COMPLETE,
      unplaced: proof,
    });
    expect(text).toContain("Entries: 2 (1 placed, 1 not placed)");
    expect(text).toContain("Entries without a timeline position:");
    expect(text).toContain("Entry without a timeline position: activityId = x");
  });

  it("splits a chain's itemless entries into the proven and the unknown when only some are proven", () => {
    const edges = [rid(5), rid(6), rid(7)].map((to, i) => ({
      ...fixtureEdges("exactPair")[0]!,
      id: `e${i}`,
      fromId: rid(4),
      toId: to,
      evidence: [],
    }));
    const model = buildCorrelationChains({
      items: [],
      timelineEdges: edges,
      totalTimelineEdges: edges.length,
      findings: [],
    });
    const chain = model.chains[0]!;
    const text = chainCopyText(
      copyInput(chain, [], {
        unplaced: { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set([rid(5), rid(6)]) },
      }),
    );
    expect(text).toContain("Entries: 4 (0 placed, 2 not placed, 2 with no loaded position)");
    expect(text).toMatch(/Entries without a timeline position:\n {4}.*record5\n {4}.*record6/);
    expect(text).toMatch(/Entries with no loaded timeline position:\n {4}.*record4\n {4}.*record7/);
  });
});
