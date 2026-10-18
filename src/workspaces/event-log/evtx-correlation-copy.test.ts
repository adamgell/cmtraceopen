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
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  NOT_READ_NOTE,
  NO_SELECTION_TEXT,
  NO_SESSION_TEXT,
  READING_WINDOW_TEXT,
  SCOPE_NOT_KNOWN_NOTICE,
  STRENGTH_LABELS,
  UNREAD_SOURCES_NOTE,
  UNTIMED_TEXT,
  ambiguousEventNote,
  chainCopyText,
  coverageGapNotice,
  dockOmissionNotice,
  dockSubtitle,
  edgeErrorNotice,
  edgeInputNotice,
  emptyWindowText,
  keyKindLabel,
  nearbyReason,
  openDisabledText,
  moreText,
  notReadNote,
  outsideWindowNote,
  partialChainTitle,
  pastCapNotice,
  plotOmissionNotice,
  renderCapNotice,
  scanNotice,
  sharedOriginNote,
  scopeDisclosure,
  sourcesText,
  unmatchableNote,
  unresolvedNotice,
  whyHeading,
  whyStatement,
  windowFailureText,
  windowNotice,
  windowWidthLabel,
  type ChainCopyInput,
  type UnplacedEvidence,
} from "./evtx-correlation-copy";
import * as copyExports from "./evtx-correlation-copy";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import * as viewModelExports from "./evtx-correlation-view-model";
import {
  IN_ANOTHER_CHAIN_LABEL,
  LINK_TO_EVENT_UNKNOWN_LABEL,
  NOT_IN_THIS_CHAIN_LABEL,
  NOT_LINKED_LABEL,
  NO_LOADED_LINK_LABEL,
  UNLOADED_ENTRY,
  UNTITLED_CHAIN,
  axisTicks,
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
  tickLabels,
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

describe("scopeDisclosure with a scope that is not known (P5)", () => {
  it("says so, and never reads it as nothing narrowed", () => {
    const disclosure = scopeDisclosure(null);
    expect(disclosure).toEqual({ strengthNote: SCOPE_NOT_KNOWN_NOTICE, textLogNote: null });
    expect(SCOPE_NOT_KNOWN_NOTICE).toBe(
      "The events this model was built from are not known here, so events outside them may make an Exact link ambiguous.",
    );
  });

  it("goes into the copied text, so a paste cannot read as more certain than the view", () => {
    const text = chainCopyText({
      chain: chainFor("exactPair", [eventItem(1, T0, "info", "a", 101), eventItem(2, T0 + 1_000, "info", "b", 102)]),
      itemsById: mapOf([eventItem(1, T0, "info", "a", 101), eventItem(2, T0 + 1_000, "info", "b", 102)]),
      timeZoneMode: "utc",
      scope: scopeDisclosure(null),
      edgeInput: COMPLETE,
      unplaced: PROVEN,
    });
    expect(text).toContain(SCOPE_NOT_KNOWN_NOTICE);
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

describe("pastCapNotice", () => {
  it("says the selected row is listed after the rows the cap kept, with the number it kept", () => {
    expect(pastCapNotice(100)).toBe("The selected chain is past the first 100 rows, so it is listed after them.");
    expect(pastCapNotice(1_000)).toContain("first 1,000 rows");
  });

  it("is not the cap line and claims nothing about edges", () => {
    expect(pastCapNotice(100)).not.toMatch(/omitted|paged|bounded|edges/);
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

describe("coverageGapNotice", () => {
  const gaps = (global: boolean, previewCut: boolean) => ({ originIds: new Set<string>(), global, previewCut });

  it("says nothing when no gap stops the view from being whole", () => {
    expect(coverageGapNotice(gaps(false, false))).toBeNull();
    // A gap that names one origin is attributed to that origin, not to the whole view.
    expect(coverageGapNotice({ originIds: new Set(["a"]), global: false, previewCut: false })).toBeNull();
  });

  it("states each cause in its own words, and always as a coverage state, never as no link", () => {
    expect(coverageGapNotice(gaps(true, false))).toBe(
      "The engine limited correlation, so some entries may not have been correlated and chains may be incomplete.",
    );
    expect(coverageGapNotice(gaps(false, true))).toBe(
      "More coverage gaps may exist than are listed, so some entries may not have been correlated and chains may be incomplete.",
    );
    expect(coverageGapNotice(gaps(true, true))).toMatch(/limited correlation and may report more coverage gaps/);
    for (const [global, cut] of [[true, false], [false, true], [true, true]] as const) {
      expect(coverageGapNotice(gaps(global, cut))).not.toMatch(/no link|not linked/i);
    }
  });

  it("is on for the safe value of an unknown session", () => {
    expect(coverageGapNotice({ originIds: new Set(), global: false, previewCut: true })).not.toBeNull();
  });
});

describe("scanNotice and edgeErrorNotice", () => {
  it("say nothing unless reading the timeline stopped early", () => {
    for (const state of ["idle", "running", "complete"] as const) {
      expect(scanNotice({ state, stoppedBy: null, error: null }), state).toBeNull();
    }
    expect(edgeErrorNotice(null)).toBeNull();
  });

  it("name what stopped the read, and only claim that no position was loaded", () => {
    expect(scanNotice({ state: "incomplete", stoppedBy: "budget", error: null })).toBe(
      "Reading the timeline stopped at its memory limit, so some entries have no loaded timeline position.",
    );
    expect(scanNotice({ state: "incomplete", stoppedBy: "error", error: "timeline down" })).toBe(
      "Reading the timeline stopped on an error (timeline down), so some entries have no loaded timeline position.",
    );
    expect(scanNotice({ state: "incomplete", stoppedBy: "error", error: null })).toBe(
      "Reading the timeline stopped on an error, so some entries have no loaded timeline position.",
    );
    expect(scanNotice({ state: "incomplete", stoppedBy: null, error: null })).toBe(
      "Reading the timeline did not finish, so some entries have no loaded timeline position.",
    );
    expect(edgeErrorNotice("edges down")).toBe("Loading correlation edges stopped on an error (edges down).");
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
 * over each way the proof can fail. The manifest below makes a new export fail this file until it
 * is named, by hand, as producing text or not; it does not show that a path inside an existing
 * export is reached by the audit, or that a name is in the right set.
 */
describe("no string claims an entry is unplaced without proof", () => {
  const STRING_EXPORTS = new Set([
    // evtx-correlation-copy.ts
    "DOCK_SCOPE_NOTE",
    "LINKS_LOADING_TEXT",
    "NOT_IN_TIMELINE_NOTE",
    "NOT_READ_NOTE",
    "NO_SELECTION_TEXT",
    "NO_SESSION_TEXT",
    "READING_WINDOW_TEXT",
    "SCOPE_NOT_KNOWN_NOTICE",
    "STRENGTH_LABELS",
    "UNREAD_SOURCES_NOTE",
    "ambiguousEventNote",
    "chainCopyText",
    "coverageGapNotice",
    "dockOmissionNotice",
    "dockSubtitle",
    "edgeErrorNotice",
    "edgeInputNotice",
    "emptyWindowText",
    "keyKindLabel",
    "nearbyReason",
    "openDisabledText",
    "moreText",
    "notReadNote",
    "outsideWindowNote",
    "partialChainTitle",
    "pastCapNotice",
    "plotOmissionNotice",
    "renderCapNotice",
    "scanNotice",
    "scopeDisclosure",
    "sharedOriginNote",
    "sourcesText",
    "unmatchableNote",
    "unresolvedNotice",
    "whyHeading",
    "whyStatement",
    "windowFailureText",
    "windowNotice",
    "windowWidthLabel",
    // evtx-correlation-view-model.ts
    "IN_ANOTHER_CHAIN_LABEL",
    "LINK_TO_EVENT_UNKNOWN_LABEL",
    "NOT_IN_THIS_CHAIN_LABEL",
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
    "tickLabels",
    "whyRows",
  ]);
  const NOT_STRINGS = new Set([
    // The dock's untimed sentence states a fact read from the SELECTED EVENT'S OWN timestamp field
    // (a record is untimed when its epoch is not a usable time). It says nothing about an entry of
    // the unplaced list, which is what this audit guards, so the audit does not print it.
    "UNTIMED_TEXT",
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
    "listedRows",
    "memberLinkSummary",
    "partitionUnplaced",
    "placeInWindow",
    "reconcileSelection",
    // A predicate over the plot's inputs: it produces no text.
    "sessionSpeaksForAbsence",
  ]);

  it("names every runtime export of both modules in one of the two sets", () => {
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

  /** Every string the dock can say, over every state that changes its words. */
  function dockStrings(): string[] {
    const partial = { complete: false, windowItems: 40, omittedItems: 15, items: new Array(25), halfWidthMs: 75_000, error: null };
    return [
      DOCK_SCOPE_NOTE,
      LINKS_LOADING_TEXT,
      NOT_IN_TIMELINE_NOTE,
      NOT_READ_NOTE,
      NO_SELECTION_TEXT,
      NO_SESSION_TEXT,
      READING_WINDOW_TEXT,
      UNREAD_SOURCES_NOTE,
      ambiguousEventNote(2),
      ambiguousEventNote(5),
      unmatchableNote(0, 75_000),
      unmatchableNote(1, 75_000),
      unmatchableNote(2_500, 120_000),
      ...[30_000, 75_000, 120_000, 300_000, 90_000, 500].map((ms) => windowWidthLabel(ms)),
      sourcesText(3, true),
      sourcesText(1, false),
      dockSubtitle({ eventId: 7, timeText: "10:20:00", halfWidthMs: 75_000, sources: sourcesText(2, true) }),
      dockSubtitle({ eventId: 7, timeText: "10:20:00", halfWidthMs: 120_000, sources: null }),
      windowFailureText(null),
      windowFailureText("session was not found"),
      windowNotice({ ...partial, stoppedBy: "callLimit" }) ?? "",
      windowNotice({ ...partial, stoppedBy: "budget" }) ?? "",
      windowNotice({ ...partial, stoppedBy: "error", error: "timeline down" }) ?? "",
      windowNotice({ ...partial, windowItems: null, omittedItems: null, items: [], stoppedBy: "error", error: "x" }) ?? "",
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 0 }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: true, unreadSources: false, updating: false, unplacedTotal: 0 }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: true, updating: false, unplacedTotal: 0 }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: true, unreadSources: true, updating: false, unplacedTotal: 0 }).text,
      outsideWindowNote(1, 3) ?? "",
      outsideWindowNote(3, 5) ?? "",
      sharedOriginNote(1) ?? "",
      sharedOriginNote(4) ?? "",
      notReadNote(1, 3) ?? "",
      notReadNote(3, 5) ?? "",
      partialChainTitle(5, 2, true),
      partialChainTitle(5, 2, false),
      moreText(3, true) ?? "",
      moreText(3, false) ?? "",
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: false, updating: true, unplacedTotal: 0 }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: false, updating: false, unplacedTotal: null }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 1 }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 12 }).text,
      ...(["notLinked", "noLoadedLink", "inAnotherChain", "linkUnknownToEvent", "ambiguousWithEvent", "coverageBlockedWithEvent"] as const).map((reason) => nearbyReason(reason)),
      dockOmissionNotice({ omittedMarkers: 2, omittedNearby: 3, omittedConnectors: 1, omittedSources: 2, omittedSourceEntries: 9 }) ?? "",
      dockOmissionNotice({ omittedMarkers: 1, omittedNearby: 1, omittedConnectors: 0, omittedSources: 1, omittedSourceEntries: 1 }) ?? "",
      ...(["loading", "notInTimeline", "notRead", "unmatchable", "notInChain", "ambiguous"] as const).map((reason) => openDisabledText(reason)),
    ];
  }

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
      IN_ANOTHER_CHAIN_LABEL,
      LINK_TO_EVENT_UNKNOWN_LABEL,
      NOT_IN_THIS_CHAIN_LABEL,
      entriesText(chain.memberCount),
      whyHeading(chain.strength),
      whyStatement(chain),
      STRENGTH_LABELS[chain.strength],
      edgeInputNotice(incomplete) ?? "",
      edgeInputNotice({ edgeInputComplete: false, unloadedEdgeCount: 0 }) ?? "",
      renderCapNotice({ shown: 100, totalCount: 120, omittedCount: 20 }) ?? "",
      pastCapNotice(100),
      ...dockStrings(),
      plotOmissionNotice({ omittedMarkers: 4, omittedConnectors: 2 }) ?? "",
      coverageGapNotice({ originIds: new Set(), global: true, previewCut: true }) ?? "",
      coverageGapNotice({ originIds: new Set(), global: true, previewCut: false }) ?? "",
      coverageGapNotice({ originIds: new Set(), global: false, previewCut: true }) ?? "",
      scanNotice({ state: "incomplete", stoppedBy: "budget", error: null }) ?? "",
      scanNotice({ state: "incomplete", stoppedBy: "error", error: "timeline down" }) ?? "",
      scanNotice({ state: "incomplete", stoppedBy: null, error: null }) ?? "",
      edgeErrorNotice("edges down") ?? "",
      narrowed?.strengthNote ?? "",
      SCOPE_NOT_KNOWN_NOTICE,
      scopeDisclosure(null)?.strengthNote ?? "",
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
      ...[0, 1, 850, 3_300, 60_000, 125_000, 3_840_000, 97_200_000, -5_000].map((ms) => formatDelta(ms)),
      middleTruncate("{3b7e9c1a-5d24-4f8e-a0c6-1e2b3d4f5a6b}"),
      // The axis labels, a clock or a day and a clock: they name a time, never a position.
      ...tickLabels(axisTicks({ startMs: T0, endMs: T0 + 10_000 }), "utc", { nowMs: T0 }),
      ...tickLabels(axisTicks({ startMs: T0, endMs: T0 + 48 * 3_600_000 }), "utc", { nowMs: T0 }),
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

  it("calls every string-producing export, by name, in the helper", () => {
    // The manifest check shows each export is named in one of the two sets, not that it is named
    // in the right one. This reads the helper's source as text and fails unless every export named
    // as producing text is called (a function) or read (a constant) in it; a call in a branch that
    // never runs would also pass. The list is the manifest itself, so an export added to it and
    // never called here fails. Only UNPLACED_ENTRY is left out: it is the one string that may say
    // "not placed", and only with proof, so the audit cannot print it without defeating its own
    // purpose.
    const called = everyString.toString() + dockStrings.toString();
    const producers = [...STRING_EXPORTS].filter((name) => name !== "UNPLACED_ENTRY");
    expect(producers.length).toBeGreaterThan(20);
    for (const name of producers) {
      // A function must be called, not merely named; a constant must be read. The test runner
      // rewrites an imported call to `(0, import.name)(...)`, hence the optional ")".
      const isConstant = /^[A-Z][A-Z0-9_]*$/.test(name);
      expect(called, name).toMatch(new RegExp(isConstant ? `\\b${name}\\b` : `\\b${name}\\)?\\(`));
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

describe("the dock's words (spec 8.12, #842)", () => {
  describe("windowWidthLabel", () => {
    it.each([
      [30_000, "\u00b130 s"],
      [75_000, "\u00b175 s"],
      [120_000, "\u00b12 min"],
      [300_000, "\u00b15 min"],
      [60_000, "\u00b11 min"],
      [90_000, "\u00b190 s"],
      [500, "\u00b1500 ms"],
    ])("names %i ms as %s", (ms, label) => {
      expect(windowWidthLabel(ms)).toBe(label);
    });
  });

  describe("sourcesText", () => {
    it("counts sources, singular for one", () => {
      expect(sourcesText(3, true)).toBe("3 sources");
      expect(sourcesText(1, true)).toBe("1 source");
    });

    it("says at least when the window was not read whole", () => {
      expect(sourcesText(3, false)).toBe("at least 3 sources");
      expect(sourcesText(1, false)).toBe("at least 1 source");
    });
  });

  describe("dockSubtitle", () => {
    it("is the spec's header line", () => {
      expect(dockSubtitle({ eventId: 4624, timeText: "10:20:00.000", halfWidthMs: 75_000, sources: "3 sources" })).toBe(
        "around Event 4624 \u00b7 10:20:00.000 \u00b7 window \u00b175 s \u00b7 3 sources",
      );
    });

    it("leaves the source count out when the window was not read, never as 0", () => {
      const text = dockSubtitle({ eventId: 7, timeText: "10:20:00", halfWidthMs: 120_000, sources: null });
      expect(text).toBe("around Event 7 \u00b7 10:20:00 \u00b7 window \u00b12 min");
      expect(text).not.toMatch(/source|\b0\b/);
    });
  });

  describe("the sentences the selection and the session can leave", () => {
    it("says what the spec says for an event with no timestamp", () => {
      expect(UNTIMED_TEXT).toBe("This event has no timestamp; it cannot be placed.");
    });

    it("asks for a selection in plain words", () => {
      expect(NO_SELECTION_TEXT).toBe("Select an event to see what happened around it.");
    });

    it("claims no link while the links are not in", () => {
      expect(LINKS_LOADING_TEXT).toMatch(/still loading/);
      expect(LINKS_LOADING_TEXT).not.toMatch(/not linked|no link/i);
    });
  });

  describe("windowNotice", () => {
    const base = { complete: false, windowItems: 2_500, omittedItems: 1_900, items: new Array(600), halfWidthMs: 75_000, error: null };

    it("is silent for a window that was read whole", () => {
      expect(windowNotice({ ...base, complete: true, omittedItems: 0, stoppedBy: null })).toBeNull();
    });

    it("gives exact numbers and names the call limit", () => {
      expect(windowNotice({ ...base, stoppedBy: "callLimit" })).toBe(
        "Showing 600 of 2,500 entries within \u00b175 s; reading stopped at its call limit, so entries and sources may be missing.",
      );
    });

    it("names the memory limit and an error, with the error's own words", () => {
      expect(windowNotice({ ...base, stoppedBy: "budget" })).toContain("reading stopped at its memory limit");
      expect(windowNotice({ ...base, stoppedBy: "error", error: "timeline down" })).toContain(
        "reading stopped at an error (timeline down)",
      );
      expect(windowNotice({ ...base, stoppedBy: "error", error: null })).toContain("reading stopped at an error,");
    });

    it("says the read failed, with no count, when the first reply never came, never '0 entries'", () => {
      const text = windowNotice({ ...base, windowItems: null, omittedItems: null, items: [], stoppedBy: "error", error: "gone" });
      expect(text).toBe("The entries around this event could not be read (gone).");
      expect(text).not.toMatch(/\b0\b|showing/i);
      expect(windowFailureText(null)).toBe("The entries around this event could not be read.");
    });

    it("never says the unread entries do not exist", () => {
      for (const stoppedBy of ["callLimit", "budget", "error"] as const) {
        expect(windowNotice({ ...base, stoppedBy }) ?? "").not.toMatch(/no other|none|nothing|do not exist/i);
      }
    });
  });

  describe("emptyWindowText (an absence claim, so conditional)", () => {
    const width = 75_000;

    it("makes the spec's claim only when nothing is narrowed and no source went unread", () => {
      expect(emptyWindowText({ halfWidthMs: width, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 0 })).toEqual({
        text: "No other sources have entries within \u00b175 s.",
        absolute: true,
      });
    });

    it("says what it looked in, and what it did not, when narrowed", () => {
      const { text, absolute } = emptyWindowText({ halfWidthMs: width, narrowed: true, unreadSources: false, updating: false, unplacedTotal: 0 });
      expect(absolute).toBe(false);
      expect(text).toBe(
        "No other visible sources have entries within \u00b175 s. Events hidden by the current filters or time range are not searched.",
      );
    });

    it("says it when a source went unread", () => {
      const { text, absolute } = emptyWindowText({ halfWidthMs: width, narrowed: false, unreadSources: true, updating: false, unplacedTotal: 0 });
      expect(absolute).toBe(false);
      expect(text).toBe(
        "No other visible sources have entries within \u00b175 s. Some sources were not fully read, so entries may be missing.",
      );
    });

    it("withdraws the claim while the pair is an earlier session's, and says the timeline is being rebuilt", () => {
      const { text, absolute } = emptyWindowText({ halfWidthMs: width, narrowed: false, unreadSources: false, updating: true, unplacedTotal: 0 });
      expect(absolute).toBe(false);
      expect(text).toBe("No other visible sources have entries within \u00b175 s. The timeline is being rebuilt, so this may change.");
    });

    describe("entries the engine could not place are in no window, so a window cannot speak for them (#842, review A1)", () => {
      const clear = { halfWidthMs: width, narrowed: false, unreadSources: false, updating: false };

      it("makes the claim only for a KNOWN count of zero", () => {
        expect(emptyWindowText({ ...clear, unplacedTotal: 0 }).absolute).toBe(true);
      });

      it("withdraws the claim for an unknown count, and says it is not known, never reading it as zero", () => {
        const { text, absolute } = emptyWindowText({ ...clear, unplacedTotal: null });
        expect(absolute).toBe(false);
        expect(text).toBe(
          "No other visible sources have entries within \u00b175 s. How many entries have no usable time is not known, and such entries are in no window.",
        );
      });

      it("withdraws the claim for a positive count and names it", () => {
        expect(emptyWindowText({ ...clear, unplacedTotal: 1 })).toEqual({
          text: "No other visible sources have entries within \u00b175 s. 1 entry has no usable time and appears in no window.",
          absolute: false,
        });
        expect(emptyWindowText({ ...clear, unplacedTotal: 1_200 }).text).toContain("1,200 entries have no usable time and appear in no window.");
      });

      it("says nothing about unplaced entries when the claim is made, and adds it to the other qualifiers when it is not", () => {
        expect(emptyWindowText({ ...clear, unplacedTotal: 0 }).text).not.toMatch(/usable time/);
        const all = emptyWindowText({ halfWidthMs: width, narrowed: true, unreadSources: true, updating: true, unplacedTotal: 3 }).text;
        expect(all).toMatch(/not searched\..*not fully read.*being rebuilt.*3 entries have no usable time/);
      });
    });

    it("says both when both hold, and follows the chosen width", () => {
      const { text } = emptyWindowText({ halfWidthMs: 300_000, narrowed: true, unreadSources: true, updating: false, unplacedTotal: 0 });
      expect(text).toContain("within \u00b15 min.");
      expect(text).toContain("not searched.");
      expect(text).toContain("not fully read");
    });
  });

  describe("outsideWindowNote and partialChainTitle", () => {
    it("is silent when every entry of the row is in the window", () => {
      expect(outsideWindowNote(0, 4)).toBeNull();
    });

    it("counts the entries the window does not hold, and never places them", () => {
      expect(outsideWindowNote(1, 3)).toBe("1 of 3 entries of this chain is outside this window, so it is not shown here.");
      expect(outsideWindowNote(3, 5)).toBe("3 of 5 entries of this chain are outside this window, so they are not shown here.");
    });

    it("claims no title for a row the window holds only part of", () => {
      expect(partialChainTitle(5, 2, true)).toBe("Chain of 5 entries (2 in this window)");
    });
  });

  describe("a window that was not read whole never says an entry is outside it (#842, review A1)", () => {
    it("counts the entries of the row that are not among those read, exactly, and says nothing of where they are", () => {
      expect(notReadNote(0, 3)).toBeNull();
      expect(notReadNote(1, 2)).toBe("1 of 2 entries of this chain is not among the entries read, so it is not shown here.");
      expect(notReadNote(3, 5)).toBe("3 of 5 entries of this chain are not among the entries read, so they are not shown here.");
      expect(notReadNote(3, 5)).not.toMatch(/outside/);
    });

    it("titles a row by how many entries were READ when the window was not read whole, and in the window when it was", () => {
      expect(partialChainTitle(2, 1, false)).toBe("Chain of 2 entries (1 read)");
      expect(partialChainTitle(2, 1, false)).not.toMatch(/in this window/);
      expect(partialChainTitle(2, 1, true)).toBe("Chain of 2 entries (1 in this window)");
    });

    it("says 'at least' for a count taken from the entries read, and '+n' only for an exact one", () => {
      expect(moreText(0, true)).toBeNull();
      expect(moreText(0, false)).toBeNull();
      expect(moreText(6, true)).toBe("+6 more");
      expect(moreText(6, false)).toBe("at least 6 more");
      expect(moreText(1_200, false)).toBe("at least 1,200 more");
    });
  });

  describe("nearbyReason (evidence first: by time, never a link)", () => {
    const reasons = ["notLinked", "noLoadedLink", "inAnotherChain", "linkUnknownToEvent", "ambiguousWithEvent", "coverageBlockedWithEvent"] as const;

    it("says time only in the three ruled reasons", () => {
      for (const reason of ["notLinked", "noLoadedLink", "inAnotherChain"] as const) {
        expect(nearbyReason(reason)).toMatch(/^time only/);
      }
    });

    it("does not call an entry time only when the engine reported a shared key with the event (additions awaiting a ruling)", () => {
      expect(nearbyReason("ambiguousWithEvent")).toBe("ambiguous with this event");
      expect(nearbyReason("coverageBlockedWithEvent")).toBe("coverage blocked with this event");
      for (const reason of ["ambiguousWithEvent", "coverageBlockedWithEvent"] as const) {
        expect(nearbyReason(reason)).not.toMatch(/time only|not linked|no link/);
      }
    });

    it("says 'not linked' only for the entry the session can speak for", () => {
      expect(nearbyReason("notLinked")).toBe("time only, not linked");
      for (const reason of reasons.filter((r) => r !== "notLinked")) {
        expect(nearbyReason(reason)).not.toMatch(/not linked/);
      }
      expect(nearbyReason("noLoadedLink")).toBe("time only, no loaded link");
      expect(nearbyReason("inAnotherChain")).toBe("time only; in another chain");
    });

    it("says an entry is linked but not known to be linked to THIS event, when the event could not be identified", () => {
      expect(nearbyReason("linkUnknownToEvent")).toBe("linked, but its link to this event is not known");
      expect(nearbyReason("linkUnknownToEvent")).not.toMatch(/time only|in another chain|not linked/);
    });

    it("keeps the six reasons apart", () => {
      expect(new Set(reasons.map((reason) => nearbyReason(reason))).size).toBe(6);
    });
  });

  describe("dockOmissionNotice", () => {
    const none = { omittedMarkers: 0, omittedNearby: 0, omittedConnectors: 0, omittedSources: 0, omittedSourceEntries: 0 };

    it("is silent when nothing was left out", () => {
      expect(dockOmissionNotice(none)).toBeNull();
    });

    it("says how many sources and entries each cap left out", () => {
      expect(dockOmissionNotice({ ...none, omittedSources: 2, omittedSourceEntries: 9 })).toBe(
        "2 more sources not drawn (9 entries).",
      );
      expect(dockOmissionNotice({ ...none, omittedSources: 1, omittedSourceEntries: 1 })).toBe(
        "1 more source not drawn (1 entry).",
      );
      expect(dockOmissionNotice({ ...none, omittedMarkers: 2 })).toBe("2 entries of this chain not drawn.");
      expect(dockOmissionNotice({ ...none, omittedNearby: 1 })).toBe("1 more nearby entry not drawn.");
      expect(dockOmissionNotice({ ...none, omittedConnectors: 3 })).toBe("3 connectors are not drawn.");
    });

    it("joins what several caps left out", () => {
      expect(dockOmissionNotice({ ...none, omittedSources: 1, omittedSourceEntries: 4, omittedNearby: 2 })).toBe(
        "1 more source not drawn (4 entries); 2 more nearby entries not drawn.",
      );
    });
  });

  describe("what is said when the selected event cannot be identified (#842, review A1)", () => {
    it("gives the absence claim its own words and the unread case its own, never the same", () => {
      expect(NOT_IN_TIMELINE_NOTE).toMatch(/not among the entries this timeline was built from/);
      expect(NOT_READ_NOTE).toBe(
        "The read of this window stopped before this event was found, so whether it is among the entries, and what it is linked to, are not known.",
      );
      expect(NOT_READ_NOTE).not.toMatch(/not among|filters/);
    });

    it("counts the entries that could each be the event, and leaves them out of the context", () => {
      expect(ambiguousEventNote(2)).toBe(
        "2 entries of this window match this event, so which one it is cannot be told. They are not drawn as context, and no link is shown.",
      );
      expect(ambiguousEventNote(1_200)).toContain("1,200 entries");
    });

    it("says an event with no record identity cannot be found among the entries, with the exact count", () => {
      expect(unmatchableNote(2_500, 75_000)).toBe(
        "This event has no record identity the timeline can match, so which of the 2,500 entries within \u00b175 s it is cannot be told. They are not drawn, and no link is shown.",
      );
      expect(unmatchableNote(1, 120_000)).toContain("which of the 1 entry within \u00b12 min it is");
      expect(unmatchableNote(0, 75_000)).toBe(
        "This event has no record identity the timeline can match, so it cannot be found among the entries within \u00b175 s. No link is shown.",
      );
      for (const entries of [0, 1, 2_500]) expect(unmatchableNote(entries, 75_000)).not.toMatch(/not among|filters/);
    });
  });

  describe("openDisabledText", () => {
    it("gives each reason its own visible words", () => {
      const reasons = (["loading", "notInTimeline", "notRead", "unmatchable", "notInChain", "ambiguous"] as const).map((r) => openDisabledText(r));
      expect(new Set(reasons).size).toBe(6);
      expect(openDisabledText("notInChain")).toBe("Not in a loaded chain.");
    });
  });

  it("says nothing in the dock reads as cause or consequence", () => {
    const causal = /caused|because of|as a result|led to|results? in|follows from|explains|due to/i;
    const strings = [
      ambiguousEventNote(3),
      unmatchableNote(40, 75_000),
      NOT_READ_NOTE,
      DOCK_SCOPE_NOTE,
      LINKS_LOADING_TEXT,
      NOT_IN_TIMELINE_NOTE,
      NO_SELECTION_TEXT,
      NO_SESSION_TEXT,
      READING_WINDOW_TEXT,
      UNREAD_SOURCES_NOTE,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: true, unreadSources: true, updating: false, unplacedTotal: 0 }).text,
      emptyWindowText({ halfWidthMs: 75_000, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 0 }).text,
      ...(["notLinked", "noLoadedLink", "inAnotherChain", "linkUnknownToEvent", "ambiguousWithEvent", "coverageBlockedWithEvent"] as const).map((r) => nearbyReason(r)),
    ];
    for (const text of strings) expect(text).not.toMatch(causal);
  });
});

/**
 * The Details context list says "entries" where the dock says "sources" and "listed" where the dock
 * says "drawn" (#843). Same facts, same conditions, so the same functions with a different noun; the
 * dock's own words are untouched.
 */
describe("the notes shared by the dock and the Details context list", () => {
  const WIDTH = 300_000;
  const whole = { halfWidthMs: WIDTH, narrowed: false, unreadSources: false, updating: false, unplacedTotal: 0 };

  describe("emptyWindowText with a subject", () => {
    it("says 'sources' by default and when asked, exactly as before", () => {
      expect(emptyWindowText(whole)).toEqual({ text: "No other sources have entries within \u00b15 min.", absolute: true });
      expect(emptyWindowText({ ...whole, subject: "sources" })).toEqual(emptyWindowText(whole));
    });

    it("says 'entries' for the list, and makes the absolute claim only under the same five inputs", () => {
      const list = { ...whole, subject: "entries" as const };
      expect(emptyWindowText(list)).toEqual({ text: "No other entries within \u00b15 min.", absolute: true });
      for (const [why, change] of [
        ["a narrowed scope", { narrowed: true }],
        ["an unread source", { unreadSources: true }],
        ["an earlier session's pair", { updating: true }],
        ["an unknown unplaced count", { unplacedTotal: null }],
        ["entries that have no usable time", { unplacedTotal: 3 }],
      ] as const) {
        const said = emptyWindowText({ ...list, ...change });
        expect(said.absolute, why).toBe(false);
        expect(said.text, why).toMatch(/^No other visible entries within \u00b15 min\./);
      }
    });

    it("keeps the qualifiers of the dock's sentence for either subject", () => {
      const dock = emptyWindowText({ ...whole, narrowed: true, unreadSources: true, updating: true, unplacedTotal: 2 });
      const list = emptyWindowText({ ...whole, narrowed: true, unreadSources: true, updating: true, unplacedTotal: 2, subject: "entries" });
      const tail = (text: string) => text.slice(text.indexOf("\u00b15 min.") + "\u00b15 min.".length);
      expect(tail(list.text)).toBe(tail(dock.text));
      expect(list.text).not.toMatch(NO_UNPROVEN_CLAIM);
    });
  });

  describe("the notes about the event that cannot be told from the entries", () => {
    it("say 'not drawn' for the dock by default and for 'dock'", () => {
      expect(ambiguousEventNote(2)).toContain("They are not drawn as context");
      expect(ambiguousEventNote(2, "dock")).toBe(ambiguousEventNote(2));
      expect(unmatchableNote(3, 75_000)).toContain("They are not drawn");
      expect(unmatchableNote(3, 75_000, "dock")).toBe(unmatchableNote(3, 75_000));
    });

    it("say 'not listed' for the list, and never 'drawn'", () => {
      expect(ambiguousEventNote(2, "list")).toBe(
        "2 entries of this window match this event, so which one it is cannot be told. They are not listed, and no link is shown.",
      );
      expect(unmatchableNote(3, WIDTH, "list")).toBe(
        "This event has no record identity the timeline can match, so which of the 3 entries within \u00b15 min it is cannot be told. They are not listed, and no link is shown.",
      );
      for (const text of [ambiguousEventNote(5, "list"), unmatchableNote(1, WIDTH, "list"), unmatchableNote(0, WIDTH, "list")]) {
        expect(text).not.toMatch(/drawn/);
      }
    });

    it("count the same entries for either surface", () => {
      expect(unmatchableNote(0, WIDTH, "list")).toBe(unmatchableNote(0, WIDTH));
      expect(ambiguousEventNote(7, "list")).toContain("7 entries");
      expect(unmatchableNote(1, WIDTH, "list")).toContain("which of the 1 entry within");
    });
  });
});

describe("the note about entries read from an origin more than once (#843)", () => {
  it("is said for one entry and for several, and claims only what the count proves", () => {
    expect(sharedOriginNote(1)).toBe("1 entry read repeats another entry's origin and is counted once.");
    expect(sharedOriginNote(3)).toBe("3 entries read repeat another entry's origin and are counted once.");
    expect(sharedOriginNote(1500)).toBe("1,500 entries read repeat another entry's origin and are counted once.");
  });

  it("says nothing about a list or about the window, which it cannot know", () => {
    for (const text of [sharedOriginNote(1), sharedOriginNote(5)]) {
      expect(text).not.toMatch(/listed|window|shown|drawn/i);
      expect(text).not.toMatch(NO_UNPROVEN_CLAIM);
    }
  });

  it("is not said when there is nothing to say, and never for a negative count", () => {
    expect(sharedOriginNote(0)).toBeNull();
    expect(sharedOriginNote(-2)).toBeNull();
  });
});
