import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  countProblemLevels,
  countTextLogSources,
  hasReadAnything,
  loadedChannelCountFor,
  summarizeEvtxCorrelationStatus,
  summarizeVisibleRecords,
  useEvtxCorrelationStatusStore,
  useEvtxVisibleSummaryStore,
  valueForGeneration,
} from "./evtx-status-summary";
import moduleSource from "./evtx-status-summary.ts?raw";
import type { EvtxLevel, EvtxRecord } from "./types";
import {
  assertUnifiedTimelineShape,
  type TimelineCorrelationEdge,
} from "./unified-timeline";

const levels = (...list: EvtxLevel[]) => list.map((level) => ({ level }));

describe("countProblemLevels", () => {
  it("counts Critical and Error as errors, Warning as warnings, and ignores the rest", () => {
    expect(
      countProblemLevels(
        levels("Critical", "Error", "Warning", "Information", "Verbose", "Error"),
      ),
    ).toEqual({ errors: 3, warnings: 1 });
  });

  it("counts nothing for no records", () => {
    expect(countProblemLevels([])).toEqual({ errors: 0, warnings: 0 });
  });
});

/** A loaded record reduced to what the channel count reads. */
const loaded = (
  channel: string,
  originKind?: EvtxRecord["originKind"],
): Pick<EvtxRecord, "channel" | "originKind"> => ({ channel, originKind });

describe("loadedChannelCountFor", () => {
  const none = new Set<string>();

  it("counts the channels whose load completed in live mode, whatever the records say", () => {
    expect(
      loadedChannelCountFor({
        sourceMode: "live",
        loadedChannels: new Set(["System", "Application"]),
        records: [loaded("System")],
      }),
    ).toBe(2);
    expect(
      loadedChannelCountFor({ sourceMode: "live", loadedChannels: none, records: [loaded("System")] }),
    ).toBe(0);
  });

  it("counts the distinct channel names of the loaded event records in files mode", () => {
    expect(
      loadedChannelCountFor({
        sourceMode: "files",
        loadedChannels: none,
        records: [loaded("System"), loaded("Application"), loaded("System")],
      }),
    ).toBe(2);
  });

  it("does not count an archived text log as a channel", () => {
    // The archive reader sets `channel` to the text log's source label.
    expect(
      loadedChannelCountFor({
        sourceMode: "files",
        loadedChannels: none,
        records: [
          loaded("System", "event"),
          loaded("C:\\Evidence\\IntuneManagementExtension.log", "log"),
          loaded("C:\\Evidence\\IntuneManagementExtension.log", "log"),
        ],
      }),
    ).toBe(1);
  });

  it("counts a channel once when two files share it", () => {
    // Rotated archives repeat one channel once per file (Archive-System-1.evtx and -2.evtx).
    expect(
      loadedChannelCountFor({
        sourceMode: "files",
        loadedChannels: none,
        records: [
          loaded("System"),
          loaded("System"),
          loaded("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"),
        ],
      }),
    ).toBe(2);
  });

  it("counts nothing for a file that contributed no records", () => {
    // The parse result still lists the empty file's channel; no record names it.
    expect(
      loadedChannelCountFor({
        sourceMode: "files",
        loadedChannels: none,
        records: [loaded("System")],
      }),
    ).toBe(1);
    expect(loadedChannelCountFor({ sourceMode: "files", loadedChannels: none, records: [] })).toBe(0);
  });

  it("treats a record with no origin kind as an event, and nothing loaded as zero", () => {
    expect(
      loadedChannelCountFor({
        sourceMode: "files",
        loadedChannels: none,
        records: [loaded("Security", undefined)],
      }),
    ).toBe(1);
    expect(loadedChannelCountFor({ sourceMode: null, loadedChannels: none, records: [] })).toBe(0);
  });
});

describe("hasReadAnything", () => {
  it("needs a completed channel in live mode, whatever records are on screen", () => {
    expect(hasReadAnything({ sourceMode: "live", loadedChannelCount: 2, recordCount: 0 })).toBe(true);
    // A cancelled or refused read leaves loadedChannels empty even when partial records show.
    expect(hasReadAnything({ sourceMode: "live", loadedChannelCount: 0, recordCount: 40 })).toBe(false);
  });

  it("needs a record in files mode, event or archived text log", () => {
    expect(hasReadAnything({ sourceMode: "files", loadedChannelCount: 0, recordCount: 1 })).toBe(true);
    expect(hasReadAnything({ sourceMode: "files", loadedChannelCount: 0, recordCount: 0 })).toBe(false);
  });

  it("reads nothing when no source is open", () => {
    expect(hasReadAnything({ sourceMode: null, loadedChannelCount: 3, recordCount: 3 })).toBe(false);
  });
});

describe("countTextLogSources", () => {
  const archived = (sourceLabel: string): Pick<EvtxRecord, "originKind" | "sourceLabel"> => ({
    originKind: "log",
    sourceLabel,
  });
  const event = (sourceLabel: string): Pick<EvtxRecord, "originKind" | "sourceLabel"> => ({
    originKind: "event",
    sourceLabel,
  });

  it("counts distinct log-store files, not lines", () => {
    expect(
      countTextLogSources([{ filePath: "a.log" }, { filePath: "a.log" }, { filePath: "b.log" }], []),
    ).toBe(2);
  });

  it("adds the distinct source labels of archived text-log records", () => {
    expect(
      countTextLogSources(
        [{ filePath: "a.log" }],
        [archived("AgentExecutor.log"), archived("AgentExecutor.log"), archived("ime.log")],
      ),
    ).toBe(3);
  });

  it("counts a source that is both a log-store file and an archived record once", () => {
    expect(countTextLogSources([{ filePath: "ime.log" }], [archived("ime.log")])).toBe(1);
  });

  it("ignores event records, whose source label names an evtx file", () => {
    expect(countTextLogSources([], [event("System.evtx"), event("System.evtx")])).toBe(0);
    expect(countTextLogSources([], [])).toBe(0);
  });
});

describe("summarizeVisibleRecords", () => {
  it("summarizes the rows it is given and the loaded count behind them", () => {
    expect(
      summarizeVisibleRecords(
        levels("Error", "Critical", "Warning", "Information"),
        { events: 40, channels: 3, textLogs: 2 },
        7,
      ),
    ).toEqual({
      generation: 7,
      visible: 4,
      loaded: 40,
      channels: 3,
      textLogs: 2,
      errors: 2,
      warnings: 1,
    });
  });

  it("reports an empty grid as zero visible with the loaded count intact", () => {
    expect(summarizeVisibleRecords([], { events: 12, channels: 2, textLogs: 0 }, 3)).toEqual({
      generation: 3,
      visible: 0,
      loaded: 12,
      channels: 2,
      textLogs: 0,
      errors: 0,
      warnings: 0,
    });
  });
});

describe("valueForGeneration", () => {
  const summary = summarizeVisibleRecords(
    levels("Error"),
    { events: 1, channels: 1, textLogs: 0 },
    5,
  );

  it("returns the value only for the generation it was published under", () => {
    expect(valueForGeneration(summary, 5)).toBe(summary);
    expect(valueForGeneration(summary, 6)).toBeNull();
    expect(valueForGeneration(summary, 4)).toBeNull();
  });

  it("treats a missing value as not published", () => {
    expect(valueForGeneration(null, 5)).toBeNull();
    expect(valueForGeneration(undefined, 5)).toBeNull();
  });
});

/** An analysis session on screen: generation, session id and revision. */
const key = (generation: number, sessionId = "session-1", revision = 1) => ({
  generation,
  sessionId,
  revision,
});

describe("summarizeEvtxCorrelationStatus", () => {
  function pair(
    id: string,
    strength: TimelineCorrelationEdge["strength"],
    coverage: TimelineCorrelationEdge["coverage"] = { state: "covered" },
  ): TimelineCorrelationEdge {
    return {
      id,
      fromId: `${id}-a`,
      toId: `${id}-b`,
      key: { kind: "activityId", value: `key-${id}` },
      strength,
      confidence: "high",
      candidateIds: [],
      evidence: [{ originId: `${id}-a`, field: "activityId", value: `key-${id}` }],
      coverage,
    };
  }

  /**
   * `pairAndGroupDisjoint` is real parser output: one exact pair beside a three-member ambiguous
   * group. The candidate and coverage-blocked pairs are built by hand on fresh ids.
   */
  function chainModel(extra: TimelineCorrelationEdge[] = []) {
    const scenarios = fixtureDocument.scenarios as unknown as Record<
      string,
      { edges: unknown[]; coverageGaps: [] }
    >;
    const scenario = scenarios.pairAndGroupDisjoint;
    const decoded = assertUnifiedTimelineShape({
      items: [],
      unplaced: [],
      edges: scenario.edges,
      coverageGaps: scenario.coverageGaps,
    });
    const timelineEdges = [...decoded.edges, ...extra];
    return buildCorrelationChains({
      items: [],
      timelineEdges,
      totalTimelineEdges: timelineEdges.length,
      findings: [],
    });
  }

  it("takes the strength counts and the session's unplaced total, keyed by generation", () => {
    const model = chainModel([
      pair("candidate", "candidate"),
      pair("blocked", "exact", {
        state: "gap",
        gap: { source: "Live", reason: "channel not collected" },
      }),
    ]);

    expect(model.counts).toEqual({
      exact: 1,
      candidate: 1,
      ambiguous: 1,
      coverageBlocked: 1,
    });
    expect(summarizeEvtxCorrelationStatus(model, 4, key(9))).toEqual({
      generation: 9,
      sessionId: "session-1",
      revision: 1,
      exact: 1,
      candidate: 1,
      ambiguous: 1,
      unplaced: 4,
    });
  });

  it("yields no counts from a bounded edge preview, whose totals it cannot back", () => {
    const incomplete = buildCorrelationChains({
      items: [],
      timelineEdges: [pair("one", "exact")],
      // The session holds more edges than the preview carried.
      totalTimelineEdges: 250,
      findings: [],
    });

    expect(incomplete.edgeInputComplete).toBe(false);
    expect(summarizeEvtxCorrelationStatus(incomplete, 0, key(1))).toBeNull();
  });

  it("yields no counts for an invalid unplaced total", () => {
    const complete = chainModel();
    expect(summarizeEvtxCorrelationStatus(complete, 3, key(1))).not.toBeNull();
    expect(summarizeEvtxCorrelationStatus(complete, -1, key(1))).toBeNull();
    expect(summarizeEvtxCorrelationStatus(complete, Number.NaN, key(1))).toBeNull();
    expect(summarizeEvtxCorrelationStatus(complete, 1.5, key(1))).toBeNull();
  });
});

describe("published stores", () => {
  beforeEach(() => {
    useEvtxVisibleSummaryStore.setState({ summary: null });
    useEvtxCorrelationStatusStore.setState({ analysis: null, status: null });
  });
  afterEach(() => {
    useEvtxVisibleSummaryStore.setState({ summary: null });
    useEvtxCorrelationStatusStore.setState({ analysis: null, status: null });
  });

  const completeModel = {
    counts: { exact: 2, candidate: 1, ambiguous: 0, coverageBlocked: 0 },
    edgeInputComplete: true,
  };
  const statusFor = (analysis: ReturnType<typeof key>) => {
    const status = summarizeEvtxCorrelationStatus(completeModel, 0, analysis);
    if (status === null) throw new Error("expected a status");
    return status;
  };
  const current = () => useEvtxCorrelationStatusStore.getState().status;

  it("publishes and clears the visible summary", () => {
    expect(useEvtxVisibleSummaryStore.getState().summary).toBeNull();
    const summary = summarizeVisibleRecords(
      levels("Warning"),
      { events: 1, channels: 1, textLogs: 0 },
      2,
    );
    useEvtxVisibleSummaryStore.getState().publish(summary);
    expect(useEvtxVisibleSummaryStore.getState().summary).toBe(summary);
    useEvtxVisibleSummaryStore.getState().publish(null);
    expect(useEvtxVisibleSummaryStore.getState().summary).toBeNull();
  });

  it("holds counts only for the analysis session the workspace named", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    // Nothing is on screen yet, so counts from any session are refused.
    store.publish(statusFor(key(2)));
    expect(current()).toBeNull();

    store.setAnalysis(key(2));
    store.publish(statusFor(key(2)));
    expect(current()).toMatchObject({ sessionId: "session-1", revision: 1, exact: 2 });
  });

  it("refuses counts built for another session, revision or generation", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2, "session-2", 4));

    store.publish(statusFor(key(2, "session-1", 4)));
    store.publish(statusFor(key(2, "session-2", 3)));
    store.publish(statusFor(key(1, "session-2", 4)));

    expect(current()).toBeNull();
  });

  it("drops counts when the workspace names the next revision, and refuses them when published late", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2, "session-1", 1));
    store.publish(statusFor(key(2, "session-1", 1)));
    expect(current()).not.toBeNull();

    // The analysis was rebuilt: the old counts go, and work that finishes late cannot bring them back.
    store.setAnalysis(key(2, "session-1", 2));
    expect(current()).toBeNull();
    store.publish(statusFor(key(2, "session-1", 1)));
    expect(current()).toBeNull();

    store.publish(statusFor(key(2, "session-1", 2)));
    expect(current()).toMatchObject({ revision: 2 });
  });

  it("keeps counts when the same session is named again, and drops them when it is cleared", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2));
    store.publish(statusFor(key(2)));

    store.setAnalysis(key(2));
    expect(current()).not.toBeNull();

    store.setAnalysis(null);
    expect(current()).toBeNull();
    expect(useEvtxCorrelationStatusStore.getState().analysis).toBeNull();
    store.publish(statusFor(key(2)));
    expect(current()).toBeNull();
  });

  it("clears the counts on publish(null)", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2));
    store.publish(statusFor(key(2)));
    store.publish(null);
    expect(current()).toBeNull();
  });
});

/** Every module specifier a source imports, re-exports or dynamically imports. */
function moduleSpecifiers(source: string): string[] {
  const code = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
  const specifiers = new Set<string>();
  const patterns = [
    // import x from "m"; import type { x } from 'm'; export { x } from "m"; export * from "m";
    /\b(?:import|export)\b[^"'`;]*?\bfrom\s*(["'`])([^"'`]+)\1/g,
    // import "m"; (a bare side-effect import)
    /\bimport\s*(["'`])([^"'`]+)\1/g,
    // import("m")
    /\bimport\s*\(\s*(["'`])([^"'`]+)\1\s*\)/g,
    // require("m")
    /\brequire\s*\(\s*(["'`])([^"'`]+)\1\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of code.matchAll(pattern)) specifiers.add(match[2]);
  }
  return [...specifiers].sort();
}

describe("module purity", () => {
  it("collects imports in every form, so the purity check below cannot miss one", () => {
    expect(
      moduleSpecifiers(`
        import a from "./one";
        import type { B } from './two';
        import {
          c,
          d,
        } from "./three";
        import "./four";
        import './five';
        export { e } from "./six";
        export * from './seven';
        export type { F } from "./eight";
        const lazy = () => import("./nine");
        const cjs = require('./ten');
        // import "./commented";
        /* import "./blocked"; */
        const text = "not an import";
      `),
    ).toEqual(
      [
        "./one", "./two", "./three", "./four", "./five", "./six", "./seven", "./eight",
        "./nine", "./ten",
      ].sort(),
    );
  });

  it("imports neither the status bar, the evtx store, Tauri nor React", () => {
    expect(moduleSpecifiers(moduleSource)).toEqual(
      ["./evtx-correlation-chains", "./types", "zustand"].sort(),
    );
  });
});
