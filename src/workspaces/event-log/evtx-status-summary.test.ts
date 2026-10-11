import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  countProblemLevels,
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

describe("summarizeVisibleRecords", () => {
  it("summarizes the rows it is given and the loaded count behind them", () => {
    expect(
      summarizeVisibleRecords(
        levels("Error", "Critical", "Warning", "Information"),
        { events: 40, channels: 3 },
        7,
      ),
    ).toEqual({ generation: 7, visible: 4, loaded: 40, channels: 3, errors: 2, warnings: 1 });
  });

  it("reports an empty grid as zero visible with the loaded count intact", () => {
    expect(summarizeVisibleRecords([], { events: 12, channels: 2 }, 3)).toEqual({
      generation: 3,
      visible: 0,
      loaded: 12,
      channels: 2,
      errors: 0,
      warnings: 0,
    });
  });
});

describe("valueForGeneration", () => {
  const summary = summarizeVisibleRecords(levels("Error"), { events: 1, channels: 1 }, 5);

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
    expect(summarizeEvtxCorrelationStatus(model, 4, 9)).toEqual({
      generation: 9,
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
    expect(summarizeEvtxCorrelationStatus(incomplete, 0, 1)).toBeNull();
  });

  it("yields no counts for an invalid unplaced total", () => {
    const complete = chainModel();
    expect(summarizeEvtxCorrelationStatus(complete, 3, 1)).not.toBeNull();
    expect(summarizeEvtxCorrelationStatus(complete, -1, 1)).toBeNull();
    expect(summarizeEvtxCorrelationStatus(complete, Number.NaN, 1)).toBeNull();
    expect(summarizeEvtxCorrelationStatus(complete, 1.5, 1)).toBeNull();
  });
});

describe("published stores", () => {
  beforeEach(() => {
    useEvtxVisibleSummaryStore.setState({ summary: null });
    useEvtxCorrelationStatusStore.setState({ status: null });
  });
  afterEach(() => {
    useEvtxVisibleSummaryStore.setState({ summary: null });
    useEvtxCorrelationStatusStore.setState({ status: null });
  });

  it("starts empty, publishes, and clears", () => {
    expect(useEvtxVisibleSummaryStore.getState().summary).toBeNull();
    const summary = summarizeVisibleRecords(levels("Warning"), { events: 1, channels: 1 }, 2);
    useEvtxVisibleSummaryStore.getState().publish(summary);
    expect(useEvtxVisibleSummaryStore.getState().summary).toBe(summary);
    useEvtxVisibleSummaryStore.getState().publish(null);
    expect(useEvtxVisibleSummaryStore.getState().summary).toBeNull();

    const status = { generation: 2, exact: 1, candidate: 0, ambiguous: 0, unplaced: 0 };
    useEvtxCorrelationStatusStore.getState().publish(status);
    expect(useEvtxCorrelationStatusStore.getState().status).toBe(status);
    useEvtxCorrelationStatusStore.getState().publish(null);
    expect(useEvtxCorrelationStatusStore.getState().status).toBeNull();
  });
});

describe("module purity", () => {
  it("imports neither the status bar, the evtx store, Tauri nor React", () => {
    const code = moduleSource
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/.*$/gm, "$1");
    const imports = [...code.matchAll(/^import[^;]*?from\s+"([^"]+)";/gms)].map(
      (match) => match[1],
    );

    expect(imports.sort()).toEqual(
      ["./evtx-correlation-chains", "./types", "zustand"].sort(),
    );
  });
});
