import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  countProblemLevels,
  summarizeEvtxCorrelationStatus,
  summarizeVisibleRecords,
  useEvtxCorrelationStatusStore,
  useEvtxVisibleSummaryStore,
  valueForGeneration,
} from "./evtx-status-summary";
import moduleSource from "./evtx-status-summary.ts?raw";
import type { EvtxLevel } from "./types";
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

describe("summarizeVisibleRecords", () => {
  it("summarizes the rows it is given and the loaded count behind them", () => {
    expect(
      summarizeVisibleRecords(levels("Error", "Critical", "Warning", "Information"), 40, 7),
    ).toEqual({ generation: 7, visible: 4, loaded: 40, errors: 2, warnings: 1 });
  });

  it("reports an empty grid as zero visible with the loaded count intact", () => {
    expect(summarizeVisibleRecords([], 12, 3)).toEqual({
      generation: 3,
      visible: 0,
      loaded: 12,
      errors: 0,
      warnings: 0,
    });
  });
});

describe("valueForGeneration", () => {
  const summary = summarizeVisibleRecords(levels("Error"), 1, 5);

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
    const summary = summarizeVisibleRecords(levels("Warning"), 1, 2);
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
