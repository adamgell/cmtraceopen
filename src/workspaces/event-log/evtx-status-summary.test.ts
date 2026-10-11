import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseAst } from "vite";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  countProblemLevels,
  countTextLogSources,
  currentCorrelationStatus,
  loadedChannelCountFor,
  readStateFor,
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

describe("readStateFor", () => {
  const event = { originKind: "event" as const };
  const textLog = { originKind: "log" as const };
  const bare = {}; // an event record carries no origin kind

  it("needs a completed channel in live mode, whatever records are on screen", () => {
    expect(readStateFor({ sourceMode: "live", loadedChannelCount: 2, records: [] })).toBe("events");
    // A cancelled or refused read leaves loadedChannels empty even when partial records show.
    expect(
      readStateFor({ sourceMode: "live", loadedChannelCount: 0, records: [event, event] }),
    ).toBe("nothing");
  });

  it("needs an EVENT record to have read events in files mode", () => {
    expect(readStateFor({ sourceMode: "files", loadedChannelCount: 0, records: [event] })).toBe("events");
    expect(readStateFor({ sourceMode: "files", loadedChannelCount: 0, records: [bare] })).toBe("events");
    expect(
      readStateFor({ sourceMode: "files", loadedChannelCount: 0, records: [textLog, textLog, event] }),
    ).toBe("events");
  });

  it("reads records that are all text logs as text logs only: no event was read", () => {
    // An evidence archive whose two .evtx files failed to read, beside one readable text log.
    expect(
      readStateFor({ sourceMode: "files", loadedChannelCount: 0, records: [textLog, textLog] }),
    ).toBe("textLogsOnly");
  });

  it("reads a files source with no records as nothing", () => {
    expect(readStateFor({ sourceMode: "files", loadedChannelCount: 0, records: [] })).toBe("nothing");
  });

  it("reads nothing when no source is open", () => {
    expect(readStateFor({ sourceMode: null, loadedChannelCount: 3, records: [event] })).toBe("nothing");
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
        { records: 40, channels: 3, textLogs: 2, eventsRead: true },
        7,
      ),
    ).toEqual({
      generation: 7,
      textLogs: 2,
      events: { visible: 4, loaded: 40, channels: 3, errors: 2, warnings: 1 },
    });
  });

  it("reports an empty grid as zero visible with the loaded count intact", () => {
    expect(
      summarizeVisibleRecords([], { records: 12, channels: 2, textLogs: 0, eventsRead: true }, 3),
    ).toEqual({
      generation: 3,
      textLogs: 0,
      events: { visible: 0, loaded: 12, channels: 2, errors: 0, warnings: 0 },
    });
  });

  it("leaves the event counts absent, not zero, when no event record was read", () => {
    // The grid shows text-log lines, but the event channels were not read: their counts are unknown.
    const summary = summarizeVisibleRecords(
      levels("Information", "Warning"),
      { records: 2, channels: 0, textLogs: 1, eventsRead: false },
      4,
    );

    expect(summary).toEqual({ generation: 4, textLogs: 1, events: null });
  });
});

describe("valueForGeneration", () => {
  const summary = summarizeVisibleRecords(
    levels("Error"),
    { records: 1, channels: 1, textLogs: 0, eventsRead: true },
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
      { records: 1, channels: 1, textLogs: 0, eventsRead: true },
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

  it("refuses a status the summarizer did not issue, even a spread of one that it did", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2));
    const issued = statusFor(key(2));

    // The brand survives a spread, so the type allows this; the store checks the object itself.
    store.publish({ ...issued, exact: 99 });
    expect(current()).toBeNull();

    store.publish(issued);
    expect(current()).toBe(issued);
    expect(Object.isFrozen(issued)).toBe(true);
  });

  it("keeps counts across a generation change that rebuilt nothing", () => {
    // A refused or failed open bumps the load generation and leaves the session on screen. The
    // session is named by its id and revision, and the bar compares with that, not the generation.
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2));
    store.publish(statusFor(key(2)));

    expect(
      currentCorrelationStatus(useEvtxCorrelationStatusStore.getState()),
    ).toMatchObject({ exact: 2 });
  });

  it("reads no counts when the status does not name the session on screen", () => {
    const issued = statusFor(key(2));
    expect(currentCorrelationStatus({ analysis: null, status: issued })).toBeNull();
    expect(currentCorrelationStatus({ analysis: key(2), status: null })).toBeNull();
    expect(currentCorrelationStatus({ analysis: key(2, "other"), status: issued })).toBeNull();
    expect(currentCorrelationStatus({ analysis: key(2, "session-1", 9), status: issued })).toBeNull();
    expect(currentCorrelationStatus({ analysis: key(2), status: issued })).toBe(issued);
  });

  it("clears the counts on publish(null)", () => {
    const store = useEvtxCorrelationStatusStore.getState();
    store.setAnalysis(key(2));
    store.publish(statusFor(key(2)));
    store.publish(null);
    expect(current()).toBeNull();
  });
});

/** Stands for a specifier that is not a string literal, so it can never match an allowed one. */
const NON_LITERAL_SPECIFIER = "<non-literal specifier>";

interface AstNode {
  type: string;
  [key: string]: unknown;
}

const isNode = (value: unknown): value is AstNode =>
  typeof value === "object" &&
  value !== null &&
  typeof (value as { type?: unknown }).type === "string";

function stringLiteral(node: unknown): string | undefined {
  return isNode(node) && node.type === "Literal" && typeof node.value === "string"
    ? node.value
    : undefined;
}

/**
 * Every module a source pulls in: imports, re-exports, `import x = require()`, `import()` with or
 * without an options argument, type-level `import("m")`, `require()`, and Vite's
 * `import.meta.glob`. Parsed with Vite's own parser rather than matched with regexes, so comments
 * and strings that merely look like code are not read as code. A specifier that is not a string
 * literal, and any `import.meta.glob`, is reported by name so it can never pass an allow-list.
 */
function moduleSpecifiers(source: string): string[] {
  const found = new Set<string>();
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!isNode(value)) return;
    switch (value.type) {
      case "ImportDeclaration":
      case "ExportAllDeclaration":
      case "ExportNamedDeclaration":
      case "ImportExpression":
      case "TSImportType":
        // `export const x` has no source; every other form here names a module.
        if (value.source !== null && value.source !== undefined) {
          found.add(stringLiteral(value.source) ?? NON_LITERAL_SPECIFIER);
        }
        break;
      case "TSExternalModuleReference":
        found.add(stringLiteral(value.expression) ?? NON_LITERAL_SPECIFIER);
        break;
      case "CallExpression":
        if (
          isNode(value.callee) &&
          value.callee.type === "Identifier" &&
          value.callee.name === "require" &&
          Array.isArray(value.arguments)
        ) {
          found.add(stringLiteral(value.arguments[0]) ?? NON_LITERAL_SPECIFIER);
        }
        break;
      case "MemberExpression":
        if (
          isNode(value.object) &&
          value.object.type === "MetaProperty" &&
          isNode(value.property) &&
          (value.property.name === "glob" || value.property.name === "globEager")
        ) {
          found.add(`import.meta.${String(value.property.name)}`);
        }
        break;
    }
    for (const child of Object.values(value)) visit(child);
  };
  visit(parseAst(source, { lang: "ts" }));
  return [...found].sort();
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
        import eq = require("./eleven");
        type Q = typeof import("./twelve");
        type R = import("./thirteen").X;
        const withOptions = await import("./fourteen", { with: { type: "json" } });
        export const local = 1;
        // import "./commented";
        /* import "./blocked"; */
        const text = "not an import";
      `),
    ).toEqual(
      [
        "./one", "./two", "./three", "./four", "./five", "./six", "./seven", "./eight",
        "./nine", "./ten", "./eleven", "./twelve", "./thirteen", "./fourteen",
      ].sort(),
    );
  });

  it("reads a dynamic import with an options argument and import.meta.glob", () => {
    // The store's Tauri listeners register as soon as it is imported by any of these routes.
    expect(
      moduleSpecifiers(`const store = await import("./evtx-store", { with: {} });`),
    ).toEqual(["./evtx-store"]);
    expect(
      moduleSpecifiers(`const all = import.meta.glob("./evtx-store.ts", { eager: true });`),
    ).toEqual(["import.meta.glob"]);
    expect(moduleSpecifiers(`const all = import.meta.globEager("./*.ts");`)).toEqual([
      "import.meta.globEager",
    ]);
  });

  it("flags a specifier that is not a string literal", () => {
    expect(moduleSpecifiers(`const m = await import(name);`)).toEqual([NON_LITERAL_SPECIFIER]);
    expect(moduleSpecifiers(`const m = require(path + ".js");`)).toEqual([NON_LITERAL_SPECIFIER]);
  });

  it("is not fooled by comment markers inside strings", () => {
    // A regex comment-stripper would drop everything after the "//" or up to the next "*/".
    expect(
      moduleSpecifiers(`
        const url = "https://example.test/a";
        const glob = "/* not a comment";
        import real from "./real";
        const end = "*/";
      `),
    ).toEqual(["./real"]);
  });

  it("imports neither the status bar, the evtx store, Tauri nor React", () => {
    expect(moduleSpecifiers(moduleSource)).toEqual(
      ["./evtx-correlation-chains", "./types", "zustand"].sort(),
    );
  });
});
