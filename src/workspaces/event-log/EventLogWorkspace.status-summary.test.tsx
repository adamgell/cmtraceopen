/**
 * EventLogWorkspace publishes the grid's counts for the global status bar (spec 8.14): the rows it
 * already computed, keyed by load generation, withheld while a query runs or when nothing was
 * read, and cleared on unmount. It also names the analysis session on screen for the correlation
 * counts. The last tests render the real grid beside the real StatusBar.
 */
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
vi.mock("../../lib/commands", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/commands")>()),
  closeEventLogAnalysisSession: vi.fn().mockResolvedValue(undefined),
  queryEventLogAnalysisTimeline: vi.fn(),
}));
vi.mock("./event-analysis-session", () => ({
  buildEventLogAnalysisSession: vi.fn(() => new Promise(() => undefined)),
  EventLogAnalysisCancelled: class EventLogAnalysisCancelled extends Error {},
}));
// jsdom has no layout, so the real virtualizer would render no rows. The grid's own row count
// (its aria-label) does not depend on it, which is all these tests read.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: () => ({
    getVirtualItems: () => [],
    getTotalSize: () => 0,
    measureElement: () => undefined,
    resizeItem: () => undefined,
    measure: () => undefined,
    scrollToIndex: () => undefined,
  }),
}));
vi.mock("./SourcePicker", () => ({ SourcePicker: () => null }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { StatusBar } from "../../components/layout/StatusBar";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { EventLogWorkspace } from "./EventLogWorkspace";
import { buildEventLogAnalysisSession } from "./event-analysis-session";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { selectVisibleRecords } from "./evtx-filter";
import { useEvtxStore } from "./evtx-store";
import {
  summarizeEvtxCorrelationStatus,
  useEvtxCorrelationStatusStore,
  useEvtxVisibleSummaryStore,
} from "./evtx-status-summary";
import type { EvtxLevel, EvtxRecord } from "./types";

let nextRecordId = 0;
const HOUR_MS = 60 * 60 * 1000;

/** Placeholder machine and provider names only. */
function record(
  level: EvtxLevel,
  options: { channel?: string; ageMs?: number } = {},
): EvtxRecord {
  nextRecordId += 1;
  return {
    id: nextRecordId,
    eventRecordId: nextRecordId,
    timestamp: "2026-10-10T12:00:00Z",
    timestampEpoch: Date.now() - (options.ageMs ?? 0),
    provider: "Contoso-Provider",
    channel: options.channel ?? "Application",
    eventId: 1000 + nextRecordId,
    level,
    computer: "CONTOSO-PC01",
    message: `event ${nextRecordId}`,
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "sample.evtx",
  };
}

function archivedTextLog(label: string): EvtxRecord {
  return { ...record("Information", { channel: label }), originKind: "log", sourceLabel: label };
}

const LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information"];

function loadFiles(records: EvtxRecord[]) {
  useEvtxStore.setState({
    records,
    channels: [
      {
        name: "Application",
        eventCount: records.length,
        sourceType: { file: { path: "C:\\Evidence\\Application.evtx" } },
      },
    ],
    selectedChannels: new Set(records.map((r) => r.channel)),
    isLoading: false,
    sourceMode: "files",
    timeWindow: "all",
  });
}

function logEntry(id: number, filePath: string) {
  return {
    id,
    lineNumber: id,
    message: `line ${id}`,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info" as const,
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped" as const,
    filePath,
    timezoneOffset: null,
  };
}

const visibleSummary = () => useEvtxVisibleSummaryStore.getState().summary;
const correlation = () => useEvtxCorrelationStatusStore.getState();

describe("EventLogWorkspace status summary", () => {
  beforeEach(() => {
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
    useEvtxVisibleSummaryStore.setState({ summary: null });
    useEvtxCorrelationStatusStore.setState({ analysis: null, status: null });
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ activeView: "event-log", activeWorkspace: "event-log" });
    vi.mocked(buildEventLogAnalysisSession).mockImplementation(
      () => new Promise(() => undefined),
    );
    loadFiles(LEVELS.map((level) => record(level)));
  });

  afterEach(cleanup);

  it("publishes the visible rows, the errors and warnings among them, and the loaded counts", () => {
    render(<EventLogWorkspace />);

    expect(visibleSummary()).toEqual({
      generation: useEvtxStore.getState().loadGeneration,
      visible: 4,
      loaded: 4,
      channels: 1,
      textLogs: 0,
      errors: 2,
      warnings: 1,
    });
  });

  it("publishes the rows the grid selects, not the loaded events, when a filter narrows them", () => {
    render(<EventLogWorkspace />);
    act(() => useEvtxStore.setState({ filterLevels: new Set<EvtxLevel>(["Error"]) }));

    const state = useEvtxStore.getState();
    const gridRows = selectVisibleRecords({
      records: state.records,
      selectedChannels: state.selectedChannels,
      filterLevels: state.filterLevels,
      nowEpoch: Date.now(),
      filterEventIds: state.filterEventIds,
      filterSearch: state.filterSearch,
      quickFilter: state.quickFilter,
      visibleColumns: state.columnConfig.order,
      timeZoneMode: state.timeZoneMode,
      timeWindow: state.timeWindow,
    });
    expect(gridRows).toHaveLength(1);
    expect(visibleSummary()).toMatchObject({
      visible: gridRows.length,
      loaded: 4,
      errors: 1,
      warnings: 0,
    });
  });

  describe("channels", () => {
    it("counts the event channels that loaded, not the parse result's channel list", () => {
      const archivedLog = archivedTextLog("C:\\Evidence\\AgentExecutor.log");
      useEvtxStore.setState({
        records: [
          record("Warning", { channel: "System" }),
          record("Information", { channel: "System" }),
          archivedLog,
        ],
        // The files held System twice, Application with no records, and a text log.
        channels: ["System", "System", "Application", archivedLog.channel].map((name) => ({
          name,
          eventCount: 1,
          sourceType: { file: { path: `C:\\Evidence\\${name}.evtx` } },
        })),
        selectedChannels: new Set(["System", "Application", archivedLog.channel]),
      });
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toMatchObject({ visible: 3, loaded: 3, channels: 1 });
    });

    it("counts the channels whose load completed in live mode", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["Application", "System", "Setup"]),
      });
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toMatchObject({ channels: 3 });
    });
  });

  describe("text logs", () => {
    it("counts the log-store files after the same scoping the analysis session gets", () => {
      useLogStore.setState({
        entries: [
          logEntry(1, "C:\\Logs\\Intune\\a.log"),
          logEntry(2, "C:\\Logs\\Intune\\a.log"),
          logEntry(3, "C:\\Logs\\Intune\\b.log"),
          logEntry(4, "C:\\Logs\\Other\\c.log"),
        ],
        sourceOpenMode: "single-file",
        activeSource: { kind: "folder", path: "C:\\Logs\\Intune" },
      });
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toMatchObject({ textLogs: 2 });
    });

    it("adds the distinct archived text-log sources, once even when a file is also open", () => {
      useLogStore.setState({
        entries: [logEntry(1, "C:\\Evidence\\ime.log")],
        sourceOpenMode: "merged",
      });
      loadFiles([
        record("Warning", { channel: "System" }),
        archivedTextLog("C:\\Evidence\\ime.log"),
        archivedTextLog("C:\\Evidence\\ime.log"),
        archivedTextLog("C:\\Evidence\\AgentExecutor.log"),
      ]);
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toMatchObject({ textLogs: 2, channels: 1 });
    });
  });

  describe("withheld summary", () => {
    it("publishes nothing while a query runs and publishes again when it settles", () => {
      render(<EventLogWorkspace />);
      expect(visibleSummary()).not.toBeNull();

      act(() => useEvtxStore.setState({ isLoading: true }));
      // The grid has no rows while loading, which must not read as "0 events".
      expect(visibleSummary()).toBeNull();

      act(() => useEvtxStore.setState({ isLoading: false }));
      expect(visibleSummary()).toMatchObject({ visible: 4, loaded: 4 });
    });

    it("publishes nothing for a live load in which no channel completed", () => {
      // Every core-channel query was refused: the source stays "live" with no loaded channel,
      // and the error and warning counts are unknown, not zero.
      useEvtxStore.setState({
        sourceMode: "live",
        records: [],
        loadedChannels: new Set(),
        coverageGaps: ["Security: access denied"],
      });
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toBeNull();

      act(() => useEvtxStore.setState({ loadedChannels: new Set(["Application"]) }));
      expect(visibleSummary()).toMatchObject({ visible: 0, loaded: 0, channels: 1 });
    });

    it("publishes nothing for a files load that produced no records", () => {
      // A folder of corrupt files: only per-file errors came back.
      useEvtxStore.setState({
        sourceMode: "files",
        records: [],
        coverageGaps: ["C:\\Evidence\\System.evtx: file is corrupt"],
      });
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toBeNull();
    });

    it("does publish for a files source whose records are all archived text logs", () => {
      loadFiles([archivedTextLog("C:\\Evidence\\ime.log")]);
      render(<EventLogWorkspace />);

      expect(visibleSummary()).toMatchObject({ visible: 1, channels: 0, textLogs: 1 });
    });
  });

  it("keys the summary by load generation and republishes under the next one", () => {
    render(<EventLogWorkspace />);
    const first = useEvtxStore.getState().loadGeneration;
    expect(visibleSummary()?.generation).toBe(first);

    act(() => useEvtxStore.setState({ loadGeneration: first + 1 }));
    expect(visibleSummary()?.generation).toBe(first + 1);
  });

  describe("correlation counts", () => {
    const complete = {
      counts: { exact: 2, candidate: 1, ambiguous: 0, coverageBlocked: 0 },
      edgeInputComplete: true,
    };
    const sessionResult = (sessionId: string, revision: number) => ({
      status: {
        sessionId,
        revision,
        totalItems: 0,
        eventItems: 0,
        logItems: 0,
        totalUnplaced: 0,
        totalEdges: 0,
        totalCoverageGaps: 0,
        finalized: true,
      },
      initialPage: {},
      diagnosis: {},
    });

    it("names the analysis session on screen once it is ready, under the current generation", async () => {
      vi.mocked(buildEventLogAnalysisSession).mockResolvedValueOnce(
        sessionResult("session-7", 3) as never,
      );
      render(<EventLogWorkspace />);

      await vi.waitFor(() => expect(correlation().analysis).not.toBeNull());
      expect(correlation().analysis).toEqual({
        generation: useEvtxStore.getState().loadGeneration,
        sessionId: "session-7",
        revision: 3,
      });
    });

    it("unnames the session at the start of a rebuild, so counts for it are dropped", async () => {
      vi.mocked(buildEventLogAnalysisSession).mockResolvedValueOnce(
        sessionResult("session-7", 3) as never,
      );
      render(<EventLogWorkspace />);
      await vi.waitFor(() => expect(correlation().analysis).not.toBeNull());
      const analysis = correlation().analysis!;
      const status = summarizeEvtxCorrelationStatus(complete, 0, analysis);
      act(() => correlation().publish(status));
      expect(correlation().status).not.toBeNull();

      // A tail append changes the analysis input, which rebuilds the session.
      act(() =>
        useEvtxStore.setState((state) => ({ records: [...state.records, record("Warning")] })),
      );

      expect(correlation().analysis).toBeNull();
      expect(correlation().status).toBeNull();
      // Work for the old session that finishes late is refused.
      act(() => correlation().publish(status));
      expect(correlation().status).toBeNull();
    });

    it("clears the summaries and the session on unmount", async () => {
      vi.mocked(buildEventLogAnalysisSession).mockResolvedValueOnce(
        sessionResult("session-7", 3) as never,
      );
      const { unmount } = render(<EventLogWorkspace />);
      await vi.waitFor(() => expect(correlation().analysis).not.toBeNull());
      act(() =>
        correlation().publish(summarizeEvtxCorrelationStatus(complete, 0, correlation().analysis!)),
      );
      expect(visibleSummary()).not.toBeNull();

      unmount();

      expect(visibleSummary()).toBeNull();
      expect(correlation().analysis).toBeNull();
      expect(correlation().status).toBeNull();
    });
  });

  describe("beside the real grid and status bar", () => {
    /**
     * The grid's own row count: its aria-label. A grouped grid is a "treegrid", and a grid with no
     * rows renders the empty-state message in place of the grid.
     */
    const gridCount = () => {
      const grid = screen.queryByLabelText(/^Event log timeline - \d+ records$/);
      if (grid === null) {
        expect(screen.getByText("No records match the current filters.")).toBeInTheDocument();
        return 0;
      }
      return Number(/(\d+) records$/.exec(grid.getAttribute("aria-label") ?? "")?.[1]);
    };
    const barCount = () => {
      const match = /· (\d+) events?\b/.exec(screen.getByTestId("status-bar-left").textContent ?? "");
      return Number(match?.[1]);
    };
    const bar = () => screen.getByTestId("status-bar-left");

    beforeEach(() => {
      useEvtxStore.setState({
        // Four events inside 24 hours, two outside it.
        records: [
          record("Error", { ageMs: 2 * HOUR_MS }),
          record("Warning", { ageMs: 3 * HOUR_MS }),
          record("Information", { ageMs: 5 * HOUR_MS }),
          record("Critical", { ageMs: 10 * HOUR_MS }),
          record("Error", { ageMs: 30 * HOUR_MS }),
          record("Warning", { ageMs: 48 * HOUR_MS }),
        ],
        timeWindow: "24h",
        groupBy: ["level"],
      });
    });

    it("shows the same count as the grid through grouping, a collapsed group, a 24 h window and a tail append", () => {
      render(
        <>
          <EventLogWorkspace />
          <StatusBar />
        </>,
      );

      // Grouped by level, 24 h window: the two older events are outside it.
      expect(gridCount()).toBe(4);
      expect(barCount()).toBe(4);
      expect(bar()).toHaveTextContent("4 events · 2 errors · 1 warning");

      // Collapsing a group hides its rows, not its records: neither number moves.
      act(() => useEvtxStore.getState().toggleGroup("/level=Error"));
      expect(useEvtxStore.getState().collapsedGroups.has("/level=Error")).toBe(true);
      expect(gridCount()).toBe(4);
      expect(barCount()).toBe(4);

      // A tail append inside the window moves both ...
      act(() =>
        useEvtxStore.setState((state) => ({
          records: [...state.records, record("Warning", { ageMs: 1000 })],
        })),
      );
      expect(gridCount()).toBe(5);
      expect(barCount()).toBe(5);
      expect(bar()).toHaveTextContent("5 events · 2 errors · 2 warnings");

      // ... and one outside it moves neither.
      act(() =>
        useEvtxStore.setState((state) => ({
          records: [...state.records, record("Error", { ageMs: 60 * HOUR_MS })],
        })),
      );
      expect(gridCount()).toBe(5);
      expect(barCount()).toBe(5);
      // The bar still says how many are loaded behind the window.
      expect(bar().getAttribute("title")).toMatch(/\(8 loaded\)$/);

      // Widening the window brings the old events into both.
      act(() => useEvtxStore.setState({ timeWindow: "all" }));
      expect(gridCount()).toBe(8);
      expect(barCount()).toBe(8);
    });

    it("keeps matching the grid under a level filter and a search", () => {
      render(
        <>
          <EventLogWorkspace />
          <StatusBar />
        </>,
      );

      act(() => useEvtxStore.setState({ filterLevels: new Set<EvtxLevel>(["Error", "Critical"]) }));
      expect(gridCount()).toBe(2);
      expect(barCount()).toBe(2);
      expect(bar()).toHaveTextContent("2 events · 2 errors · 0 warnings");

      act(() => useEvtxStore.setState({ filterSearch: "no such message" }));
      expect(gridCount()).toBe(0);
      expect(barCount()).toBe(0);
    });
  });
});
