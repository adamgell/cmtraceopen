/**
 * EventLogWorkspace publishes the grid's counts for the global status bar (spec 8.14): the rows it
 * already computed, keyed by load generation, cleared while a query runs, on every analysis
 * rebuild and on unmount. The last test renders the real StatusBar next to the workspace.
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
vi.mock("./SourcePicker", () => ({ SourcePicker: () => null }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({ EvtxTimeline: () => null }));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { StatusBar } from "../../components/layout/StatusBar";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { EventLogWorkspace } from "./EventLogWorkspace";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { selectVisibleRecords } from "./evtx-filter";
import { useEvtxStore } from "./evtx-store";
import {
  useEvtxCorrelationStatusStore,
  useEvtxVisibleSummaryStore,
} from "./evtx-status-summary";
import type { EvtxLevel, EvtxRecord } from "./types";

let nextRecordId = 0;

/** Placeholder machine and provider names only. */
function record(level: EvtxLevel): EvtxRecord {
  nextRecordId += 1;
  return {
    id: nextRecordId,
    eventRecordId: nextRecordId,
    timestamp: "2026-10-10T12:00:00Z",
    timestampEpoch: Date.UTC(2026, 9, 10, 12, 0, nextRecordId),
    provider: "Contoso-Provider",
    channel: "Application",
    eventId: 1000 + nextRecordId,
    level,
    computer: "CONTOSO-PC01",
    message: `event ${nextRecordId}`,
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "sample.evtx",
  };
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
    selectedChannels: new Set(["Application"]),
    isLoading: false,
    sourceMode: "files",
    timeWindow: "all",
  });
}

const visibleSummary = () => useEvtxVisibleSummaryStore.getState().summary;

describe("EventLogWorkspace status summary", () => {
  beforeEach(() => {
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
    useEvtxVisibleSummaryStore.setState({ summary: null });
    useEvtxCorrelationStatusStore.setState({ status: null });
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ activeView: "event-log", activeWorkspace: "event-log" });
    loadFiles(LEVELS.map(record));
  });

  afterEach(cleanup);

  it("publishes the visible rows, the errors and warnings among them, and the loaded count", () => {
    render(<EventLogWorkspace />);

    expect(visibleSummary()).toEqual({
      generation: useEvtxStore.getState().loadGeneration,
      visible: 4,
      loaded: 4,
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

  it("clears the summary while a query runs and publishes again when it settles", () => {
    render(<EventLogWorkspace />);
    expect(visibleSummary()).not.toBeNull();

    act(() => useEvtxStore.setState({ isLoading: true }));
    // The grid has no rows while loading, which must not read as "0 events".
    expect(visibleSummary()).toBeNull();

    act(() => useEvtxStore.setState({ isLoading: false }));
    expect(visibleSummary()).toMatchObject({ visible: 4, loaded: 4 });
  });

  it("keys the summary by load generation and republishes under the next one", () => {
    render(<EventLogWorkspace />);
    const first = useEvtxStore.getState().loadGeneration;
    expect(visibleSummary()?.generation).toBe(first);

    act(() => useEvtxStore.setState({ loadGeneration: first + 1 }));
    expect(visibleSummary()?.generation).toBe(first + 1);
  });

  it("clears both summaries on unmount", () => {
    const { unmount } = render(<EventLogWorkspace />);
    expect(visibleSummary()).not.toBeNull();
    act(() =>
      useEvtxCorrelationStatusStore.getState().publish({
        generation: useEvtxStore.getState().loadGeneration,
        exact: 1,
        candidate: 0,
        ambiguous: 0,
        unplaced: 0,
      }),
    );

    unmount();

    expect(visibleSummary()).toBeNull();
    expect(useEvtxCorrelationStatusStore.getState().status).toBeNull();
  });

  it("clears the correlation counts whenever the analysis session is rebuilt", () => {
    render(<EventLogWorkspace />);
    act(() =>
      useEvtxCorrelationStatusStore.getState().publish({
        generation: useEvtxStore.getState().loadGeneration,
        exact: 2,
        candidate: 1,
        ambiguous: 0,
        unplaced: 3,
      }),
    );
    expect(useEvtxCorrelationStatusStore.getState().status).not.toBeNull();

    // A tail append changes the analysis input, which rebuilds the session.
    act(() =>
      useEvtxStore.setState((state) => ({ records: [...state.records, record("Warning")] })),
    );

    expect(useEvtxCorrelationStatusStore.getState().status).toBeNull();
  });

  it("feeds the real status bar the same rows", () => {
    render(
      <>
        <EventLogWorkspace />
        <StatusBar />
      </>,
    );
    const left = () => screen.getByTestId("status-bar-left");
    expect(left()).toHaveTextContent(
      "Files · 1 channel · 0 text logs · 4 events · 2 errors · 1 warning",
    );
    expect(left().getAttribute("title")).not.toMatch(/loaded/);

    act(() => useEvtxStore.setState({ filterLevels: new Set<EvtxLevel>(["Error"]) }));

    expect(left()).toHaveTextContent(
      "Files · 1 channel · 0 text logs · 1 event · 1 error · 0 warnings",
    );
    expect(left()).toHaveAttribute(
      "title",
      "Files · 1 channel · 0 text logs · 1 event · 1 error · 0 warnings (4 loaded)",
    );
  });
});
