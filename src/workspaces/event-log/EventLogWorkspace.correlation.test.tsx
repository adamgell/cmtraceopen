/**
 * The workspace's wiring of the shared correlation model and the Correlation view. The analysis
 * session is faked (as in the other workspace integration tests) with a first page that holds a
 * real engine-shaped exact pair, so the REAL hook builds a real model with no further IPC, and the
 * REAL lazy view, view bar and Escape handler are exercised end to end.
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const mocks = vi.hoisted(() => ({
  buildAnalysis: vi.fn(),
  closeAnalysis: vi.fn(),
  queryTimeline: vi.fn(),
  queryEdges: vi.fn(),
  hook: vi.fn(),
  rail: vi.fn(),
  viewLoaded: vi.fn(),
}));

vi.mock("../../lib/commands", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/commands")>()),
  closeEventLogAnalysisSession: mocks.closeAnalysis,
  queryEventLogAnalysisTimeline: mocks.queryTimeline,
  queryEventLogAnalysisEdges: mocks.queryEdges,
}));
vi.mock("./event-analysis-session", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./event-analysis-session")>()),
  buildEventLogAnalysisSession: mocks.buildAnalysis,
  EventLogAnalysisCancelled: class EventLogAnalysisCancelled extends Error {},
}));
vi.mock("./SourcePicker", () => ({ SourcePicker: () => null }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({ EvtxTimeline: () => null }));
vi.mock("./EvtxInsightsRail", () => ({
  EvtxInsightsRail: (props: unknown) => {
    mocks.rail(props);
    return null;
  },
}));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));
// Counts how often the lazy view's module is evaluated: once it is first needed, not before.
vi.mock("./EvtxCorrelationView", async (importOriginal) => {
  mocks.viewLoaded();
  return importOriginal<typeof import("./EvtxCorrelationView")>();
});
// The real hook, with its options recorded.
vi.mock("./useEvtxCorrelation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./useEvtxCorrelation")>();
  return {
    ...actual,
    useEvtxCorrelation: (options: Parameters<typeof actual.useEvtxCorrelation>[0]) => {
      mocks.hook(options);
      return actual.useEvtxCorrelation(options);
    },
  };
});

import { EventLogWorkspace } from "./EventLogWorkspace";
import workspaceSource from "./EventLogWorkspace.tsx?raw";
import {
  T0,
  eventItem,
  fixtureEdges,
  recordFor,
} from "./evtx-correlation-test-fixtures";
import { evtxViewTabId, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import { useEvtxStore } from "./evtx-store";
import { deferred } from "../../test-utils/deferred";
import { useLogStore } from "../../stores/log-store";
import type { UseEvtxCorrelationOptions } from "./useEvtxCorrelation";
import type { LogEntry } from "../../types/log";

const EDGES = fixtureEdges("exactPair");

function analysisResult(sessionId: string, eventItems = 2, pageable = false) {
  const items = [eventItem(1, T0, "error", "first failed"), eventItem(2, T0 + 6_000, "info", "second ok")];
  const status = {
    sessionId,
    revision: 1,
    totalItems: items.length,
    eventItems,
    logItems: 0,
    totalUnplaced: 0,
    totalEdges: EDGES.length,
    totalCoverageGaps: 0,
    finalized: true,
  };
  return {
    status,
    initialPage: {
      sessionId,
      revision: status.revision,
      offset: 0,
      // A page that says more follows makes the member scan go on to read it.
      nextOffset: pageable ? 1_000 : null,
      serializedBytes: 1_024,
      totalItems: status.totalItems,
      eventItems: status.eventItems,
      logItems: status.logItems,
      totalUnplaced: status.totalUnplaced,
      totalEdges: status.totalEdges,
      totalCoverageGaps: status.totalCoverageGaps,
      items,
      unplacedPreview: [],
      edgesPreview: EDGES,
      coverageGapsPreview: [],
    },
    diagnosis: {},
  };
}

function seed(): void {
  const records = [
    recordFor(1),
    recordFor(2),
    { ...recordFor(3), level: "Warning" as const },
  ];
  useEvtxStore.getState().reset();
  useEvtxStore.setState({
    records,
    channels: [{ name: "System", eventCount: records.length, sourceType: { file: { path: "sample.evtx" } } }],
    selectedChannels: new Set(["System"]),
    loadedChannels: new Set(["System"]),
    sourceMode: "files",
    timeWindow: "all",
    timeZoneMode: "utc",
    isLoading: false,
  });
}

const hookCalls = () => mocks.hook.mock.calls.map((call) => call[0] as UseEvtxCorrelationOptions);
const lastHookCall = () => {
  const calls = hookCalls();
  return calls[calls.length - 1]!;
};
const tab = (name: string) => screen.getByRole("tab", { name });
type RailScope = { visibleCount: number; loadedCount: number; textLogCount: number } | null;
const lastRailScope = (): RailScope => {
  const calls = mocks.rail.mock.calls;
  return (calls[calls.length - 1]?.[0] as { scope?: RailScope } | undefined)?.scope ?? null;
};

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  mocks.closeAnalysis.mockResolvedValue(undefined);
  let built = 0;
  mocks.buildAnalysis.mockImplementation(async () => analysisResult(`session-${(built += 1)}`));
  useEvtxLayoutStore.setState({ activeView: "table" });
  useEvtxCorrelationStore.setState({ selectedChainId: null });
  useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
  seed();
});
afterEach(cleanup);

describe("what the workspace gives the shared hook", () => {
  it("has not loaded the view's module before the Correlation view is chosen", () => {
    render(<EventLogWorkspace />);
    expect(mocks.viewLoaded).not.toHaveBeenCalled();
    expect(workspaceSource).toMatch(/lazy\(\(\) => import\("\.\/EvtxCorrelationView"\)\)/);
    // The hook and the provider are not lazy: the Insights card reads them without the view.
    expect(workspaceSource).not.toMatch(/lazy\(\(\) => import\("\.\/useEvtxCorrelation"\)\)/);
    expect(hookCalls().length).toBeGreaterThan(0);
  });

  it("passes the session's status and its first page as one stable object, and pending while it is built", async () => {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(lastHookCall().status).not.toBeNull());
    const calls = hookCalls();
    // While the session is being built the hook is told so, with no status and no page.
    expect(calls.some((call) => call.pending && call.status === null && call.initialPage === null)).toBe(true);
    const published = calls.filter((call) => call.initialPage !== null);
    expect(published.length).toBeGreaterThan(0);
    // One object for the life of the session: a fresh one per render would restart the hook each time.
    expect(new Set(published.map((call) => call.initialPage)).size).toBe(1);
    const built = await mocks.buildAnalysis.mock.results[0]!.value;
    expect(published[0]!.initialPage).toBe(built.initialPage);
    expect(published[0]!.status).toBe(built.status);
    expect(lastHookCall().pending).toBe(false);
  });

  it("asks for items only while the Correlation view is the one shown", async () => {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(lastHookCall().status).not.toBeNull());
    expect(hookCalls().every((call) => call.needItems === false)).toBe(true);
    fireEvent.click(tab("Correlation"));
    await waitFor(() => expect(lastHookCall().needItems).toBe(true));
    // The module was evaluated when the view was first chosen, not before (the first test checked).
    await screen.findByTestId("correlation-view");
    expect(mocks.viewLoaded).toHaveBeenCalledTimes(1);
    fireEvent.click(tab("Table"));
    await waitFor(() => expect(lastHookCall().needItems).toBe(false));
    fireEvent.click(tab("Charts"));
    expect(lastHookCall().needItems).toBe(false);
  });
});

/**
 * V1: one scope per session, read at one moment, for the Correlation view and the Insights rail.
 * `visible` and the text logs are what the session was BUILT from; `loaded` is what the store holds
 * at the PUBLISH. An event the filter hides that arrives while the build is pending is loaded, and
 * the session was not built from it, so the session is narrowed on both surfaces.
 */
describe("the scope of a session published after a hidden event arrived during its build (V1)", () => {
  const SESSION_SCOPE = { visibleCount: 3, loadedCount: 4, textLogCount: 3 };
  const logEntry = (n: number) => ({ id: n, lineNumber: n, message: `log ${n}` }) as unknown as LogEntry;
  const hiddenRecord = (n: number) => ({ ...recordFor(n), level: "Verbose" as const });

  /** Three visible events, a filter that hides Verbose, three text logs, and a build left pending. */
  async function buildPendingWithAHiddenAppend() {
    const records = [recordFor(1), recordFor(2), { ...recordFor(3), level: "Warning" as const }];
    act(() => {
      useEvtxStore.setState({ records, filterLevels: new Set(["Information", "Warning"]) });
      useLogStore.setState({ entries: [logEntry(1), logEntry(2), logEntry(3)], sourceOpenMode: "merged" });
    });
    const build = deferred<ReturnType<typeof analysisResult>>();
    mocks.buildAnalysis.mockImplementationOnce(() => build.promise);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    // The snapshot holds three visible events and three loaded. Now a fourth arrives and the
    // filter hides it: the visible set is the same, so the build is neither restarted nor cancelled.
    act(() => useEvtxStore.setState({ records: [...useEvtxStore.getState().records, hiddenRecord(4)] }));
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);
    await act(async () => {
      build.resolve(analysisResult("hidden-append"));
    });
    await waitFor(() => expect(lastHookCall().scope).not.toBeNull());
  }

  it("counts the hidden event as loaded, so the session is narrowed (visible < loaded)", async () => {
    await buildPendingWithAHiddenAppend();
    expect(lastHookCall().scope).toEqual(SESSION_SCOPE);
  });

  it("gives the rail and the view the SAME scope object, read once", async () => {
    await buildPendingWithAHiddenAppend();
    await waitFor(() => expect(lastRailScope()).not.toBeNull());
    expect(lastRailScope()).toEqual(SESSION_SCOPE);
    expect(lastRailScope()).toBe(lastHookCall().scope);
  });

  it("shows the narrowed-set disclosure and the text-log line in the view for that session", async () => {
    await buildPendingWithAHiddenAppend();
    fireEvent.click(tab("Correlation"));
    await screen.findAllByRole("option");
    await waitFor(() =>
      expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
        "Links and strengths are computed over the 3 events visible.",
      ),
    );
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent("Text logs are not scoped.");
  });

  it("keeps that scope while later hidden events arrive and the view is opened (it is the session's, not the store's now)", async () => {
    await buildPendingWithAHiddenAppend();
    const published = lastHookCall().scope;
    act(() => useEvtxStore.setState({ records: [...useEvtxStore.getState().records, hiddenRecord(5), hiddenRecord(6)] }));
    // Opening the view re-runs the hook for the same session; it must be given the same scope.
    fireEvent.click(tab("Correlation"));
    await screen.findAllByRole("option");
    expect(lastHookCall().scope).toBe(published);
    expect(lastHookCall().scope).toEqual(SESSION_SCOPE);
    expect(lastRailScope()).toBe(published);
  });
});

describe("the Correlation view in the workspace", () => {
  async function openView() {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(lastHookCall().status).not.toBeNull());
    fireEvent.click(tab("Correlation"));
    return screen.findAllByRole("option");
  }

  it("shows the chain the real model built, in the tabpanel the layout tablist controls", async () => {
    const options = await openView();
    expect(options).toHaveLength(1);
    expect(within(options[0]!).getByText("Exact")).toBeInTheDocument();
    // The counts arrive first, untitled; the title comes with the entries the scan read.
    await waitFor(() => expect(within(screen.getAllByRole("option")[0]!).getByText("101 · first failed")).toBeInTheDocument());
    expect(screen.getByRole("tabpanel", { name: "Correlation" })).toContainElement(
      screen.getByTestId("correlation-view"),
    );
    await waitFor(() => expect(document.querySelectorAll("line[data-connector]")).toHaveLength(1));
  });

  it("states no narrowing while every loaded event is visible, and the scope of the session that was narrowed", async () => {
    await openView();
    await screen.findByRole("figure");
    expect(screen.queryByTestId("correlation-notices")).toBeNull();
    // A level filter hides one of the three loaded events: the next session is built from two.
    act(() => useEvtxStore.setState({ filterLevels: new Set(["Information"]) }));
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
        "Links and strengths are computed over the 2 events visible.",
      ),
    );
    const snapshot = mocks.buildAnalysis.mock.calls[1]![0] as { records: unknown[] };
    expect(snapshot.records).toHaveLength(2);
  });

  it("keeps the scope of the model on show after five newer sessions are published, none scanned (P5)", async () => {
    // The first session is narrowed to the two Information events of three loaded, and was given
    // three text-log entries that the narrowing does not touch.
    const logEntry = (n: number) => ({ id: n, lineNumber: n, message: `log ${n}` }) as unknown as LogEntry;
    act(() => {
      useLogStore.setState({ entries: [logEntry(1), logEntry(2), logEntry(3)], sourceOpenMode: "merged" });
      useEvtxStore.setState({ filterLevels: new Set(["Information"]) });
    });
    await openView();
    await screen.findByRole("figure");
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
      "Links and strengths are computed over the 2 events visible.",
    );
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent("Text logs are not scoped.");
    // The hook was given the session's own counts together with its status and page.
    const withScope = hookCalls().filter((call) => call.initialPage !== null && call.scope !== null);
    expect(withScope[withScope.length - 1]!.scope).toEqual({ visibleCount: 2, loadedCount: 3, textLogCount: 3 });
    // Every later session says more pages follow, and the page never arrives: its scan cannot
    // finish, so the first session's full model stays on show, marked updating.
    mocks.queryTimeline.mockReturnValue(new Promise(() => undefined));
    let built = 1;
    mocks.buildAnalysis.mockImplementation(async () => analysisResult(`late-${(built += 1)}`, 2, true));
    const levels = [["Warning"], ["Information", "Warning"], ["Information"], ["Warning"], ["Information", "Warning"]] as const;
    for (const next of levels) {
      const before = mocks.buildAnalysis.mock.calls.length;
      act(() => useEvtxStore.setState({ filterLevels: new Set(next) }));
      await waitFor(() => expect(mocks.buildAnalysis.mock.calls.length).toBe(before + 1));
    }
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(6);
    // The newest session is built from all three events: its own scope narrows nothing.
    const snapshots = mocks.buildAnalysis.mock.calls.map((call) => (call[0] as { records: unknown[] }).records.length);
    expect(snapshots[snapshots.length - 1]).toBe(3);
    // The model on show is still the first session's, and so is the scope beside it.
    expect(screen.getByTestId("correlation-updating")).toHaveTextContent("Updating correlation");
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
      "Links and strengths are computed over the 2 events visible.",
    );
  });

  it("filters the table to the chain, switches to Table and moves focus to the Table tab", async () => {
    await openView();
    await screen.findByRole("figure");
    await waitFor(() => expect(screen.getByRole("button", { name: "Filter table to chain" })).not.toHaveAttribute("aria-disabled", "true"));
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    const scope = useEvtxStore.getState().recordScope;
    expect(scope?.kind).toBe("chain");
    expect([...(scope?.records ?? [])].map((record) => record.eventRecordId).sort()).toEqual([1, 2]);
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    const tableTab = document.getElementById(evtxViewTabId("table"));
    expect(tableTab).not.toBeNull();
    expect(tableTab).toHaveFocus();
    expect(tab("Table")).toHaveAttribute("aria-selected", "true");
    // The chip says whose scope it is, and its tooltip speaks of the chain, not of a finding.
    const chip = await screen.findByText(/^Chain: 101/);
    expect(chip).toBeInTheDocument();
  });

  it("keeps an active time range when Escape is pressed on a plot marker, and still clears it elsewhere", async () => {
    await openView();
    await screen.findByRole("figure");
    act(() => useEvtxStore.getState().setTimeRange({ startMs: T0, endMs: T0 + 60_000 }));
    const marker = document.querySelector<HTMLElement>("button[data-marker]")!;
    marker.focus();
    fireEvent.keyDown(marker, { key: "Escape" });
    expect(useEvtxStore.getState().timeRange).not.toBeNull();
    expect(screen.getByRole("listbox")).toHaveFocus();
    fireEvent.keyDown(screen.getByRole("listbox"), { key: "Escape" });
    expect(useEvtxStore.getState().timeRange).not.toBeNull();
    // Anywhere else in the workspace Escape is still the time range's.
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(useEvtxStore.getState().timeRange).toBeNull();
  });
});
