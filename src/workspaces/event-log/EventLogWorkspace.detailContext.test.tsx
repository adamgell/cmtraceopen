/**
 * The Details Context section on the real mount (#843): the real workspace, the real rail, the real
 * Details pane and the real lazy section, with the analysis session faked as in the other workspace
 * integration tests. This is where the surface the section sits on is the rail's own (bg2, the
 * surface the eyebrow's contrast was measured on), and where "reads only while the Insights panel is
 * shown" is shown on the workspace's own layout state rather than on a stand-in.
 */
import { tokens } from "@fluentui/react-components";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The pane asks the backend to read the error codes in an event's text, and the markers for its file.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn().mockResolvedValue([]) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const mocks = vi.hoisted(() => ({
  buildAnalysis: vi.fn(),
  closeAnalysis: vi.fn(),
  queryTimeline: vi.fn(),
  queryEdges: vi.fn(),
  queryWindow: vi.fn(),
}));

vi.mock("../../lib/commands", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/commands")>()),
  closeEventLogAnalysisSession: mocks.closeAnalysis,
  queryEventLogAnalysisTimeline: mocks.queryTimeline,
  queryEventLogAnalysisEdges: mocks.queryEdges,
  queryEventLogAnalysisTimelineWindow: mocks.queryWindow,
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
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));
vi.mock("./EventDiagnosisPanel", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./EventDiagnosisPanel")>()),
  EventDiagnosisPanel: () => <section aria-label="Operational diagnosis" />,
}));

import { EventLogWorkspace } from "./EventLogWorkspace";
import { DETAIL_CONTEXT_TITLE } from "./evtx-detail-context-model";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { selectRecordAndShowDetails } from "./evtx-select-record";
import { useEvtxStore } from "./evtx-store";
import { T0, eventItem, fixtureEdges, recordFor } from "./evtx-correlation-test-fixtures";
import { windowReplyFor } from "./evtx-detail-context-test-helpers";
import { useLogStore } from "../../stores/log-store";

const EDGES = fixtureEdges("exactPair");
const CENTER = recordFor(2).timestampEpoch;
const ITEMS = [eventItem(1, T0 + 1_000), eventItem(2, T0 + 2_000), eventItem(3, T0 + 3_000)];

function analysisResult(sessionId: string) {
  const status = {
    sessionId,
    revision: 1,
    totalItems: ITEMS.length,
    eventItems: ITEMS.length,
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
      revision: 1,
      offset: 0,
      nextOffset: null,
      serializedBytes: 1_024,
      totalItems: status.totalItems,
      eventItems: status.eventItems,
      logItems: 0,
      totalUnplaced: 0,
      totalEdges: status.totalEdges,
      totalCoverageGaps: 0,
      items: ITEMS,
      unplacedPreview: [],
      edgesPreview: EDGES,
      coverageGapsPreview: [],
    },
    // What the rail reads of a diagnosis (the panel is a stand-in): no findings, none actionable.
    diagnosis: { findings: [], overview: { actionableFindingCount: 0 } },
  };
}

function seed(): void {
  const records = [recordFor(1), recordFor(2), recordFor(3)];
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

/** The nearest inline background colour at or above the element: the surface it is drawn on. */
function surfaceOf(element: HTMLElement): string | null {
  for (let node: HTMLElement | null = element; node !== null; node = node.parentElement) {
    if (node.style.backgroundColor !== "") return node.style.backgroundColor;
  }
  return null;
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  mocks.closeAnalysis.mockResolvedValue(undefined);
  mocks.buildAnalysis.mockImplementation(async () => analysisResult("session-1"));
  mocks.queryWindow.mockImplementation(async (sessionId: string, startMs: number, endMs: number) =>
    windowReplyFor(
      sessionId,
      1,
      startMs,
      endMs,
      ITEMS.filter((item) => item.timestampMs >= startMs && item.timestampMs <= endMs),
    ),
  );
  useEvtxLayoutStore.setState({ activeView: "table", railTab: "insights" });
  useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
  seed();
});

afterEach(cleanup);

const settleFor = (ms: number) =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });

describe("the Context section in the real rail", () => {
  it("is drawn on the rail's own surface, bg2, where the eyebrow's contrast was measured", async () => {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalled());
    act(() => selectRecordAndShowDetails(2));
    const section = await screen.findByRole("group", { name: DETAIL_CONTEXT_TITLE });
    const rail = document.querySelector<HTMLElement>('[data-evtx-region="rail"]') as HTMLElement;
    expect(rail).toContainElement(section);
    const eyebrow = within(section).getByText(DETAIL_CONTEXT_TITLE);
    expect(surfaceOf(eyebrow)).toBe(tokens.colorNeutralBackground2);
    expect(rail.style.backgroundColor).toBe(tokens.colorNeutralBackground2);
    // The list's own card is bg1, and holds everything but the eyebrow and its right label.
    const row = await within(section).findAllByRole("listitem");
    expect(row.length).toBeGreaterThan(0);
    expect(surfaceOf(row[0] as HTMLElement)).toBe(tokens.colorNeutralBackground1);
  });

  it("reads the session's window at ±5 min around the selected record, and lists it", async () => {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalled());
    act(() => selectRecordAndShowDetails(2));
    const section = await screen.findByRole("group", { name: DETAIL_CONTEXT_TITLE });
    await waitFor(() => expect(within(section).getAllByRole("listitem")).toHaveLength(3));
    expect(mocks.queryWindow).toHaveBeenCalledTimes(1);
    expect(mocks.queryWindow.mock.calls[0]).toEqual(["session-1", CENTER - 300_000, CENTER + 300_000, 1000]);
    // The selected record is the highlighted row, and the exact pair of the session's edges is marked.
    expect(within(section).getAllByRole("listitem").filter((item) => item.getAttribute("aria-current") === "true")).toHaveLength(1);
  });

  it("reads nothing while the Insights panel is hidden, though the rail is on Details", async () => {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalled());
    act(() => selectRecordAndShowDetails(2));
    await screen.findByRole("group", { name: DETAIL_CONTEXT_TITLE });
    await waitFor(() => expect(mocks.queryWindow).toHaveBeenCalledTimes(1));

    act(() => useEvtxLayoutStore.getState().setPanel("insights", false));
    act(() => useEvtxStore.getState().setSelectedRecordId(3));
    await settleFor(400);
    expect(mocks.queryWindow).toHaveBeenCalledTimes(1);

    act(() => useEvtxLayoutStore.getState().setPanel("insights", true));
    await waitFor(() => expect(mocks.queryWindow).toHaveBeenCalledTimes(2));
    expect(mocks.queryWindow.mock.calls[1]![1]).toBe(recordFor(3).timestampEpoch - 300_000);
  });

  it("reads nothing while the rail is on the Insights tab", async () => {
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalled());
    act(() => useEvtxStore.getState().setSelectedRecordId(2));
    await settleFor(400);
    expect(screen.queryByRole("group", { name: DETAIL_CONTEXT_TITLE })).toBeNull();
    expect(mocks.queryWindow).not.toHaveBeenCalled();
  });
});
