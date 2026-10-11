import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
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
vi.mock("./ChannelPicker", () => ({
  ChannelPicker: () => <input aria-label="Filter channels" data-testid="channel-picker" />,
}));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({
  EvtxTimeline: () => <div data-testid="records-table">records</div>,
}));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({
  UnifiedTimelineView: () => <div data-testid="unified-timeline" />,
}));

import { useLogStore } from "../../stores/log-store";
import { EventLogWorkspace } from "./EventLogWorkspace";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import type { EvtxRecord } from "./types";

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: 1,
  provider: "Example Provider",
  channel: "Application",
  eventId: 42,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

const region = (name: string) =>
  document.querySelector<HTMLElement>(`[data-evtx-region="${name}"]`);

describe("EventLogWorkspace three-column shell", () => {
  beforeEach(() => {
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [RECORD],
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      isLoading: false,
      sourceMode: "files",
      timeWindow: "all",
    });
    useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
  });

  afterEach(cleanup);

  it("renders the view bar, channel pane, main view and rail", () => {
    render(<EventLogWorkspace />);
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
    expect(screen.getByTestId("channel-picker")).toBeVisible();
    expect(screen.getByRole("tabpanel")).toContainElement(screen.getByTestId("records-table"));
    expect(region("rail")).toBeVisible();
    expect(region("rail")).toHaveStyle({ width: "340px" });
    expect(region("dock")).toBeNull();
  });

  it("hides and shows regions with the panel toggles without discarding their state", () => {
    render(<EventLogWorkspace />);
    const search = screen.getByTestId("channel-picker");
    fireEvent.change(search, { target: { value: "kept" } });

    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    expect(region("channels")).not.toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Insights" }));
    expect(region("rail")).not.toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Correlation dock" }));
    expect(region("dock")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: "Insights" }));
    expect(region("channels")).toBeVisible();
    expect(region("rail")).toBeVisible();
    // The same node, not a remount: the typed text survives.
    expect(screen.getByTestId("channel-picker")).toBe(search);
    expect(search).toHaveValue("kept");
  });

  it("opens the dock at its default height and clamps it to half the viewport", () => {
    Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
    render(<EventLogWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Correlation dock" }));
    expect(region("dock")).toHaveStyle({ height: "210px" });
    act(() => useEvtxLayoutStore.getState().setDockHeight(5000));
    expect(region("dock")).toHaveStyle({ height: "450px" });
  });

  it("resizes the rail from its separator, clamped to 280 through 480", () => {
    render(<EventLogWorkspace />);
    const handle = screen.getByRole("separator", { name: "Resize insights rail" });
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(useEvtxLayoutStore.getState().railWidth).toBe(356);
    fireEvent.keyDown(handle, { key: "End" });
    expect(useEvtxLayoutStore.getState().railWidth).toBe(480);
    fireEvent.keyDown(handle, { key: "Home" });
    expect(useEvtxLayoutStore.getState().railWidth).toBe(280);
  });

  it("shows a placeholder for views that are not built yet, behind the same tablist", () => {
    render(<EventLogWorkspace />);
    for (const name of ["Grouped", "Timeline", "Charts", "Correlation"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
      expect(screen.getByRole("tab", { name })).toHaveAttribute("aria-selected", "true");
      expect(screen.getByText(`${name} view`)).toBeVisible();
      expect(screen.getAllByText(/Not implemented in this phase/).length).toBeGreaterThan(0);
      expect(screen.getByTestId("records-table")).not.toBeVisible();
    }
  });

  it("keeps selection and filters when switching views and returning to the table", () => {
    useEvtxStore.setState({ selectedRecordId: RECORD.id, filterSearch: "kept" });
    render(<EventLogWorkspace />);
    const table = screen.getByTestId("records-table");
    fireEvent.click(screen.getByRole("tab", { name: "Charts" }));
    fireEvent.click(screen.getByRole("tab", { name: "Table" }));
    expect(useEvtxStore.getState().selectedRecordId).toBe(RECORD.id);
    expect(useEvtxStore.getState().filterSearch).toBe("kept");
    expect(screen.getByTestId("records-table")).toBe(table);
    expect(table).toBeVisible();
  });
});
