import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { lazy } from "react";
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
import { EventLogWorkspace, EvtxViewHost, type EvtxViewEntry } from "./EventLogWorkspace";
import { CHART_DATA_THROTTLE_MS } from "./EvtxChartsView";
import { EvtxViewBar } from "./EvtxViewBar";
import { requireElement, stubLayout } from "./evtx-test-dom";
import {
  EVTX_LAYOUT_STORAGE_KEY,
  sanitizeLayout,
  useEvtxLayoutStore,
} from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import type { EvtxRecord } from "./types";
import type { LogEntry } from "../../types/log";

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
const requireRegion = (name: string) => requireElement(region(name), `the ${name} region`);

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

  it("renders the view bar, channel pane and main view, with the rail and dock hidden", () => {
    render(<EventLogWorkspace />);
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
    expect(screen.getByTestId("channel-picker")).toBeVisible();
    expect(screen.getByRole("tabpanel")).toContainElement(screen.getByTestId("records-table"));
    // The regions exist so Phase 4 and 11 only enable the toggle, but nothing shows by default.
    expect(region("rail")).not.toBeNull();
    expect(region("rail")).not.toBeVisible();
    expect(region("rail")).toHaveStyle({ width: "340px" });
    expect(region("dock")).not.toBeNull();
    expect(region("dock")).not.toBeVisible();
    for (const note of screen.queryAllByText(/Not implemented in this phase/)) {
      expect(note).not.toBeVisible();
    }
  });

  it("caps the channel region and the rail on the body row's own children, not on a sized wrapper", () => {
    render(<EventLogWorkspace />);
    const row = requireElement(requireRegion("main").parentElement, "the body row");
    // Both regions are direct children of the row, whose width is definite, so 40% is 40% of it.
    for (const name of ["channels", "rail"]) {
      const el = requireRegion(name);
      expect(el.parentElement).toBe(row);
      expect(el).toHaveStyle({ maxWidth: "40%", minWidth: "0px" });
    }
    // The pane inside the channel region carries no percentage cap of its own.
    const pane = requireElement(
      requireRegion("channels").firstElementChild,
      "the channel pane inside its region",
    ) as HTMLElement;
    expect(pane.style.maxWidth).toBe("");
  });

  it("reports the rail's rendered width and caps its maximum when the row is narrow", () => {
    // A 600 px row caps the rail at 240 px, below the 280 px minimum and the 340 px stored width.
    const restore = stubLayout({ "evtx-insights-rail": 240 }, 600);
    try {
      render(<EventLogWorkspace />);
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      const handle = screen.getByRole("separator", { name: "Resize insights rail", hidden: true });
      expect(handle).toHaveAttribute("aria-valuenow", "240");
      expect(handle).toHaveAttribute("aria-valuemax", "240");
      expect(handle).toHaveAttribute("aria-valuemin", "240");
      // Neither a key step nor End changes the visible rail, so the requested 340 px survives.
      fireEvent.keyDown(handle, { key: "ArrowLeft" });
      fireEvent.keyDown(handle, { key: "End" });
      expect(useEvtxLayoutStore.getState().railWidth).toBe(340);
      expect(handle).toHaveAttribute("aria-valuenow", "240");
      // The row widens: the rail returns to the requested width.
      restore.set({ "evtx-insights-rail": 340 }, 1440);
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      expect(handle).toHaveAttribute("aria-valuenow", "340");
      expect(handle).toHaveAttribute("aria-valuemax", "480");
    } finally {
      restore();
    }
  });

  it("keeps the rail value in range on a fractional cap and never overwrites the stored width", () => {
    useEvtxLayoutStore.getState().setRailWidth(480);
    const restore = stubLayout({ "evtx-insights-rail": 401.6 }, 1004);
    try {
      render(<EventLogWorkspace />);
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      const handle = screen.getByRole("separator", { name: "Resize insights rail", hidden: true });
      expect(Number(handle.getAttribute("aria-valuemax"))).toBe(401);
      expect(Number(handle.getAttribute("aria-valuenow"))).toBeLessThanOrEqual(401);
      fireEvent.keyDown(handle, { key: "ArrowLeft" });
      fireEvent.keyDown(handle, { key: "End" });
      // A leftward drag grows the rail; it cannot pass the cap either.
      fireEvent.pointerDown(handle, { clientX: 700, button: 0, isPrimary: true, pointerId: 1 });
      fireEvent.pointerMove(handle, { clientX: 500, buttons: 1, pointerId: 1 });
      fireEvent.pointerUp(handle, { pointerId: 1 });
      expect(useEvtxLayoutStore.getState().railWidth).toBe(480);
    } finally {
      restore();
    }
  });

  it("measures the rail after the first-open path (source picker, then load)", () => {
    // The rail ships unavailable; show it through the store, as Phase 4 will.
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: true, dock: false } });
    useEvtxStore.setState({ records: [], channels: [], sourceMode: null, loadedChannels: new Set() });
    const restore = stubLayout({ "evtx-insights-rail": 240 }, 600);
    try {
      render(<EventLogWorkspace />);
      // Nothing loaded: the source picker renders and the rail does not exist yet.
      expect(region("rail")).toBeNull();
      act(() => {
        useEvtxStore.setState({
          records: [RECORD],
          channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
          selectedChannels: new Set(["Application"]),
          loadedChannels: new Set(["Application"]),
          sourceMode: "files",
        });
      });
      const handle = screen.getByRole("separator", { name: "Resize insights rail" });
      expect(handle).toHaveAttribute("aria-valuenow", "240");
      expect(handle).toHaveAttribute("aria-valuemax", "240");
    } finally {
      restore();
    }
  });

  it("keeps stepping the rail with ArrowLeft when ResizeObserver is unavailable and a width is measured", () => {
    expect(typeof ResizeObserver).toBe("undefined");
    const restore = stubLayout({ "evtx-insights-rail": "style" }, 1440);
    try {
      render(<EventLogWorkspace />);
      const handle = screen.getByRole("separator", { name: "Resize insights rail", hidden: true });
      expect(handle).toHaveAttribute("aria-valuenow", "340");
      fireEvent.keyDown(handle, { key: "ArrowLeft" });
      expect(useEvtxLayoutStore.getState().railWidth).toBe(356);
      expect(handle).toHaveAttribute("aria-valuenow", "356");
      fireEvent.keyDown(handle, { key: "ArrowLeft" });
      expect(useEvtxLayoutStore.getState().railWidth).toBe(372);
      expect(handle).toHaveAttribute("aria-valuenow", "372");
    } finally {
      restore();
    }
  });

  it("hides and shows the channel pane without discarding its state", () => {
    render(<EventLogWorkspace />);
    const search = screen.getByTestId("channel-picker");
    fireEvent.change(search, { target: { value: "kept" } });

    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    expect(region("channels")).not.toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    expect(region("channels")).toBeVisible();
    // The same node, not a remount: the typed text survives.
    expect(screen.getByTestId("channel-picker")).toBe(search);
    expect(search).toHaveValue("kept");
  });

  it("keeps the dock mounted and sizes it from the store, clamped to half the viewport", () => {
    Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
    render(<EventLogWorkspace />);
    const dock = requireRegion("dock");
    expect(dock).toHaveStyle({ height: "210px" });
    act(() => useEvtxLayoutStore.getState().setDockHeight(5000));
    expect(region("dock")).toBe(dock);
    expect(dock).toHaveStyle({ height: "450px" });
  });

  it("keeps the stored dock height when the viewport caps it and a resize changes nothing", () => {
    Object.defineProperty(window, "innerHeight", { configurable: true, value: 400 });
    try {
      render(<EventLogWorkspace />);
      // 50vh of 400 px is 200 px: the stored 210 px renders as 200 px.
      expect(requireRegion("dock")).toHaveStyle({ height: "200px" });
      const handle = screen.getByRole("separator", { name: "Resize correlation dock", hidden: true });
      fireEvent.keyDown(handle, { key: "ArrowUp" });
      fireEvent.keyDown(handle, { key: "End" });
      expect(useEvtxLayoutStore.getState().dockHeight).toBe(210);
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      expect(requireRegion("dock")).toHaveStyle({ height: "210px" });
    } finally {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 768 });
    }
  });

  it("resizes the hidden rail from its separator, clamped to 280 through 480", () => {
    render(<EventLogWorkspace />);
    const handle = screen.getByRole("separator", { name: "Resize insights rail", hidden: true });
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(useEvtxLayoutStore.getState().railWidth).toBe(356);
    fireEvent.keyDown(handle, { key: "End" });
    expect(useEvtxLayoutStore.getState().railWidth).toBe(480);
    fireEvent.keyDown(handle, { key: "Home" });
    expect(useEvtxLayoutStore.getState().railWidth).toBe(280);
  });

  it("honors a rehydrated layout on mount", async () => {
    localStorage.setItem(
      EVTX_LAYOUT_STORAGE_KEY,
      JSON.stringify({
        version: 1,
        state: {
          activeView: "charts",
          panels: { channels: false, insights: true, dock: true },
          railTab: "details",
          railWidth: 400,
          dockHeight: 250,
        },
      }),
    );
    await useEvtxLayoutStore.persist.rehydrate();
    render(<EventLogWorkspace />);
    expect(screen.getByRole("tab", { name: "Charts" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByTestId("evtx-charts-view", {}, { timeout: 10_000 })).toBeVisible();
    expect(region("channels")).not.toBeVisible();
    expect(region("rail")).toHaveStyle({ width: "400px" });
    expect(region("dock")).toHaveStyle({ height: "250px" });
    // Panels with no content yet stay off even if storage says otherwise.
    expect(region("rail")).not.toBeVisible();
    expect(region("dock")).not.toBeVisible();
  });

  it("links the layout tabs and the tabpanel in both directions", () => {
    render(<EventLogWorkspace />);
    const panel = screen.getByRole("tabpanel");
    for (const name of ["Table", "Charts"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      const tab = screen.getByRole("tab", { name });
      expect(tab).toHaveAttribute("aria-controls", panel.id);
      expect(panel).toHaveAttribute("aria-labelledby", tab.id);
    }
  });

  it("shows a placeholder for views that are not built yet, behind the same tablist", () => {
    render(<EventLogWorkspace />);
    for (const name of ["Grouped", "Timeline", "Correlation"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
      expect(screen.getByRole("tab", { name })).toHaveAttribute("aria-selected", "true");
      expect(screen.getByText(`${name} view`)).toBeVisible();
      expect(screen.getAllByText(/Not implemented in this phase/).length).toBeGreaterThan(0);
      expect(screen.getByTestId("records-table")).not.toBeVisible();
    }
  });

  it("loads the Charts view lazily behind the same tablist", async () => {
    render(<EventLogWorkspace />);
    fireEvent.click(screen.getByRole("tab", { name: "Charts" }));
    expect(screen.getByRole("tab", { name: "Charts" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByTestId("evtx-charts-view", {}, { timeout: 10_000 })).toBeVisible();
    expect(screen.getAllByRole("figure")).toHaveLength(4);
    expect(screen.getByTestId("records-table")).not.toBeVisible();
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

  it("shows the Loading view fallback inside the tabpanel while a lazy view loads, with the tablist mounted", async () => {
    let resolveView!: (module: { default: () => React.ReactElement }) => void;
    const Lazy = lazy(
      () =>
        new Promise<{ default: () => React.ReactElement }>((resolve) => {
          resolveView = resolve;
        }),
    );
    const placeholder: EvtxViewEntry = { keepAlive: false, render: () => <div>stub</div> };
    const views: Record<string, EvtxViewEntry> = {
      table: placeholder,
      grouped: placeholder,
      timeline: placeholder,
      charts: { keepAlive: false, render: () => <Lazy /> },
      correlation: placeholder,
    };
    useEvtxLayoutStore.setState({ activeView: "charts" });
    render(
      <>
        <EvtxViewBar nowEpoch={0} />
        <EvtxViewHost views={views as never} activeView="charts" />
      </>,
    );
    const panel = screen.getByRole("tabpanel");
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
    expect(panel).toHaveTextContent("Loading view");

    await act(async () => {
      resolveView({ default: () => <div>Charts loaded</div> });
    });
    expect(panel).toHaveTextContent("Charts loaded");
    expect(panel).not.toHaveTextContent("Loading view");
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
  });
});

describe("EventLogWorkspace Charts view wiring", () => {
  const fresh = { ...RECORD, timestampEpoch: Date.now(), timestamp: new Date().toISOString() };

  beforeEach(() => {
    localStorage.clear();
    useEvtxLayoutStore.setState({ ...sanitizeLayout(undefined), activeView: "charts" });
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [fresh],
      channels: [
        { name: "Application", eventCount: 1, sourceType: "live" },
        { name: "System", eventCount: 0, sourceType: "live" },
        { name: "Setup", eventCount: 0, sourceType: "live" },
      ],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      isLoading: false,
      sourceMode: "files",
      timeWindow: "all",
    });
    useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
  });

  afterEach(cleanup);

  const eventsTile = async () => {
    render(<EventLogWorkspace />);
    await screen.findByTestId("evtx-charts-view", {}, { timeout: 10_000 });
    return document.querySelector<HTMLElement>('[data-kpi="events"]')!;
  };

  const logLine = (filePath: string) => ({ filePath }) as unknown as LogEntry;

  it("counts distinct event-record channels in files mode, and the window as all loaded", async () => {
    const system = (id: number, sourceLabel: string): EvtxRecord => ({
      ...fresh,
      id,
      eventRecordId: 100 + id,
      channel: "System",
      sourceLabel,
    });
    const archivedLog: EvtxRecord = {
      ...fresh,
      id: 9,
      originKind: "log",
      channel: "bundle.zip::logs/agent.log",
      sourceLabel: "bundle.zip::logs/agent.log",
    };
    useEvtxStore.setState({
      // Two files share the channel name "System"; an archived text log's channel is its label;
      // the parse result also lists channels of files that contributed no records.
      records: [fresh, system(2, "System.evtx"), system(3, "Archive-System-2026.evtx"), archivedLog],
    });
    const tile = await eventsTile();
    expect(tile).toHaveTextContent("Events (all loaded)");
    expect(tile).toHaveTextContent("2 channels · 1 text log");
  });

  it("counts completed loads (not enumerated channels) in live mode", async () => {
    useEvtxStore.setState({ sourceMode: "live", timeWindow: "7d" });
    const tile = await eventsTile();
    expect(tile).toHaveTextContent("Events (7 d)");
    expect(tile).toHaveTextContent("1 channel · 0 text logs");
  });

  it("counts text-log sources, not lines", async () => {
    useLogStore.setState({
      entries: [logLine("C:/logs/a.log"), logLine("C:/logs/a.log"), logLine("C:/logs/a.log")],
    });
    expect(await eventsTile()).toHaveTextContent("1 channel · 1 text log");
  });

  it("counts two text-log sources as text logs", async () => {
    useLogStore.setState({ entries: [logLine("C:/logs/a.log"), logLine("C:/logs/b.log")] });
    expect(await eventsTile()).toHaveTextContent("1 channel · 2 text logs");
  });

  it("shows a loading state, not 'no events', while a load runs with records present", async () => {
    useEvtxStore.setState({ isLoading: true });
    render(<EventLogWorkspace />);
    await screen.findByText("Loading events...", {}, { timeout: 10_000 });
    expect(screen.queryByText(/No events to chart/)).toBeNull();
  });

  it("does not say 'No events' between a load ending and its records being drawn", async () => {
    useEvtxStore.setState({ isLoading: true });
    render(<EventLogWorkspace />);
    // Real timers until the lazy chunk has loaded; fake timers only for the flip.
    await screen.findByText("Loading events...", {}, { timeout: 10_000 });
    vi.useFakeTimers();
    try {
      // The visible rows come back in the same store update that ends the load.
      act(() => {
        useEvtxStore.setState({ isLoading: false });
      });
      expect(screen.queryByText(/No events to chart/)).toBeNull();
      expect(screen.getByText("Loading events...")).toBeInTheDocument();
      act(() => {
        vi.advanceTimersByTime(CHART_DATA_THROTTLE_MS - 1);
      });
      expect(screen.queryByText(/No events to chart/)).toBeNull();
      expect(screen.getByText("Loading events...")).toBeInTheDocument();
      act(() => {
        vi.advanceTimersByTime(1);
      });
      expect(screen.queryByText(/No events to chart/)).toBeNull();
      expect(screen.queryByText("Loading events...")).toBeNull();
      expect(screen.getByTestId("kpi-value-events")).toHaveTextContent("1");
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows n/a for the chains tile until a timeline page exists", async () => {
    await eventsTile();
    expect(screen.getByTestId("kpi-value-chains").textContent).toBe("n/a");
  });
});
