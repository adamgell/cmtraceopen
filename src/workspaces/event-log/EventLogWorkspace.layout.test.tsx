import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
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
vi.mock("./EvtxDetailPane", () => ({
  EvtxDetailPane: () => <div role="region" aria-label="Event log details" />,
}));
vi.mock("./EventDiagnosisPanel", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./EventDiagnosisPanel")>()),
  EventDiagnosisPanel: () => <section aria-label="Operational diagnosis" />,
}));
vi.mock("./UnifiedTimelineView", () => ({
  UnifiedTimelineView: () => <div data-testid="unified-timeline" />,
}));

import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { DEFAULT_LOG_LIST_FONT_SIZE, getLogListMetrics } from "../../lib/log-accessibility";
import { EventLogWorkspace, EvtxViewHost, type EvtxViewEntry } from "./EventLogWorkspace";
import { EvtxViewBar } from "./EvtxViewBar";
import {
  EVTX_LAYOUT_STORAGE_KEY,
  EVTX_LAYOUT_VERSION,
  EVTX_VIEW_PANEL_ID,
  sanitizeLayout,
  useEvtxLayoutStore,
} from "./evtx-layout-store";
import { dockMinHeightPx, gridRecordRowPx } from "./evtx-main-column-layout";
import { selectRecordAndShowDetails } from "./evtx-select-record";
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
    // Whether the dock is collapsed is not part of the stored layout, so reset it with the rest.
    useEvtxLayoutStore.setState({ ...sanitizeLayout(undefined), dockCollapsed: false });
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

  it("renders the view bar, channel pane, main view and the Insights rail, with the dock hidden", () => {
    render(<EventLogWorkspace />);
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
    expect(screen.getByTestId("channel-picker")).toBeVisible();
    expect(screen.getByRole("tabpanel", { name: "Table" })).toContainElement(
      screen.getByTestId("records-table"),
    );
    expect(region("rail")).toBeVisible();
    expect(region("rail")).toHaveStyle({ width: "340px" });
    expect(region("dock")).not.toBeNull();
    expect(region("dock")).not.toBeVisible();
    for (const note of screen.queryAllByText(/Not implemented in this phase/)) {
      expect(note).not.toBeVisible();
    }
  });

  it("caps the channel region and the rail on the body row's own children, not on a sized wrapper", () => {
    render(<EventLogWorkspace />);
    const row = region("main")!.parentElement as HTMLElement;
    // Both regions are direct children of the row, whose width is definite, so 40% is 40% of it.
    for (const name of ["channels", "rail"]) {
      const el = region(name)!;
      expect(el.parentElement).toBe(row);
      expect(el).toHaveStyle({ maxWidth: "40%", minWidth: "0px" });
    }
    // The pane inside the channel region carries no percentage cap of its own.
    const pane = region("channels")!.firstElementChild as HTMLElement;
    expect(pane.style.maxWidth).toBe("");
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
    const dock = region("dock")!;
    expect(dock).toHaveStyle({ height: "210px" });
    act(() => useEvtxLayoutStore.getState().setDockHeight(5000));
    expect(region("dock")).toBe(dock);
    expect(dock).toHaveStyle({ height: "450px" });
    // Only the rendered height clamps: what the user chose is kept as it was.
    expect(useEvtxLayoutStore.getState().dockHeight).toBe(5000);
  });

  // jsdom does no layout, so these are style guards: the numbers the browser spec measures
  // (e2e/screenshots/event-logs.spec.ts, "event-logs correlation dock") come from the styles below.
  describe("the floors of the main column", () => {
    // One row of the grid, by the function the grid sizes its rows with: the floor counts these.
    const gridRowPx = () =>
      gridRecordRowPx(
        getLogListMetrics(useUiStore.getState().logListFontSize).rowHeight,
        useEvtxStore.getState().columnConfig.order,
      );
    const resizeTo = (height: number) => {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: height });
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
    };
    const tableView = () => document.querySelector<HTMLElement>('[data-evtx-view="table"]')!;
    const strip = () => tableView().children[0] as HTMLElement;
    const gridBox = () => tableView().children[1] as HTMLElement;
    const panel = () => document.getElementById(EVTX_VIEW_PANEL_ID) as HTMLElement;

    it("gives the Table view its strip and five grid rows as a floor, so a short window scrolls it", () => {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
      render(<EventLogWorkspace />);
      expect(strip()).toHaveStyle({ height: "320px", flexShrink: "0" });
      expect(gridBox()).toHaveStyle({ minHeight: `${5 * gridRowPx()}px` });
      expect(panel()).toHaveStyle({ minHeight: `${320 + 5 * gridRowPx()}px` });
    });

    it("counts five of the grid's own rows, so the floor follows the Level column and the font", () => {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
      // 23 px of row at the default font; a grid record row is 29 px with the Level column on and
      // 25 px without it (a list row), so the floor is 145 px and then 125 px.
      expect(getLogListMetrics(DEFAULT_LOG_LIST_FONT_SIZE).rowHeight).toBe(23);
      expect(gridRecordRowPx(23, ["timestamp", "level"])).toBe(29);
      expect(gridRecordRowPx(23, ["timestamp"])).toBe(25);
      render(<EventLogWorkspace />);
      expect(useEvtxStore.getState().columnConfig.order).toContain("level");
      expect(gridBox()).toHaveStyle({ minHeight: "145px" });
      expect(panel()).toHaveStyle({ minHeight: "465px" });
      act(() => useEvtxStore.getState().toggleColumnVisible("level"));
      expect(gridBox()).toHaveStyle({ minHeight: "125px" });
      expect(panel()).toHaveStyle({ minHeight: "445px" });
      act(() => useEvtxStore.getState().toggleColumnVisible("level"));
      expect(gridBox()).toHaveStyle({ minHeight: "145px" });
      // A larger font makes a taller row, and the floor follows it.
      try {
        act(() => useUiStore.setState({ logListFontSize: 20 }));
        expect(gridBox()).toHaveStyle({ minHeight: `${5 * (getLogListMetrics(20).rowHeight + 6)}px` });
      } finally {
        act(() => useUiStore.setState({ logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE }));
      }
    });

    it("draws the strip at half the window when that is under 320 px, and never under 240 px", () => {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
      render(<EventLogWorkspace />);
      resizeTo(560);
      expect(strip()).toHaveStyle({ height: "280px" });
      expect(panel()).toHaveStyle({ minHeight: `${280 + 5 * gridRowPx()}px` });
      resizeTo(400);
      expect(strip()).toHaveStyle({ height: "240px" });
      expect(panel()).toHaveStyle({ minHeight: `${240 + 5 * gridRowPx()}px` });
    });

    it("holds no floor for a view that is not the Table", () => {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
      render(<EventLogWorkspace />);
      act(() => useEvtxLayoutStore.getState().setActiveView("charts"));
      expect(panel()).toHaveStyle({ minHeight: "0px" });
    });

    it("scrolls the main column instead of clipping it", () => {
      render(<EventLogWorkspace />);
      expect(region("main")).toHaveStyle({ overflowX: "hidden", overflowY: "auto" });
    });

    it("lets an expanded dock give way, down to its header and one lane, and keeps a collapsed one whole", async () => {
      Object.defineProperty(window, "innerHeight", { configurable: true, value: 900 });
      render(<EventLogWorkspace />);
      const dock = region("dock")!;
      const minimum = dockMinHeightPx(useUiStore.getState().logListFontSize);
      expect(dock).toHaveStyle({ height: "210px", flexShrink: "1", minHeight: `${minimum}px` });
      // The minimum is under the least the user can drag it to, so the dock has room to give.
      expect(minimum).toBeLessThan(useEvtxLayoutStore.getState().dockHeight);
      act(() => useEvtxLayoutStore.getState().setPanel("dock", true));
      fireEvent.click(await screen.findByRole("button", { name: "Collapse correlation" }));
      expect(dock).toHaveStyle({ flexShrink: "0" });
      expect(dock.style.minHeight).toBe("");
    });
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
        version: EVTX_LAYOUT_VERSION,
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
    expect(screen.getByText("Charts view")).toBeVisible();
    expect(region("channels")).not.toBeVisible();
    expect(region("rail")).toHaveStyle({ width: "400px" });
    expect(region("dock")).toHaveStyle({ height: "250px" });
    // The dock is available, so the envelope's choice shows it, with the dock in it.
    expect(region("rail")).toBeVisible();
    expect(region("dock")).toBeVisible();
    expect(await screen.findByRole("region", { name: "Correlation dock" })).toBeInTheDocument();
  });

  it("opens the dock from its toggle, and Close hides it and gives focus back to the toggle", async () => {
    render(<EventLogWorkspace />);
    const toggle = screen.getByRole("button", { name: "Correlation dock" });
    expect(region("dock")).not.toBeVisible();
    expect(screen.queryByRole("region", { name: "Correlation dock" })).toBeNull();
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(region("dock")).toBeVisible();
    const dock = await screen.findByRole("region", { name: "Correlation dock" });
    expect(region("dock")).toContainElement(dock);
    fireEvent.click(screen.getByRole("button", { name: "Close correlation dock" }));
    expect(region("dock")).not.toBeVisible();
    expect(screen.queryByRole("region", { name: "Correlation dock" })).toBeNull();
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    expect(toggle).toHaveFocus();
  });

  it("shows a dock that was collapsed expanded when its toggle opens it again", async () => {
    render(<EventLogWorkspace />);
    const toggle = screen.getByRole("button", { name: "Correlation dock" });
    fireEvent.click(toggle);
    fireEvent.click(await screen.findByRole("button", { name: "Collapse correlation" }));
    expect(region("dock")!.style.height).toBe("auto");
    fireEvent.click(toggle);
    fireEvent.click(toggle);
    expect(await screen.findByRole("button", { name: "Collapse correlation" })).toBeInTheDocument();
    expect(region("dock")).toHaveStyle({ height: "210px" });
  });

  it("links the layout tabs and the tabpanel in both directions", () => {
    render(<EventLogWorkspace />);
    const panel = document.getElementById(EVTX_VIEW_PANEL_ID) as HTMLElement;
    for (const name of ["Table", "Charts"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      const tab = screen.getByRole("tab", { name });
      expect(tab).toHaveAttribute("aria-controls", panel.id);
      expect(panel).toHaveAttribute("aria-labelledby", tab.id);
    }
  });

  it("shows a placeholder for views that are not built yet, behind the same tablist", () => {
    render(<EventLogWorkspace />);
    for (const name of ["Grouped", "Timeline", "Charts"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
      expect(screen.getByRole("tab", { name })).toHaveAttribute("aria-selected", "true");
      expect(screen.getByText(`${name} view`)).toBeVisible();
      expect(screen.getAllByText(/Not implemented in this phase/).length).toBeGreaterThan(0);
      expect(screen.getByTestId("records-table")).not.toBeVisible();
    }
  });

  it("builds the Correlation view instead of a placeholder, behind the same tablist and panel", async () => {
    render(<EventLogWorkspace />);
    fireEvent.click(screen.getByRole("tab", { name: "Correlation" }));
    expect(await screen.findByTestId("correlation-view")).toBeVisible();
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Correlation" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("Correlation view")).toBeNull();
    expect(screen.getByRole("tabpanel", { name: "Correlation" })).toContainElement(
      screen.getByTestId("correlation-view"),
    );
    // No analysis session is built yet in this test: the view says so rather than showing a count.
    expect(screen.getByTestId("correlation-view")).toHaveTextContent("Reading correlation edges");
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

  it("mounts the Insights rail in the rail region and no longer renders the old card or bottom pane", () => {
    render(<EventLogWorkspace />);

    const rail = region("rail");
    expect(rail).not.toBeNull();
    expect(within(rail as HTMLElement).getByRole("tablist", { name: "Rail tabs" })).toBeInTheDocument();
    // The diagnosis lives in the rail only: once, and not above the body.
    const diagnosis = screen.getAllByLabelText("Operational diagnosis");
    expect(diagnosis).toHaveLength(1);
    expect(rail).toContainElement(diagnosis[0]);
    // No selection, no details pane; with one, the pane is in the rail and not under the grid.
    expect(screen.queryByRole("region", { name: "Event log details" })).toBeNull();
    act(() => selectRecordAndShowDetails(RECORD.id));
    const detail = screen.getByRole("region", { name: "Event log details" });
    expect(rail).toContainElement(detail);
    expect(region("main")).not.toContainElement(detail);
  });

  it("selecting a record switches the rail to Details and shows a hidden rail", () => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
    render(<EventLogWorkspace />);
    expect(region("rail")).not.toBeVisible();

    act(() => selectRecordAndShowDetails(RECORD.id));

    expect(region("rail")).toBeVisible();
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(screen.getByRole("tab", { name: "Event 42" })).toHaveAttribute("aria-selected", "true");
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
