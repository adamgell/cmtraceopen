import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
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
vi.mock("./EvtxTimeline", () => ({
  EvtxTimeline: () => <div data-testid="records-table" />,
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
import { installRecordingCanvas, type RecordingCanvases } from "./__fixtures__/recording-canvas";
import { EventLogWorkspace } from "./EventLogWorkspace";
import workspaceSource from "./EventLogWorkspace.tsx?raw";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { buildAxisTicks, buildHistogram } from "./evtx-histogram";
import { buildSwimlanes } from "./evtx-swimlanes";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS } from "./evtx-throttle";
import { formatTimeRange, timeRangeNeedsYear } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const T0 = Date.UTC(2026, 9, 16, 12, 0, 0);
const LEFT = 100;
const PLOT_W = 360;
const LANE = 36;

const record = (id: number, timestampEpoch: number, provider: string, level: EvtxLevel = "Information"): EvtxRecord => ({
  id,
  eventRecordId: 100 + id,
  timestamp: new Date(timestampEpoch).toISOString(),
  timestampEpoch,
  provider,
  channel: "Application",
  eventId: 42,
  level,
  computer: "TEST-PC",
  message: `Example event ${id}`,
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
});

/** Twelve events, one every 20 minutes, in two providers. */
const twelve = () =>
  Array.from({ length: 12 }, (_, i) =>
    record(i + 1, T0 - (12 - i) * 20 * MINUTE, i % 3 === 0 ? "Alpha" : "Beta", i % 4 === 0 ? "Error" : "Information"),
  );

function seed(records: EvtxRecord[], overrides: Record<string, unknown> = {}) {
  localStorage.clear();
  useEvtxLayoutStore.setState(sanitizeLayout(undefined));
  useEvtxStore.getState().reset();
  useEvtxStore.setState({
    records,
    channels: [{ name: "Application", eventCount: records.length, sourceType: "live" }],
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application"]),
    isLoading: false,
    sourceMode: "files",
    timeWindow: "all",
    timeZoneMode: "utc",
    ...overrides,
  });
  useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: "merged" });
}

let canvases: RecordingCanvases;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  canvases = installRecordingCanvas();
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(
    () =>
      ({
        left: LEFT,
        top: 0,
        right: LEFT + PLOT_W,
        bottom: 200,
        width: PLOT_W,
        height: 200,
        x: LEFT,
        y: 0,
        toJSON: () => ({}),
      }) as DOMRect,
  );
  Object.defineProperty(window, "devicePixelRatio", { value: 1, configurable: true });
});

afterEach(() => {
  cleanup();
  canvases.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const showTimeline = async () => {
  fireEvent.click(screen.getByRole("tab", { name: "Timeline" }));
  return screen.findByRole("figure", { name: /^Events by / });
};
const lanesSlider = () => screen.getByRole("slider", { name: "Time range, by lane" });
const histogramRegion = () => document.querySelector<HTMLElement>('[data-evtx-region="histogram"]')!;
const lanesRegion = () => document.querySelector<HTMLElement>('[data-evtx-region="swimlanes"]');
const storeRange = () => useEvtxStore.getState().timeRange;
const readout = () => document.querySelector("[data-evtx-filter-count]")?.textContent ?? null;
const laneLabels = () =>
  [...(lanesRegion()?.querySelectorAll<HTMLElement>("[data-evtx-lane]") ?? [])].map((li) => li.children[0].textContent);
const tickLabels = () =>
  [...(lanesRegion()?.querySelectorAll<HTMLElement>("[data-evtx-tick]") ?? [])].map((tick) => tick.textContent);
const flushThrottle = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, DERIVATION_THROTTLE_MS + 30));
  });

describe("the Timeline view in the workspace", () => {
  it("is the view bar's Timeline tab: the lanes load into the tabpanel, under the histogram, in place of the placeholder", async () => {
    seed(twelve());
    render(<EventLogWorkspace />);
    expect(lanesRegion()).toBeNull();
    const figure = await showTimeline();
    const panel = screen.getByRole("tabpanel", { name: "Timeline" });
    expect(panel).toContainElement(figure);
    expect(screen.queryByText("Timeline view")).toBeNull();
    // (The hidden correlation dock keeps its own placeholder until Phase 11; the view has none.)
    expect(within(panel).queryByText(/Not implemented in this phase/)).toBeNull();
    // The histogram stays above the body on every view, so both charts share the screen.
    const main = document.querySelector('[data-evtx-region="main"]')!;
    expect(histogramRegion().compareDocumentPosition(main) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(histogramRegion()).getByRole("slider", { name: "Time range" })).toBeInTheDocument();
    expect(within(figure).getByRole("slider", { name: "Time range, by lane" })).toBeInTheDocument();
    expect(laneLabels()).toEqual(["Beta", "Alpha"]);
  });

  it("shows the Loading view fallback while the lazily loaded view arrives, with the tablist mounted", async () => {
    seed(twelve());
    render(<EventLogWorkspace />);
    fireEvent.click(screen.getByRole("tab", { name: "Timeline" }));
    expect(screen.getByRole("tablist", { name: "Layout" })).toBeInTheDocument();
    await screen.findByRole("figure", { name: /^Events by / });
    expect(screen.queryByText("Loading view...")).toBeNull();
  });

  it("loads the canvas code on demand: the workspace imports it lazily and not at the top", () => {
    const code = workspaceSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    expect(code).toMatch(/lazy\(\s*\(\)\s*=>\s*import\("\.\/EvtxSwimlaneView"\)/);
    expect(code).not.toMatch(/^import .* from "\.\/EvtxSwimlaneView";/m);
  });

  it("is not kept alive: leaving the view unmounts the lanes, and the Table view is back as it was", async () => {
    seed(twelve());
    render(<EventLogWorkspace />);
    const table = screen.getByTestId("records-table");
    await showTimeline();
    expect(table).not.toBeVisible();
    fireEvent.click(screen.getByRole("tab", { name: "Table" }));
    expect(lanesRegion()).toBeNull();
    expect(screen.getByTestId("records-table")).toBe(table);
    expect(table).toBeVisible();
  });

  it("opens straight onto the lanes when the last view used was the Timeline", async () => {
    seed(twelve());
    useEvtxLayoutStore.setState({ activeView: "timeline" });
    render(<EventLogWorkspace />);
    await screen.findByRole("figure", { name: /^Events by / });
    expect(screen.getByRole("tab", { name: "Timeline" })).toHaveAttribute("aria-selected", "true");
  });

  it("charts the context: the axis and the lanes are the histogram's, and a brush changes neither", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const histogram = buildHistogram(records, "utc", undefined, Date.now());
    expect(tickLabels()).toEqual(buildAxisTicks(histogram, "utc").map((tick) => tick.label));
    const histogramTicks = [...histogramRegion().querySelectorAll<HTMLElement>("[data-evtx-tick]")].map((tick) => tick.textContent);
    expect(tickLabels()).toEqual(histogramTicks);
    const labelsBefore = laneLabels();
    const countsBefore = [...lanesRegion()!.querySelectorAll("[data-evtx-lane-count]")].map((count) => count.textContent);

    act(() => {
      useEvtxStore.setState({ timeRange: { startMs: histogram.edges[2], endMs: histogram.edges[4] } });
    });
    await flushThrottle();
    expect(readout()).not.toBe("Showing 12 of 12");
    expect(tickLabels()).toEqual(histogramTicks);
    expect(laneLabels()).toEqual(labelsBefore);
    expect([...lanesRegion()!.querySelectorAll("[data-evtx-lane-count]")].map((count) => count.textContent)).toEqual(
      countsBefore,
    );
    expect(lanesRegion()!.querySelector('[data-evtx-layer="wash"]')).not.toBeNull();
  });

  it("brushes with the pointer on the lanes: the chip appears, the count narrows, the lanes keep every dot", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const histogram = buildHistogram(records, "utc", undefined, Date.now());
    const width = PLOT_W / histogram.buckets.length;
    const slider = lanesSlider();
    fireEvent.pointerDown(slider, { clientX: LEFT + 2 * width + 1, clientY: 18, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
    fireEvent.pointerMove(slider, { clientX: LEFT + 4 * width + 1, clientY: 18, buttons: 1, pointerId: 1 });
    fireEvent.pointerUp(slider, { clientX: LEFT + 4 * width + 1, clientY: 18, pointerId: 1 });
    expect(storeRange()).toEqual({ startMs: histogram.edges[2], endMs: histogram.edges[5] });
    expect(
      screen.getByText(
        `Time: brushed ${formatTimeRange(
          histogram.edges[2],
          histogram.edges[5],
          "utc",
          timeRangeNeedsYear(histogram.edges[2], histogram.edges[5], "utc", Date.now()),
        )}`,
      ),
    ).toBeInTheDocument();
    expect(readout()).toMatch(/^Showing \d+ of 12$/);
    expect(readout()).not.toBe("Showing 12 of 12");
    await flushThrottle();
    const total = [...lanesRegion()!.querySelectorAll("[data-evtx-lane-count]")]
      .map((count) => parseInt(count.textContent!))
      .reduce((a, b) => a + b, 0);
    expect(total).toBe(12);
    // Both figures draw the same wash for the same range.
    const washOf = (root: Element) => root.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
    expect(washOf(lanesRegion()!).style.left).toBe(washOf(histogramRegion()).style.left);
    expect(washOf(lanesRegion()!).style.right).toBe(washOf(histogramRegion()).style.right);
    expect(washOf(lanesRegion()!).style.opacity).toBe(washOf(histogramRegion()).style.opacity);
  });

  it("takes Escape twice from the lanes: the pending selection first, the applied range second", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const histogram = buildHistogram(records, "utc", undefined, Date.now());
    const range = { startMs: histogram.edges[2], endMs: histogram.edges[5] };
    act(() => {
      useEvtxStore.setState({ timeRange: range });
    });
    const slider = lanesSlider();
    fireEvent.focus(slider);
    fireEvent.keyDown(slider, { key: "ArrowRight", shiftKey: true });
    expect(slider.getAttribute("aria-valuetext")).toMatch(/selecting/);
    fireEvent.keyDown(slider, { key: "Escape" });
    expect(storeRange()).toEqual(range);
    fireEvent.keyDown(slider, { key: "Escape" });
    expect(storeRange()).toBeNull();
    expect(lanesRegion()!.querySelector('[data-evtx-layer="wash"]')).toBeNull();
  });

  it("still clears the range with Escape while the pointer rests on a dot and its tooltip shows", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const histogram = buildHistogram(records, "utc", undefined, Date.now());
    act(() => {
      useEvtxStore.setState({ timeRange: { startMs: histogram.edges[2], endMs: histogram.edges[5] } });
    });
    const scene = buildSwimlanes(records, "provider", "utc");
    const target = scene.lanes[0];
    fireEvent.pointerMove(lanesSlider(), {
      clientX: LEFT + target.fractions[0] * PLOT_W,
      clientY: LANE / 2,
      buttons: 0,
      pointerId: 1,
    });
    expect(document.querySelector("[data-evtx-tooltip]")).not.toBeNull();
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(storeRange()).toBeNull();
  });

  it("clears the brush from the chip's remove button, and the wash goes", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const histogram = buildHistogram(records, "utc", undefined, Date.now());
    act(() => {
      useEvtxStore.setState({ timeRange: { startMs: histogram.edges[2], endMs: histogram.edges[5] } });
    });
    fireEvent.click(screen.getByRole("button", { name: /^Remove Time: brushed/ }));
    expect(storeRange()).toBeNull();
    expect(lanesRegion()!.querySelector('[data-evtx-layer="wash"]')).toBeNull();
  });

  it("selects a clicked dot, opens Details in the rail, and leaves the range as it was", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const scene = buildSwimlanes(records, "provider", "utc");
    const lane = scene.lanes[1];
    const target = lane.records[1];
    const x = LEFT + lane.fractions[1] * PLOT_W;
    const y = LANE + LANE / 2;
    fireEvent.pointerDown(lanesSlider(), { clientX: x, clientY: y, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
    fireEvent.pointerUp(lanesSlider(), { clientX: x, clientY: y, pointerId: 1 });
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.id);
    expect(storeRange()).toBeNull();
    expect(screen.getByRole("tab", { name: "Event 42" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("region", { name: "Event log details" })).toBeInTheDocument();
  });

  it("keeps the selection when switching to the Table and back, the selected dot ringed again", async () => {
    const records = twelve();
    seed(records);
    render(<EventLogWorkspace />);
    await showTimeline();
    const scene = buildSwimlanes(records, "provider", "utc");
    const x = LEFT + scene.lanes[0].fractions[0] * PLOT_W;
    fireEvent.pointerDown(lanesSlider(), { clientX: x, clientY: LANE / 2, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
    fireEvent.pointerUp(lanesSlider(), { clientX: x, clientY: LANE / 2, pointerId: 1 });
    const selected = useEvtxStore.getState().selectedRecordId;
    fireEvent.click(screen.getByRole("tab", { name: "Table" }));
    await showTimeline();
    expect(useEvtxStore.getState().selectedRecordId).toBe(selected);
    expect(lanesRegion()!.querySelector('[data-evtx-layer="selected"]')).not.toBeNull();
  });

  it("charts nothing while a load runs, and the Table's records are not the lanes' business", async () => {
    seed([record(1, T0 - HOUR, "Alpha")], { isLoading: true });
    useEvtxLayoutStore.setState({ activeView: "timeline" });
    render(<EventLogWorkspace />);
    const figure = await screen.findByRole("figure", { name: /^Events by / });
    expect(figure).toHaveAttribute("aria-busy", "true");
    expect(within(figure).getByRole("slider", { name: "Time range, by lane" })).toHaveAttribute("aria-disabled", "true");
    expect(figure.querySelector("canvas")).toBeNull();
  });
});
