import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import {
  installRecordingCanvas,
  lineCalls,
  markCalls,
  type RecordingCanvases,
  type RecordingContext,
} from "./__fixtures__/recording-canvas";
import { LABEL_WIDTH_PX, SWIMLANE_HELP_TEXT, EvtxSwimlaneView } from "./EvtxSwimlaneView";
import viewSource from "./EvtxSwimlaneView.tsx?raw";
import {
  HISTOGRAM_LEVEL_LABELS,
  HISTOGRAM_STACK_ORDER,
  buildAxisTicks,
  buildHistogram,
  describeCoverage,
  describeUntimed,
  RANGE_OUTSIDE_NOTE,
} from "./evtx-histogram";
import { brushPaletteFor, solveBrushOpacity } from "./evtx-histogram-brush";
import { DOT_MARKS, PLOT_INSET_PX, swimlaneColors } from "./evtx-swimlane-canvas";
import { buildSwimlanes, describeSwimlaneFigure, laneHeightFor } from "./evtx-swimlanes";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS } from "./evtx-throttle";
import { timeZoneLabel } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
/** The workspace clock is pinned so the year rule (which compares with now) does not move with the run date. */
const PINNED_NOW = Date.UTC(2026, 9, 16, 12, 0);
const LEVELS: readonly EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
const PLOT_W = 600;
const LEFT = 200;

let nextId = 0;
const rec = (partial: Partial<EvtxRecord> = {}): EvtxRecord =>
  ({
    id: nextId++,
    eventRecordId: nextId,
    timestamp: "",
    timestampEpoch: T0,
    provider: "A",
    channel: "System",
    eventId: 1,
    level: "Information",
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
    ...partial,
  }) as EvtxRecord;

/** Every level in lane A, spread over three hours, and a second lane. */
const sample = (): EvtxRecord[] => [
  ...LEVELS.map((level, i) => rec({ provider: "A", level, timestampEpoch: T0 + i * 40 * MINUTE })),
  rec({ provider: "B", level: "Error", timestampEpoch: T0 + 20 * MINUTE }),
  rec({ provider: "B", level: "Warning", timestampEpoch: T0 + 3 * HOUR }),
];

/** `n` providers with 100 - i events each, so the ranking is by name too. */
const providers = (n: number): EvtxRecord[] =>
  Array.from({ length: n }, (_, i) =>
    Array.from({ length: 100 - i }, (_, j) =>
      rec({ provider: `provider-${String(i).padStart(2, "0")}`, timestampEpoch: T0 + (i * 3 + j) * MINUTE }),
    ),
  ).flat();

let canvases: RecordingCanvases;
let rectSpy: ReturnType<typeof vi.spyOn>;

function seed(overrides: Record<string, unknown> = {}) {
  useEvtxStore.setState({
    timeZoneMode: "utc",
    timeRange: null,
    recordScope: null,
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
    ...overrides,
  });
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(PINNED_NOW);
  canvases = installRecordingCanvas();
  // Every element measures as a plot of the same size: the view reads only its plot.
  rectSpy = vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(
    () =>
      ({
        left: LEFT,
        top: 0,
        right: LEFT + PLOT_W,
        bottom: 100,
        width: PLOT_W,
        height: 100,
        x: LEFT,
        y: 0,
        toJSON: () => ({}),
      }) as DOMRect,
  );
  Object.defineProperty(window, "devicePixelRatio", { value: 1, configurable: true });
  seed();
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

afterEach(() => {
  cleanup();
  canvases.restore();
  rectSpy.mockRestore();
  vi.useRealTimers();
  vi.restoreAllMocks();
  delete (window as unknown as { matchMedia?: unknown }).matchMedia;
  vi.unstubAllGlobals();
});

const last = <T,>(items: readonly T[]): T => items[items.length - 1];
const markLayer = (container: HTMLElement) =>
  container.querySelector<HTMLCanvasElement>('canvas[data-evtx-layer="marks"]')!;
const contextOf = (container: HTMLElement): RecordingContext => canvases.contextOf(markLayer(container))!;
/** Fills of the marks that are drawn (not the knockouts that clear), in paint order. */
const drawn = (context: RecordingContext) => markCalls(context).filter((call) => call.composite === "source-over");

describe("EvtxSwimlaneView", () => {
  it("is a figure named by its field, the charted span and its zone", () => {
    const records = sample();
    const { container } = render(<EvtxSwimlaneView records={records} loading={false} />);
    const label = describeSwimlaneFigure(buildSwimlanes(records, "provider", "utc"), "utc");
    expect(label).toMatch(/^Events by provider over .+ \(UTC\), one lane per provider$/);
    const figure = screen.getByRole("figure", { name: label });
    expect(figure).toHaveAttribute("data-evtx-region", "swimlanes");
    expect(figure).toHaveAttribute("aria-busy", "false");
    expect(container.querySelector("[data-evtx-swimlane-title]")).toHaveTextContent("Swimlanes by provider");
  });

  it("says drag selects a time range, since the lanes do not zoom", () => {
    render(<EvtxSwimlaneView records={sample()} loading={false} />);
    expect(SWIMLANE_HELP_TEXT).toBe(
      "each dot is one event · larger = more severe · drag to select a time range",
    );
    expect(document.querySelector("[data-evtx-swimlane-help]")!.textContent).toBe(SWIMLANE_HELP_TEXT);
    expect(SWIMLANE_HELP_TEXT).not.toMatch(/zoom/i);
  });

  it("names each lane and counts its events, in rank order", () => {
    const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
    const lanes = [...container.querySelectorAll<HTMLElement>("[data-evtx-lane]")];
    expect(lanes.map((lane) => lane.children[0].textContent)).toEqual(["A", "B"]);
    expect(lanes.map((lane) => lane.querySelector("[data-evtx-lane-count]")!.textContent)).toEqual([
      "5 events",
      "2 events",
    ]);
    expect(screen.getByRole("list", { name: "Lanes" })).toBeInTheDocument();
  });

  it("is 36 px a lane and a 172 px label with 8 px of padding at the default size", () => {
    const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
    const lane = container.querySelector<HTMLElement>("[data-evtx-lane]")!;
    expect(lane.style.height).toBe("36px");
    expect(LABEL_WIDTH_PX).toBe(172 + 8);
    expect(laneHeightFor(13)).toBe(36);
  });

  it("makes the lane taller with the list font size, so its two label lines are not clipped", () => {
    useUiStore.setState({ logListFontSize: 20 });
    const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
    const lane = container.querySelector<HTMLElement>("[data-evtx-lane]")!;
    expect(lane.style.height).toBe(`${laneHeightFor(20)}px`);
    expect(laneHeightFor(20)).toBeGreaterThan(36);
    const [name, count] = [...lane.children] as HTMLElement[];
    expect(parseInt(name.style.lineHeight) + parseInt(count.style.lineHeight)).toBeLessThanOrEqual(laneHeightFor(20));
    expect(name.style.fontSize).toBe("19px");
    expect(count.style.fontSize).toBe("17px");
  });

  it("offers the three lane fields, and re-lanes when one is picked", () => {
    const records = [
      rec({ provider: "A", channel: "Application", eventId: 7, timestampEpoch: T0 }),
      rec({ provider: "A", channel: "System", eventId: 7, timestampEpoch: T0 + HOUR }),
      rec({ provider: "B", channel: "System", eventId: 9, timestampEpoch: T0 + 2 * HOUR }),
    ];
    const { container } = render(<EvtxSwimlaneView records={records} loading={false} />);
    const lanes = () => [...container.querySelectorAll<HTMLElement>("[data-evtx-lane]")].map((li) => li.children[0].textContent);
    expect(lanes()).toEqual(["A", "B"]);
    const dropdown = screen.getByRole("combobox", { name: "Lanes" });
    fireEvent.click(dropdown);
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["Provider", "Channel", "Event ID"]);
    fireEvent.click(screen.getByRole("option", { name: "Channel" }));
    expect(lanes()).toEqual(["System", "Application"]);
    expect(container.querySelector("[data-evtx-swimlane-title]")).toHaveTextContent("Swimlanes by channel");
    expect(screen.getByRole("figure")).toHaveAccessibleName(/^Events by channel over /);
    fireEvent.click(screen.getByRole("combobox", { name: "Lanes" }));
    fireEvent.click(screen.getByRole("option", { name: "Event ID" }));
    expect(lanes()).toEqual(["7", "9"]);
    expect(container.querySelector("[data-evtx-swimlane-title]")).toHaveTextContent("Swimlanes by event ID");
  });

  it("starts on providers every time it is mounted: the choice is not remembered across views", () => {
    const first = render(<EvtxSwimlaneView records={sample()} loading={false} />);
    fireEvent.click(screen.getByRole("combobox", { name: "Lanes" }));
    fireEvent.click(screen.getByRole("option", { name: "Channel" }));
    expect(first.container.querySelector("[data-evtx-swimlane-title]")).toHaveTextContent("by channel");
    first.unmount();
    const second = render(<EvtxSwimlaneView records={sample()} loading={false} />);
    expect(second.container.querySelector("[data-evtx-swimlane-title]")).toHaveTextContent("by provider");
  });

  describe("the Other lane", () => {
    it("folds all but the top 12 and says so in the label, its title and its table row", () => {
      const { container } = render(<EvtxSwimlaneView records={providers(20)} loading={false} />);
      const lanes = [...container.querySelectorAll<HTMLElement>("[data-evtx-lane]")];
      expect(lanes).toHaveLength(13);
      const other = lanes[12];
      expect(other.children[0].textContent).toBe("Other (8 lanes)");
      expect(other.title).toContain("8 provider lanes folded into Other");
      expect(other.title).toContain("provider-12");
      const row = within(screen.getByRole("table")).getAllByRole("row").pop()!;
      expect(within(row).getByRole("rowheader").textContent).toContain("Other (8 lanes)");
      expect(within(row).getByRole("rowheader").textContent).toContain("provider-12");
    });

    it("keeps thirteen providers as thirteen lanes", () => {
      const { container } = render(<EvtxSwimlaneView records={providers(13)} loading={false} />);
      const lanes = [...container.querySelectorAll<HTMLElement>("[data-evtx-lane]")];
      expect(lanes).toHaveLength(13);
      expect(lanes.some((lane) => lane.children[0].textContent!.startsWith("Other"))).toBe(false);
    });
  });

  it("draws the legend from the marks the canvas draws, most severe first", () => {
    render(<EvtxSwimlaneView records={sample()} loading={false} />);
    const items = within(screen.getByRole("list", { name: "Levels" })).getAllByRole("listitem");
    expect(items.map((item) => item.textContent)).toEqual(
      ["Critical", "Error", "Warning", "Information", "Verbose"].map(
        (level) => HISTOGRAM_LEVEL_LABELS[level as EvtxLevel],
      ),
    );
    items.forEach((item, index) => {
      const level = HISTOGRAM_STACK_ORDER[HISTOGRAM_STACK_ORDER.length - 1 - index];
      const swatch = item.querySelector<HTMLElement>("span")!;
      expect(item.dataset.evtxLegendLevel).toBe(level);
      expect(swatch.dataset.evtxLegendShape).toBe(DOT_MARKS[level].shape);
      expect(swatch.style.width).toBe(`${DOT_MARKS[level].size}px`);
      expect(swatch.style.height).toBe(`${DOT_MARKS[level].size}px`);
      expect(Number(swatch.style.opacity)).toBe(DOT_MARKS[level].opacity);
    });
    // Sizes 10, 9, 7 and 5 are the spec's; Verbose is the fifth entry.
    expect(items.slice(0, 4).map((item) => item.querySelector<HTMLElement>("span")!.style.width)).toEqual([
      "10px",
      "9px",
      "7px",
      "5px",
    ]);
  });

  it("shares the histogram's axis: the same ticks, and the zone beside the lanes", () => {
    const records = sample();
    const { container } = render(<EvtxSwimlaneView records={records} loading={false} />);
    const histogram = buildHistogram(records, "utc");
    const ticks = [...container.querySelectorAll<HTMLElement>("[data-evtx-tick]")];
    expect(ticks.map((tick) => tick.textContent)).toEqual(buildAxisTicks(histogram, "utc").map((tick) => tick.label));
    expect(ticks.map((tick) => parseFloat(tick.style.left))).toEqual(
      buildAxisTicks(histogram, "utc").map((tick) => tick.fraction * 100),
    );
    expect(container.querySelector("[data-evtx-zone]")!.textContent).toBe(timeZoneLabel("utc", histogram.domain!.startMs));
  });

  it("carries every lane's counts by level in a table a screen reader can reach", () => {
    const records = sample();
    render(<EvtxSwimlaneView records={records} loading={false} />);
    const scene = buildSwimlanes(records, "provider", "utc");
    const table = screen.getByRole("table");
    expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
      "Provider", "Critical", "Error", "Warning", "Info", "Verbose", "Total",
    ]);
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(scene.lanes.length);
    scene.lanes.forEach((lane, index) => {
      expect(within(rows[index]).getByRole("rowheader").textContent).toBe(lane.label);
      expect(within(rows[index]).getAllByRole("cell").map((cell) => Number(cell.textContent))).toEqual([
        lane.levelCounts.Critical, lane.levelCounts.Error, lane.levelCounts.Warning,
        lane.levelCounts.Information, lane.levelCounts.Verbose, lane.count,
      ]);
    });
    const total = rows.reduce((sum, row) => sum + Number(within(row).getAllByRole("cell").pop()!.textContent), 0);
    expect(total).toBe(scene.placed);
  });

  describe("the canvas", () => {
    it("is sized to the plot plus its inset, at device pixels, and styled in CSS pixels", () => {
      Object.defineProperty(window, "devicePixelRatio", { value: 2, configurable: true });
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const canvas = markLayer(container);
      const width = PLOT_W + 2 * PLOT_INSET_PX;
      expect(canvas.width).toBe(width * 2);
      expect(canvas.height).toBe(2 * 36 * 2);
      expect(canvas.style.width).toBe(`${width}px`);
      expect(canvas.style.height).toBe(`${2 * 36}px`);
      expect(canvas.style.left).toBe(`-${PLOT_INSET_PX}px`);
      expect(last(contextOf(container).transforms)).toEqual([2, 0, 0, 2, 0, 0]);
      expect(canvas).toHaveAttribute("aria-hidden", "true");
    });

    it("paints each level in its resolved colour, severity on top, and the lane baselines", () => {
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const colors = swimlaneColors(getAllThemes().find((theme) => theme.id === "light")!);
      const context = contextOf(container);
      expect(drawn(context).map((call) => call.color)).toEqual(
        ["Verbose", "Information", "Warning", "Error", "Critical"].map((level) => colors.dots[level as EvtxLevel]),
      );
      expect(lineCalls(context).map((call) => call.color)).toEqual([colors.baseline, colors.separator]);
    });

    it("paints once for the first render and not again for a pointer that only moves over it", () => {
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const context = contextOf(container);
      expect(context.clears).toHaveLength(1);
      fireEvent.pointerMove(markLayer(container).parentElement!, { clientX: LEFT + 50, clientY: 10 });
      expect(context.clears).toHaveLength(1);
    });

    it("repaints at the new size when the plot resizes", () => {
      let notify: () => void = () => undefined;
      vi.stubGlobal(
        "ResizeObserver",
        class {
          constructor(callback: () => void) {
            notify = callback;
          }
          observe() {}
          disconnect() {}
        },
      );
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(markLayer(container).style.width).toBe(`${PLOT_W + 2 * PLOT_INSET_PX}px`);
      rectSpy.mockImplementation(
        () => ({ left: LEFT, top: 0, right: LEFT + 400, bottom: 100, width: 400, height: 100, x: LEFT, y: 0, toJSON: () => ({}) }) as DOMRect,
      );
      act(() => notify());
      expect(markLayer(container).style.width).toBe(`${400 + 2 * PLOT_INSET_PX}px`);
      expect(markLayer(container).width).toBe(400 + 2 * PLOT_INSET_PX);
    });
  });

  describe("device pixel ratio", () => {
    function stubResolution() {
      const listeners: (() => void)[] = [];
      const queries: string[] = [];
      window.matchMedia = vi.fn((query: string) => {
        queries.push(query);
        return {
          matches: false,
          media: query,
          addEventListener: (_: string, listener: () => void) => {
            if (query.includes("resolution")) listeners.push(listener);
          },
          removeEventListener: () => undefined,
        } as unknown as MediaQueryList;
      }) as unknown as typeof window.matchMedia;
      return { listeners, queries };
    }

    it.each([1, 1.5, 2])("backs the canvas with round(css x %s) device pixels", (dpr) => {
      Object.defineProperty(window, "devicePixelRatio", { value: dpr, configurable: true });
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const width = PLOT_W + 2 * PLOT_INSET_PX;
      expect(markLayer(container).width).toBe(Math.round(width * dpr));
      expect(markLayer(container).height).toBe(Math.round(2 * 36 * dpr));
      expect(last(contextOf(container).transforms)).toEqual([dpr, 0, 0, dpr, 0, 0]);
    });

    it("repaints at the new ratio when the window moves to another screen, and watches the new ratio", () => {
      const media = stubResolution();
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const context = contextOf(container);
      expect(media.queries).toContain("(resolution: 1dppx)");
      expect(last(context.transforms)).toEqual([1, 0, 0, 1, 0, 0]);
      Object.defineProperty(window, "devicePixelRatio", { value: 2, configurable: true });
      act(() => media.listeners.forEach((listener) => listener()));
      expect(last(context.transforms)).toEqual([2, 0, 0, 2, 0, 0]);
      expect(markLayer(container).width).toBe(2 * (PLOT_W + 2 * PLOT_INSET_PX));
      expect(media.queries).toContain("(resolution: 2dppx)");
    });
  });

  describe("a theme switch", () => {
    const themes = getAllThemes();

    it.each(themes.filter((theme) => theme.id !== "light").map((theme) => [theme.id] as const))(
      "repaints in the colours of %s without a remount or a reload",
      (themeId) => {
        const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
        const canvas = markLayer(container);
        const context = contextOf(container);
        context.reset();
        act(() => useUiStore.setState({ themeId }));
        const theme = themes.find((candidate) => candidate.id === themeId)!;
        const colors = swimlaneColors(theme);
        // The same canvas node, so nothing remounted; painted exactly once more, in the new colours.
        expect(markLayer(container)).toBe(canvas);
        expect(canvases.all).toHaveLength(1);
        expect(context.clears).toHaveLength(1);
        expect(drawn(context).map((call) => call.color)).toEqual(
          ["Verbose", "Information", "Warning", "Error", "Critical"].map((level) => colors.dots[level as EvtxLevel]),
        );
        expect(lineCalls(context).map((call) => call.color)).toEqual([colors.baseline, colors.separator]);
      },
    );

    it("paints different colours in light and dark, so the repaint is a real re-resolution", () => {
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const light = drawn(contextOf(container)).map((call) => call.color);
      contextOf(container).reset();
      act(() => useUiStore.setState({ themeId: "dark" }));
      const dark = drawn(contextOf(container)).map((call) => call.color);
      expect(dark).not.toEqual(light);
    });

    it("moves the wash to the new theme's solved opacity", () => {
      seed({ timeRange: { startMs: T0, endMs: T0 + HOUR } });
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const wash = () => container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      const opacity = (id: string) => solveBrushOpacity(brushPaletteFor(themes.find((theme) => theme.id === id)!));
      expect(Number(wash().style.opacity)).toBe(opacity("light"));
      act(() => useUiStore.setState({ themeId: "high-contrast" }));
      expect(Number(wash().style.opacity)).toBe(opacity("high-contrast"));
      expect(opacity("high-contrast")).not.toBe(opacity("light"));
    });
  });

  describe("the applied range", () => {
    it("draws a wash behind the canvas, then the canvas, then the edge borders, in that document order", () => {
      seed({ timeRange: { startMs: T0, endMs: T0 + HOUR } });
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const layers = [...container.querySelectorAll<HTMLElement>("[data-evtx-layer]")].map((layer) => layer.dataset.evtxLayer);
      expect(layers).toEqual(["wash", "marks", "edge", "edge"]);
      const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      expect(wash.style.zIndex).toBe("");
      expect(markLayer(container).style.zIndex).toBe("");
    });

    it("has no wash or edges without a range", () => {
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect([...container.querySelectorAll("[data-evtx-layer]")].map((layer) => (layer as HTMLElement).dataset.evtxLayer)).toEqual([
        "marks",
      ]);
    });

    it("puts the wash where the histogram puts it for the same range", () => {
      const records = sample();
      const histogram = buildHistogram(records, "utc");
      seed({ timeRange: { startMs: histogram.edges[10], endMs: histogram.edges[20] } });
      const { container } = render(<EvtxSwimlaneView records={records} loading={false} />);
      const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      const count = histogram.buckets.length;
      expect(parseFloat(wash.style.left)).toBeCloseTo((10 / count) * 100, 6);
      expect(parseFloat(wash.style.right)).toBeCloseTo(((count - 20) / count) * 100, 6);
    });

    it("says when the range is outside the charted events, and draws no wash", () => {
      seed({ timeRange: { startMs: T0 + 30 * 24 * HOUR, endMs: T0 + 31 * 24 * HOUR } });
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(screen.getByText(RANGE_OUTSIDE_NOTE)).toBeInTheDocument();
      expect(container.querySelector('[data-evtx-layer="wash"]')).toBeNull();
    });

    it("draws the wash and the legend swatches the way the histogram does under forced colors", () => {
      seed({ timeRange: { startMs: T0, endMs: T0 + HOUR } });
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const forced = (element: HTMLElement, property: string): string[] => rulesIn(element, property, true);
      const base = (element: HTMLElement, property: string): string[] => rulesIn(element, property, false);
      const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      expect(forced(wash, "display")).toEqual(["none"]);
      expect(base(wash, "display")).toEqual([]);
      const swatches = within(screen.getByRole("list", { name: "Levels" }))
        .getAllByRole("listitem")
        .map((item) => item.querySelector<HTMLElement>("span")!);
      expect(swatches).toHaveLength(5);
      for (const swatch of swatches) {
        expect(forced(swatch, "outline-color")).toEqual(["canvastext"]);
        expect(forced(swatch, "outline-style")).toEqual(["solid"]);
        expect(forced(swatch, "forced-color-adjust")).toEqual(["none"]);
        expect(base(swatch, "outline-style")).toEqual([]);
      }
      for (const edge of container.querySelectorAll<HTMLElement>('[data-evtx-layer="edge"]')) {
        expect(forced(edge, "forced-color-adjust")).toEqual([]);
      }
    });
  });

  describe("under forced colors", () => {
    /** A live media query list for forced colors: `set` flips it, as the operating system would. */
    function forcedColors(initial: boolean) {
      const state = { matches: initial };
      const listeners: (() => void)[] = [];
      window.matchMedia = vi.fn((query: string) => ({
        get matches() {
          return query === "(forced-colors: active)" && state.matches;
        },
        media: query,
        addEventListener: (_: string, listener: () => void) => {
          if (query === "(forced-colors: active)") listeners.push(listener);
        },
        removeEventListener: () => undefined,
      })) as unknown as typeof window.matchMedia;
      const real = window.getComputedStyle.bind(window);
      vi.spyOn(window, "getComputedStyle").mockImplementation((element: Element, pseudo?: string | null) => {
        if ((element as HTMLElement).dataset?.evtxProbe === "canvas-text") {
          return { color: "rgb(255, 255, 0)" } as CSSStyleDeclaration;
        }
        return real(element, pseudo);
      });
      return {
        set: (matches: boolean) => {
          state.matches = matches;
          listeners.forEach((listener) => listener());
        },
      };
    }

    it("rings every mark in the resolved CanvasText colour, read from a probe element", () => {
      forcedColors(true);
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const rings = markCalls(contextOf(container)).filter((call) => call.color === "rgb(255, 255, 0)");
      expect(rings).toHaveLength(5);
      for (const ring of rings) {
        expect(ring.action).toBe("stroke");
        expect(ring.lineWidth).toBe(1);
      }
      // The probe is gone, so the document is as it was.
      expect(container.querySelectorAll("span[style*='CanvasText']")).toHaveLength(0);
    });

    it("draws no ring when forced colors are not active", () => {
      forcedColors(false);
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(markCalls(contextOf(container)).some((call) => call.color === "rgb(255, 255, 0)")).toBe(false);
    });

    it("rings the marks when forced colors turn on while it is showing, and stops when they turn off", () => {
      const media = forcedColors(false);
      const { container } = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const ringed = () => markCalls(contextOf(container)).some((call) => call.color === "rgb(255, 255, 0)");
      expect(ringed()).toBe(false);
      contextOf(container).reset();
      act(() => media.set(true));
      expect(ringed()).toBe(true);
      contextOf(container).reset();
      act(() => media.set(false));
      expect(ringed()).toBe(false);
      expect(contextOf(container).clears).toHaveLength(1);
    });
  });

  describe("states", () => {
    it("charts nothing and says it is loading while a load runs, never an empty chart", () => {
      const { container } = render(<EvtxSwimlaneView records={[]} loading />);
      expect(container.querySelector("canvas")).toBeNull();
      expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
      expect(screen.getByRole("figure")).toHaveAttribute("aria-busy", "true");
      expect(screen.queryByRole("table")).toBeNull();
      expect(screen.queryByRole("list", { name: "Lanes" })).toBeNull();
      expect(screen.queryByText(/No events/)).toBeNull();
      expect(canvases.all).toHaveLength(0);
    });

    it("does not draw the events it already has while a new load runs", () => {
      const { container } = render(<EvtxSwimlaneView records={sample()} loading />);
      expect(container.querySelector("canvas")).toBeNull();
      expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
    });

    it("says there are no events, and that there are none with a timestamp", () => {
      render(<EvtxSwimlaneView records={[]} loading={false} />);
      expect(screen.getByRole("status")).toHaveTextContent("No events to chart.");
      cleanup();
      render(<EvtxSwimlaneView records={[rec({ timestampEpoch: 0 }), rec({ timestampEpoch: 0 })]} loading={false} />);
      expect(screen.getByRole("status")).toHaveTextContent("No timestamped events to chart.");
      expect(screen.getByText(describeUntimed(2))).toBeInTheDocument();
    });

    it("says in a note and a table row how many events it could not place, and never places them", () => {
      const records = [...sample(), rec({ timestampEpoch: 0 }), rec({ timestampEpoch: Number.NaN })];
      const { container } = render(<EvtxSwimlaneView records={records} loading={false} />);
      expect(screen.getByText(describeUntimed(2))).toBeInTheDocument();
      const last = within(screen.getByRole("table")).getAllByRole("row").pop()!;
      expect(within(last).getByRole("rowheader").textContent).toBe("Not charted: no timestamp");
      expect(within(last).getAllByRole("cell").pop()!.textContent).toBe("2");
      // The lane counts are the placed events, so lanes plus untimed are the records given.
      const laneTotals = [...container.querySelectorAll("[data-evtx-lane-count]")].map((count) => parseInt(count.textContent!));
      expect(laneTotals.reduce((a, b) => a + b, 0) + 2).toBe(records.length);
    });

    it("makes no untimed note or row when every event is placed", () => {
      render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(screen.queryByText(/without a timestamp/)).toBeNull();
      expect(screen.queryByText("Not charted: no timestamp")).toBeNull();
    });

    it("says counts cover loaded events only when there are coverage gaps, so an empty stretch is not a zero", () => {
      seed({
        coverageGaps: ["System: newest 2000 events shown (the channel may hold more)"],
        tailCoverageGaps: ["Security: access denied"],
      });
      render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(screen.getByText(describeCoverage(2))).toBeInTheDocument();
    });

    it("counts a gap named in two lists once, as the histogram does", () => {
      seed({ coverageGaps: ["same gap"], tailCoverageGaps: ["same gap"] });
      render(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(screen.getByText(describeCoverage(1))).toBeInTheDocument();
    });

    it("shows the throttled set, and not 'no events', while the first events are still arriving", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const { rerender, container } = render(<EvtxSwimlaneView records={[]} loading={false} />);
      expect(screen.getByRole("status")).toHaveTextContent("No events to chart.");
      rerender(<EvtxSwimlaneView records={sample()} loading={false} />);
      expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
      expect(container.querySelector("canvas")).toBeNull();
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      expect(screen.queryByRole("status")).toBeNull();
      expect(container.querySelectorAll("[data-evtx-lane]")).toHaveLength(2);
    });

    it("rebuilds and repaints at most once per 75 ms while a tail appends", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const first = sample();
      const { rerender, container } = render(<EvtxSwimlaneView records={first} loading={false} />);
      const context = contextOf(container);
      const painted = context.clears.length;
      let records = first;
      for (let batch = 0; batch < 6; batch += 1) {
        records = [...records, rec({ provider: "C", timestampEpoch: T0 + (4 + batch) * HOUR })];
        rerender(<EvtxSwimlaneView records={records} loading={false} />);
      }
      expect(context.clears).toHaveLength(painted);
      expect(container.querySelectorAll("[data-evtx-lane]")).toHaveLength(2);
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS - 1);
      });
      expect(container.querySelectorAll("[data-evtx-lane]")).toHaveLength(2);
      act(() => {
        vi.advanceTimersByTime(1);
      });
      expect(container.querySelectorAll("[data-evtx-lane]")).toHaveLength(3);
      expect(context.clears).toHaveLength(painted + 1);
    });

    it("reserves the caption slot in every state, so the figure's height does not change", () => {
      const heightOf = (view: ReturnType<typeof render>) =>
        view.container.querySelector<HTMLElement>("[data-evtx-cursor-slot]")?.style.height;
      const ready = render(<EvtxSwimlaneView records={sample()} loading={false} />);
      const expected = heightOf(ready);
      expect(expected).toMatch(/^\d+px$/);
      cleanup();
      for (const view of [
        render(<EvtxSwimlaneView records={[]} loading />),
        render(<EvtxSwimlaneView records={[]} loading={false} />),
      ]) {
        expect(heightOf(view)).toBe(expected);
        view.unmount();
      }
    });
  });

  describe("the source", () => {
    const code = viewSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

    it("writes no colour literal: every colour is a token or comes from the resolved palette", () => {
      expect(code).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
      expect(code).not.toMatch(/\brgba?\(|\bhsla?\(/);
    });

    it("keeps its text off colorNeutralForeground3", () => {
      expect(code).not.toMatch(/colorNeutralForeground3/);
    });

    it("takes its text sizes from the list font size, not from literals", () => {
      expect(code).toMatch(/getLogListMetrics\(/);
    });
  });
});

/** The values the element's classes set inside (`forced`) or outside the forced-colors media query. */
function rulesIn(element: HTMLElement, property: string, forced: boolean): string[] {
  const selectors = Array.from(element.classList).map((name) => `.${name}`);
  const values: string[] = [];
  for (const sheet of Array.from(document.styleSheets)) {
    for (const rule of Array.from(sheet.cssRules)) {
      if (forced) {
        if (!(rule instanceof CSSMediaRule) || !rule.media.mediaText.includes("forced-colors: active")) continue;
        for (const inner of Array.from(rule.cssRules)) {
          if (inner instanceof CSSStyleRule && selectors.includes(inner.selectorText)) {
            const value = inner.style.getPropertyValue(property).toLowerCase();
            if (value) values.push(value);
          }
        }
      } else if (rule instanceof CSSStyleRule && selectors.includes(rule.selectorText)) {
        const value = rule.style.getPropertyValue(property).toLowerCase();
        if (value) values.push(value);
      }
    }
  }
  return values;
}
