import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { EvtxHistogram } from "./EvtxHistogram";
import histogramSource from "./EvtxHistogram.tsx?raw";
import {
  HISTOGRAM_LEVEL_LABELS,
  HISTOGRAM_STACK_ORDER,
  buildAxisTicks,
  buildHistogram,
  describeBucket,
  describeCoverage,
  describeFigure,
  describeUntimed,
} from "./evtx-histogram";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS } from "./evtx-throttle";
import { TIME_RANGE_SEPARATOR, timeZoneLabel } from "./evtx-time";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const FIRST = Date.UTC(2026, 9, 6, 10, 20, 0);

const rec = (timestampEpoch: number, level: EvtxLevel = "Information", id = 1): EvtxRecord =>
  ({
    id,
    eventRecordId: id,
    timestamp: "",
    timestampEpoch,
    provider: "P",
    channel: "System",
    eventId: 1,
    level,
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
  }) as EvtxRecord;

/** 24 hours of events: 72 buckets of 20 minutes, with a few of every level and one empty stretch. */
function dayOfEvents(): EvtxRecord[] {
  const levels: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
  const records: EvtxRecord[] = [];
  for (let bucket = 0; bucket < 72; bucket += 1) {
    if (bucket >= 30 && bucket < 36) continue;
    const at = FIRST + bucket * 20 * MINUTE;
    for (let n = 0; n < (bucket % 5) + 1; n += 1) {
      records.push(rec(at + n * 1000, levels[(bucket + n) % 5], records.length));
    }
  }
  records.push(rec(FIRST + DAY - 1, "Information", records.length));
  return records;
}

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

const tooltip = () => document.querySelector<HTMLElement>("[data-evtx-tooltip]");

function stubPlotRect(width = 720) {
  const plot = document.querySelector<HTMLElement>('[data-evtx-region="histogram"] [data-evtx-layer="bars"]')!
    .parentElement!;
  plot.getBoundingClientRect = () =>
    ({ left: 100, top: 0, right: 100 + width, bottom: 56, width, height: 56, x: 100, y: 0, toJSON: () => ({}) }) as DOMRect;
  return plot;
}

beforeEach(() => {
  seed();
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("EvtxHistogram", () => {
  it("is a figure named by its interval, span and zone", () => {
    const records = dayOfEvents();
    render(<EvtxHistogram records={records} loading={false} />);
    const label = describeFigure(buildHistogram(records, "utc"), "utc");
    expect(label).toBe(
      `Events per 20 minutes over Oct 6 10:20${TIME_RANGE_SEPARATOR}Oct 7 10:20 (UTC), stacked by level`,
    );
    expect(screen.getByRole("figure", { name: label })).toHaveAttribute("data-evtx-region", "histogram");
  });

  it("draws one column per bucket, each level a segment of its own colour, bottom to top", () => {
    const records = dayOfEvents();
    const { container } = render(<EvtxHistogram records={records} loading={false} />);
    const columns = container.querySelectorAll("[data-evtx-bucket]");
    expect(columns).toHaveLength(72);
    const tokens = buildEvtxVisualTokens(getAllThemes().find((theme) => theme.id === "light")!);
    const probe = document.createElement("div");
    const colorOf = (level: EvtxLevel) => {
      probe.style.backgroundColor = tokens.levels[level].barColor;
      return probe.style.backgroundColor;
    };
    for (const column of columns) {
      const segments = [...column.querySelectorAll<HTMLElement>("[data-evtx-level]")];
      const levels = segments.map((segment) => segment.dataset.evtxLevel as EvtxLevel);
      const order = HISTOGRAM_STACK_ORDER.filter((level) => levels.includes(level));
      expect(levels).toEqual(order);
      for (const segment of segments) {
        expect(segment.style.backgroundColor).toBe(colorOf(segment.dataset.evtxLevel as EvtxLevel));
        // 2 px of colour under the 1 px separator the segment's top border draws.
        expect(parseFloat(segment.style.height)).toBeGreaterThanOrEqual(3);
      }
      const total = segments.reduce((sum, segment) => sum + parseFloat(segment.style.height), 0);
      expect(total).toBeLessThanOrEqual(56);
    }
  });

  it("draws a lone Critical event in a tall bucket with 2 px of colour under its 1 px separator", () => {
    const tall = Array.from({ length: 3000 }, (_, i) => rec(FIRST + 1000 + (i % 60) * 1000, "Information", i));
    const records = [...tall, rec(FIRST + 5000, "Critical", 9000), rec(FIRST + 3 * HOUR, "Information", 9001)];
    const { container } = render(<EvtxHistogram records={records} loading={false} />);
    const critical = container.querySelector<HTMLElement>('[data-evtx-level="Critical"]')!;
    expect(critical.style.height).toBe("3px");
    const column = critical.parentElement!;
    const total = [...column.querySelectorAll<HTMLElement>("[data-evtx-level]")].reduce(
      (sum, segment) => sum + parseFloat(segment.style.height),
      0,
    );
    expect(total).toBeLessThanOrEqual(56);
  });

  it("names the year in the tooltip, the value text and the table when the events span a calendar year", () => {
    const years = [rec(Date.UTC(2024, 0, 5, 10), "Information", 1), rec(Date.UTC(2026, 9, 1, 10), "Error", 2)];
    render(<EvtxHistogram records={years} loading={false} />);
    const histogram = buildHistogram(years, "utc");
    expect(histogram.showYear).toBe(true);
    expect(screen.getByRole("figure", { name: describeFigure(histogram, "utc") })).toBeInTheDocument();
    const rows = within(screen.getByRole("table")).getAllByRole("rowheader").map((cell) => cell.textContent);
    expect(rows[0]).toBe(describeBucket(histogram.buckets[0], "utc", true));
    expect(rows[0]).toMatch(/2024/);
    const slider = screen.getByRole("slider", { name: "Time range" });
    expect(slider.getAttribute("aria-valuetext")).toBe(
      describeBucket(histogram.buckets[histogram.buckets.length - 1], "utc", true),
    );
    expect(slider.getAttribute("aria-valuetext")).toMatch(/2026/);
    const plot = stubPlotRect(histogram.buckets.length * 10);
    fireEvent.pointerMove(plot, { clientX: 100 + 5 });
    expect(tooltip()).toHaveTextContent(describeBucket(histogram.buckets[0], "utc", true));
  });

  it("recolours the bars from the token map in every theme", () => {
    const records = dayOfEvents();
    for (const theme of getAllThemes()) {
      useUiStore.setState({ themeId: theme.id });
      const { container, unmount } = render(<EvtxHistogram records={records} loading={false} />);
      const map = buildEvtxVisualTokens(theme);
      const probe = document.createElement("div");
      for (const level of HISTOGRAM_STACK_ORDER) {
        const segment = container.querySelector<HTMLElement>(`[data-evtx-level="${level}"]`)!;
        probe.style.backgroundColor = map.levels[level].barColor;
        expect(segment.style.backgroundColor).toBe(probe.style.backgroundColor);
      }
      unmount();
    }
  });

  it("lists the levels top to bottom in the legend with the short labels, and the zone", () => {
    render(<EvtxHistogram records={dayOfEvents()} loading={false} />);
    const legend = screen.getByRole("list", { name: "Levels" });
    const items = within(legend).getAllByRole("listitem").map((item) => item.textContent);
    expect(items).toEqual(["Critical", "Error", "Warning", "Info", "Verbose", "UTC"]);
    expect(HISTOGRAM_LEVEL_LABELS.Information).toBe("Info");
    expect(legend.style.color).toBe("var(--colorNeutralForeground2)");
  });

  it("labels the axis in seven places in the chosen zone, in the secondary text colour", () => {
    const records = dayOfEvents();
    const { container } = render(<EvtxHistogram records={records} loading={false} />);
    const expected = buildAxisTicks(buildHistogram(records, "utc"), "utc");
    const ticks = [...container.querySelectorAll<HTMLElement>("[data-evtx-tick]")];
    expect(ticks.map((tick) => tick.textContent)).toEqual(expected.map((tick) => tick.label));
    expect(ticks).toHaveLength(7);
    expect(ticks[0].textContent).toBe("Oct 6 10:20");
    expect(ticks[0].parentElement!.style.color).toBe("var(--colorNeutralForeground2)");
  });

  it("sets the axis and legend type from the log list font size", () => {
    const records = dayOfEvents();
    useUiStore.setState({ logListFontSize: 20 });
    const { container } = render(<EvtxHistogram records={records} loading={false} />);
    const axis = container.querySelector<HTMLElement>("[data-evtx-tick]")!.parentElement!;
    expect(axis.style.fontSize).toBe("16px");
    expect(screen.getByRole("list", { name: "Levels" }).style.fontSize).toBe("17px");
    cleanup();
    useUiStore.setState({ logListFontSize: 13 });
    const small = render(<EvtxHistogram records={records} loading={false} />);
    expect(small.container.querySelector<HTMLElement>("[data-evtx-tick]")!.parentElement!.style.fontSize).toBe("9px");
    expect(screen.getByRole("list", { name: "Levels" }).style.fontSize).toBe("10px");
    expect(screen.getByRole("list", { name: "Levels" }).style.minHeight).toBe("72px");
  });

  it("carries every bucket's counts in a table a screen reader can reach", () => {
    const records = dayOfEvents();
    render(<EvtxHistogram records={records} loading={false} />);
    const histogram = buildHistogram(records, "utc");
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(1 + 72);
    expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
      "Interval", "Critical", "Error", "Warning", "Info", "Verbose", "Total",
    ]);
    histogram.buckets.forEach((bucket, index) => {
      const cells = within(rows[index + 1]).getAllByRole("cell");
      expect(within(rows[index + 1]).getByRole("rowheader").textContent).toBe(describeBucket(bucket, "utc"));
      expect(cells.map((cell) => Number(cell.textContent))).toEqual([
        bucket.counts.Critical, bucket.counts.Error, bucket.counts.Warning,
        bucket.counts.Information, bucket.counts.Verbose, bucket.total,
      ]);
    });
    expect(within(table).getByText(describeFigure(histogram, "utc"))).toBeInTheDocument();
  });

  it("says in the table, and in a note, how many events it could not place", () => {
    const records = [...dayOfEvents(), rec(0), rec(Number.NaN)];
    render(<EvtxHistogram records={records} loading={false} />);
    expect(screen.getByText(describeUntimed(2))).toBeInTheDocument();
    const last = within(screen.getByRole("table")).getAllByRole("row").pop()!;
    expect(within(last).getByRole("rowheader").textContent).toBe("Not charted: no timestamp");
    expect(within(last).getAllByRole("cell").pop()!.textContent).toBe("2");
  });

  it("makes no untimed note or row when every event is placed", () => {
    render(<EvtxHistogram records={dayOfEvents()} loading={false} />);
    expect(screen.queryByText(/without a timestamp/)).toBeNull();
    expect(screen.queryByText("Not charted: no timestamp")).toBeNull();
  });

  it("says counts cover loaded events only when there are coverage gaps, so an empty bar is not a zero", () => {
    seed({
      coverageGaps: ["System: newest 2000 events shown (the channel may hold more)"],
      tailCoverageGaps: ["Security: access denied"],
    });
    render(<EvtxHistogram records={dayOfEvents()} loading={false} />);
    expect(screen.getByText(describeCoverage(2))).toBeInTheDocument();
  });

  it("counts a gap the banner counts once even when two lists name it", () => {
    seed({ coverageGaps: ["same gap"], tailCoverageGaps: ["same gap"] });
    render(<EvtxHistogram records={dayOfEvents()} loading={false} />);
    expect(screen.getByText(describeCoverage(1))).toBeInTheDocument();
  });

  it("charts nothing and says it is loading while a load runs, never an empty chart", () => {
    const { container } = render(<EvtxHistogram records={[]} loading />);
    expect(container.querySelector("[data-evtx-layer=bars]")).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
    expect(screen.getByRole("figure")).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText(/No events/)).toBeNull();
  });

  it("does not chart the old events while a load runs", () => {
    const { container } = render(<EvtxHistogram records={dayOfEvents()} loading />);
    expect(container.querySelector("[data-evtx-layer=bars]")).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
  });

  it("says there are no events, and when none has a timestamp", () => {
    render(<EvtxHistogram records={[]} loading={false} />);
    expect(screen.getByRole("status")).toHaveTextContent("No events to chart.");
    expect(screen.getByRole("figure")).toHaveAttribute("aria-busy", "false");
    cleanup();
    render(<EvtxHistogram records={[rec(0), rec(0)]} loading={false} />);
    expect(screen.getByRole("status")).toHaveTextContent("No timestamped events to chart.");
    expect(screen.getByText(describeUntimed(2))).toBeInTheDocument();
  });

  it("shows the throttled set, and not 'no events', while the first events are still arriving", () => {
    vi.useFakeTimers();
    const records = dayOfEvents();
    const { rerender, container } = render(<EvtxHistogram records={[]} loading={false} />);
    expect(screen.getByRole("status")).toHaveTextContent("No events to chart.");
    rerender(<EvtxHistogram records={records} loading={false} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
    expect(container.querySelector("[data-evtx-layer=bars]")).toBeNull();
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    expect(screen.queryByRole("status")).toBeNull();
    expect(container.querySelectorAll("[data-evtx-bucket]")).toHaveLength(72);
  });

  it("rebuckets at most once per 75 ms while a tail appends", () => {
    vi.useFakeTimers();
    const first = dayOfEvents();
    const { rerender, container } = render(<EvtxHistogram records={first} loading={false} />);
    const widthBefore = container.querySelectorAll("[data-evtx-bucket]").length;
    const more = [...first, rec(FIRST + 3 * DAY, "Error", 9999)];
    rerender(<EvtxHistogram records={more} loading={false} />);
    expect(container.querySelectorAll("[data-evtx-bucket]")).toHaveLength(widthBefore);
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS - 1);
    });
    expect(container.querySelectorAll("[data-evtx-bucket]")).toHaveLength(widthBefore);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(container.querySelectorAll("[data-evtx-bucket]").length).not.toBe(widthBefore);
  });

  it("shows a bucket's tooltip on hover with its counts and zone, and drops it when the pointer leaves", () => {
    const records = dayOfEvents();
    render(<EvtxHistogram records={records} loading={false} />);
    const plot = stubPlotRect(720);
    const histogram = buildHistogram(records, "utc");
    // Bucket 10 spans x = 100 + 10 * 10 to 100 + 11 * 10.
    fireEvent.pointerMove(plot, { clientX: 100 + 10 * 10 + 4 });
    const text = describeBucket(histogram.buckets[10], "utc");
    expect(tooltip()).toHaveTextContent(text);
    expect(text).toContain(TIME_RANGE_SEPARATOR);
    expect(text.endsWith("(UTC)")).toBe(true);
    fireEvent.pointerMove(plot, { clientX: 100 + 71 * 10 + 9 });
    expect(tooltip()).toHaveTextContent(describeBucket(histogram.buckets[71], "utc"));
    fireEvent.pointerLeave(plot);
    expect(tooltip()).toBeNull();
  });

  it("is never the only carrier of a value: the tooltip is hidden from assistive technology", () => {
    render(<EvtxHistogram records={dayOfEvents()} loading={false} />);
    const plot = stubPlotRect(720);
    fireEvent.pointerMove(plot, { clientX: 150 });
    expect(tooltip()).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByRole("tooltip")).toBeNull();
    // Its words are in the table and the slider's value text, which assistive technology reaches.
    expect(within(screen.getByRole("table")).getAllByRole("rowheader").map((cell) => cell.textContent)).toContain(
      tooltip()!.textContent,
    );
  });

  it("reads the zone from the store: local mode relabels the legend with the offset", () => {
    const records = dayOfEvents();
    render(<EvtxHistogram records={records} loading={false} />);
    expect(within(screen.getByRole("list", { name: "Levels" })).getAllByRole("listitem").pop()!.textContent).toBe("UTC");
    act(() => {
      useEvtxStore.setState({ timeZoneMode: "local" });
    });
    const histogram = buildHistogram(records, "local");
    const zone = timeZoneLabel("local", histogram.domain!.startMs);
    expect(within(screen.getByRole("list", { name: "Levels" })).getAllByRole("listitem").pop()!.textContent).toBe(zone);
    expect(screen.getByRole("figure", { name: describeFigure(histogram, "local") })).toBeInTheDocument();
  });

  describe("in forced-colors mode", () => {
    // jsdom cannot apply forced colors, so this reads the rules Griffel wrote (the EvtxFilterBar precedent).
    function forced(element: HTMLElement, property: string): string[] {
      const selectors = Array.from(element.classList).map((name) => `.${name}`);
      const values: string[] = [];
      for (const sheet of Array.from(document.styleSheets)) {
        for (const rule of Array.from(sheet.cssRules)) {
          if (!(rule instanceof CSSMediaRule) || !rule.media.mediaText.includes("forced-colors: active")) continue;
          for (const inner of Array.from(rule.cssRules)) {
            if (inner instanceof CSSStyleRule && selectors.includes(inner.selectorText)) {
              const value = inner.style.getPropertyValue(property).toLowerCase();
              if (value) values.push(value);
            }
          }
        }
      }
      return values;
    }
    /** What the element's classes set OUTSIDE the forced-colors media query. */
    function base(element: HTMLElement, property: string): string[] {
      const selectors = Array.from(element.classList).map((name) => `.${name}`);
      const values: string[] = [];
      for (const sheet of Array.from(document.styleSheets)) {
        for (const rule of Array.from(sheet.cssRules)) {
          if (rule instanceof CSSStyleRule && selectors.includes(rule.selectorText)) {
            const value = rule.style.getPropertyValue(property).toLowerCase();
            if (value) values.push(value);
          }
        }
      }
      return values;
    }

    function brushed() {
      const records = dayOfEvents();
      const histogram = buildHistogram(records, "utc");
      const view = render(<EvtxHistogram records={records} loading={false} />);
      act(() => {
        useEvtxStore.setState({ timeRange: { startMs: histogram.edges[10], endMs: histogram.edges[30] } });
      });
      return view;
    }

    it("outlines every segment in CanvasText so a bar is told from Canvas, and keeps its own colour", () => {
      const { container } = brushed();
      const segments = container.querySelectorAll<HTMLElement>("[data-evtx-level]");
      expect(segments.length).toBeGreaterThan(0);
      for (const segment of segments) {
        expect(forced(segment, "outline-color")).toEqual(["canvastext"]);
        expect(forced(segment, "outline-style")).toEqual(["solid"]);
        expect(forced(segment, "border-top-color")).toEqual(["canvastext"]);
        // The outline is the forced-colors rule alone: nothing outside the query draws one.
        expect(base(segment, "outline-style")).toEqual([]);
      }
      const bars = container.querySelector<HTMLElement>('[data-evtx-layer="bars"]')!;
      expect(forced(bars, "forced-color-adjust")).toEqual(["none"]);
    });

    it("drops the wash, so the forced edge borders carry the range", () => {
      const { container } = brushed();
      const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      expect(forced(wash, "display")).toEqual(["none"]);
      expect(base(wash, "display")).toEqual([]);
      const edges = container.querySelectorAll<HTMLElement>('[data-evtx-layer="edge"]');
      expect(edges).toHaveLength(2);
      // Border colours are forced to a system colour, which stays visible; the edge is not opted out.
      for (const edge of edges) expect(forced(edge, "forced-color-adjust")).toEqual([]);
    });
  });

  it("writes no colour literal: every colour is a token", () => {
    const code = histogramSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    expect(code).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(code).not.toMatch(/\brgba?\(|\bhsla?\(/);
  });

  it("keeps the axis and legend text off colorNeutralForeground3", () => {
    expect(histogramSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "")).not.toMatch(
      /colorNeutralForeground3/,
    );
  });
});
