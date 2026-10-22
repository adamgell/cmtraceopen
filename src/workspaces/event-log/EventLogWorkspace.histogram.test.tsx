import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const seen = vi.hoisted(() => ({ filterBar: -1, timeline: -1 }));

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
vi.mock("./EvtxFilterBar", () => ({
  EvtxFilterBar: ({ nowEpoch }: { nowEpoch: number }) => {
    seen.filterBar = nowEpoch;
    return null;
  },
}));
vi.mock("./EvtxTimeline", () => ({
  EvtxTimeline: ({ nowEpoch }: { nowEpoch: number }) => {
    seen.timeline = nowEpoch;
    return <div data-testid="records-table" />;
  },
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
import { EventLogWorkspace } from "./EventLogWorkspace";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { buildHistogram } from "./evtx-histogram";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS } from "./evtx-throttle";
import { formatTimeRange, timeRangeNeedsYear } from "./evtx-time";
import type { EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const T0 = Date.UTC(2026, 9, 16, 12, 0, 0);

const record = (id: number, timestampEpoch: number, channel = "Application"): EvtxRecord => ({
  id,
  eventRecordId: 100 + id,
  timestamp: new Date(timestampEpoch).toISOString(),
  timestampEpoch,
  provider: "Example Provider",
  channel,
  eventId: 42,
  level: id % 2 === 0 ? "Error" : "Information",
  computer: "TEST-PC",
  message: `Example event ${id}`,
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
});

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

const histogramRegion = () => document.querySelector<HTMLElement>('[data-evtx-region="histogram"]')!;
const tableText = () => within(histogramRegion()).getByRole("table").textContent;
const slider = () => within(histogramRegion()).getByRole("slider", { name: "Time range" });
const readout = () => document.querySelector("[data-evtx-filter-count]")?.textContent ?? null;
const storeRange = () => useEvtxStore.getState().timeRange;
const placed = () =>
  within(histogramRegion())
    .getAllByRole("row")
    .slice(1)
    .reduce((sum, row) => sum + Number(within(row).getAllByRole("cell").pop()!.textContent), 0);

/** Lets the histogram's 75 ms throttle publish whatever it was last given. */
const flushThrottle = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, DERIVATION_THROTTLE_MS + 30));
  });

function stubSlider(width = 360) {
  const element = slider();
  element.getBoundingClientRect = () =>
    ({ left: 0, top: 0, right: width, bottom: 56, width, height: 56, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect;
  return element;
}

describe("the histogram in the workspace", () => {
  beforeEach(() => {
    // The chart and the Time chip name the year when it is not the current one: pin the clock (Date only).
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(T0);
    seen.filterBar = -1;
    seen.timeline = -1;
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("sits under the chip row and above the body, with no panel toggle of its own", () => {
    const records = [record(1, T0 - 3 * HOUR), record(2, T0 - 2 * HOUR), record(3, T0 - HOUR)];
    seed(records);
    // After the seed: one setState that changes the source and sets a criterion clears the criterion.
    useEvtxStore.setState({ timeRange: { startMs: T0 - 3 * HOUR, endMs: T0 - 2 * HOUR } });
    render(<EventLogWorkspace />);
    const chips = document.querySelector('[data-evtx-region="chip-row"]')!;
    const main = document.querySelector('[data-evtx-region="main"]')!;
    expect(chips.compareDocumentPosition(histogramRegion()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(histogramRegion().compareDocumentPosition(main) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(histogramRegion().parentElement).toBe(chips.parentElement);
    // And above the coverage banner, which Phase 4b later moves into the rail.
    const banner = histogramRegion().nextElementSibling as HTMLElement;
    expect(banner).toHaveAttribute("role", "status");
    expect(banner).toHaveAttribute("aria-live", "polite");
    expect(banner.nextElementSibling).toBe(main.parentElement);
    // The panel toggles are Channels, Insights and Correlation dock (spec 8.2); the histogram has none.
    expect(screen.queryByRole("button", { name: /histogram/i })).toBeNull();
    for (const name of ["Channels", "Insights", "Correlation dock"]) {
      expect(screen.getByRole("button", { name })).toBeInTheDocument();
    }
  });

  it("charts the events the filters leave without the time range, so a brush never empties its own histogram", async () => {
    const records = [record(1, T0 - 3 * HOUR), record(2, T0 - 2 * HOUR), record(3, T0 - HOUR)];
    seed(records);
    render(<EventLogWorkspace />);
    expect(placed()).toBe(3);
    const full = tableText();
    act(() => {
      useEvtxStore.setState({ timeRange: { startMs: T0 - 2 * HOUR, endMs: T0 - 90 * MINUTE } });
    });
    await flushThrottle();
    expect(readout()).toBe("Showing 1 of 3");
    expect(placed()).toBe(3);
    expect(tableText()).toBe(full);
  });

  it("brushes with the pointer: the chip appears, the count narrows, the histogram keeps every bar", async () => {
    const records = Array.from({ length: 12 }, (_, i) => record(i + 1, T0 - (12 - i) * 20 * MINUTE));
    seed(records);
    render(<EventLogWorkspace />);
    const plot = stubSlider(360);
    const histogram = buildHistogram(records, "utc");
    const width = 360 / histogram.buckets.length;
    fireEvent.pointerDown(plot, { clientX: 2 * width + 1, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
    fireEvent.pointerMove(plot, { clientX: 4 * width + 1, buttons: 1, pointerId: 1 });
    fireEvent.pointerUp(plot, { clientX: 4 * width + 1, pointerId: 1 });
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
    expect(placed()).toBe(12);
  });

  it("clears the brush with Escape and with the chip's remove button", () => {
    const records = Array.from({ length: 12 }, (_, i) => record(i + 1, T0 - (12 - i) * 20 * MINUTE));
    seed(records);
    render(<EventLogWorkspace />);
    const histogram = buildHistogram(records, "utc");
    const range = { startMs: histogram.edges[2], endMs: histogram.edges[5] };
    act(() => {
      useEvtxStore.setState({ timeRange: range });
    });
    fireEvent.keyDown(slider(), { key: "Escape" });
    expect(storeRange()).toBeNull();
    expect(document.querySelector('[data-evtx-layer="wash"]')).toBeNull();

    act(() => {
      useEvtxStore.setState({ timeRange: range });
    });
    fireEvent.click(screen.getByRole("button", { name: /^Remove Time: brushed/ }));
    expect(storeRange()).toBeNull();
    expect(document.querySelector('[data-evtx-layer="wash"]')).toBeNull();
  });

  it("takes Escape twice from the keyboard: the pending selection first, the applied range second", () => {
    const records = Array.from({ length: 12 }, (_, i) => record(i + 1, T0 - (12 - i) * 20 * MINUTE));
    seed(records);
    render(<EventLogWorkspace />);
    const histogram = buildHistogram(records, "utc");
    const range = { startMs: histogram.edges[2], endMs: histogram.edges[5] };
    act(() => {
      useEvtxStore.setState({ timeRange: range });
    });
    const plot = slider();
    fireEvent.focus(plot);
    fireEvent.keyDown(plot, { key: "ArrowRight", shiftKey: true });
    expect(plot.getAttribute("aria-valuetext")).toMatch(/selecting/);
    fireEvent.keyDown(plot, { key: "Escape" });
    expect(storeRange()).toEqual(range);
    fireEvent.keyDown(plot, { key: "Escape" });
    expect(storeRange()).toBeNull();
  });

  it("still clears the range with Escape while the pointer rests on the plot and its tooltip shows", () => {
    const records = Array.from({ length: 12 }, (_, i) => record(i + 1, T0 - (12 - i) * 20 * MINUTE));
    seed(records);
    render(<EventLogWorkspace />);
    const histogram = buildHistogram(records, "utc");
    act(() => {
      useEvtxStore.setState({ timeRange: { startMs: histogram.edges[2], endMs: histogram.edges[5] } });
    });
    const plot = stubSlider();
    fireEvent.pointerMove(plot, { clientX: 100 });
    expect(document.querySelector("[data-evtx-tooltip]")).not.toBeNull();
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(storeRange()).toBeNull();
  });

  it("charts nothing while a load runs", () => {
    seed([record(1, T0 - HOUR)], { isLoading: true });
    render(<EventLogWorkspace />);
    expect(histogramRegion()).toHaveAttribute("aria-busy", "true");
    // The plot stays in the tab order, said to be unavailable, so focus is not lost to the load.
    expect(within(histogramRegion()).getByRole("slider", { name: "Time range" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(within(histogramRegion()).queryByRole("table")).toBeNull();
    expect(histogramRegion().querySelector("[data-evtx-layer=bars]")).toBeNull();
  });
});

describe("a transient criterion never moves the clock", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    seen.filterBar = -1;
    seen.timeline = -1;
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  const oldest = () => record(1, T0 - 23 * HOUR - 50 * MINUTE);
  const records = () => [oldest(), record(2, T0 - 12 * HOUR), record(3, T0 - 10 * MINUTE)];

  const settle = () =>
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });

  function mountRelative() {
    seed(records(), { timeWindow: "24h" });
    render(<EventLogWorkspace />);
    settle();
    return { clock: seen.filterBar, table: tableText(), shown: readout() };
  }

  it("keeps nowEpoch, the bucket edges and the counts when a time range is set and cleared later", () => {
    const before = mountRelative();
    expect(before.clock).toBe(T0);
    expect(seen.timeline).toBe(T0);
    expect(placed()).toBe(3);

    // 45 minutes pass: a re-anchored 24 hour window would now start after the oldest event.
    vi.setSystemTime(T0 + 45 * MINUTE);
    act(() => {
      useEvtxStore.setState({ timeRange: { startMs: T0 - 13 * HOUR, endMs: T0 - 11 * HOUR } });
    });
    settle();
    expect(seen.filterBar).toBe(before.clock);
    expect(seen.timeline).toBe(before.clock);
    expect(tableText()).toBe(before.table);
    expect(placed()).toBe(3);
    expect(readout()).toBe("Showing 1 of 3");

    vi.setSystemTime(T0 + 90 * MINUTE);
    act(() => {
      useEvtxStore.setState({ timeRange: null });
    });
    settle();
    expect(seen.filterBar).toBe(before.clock);
    expect(tableText()).toBe(before.table);
    expect(readout()).toBe(before.shown);
  });

  it("keeps nowEpoch when a record scope is set and cleared later", () => {
    const before = mountRelative();
    vi.setSystemTime(T0 + 45 * MINUTE);
    const scoped = useEvtxStore.getState().records.slice(0, 2);
    act(() => {
      expect(
        useEvtxStore.getState().setRecordScope({
          kind: "finding",
          title: "A finding",
          records: new Set(scoped),
          counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
        }),
      ).toBe(true);
    });
    settle();
    expect(seen.filterBar).toBe(before.clock);
    expect(seen.timeline).toBe(before.clock);
    // The oldest event, 23 h 50 min old at the first reading, is still inside the unmoved window.
    expect(readout()).toBe("Showing 2 of 3");

    vi.setSystemTime(T0 + 90 * MINUTE);
    act(() => {
      useEvtxStore.getState().setRecordScope(null);
    });
    settle();
    expect(seen.filterBar).toBe(before.clock);
    expect(readout()).toBe(before.shown);
  });

  it("does move the clock when the loaded records refresh, so the check above is not vacuous", () => {
    const before = mountRelative();
    vi.setSystemTime(T0 + 45 * MINUTE);
    act(() => {
      useEvtxStore.setState((state) => ({ records: [...state.records] }));
    });
    settle();
    expect(seen.filterBar).toBe(T0 + 45 * MINUTE);
    expect(seen.filterBar).not.toBe(before.clock);
    // The re-anchored window now starts after the oldest event, which drops out of the chart.
    expect(placed()).toBe(2);
  });
});
