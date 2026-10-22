import { act, render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { describe, expect, it, vi } from "vitest";
import { contrastRatio, parseHex } from "../../lib/color-contrast";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import type { EvtxChartRecord } from "./evtx-chart-data";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import EvtxChartsViewDefault, {
  EvtxChartsView,
  CHART_DATA_THROTTLE_MS,
  HEAT_EMPTY_CELL,
  type EvtxChartsViewProps,
} from "./EvtxChartsView";

const themes = getAllThemes();
const lightTokens = buildEvtxVisualTokens(themes[0]);

function rec(overrides: Partial<EvtxChartRecord> & { hour?: number } = {}): EvtxChartRecord {
  const { hour = 10, ...rest } = overrides;
  const epoch = Date.UTC(2026, 9, 8, hour, 0);
  return {
    channel: "System",
    provider: "Service Control Manager",
    eventId: 7036,
    level: "Information",
    timestamp: new Date(epoch).toISOString(),
    timestampEpoch: epoch,
    originKind: "event",
    sourceLabel: "live",
    ...rest,
  };
}

const records: EvtxChartRecord[] = [
  rec({ channel: "System", level: "Error", eventId: 1000, provider: "App", hour: 2 }),
  rec({ channel: "System", level: "Error", eventId: 1000, provider: "App", hour: 2 }),
  rec({ channel: "System", level: "Warning", eventId: 2000, provider: "Disk", hour: 2 }),
  rec({ channel: "Application", level: "Warning", eventId: 3000, provider: "Net", hour: 14 }),
  rec({ channel: "Application", level: "Critical", eventId: 41, provider: "Kernel-Power", hour: 14 }),
  rec({ channel: "Application", level: "Information", hour: 14 }),
  rec({ channel: "Application", level: "Error", eventId: 1000, provider: "App", timestampEpoch: null, timestamp: "" }),
];

/** What jsdom reads back after assigning a CSS color, so hex and rgb() compare equal. */
function css(color: string): string {
  const probe = document.createElement("span");
  probe.style.background = color;
  return probe.style.background;
}

function props(overrides: Partial<EvtxChartsViewProps> = {}): EvtxChartsViewProps {
  return {
    records,
    chains: {
      counts: { exact: 2, candidate: 1, ambiguous: 4, coverageBlocked: 0 },
      edgeInputComplete: true,
    },
    hideRules: [{ ...DEFAULT_QUICK_FILTER, mode: "eventIds", query: "7036 16384", action: "hide" }],
    channelOrder: ["System", "Application"],
    timeZoneMode: "utc",
    loadedChannelCount: 2,
    textLogCount: 0,
    windowLabel: "24 h",
    metrics: getLogListMetrics(13),
    visualTokens: lightTokens,
    ...overrides,
  };
}

describe("EvtxChartsView", () => {
  it("is the default export, so it can be loaded with React.lazy", () => {
    expect(EvtxChartsViewDefault).toBe(EvtxChartsView);
  });

  it("renders the four figures, each with an aria-label", () => {
    render(<EvtxChartsView {...props()} />);
    for (const name of [
      /^Events by channel/,
      /^Top 9 event IDs by count, excluding 7036 \/ 16384$/,
      /^Activity by hour of day and channel, heat map/,
      /^Errors and warnings per hour of day, stacked columns/,
    ]) {
      expect(screen.getByRole("figure", { name })).toBeInTheDocument();
    }
    expect(screen.getAllByRole("figure")).toHaveLength(4);
  });

  it("renders the KPI grid with values and derivable sublabels", () => {
    render(<EvtxChartsView {...props()} />);
    const value = (id: string) => screen.getByTestId(`kpi-value-${id}`).textContent;
    expect(value("events")).toBe("7");
    expect(value("errors")).toBe("3");
    expect(value("warnings")).toBe("2");
    expect(value("critical")).toBe("1");
    expect(value("distinctIds")).toBe("5");
    expect(value("chains")).toBe("3");
    expect(screen.getByText("Events (24 h)")).toBeInTheDocument();
    expect(screen.getByText("2 channels · 0 text logs")).toBeInTheDocument();
    expect(screen.getByText("Top 2 IDs = 100%")).toBeInTheDocument();
    expect(screen.getByText("Kernel-Power 41")).toBeInTheDocument();
    expect(screen.getByText("2 exact")).toBeInTheDocument();
  });

  it("shows no comparative sublabel before a comparison exists", () => {
    const { container } = render(<EvtxChartsView {...props()} />);
    expect(container.textContent).not.toMatch(/vs prior|new vs|▲|▼|∞/);
    expect(screen.queryByText(/Compar/)).toBeNull();
  });

  it("lists each channel with its counts in the row's accessible name", () => {
    render(<EvtxChartsView {...props()} />);
    expect(screen.getByLabelText("System: 3 events, 2 errors, 1 warnings")).toBeInTheDocument();
    expect(screen.getByLabelText("Application: 4 events, 1 errors, 1 warnings")).toBeInTheDocument();
  });

  it("builds the top-IDs caption from the hide rules", () => {
    const { rerender } = render(<EvtxChartsView {...props()} />);
    expect(screen.getByText("excluding 7036 / 16384")).toBeInTheDocument();
    vi.useFakeTimers();
    try {
      rerender(<EvtxChartsView {...props({ hideRules: [] })} />);
      // Throttled: the previous derivation stays until the settle time passes.
      expect(screen.getByText("excluding 7036 / 16384")).toBeInTheDocument();
      act(() => {
        vi.advanceTimersByTime(CHART_DATA_THROTTLE_MS);
      });
      expect(screen.queryByText(/excluding/)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows n/a for the chains tile when there is no chain model", () => {
    render(<EvtxChartsView {...props({ chains: null })} />);
    expect(screen.getByTestId("kpi-value-chains").textContent).toBe("n/a");
  });

  it("qualifies a zero chain count that comes from a loaded subset of edges", () => {
    render(
      <EvtxChartsView
        {...props({
          chains: {
            counts: { exact: 0, candidate: 0, ambiguous: 3, coverageBlocked: 0 },
            edgeInputComplete: false,
          },
        })}
      />,
    );
    expect(screen.getByTestId("kpi-value-chains").textContent).toBe("0");
    expect(screen.getByText("0 exact, loaded edges only")).toBeInTheDocument();
  });

  it("discloses channels beyond the cap in figure 1, figure 3 and the heat-map table", () => {
    const many = Array.from({ length: 15 }, (_, i) =>
      rec({ channel: `ch${String(i).padStart(2, "0")}`, hour: 3 }),
    );
    render(<EvtxChartsView {...props({ records: many, channelOrder: [] })} />);
    expect(screen.getAllByText("+3 more channels (3 events) not shown")).toHaveLength(2);
    const table = screen.getByRole("table", { name: /Events per hour of day by channel/ });
    expect(table).toHaveAccessibleName(/\+3 more channels \(3 events\) not shown/);
    expect(within(table).getAllByRole("row")).toHaveLength(13);
  });

  it("discloses text-log lines in figures 1 and 3, and shows them instead of empty frames", () => {
    const lines = [
      rec({ originKind: "log", channel: "a.log", sourceLabel: "a.log", provider: "A", eventId: 0 }),
      rec({ originKind: "log", channel: "a.log", sourceLabel: "a.log", provider: "A", eventId: 0 }),
    ];
    render(<EvtxChartsView {...props({ records: lines, textLogCount: 1 })} />);
    expect(screen.getAllByText("2 text-log lines not shown; text logs have no channel")).toHaveLength(2);
    expect(screen.getByRole("figure", { name: /^Events by channel/ })).toBeInTheDocument();
    expect(screen.queryByText("a.log")).toBeNull();
  });

  it("does not show the text-log line when there are none", () => {
    render(<EvtxChartsView {...props()} />);
    expect(screen.queryByText(/text-log line/)).toBeNull();
  });

  it("counts only events in figure 3's unplaced note", () => {
    const unplacedLog = rec({
      originKind: "log", channel: "a.log", sourceLabel: "a.log", provider: "A", eventId: 0,
      timestampEpoch: 0, timestamp: "",
    });
    render(<EvtxChartsView {...props({ records: [...records, unplacedLog, unplacedLog] })} />);
    const heat = screen.getByRole("figure", { name: /heat map/ });
    expect(heat).toHaveTextContent("1 event has no timestamp and is not placed");
    const hourly = screen.getByRole("figure", { name: /^Errors and warnings per hour/ });
    // The two unplaced text-log lines are Information; only the fixture's unplaced Error counts here.
    expect(hourly).toHaveTextContent("1 error or warning has no timestamp and is not placed");
  });

  it("words figure 4's unplaced note for errors and warnings", () => {
    const unplaced = (level: "Error" | "Warning") =>
      rec({ level, timestampEpoch: 0, timestamp: "", originKind: "log", channel: "a.log", sourceLabel: "a.log" });
    const { rerender } = render(<EvtxChartsView {...props({ records: [...records, unplaced("Error")] })} />);
    // `records` already holds one unplaced Error event, so the log line makes two.
    const hourly = () => screen.getByRole("figure", { name: /^Errors and warnings per hour/ });
    expect(hourly()).toHaveTextContent("2 errors and warnings have no timestamp and are not placed");
    vi.useFakeTimers();
    try {
      rerender(<EvtxChartsView {...props({ records: [rec({ hour: 3, level: "Error" }), unplaced("Warning")] })} />);
      act(() => {
        vi.advanceTimersByTime(CHART_DATA_THROTTLE_MS);
      });
      expect(hourly()).toHaveTextContent("1 error or warning has no timestamp and is not placed");
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not show the omitted line when every channel fits", () => {
    render(<EvtxChartsView {...props()} />);
    expect(screen.queryByText(/more channel/)).toBeNull();
  });

  it("names the heat map without a dark or light encoding", () => {
    render(<EvtxChartsView {...props()} />);
    const heat = screen.getByRole("figure", { name: /heat map/ });
    expect(heat).toHaveAccessibleName(/from fewer to more events/);
    expect(heat).not.toHaveAccessibleName(/dark/);
  });

  it("provides a visually hidden table of hourly counts", () => {
    render(<EvtxChartsView {...props()} />);
    const table = screen.getByRole("table", { name: "Errors and warnings per hour of day" });
    const row = within(table).getByRole("row", { name: /^02:00/ });
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["2", "1"]);
    expect(within(table).getAllByRole("row")).toHaveLength(25);
    expect(table.style.clip).toContain("rect");
    expect(screen.getByText("Peak: 02:00 (3)")).toBeInTheDocument();
  });

  it("labels the hourly figure every six hours as HH:00, in hour order", () => {
    render(<EvtxChartsView {...props()} />);
    const figure = screen.getByRole("figure", { name: /^Errors and warnings per hour/ });
    const axis = [...figure.querySelectorAll("span")]
      .filter((el) => !el.closest("table") && /^\d\d:00$/.test(el.textContent ?? ""))
      .map((el) => el.textContent);
    expect(axis).toEqual(["00:00", "06:00", "12:00", "18:00"]);
    const hours = [...figure.querySelectorAll<HTMLElement>("[data-hour]")].map((el) => el.dataset.hour);
    expect(hours).toEqual(Array.from({ length: 24 }, (_, i) => String(i)));
  });

  it("provides a visually hidden table behind the heat map", () => {
    render(<EvtxChartsView {...props()} />);
    const table = screen.getByRole("table", { name: "Events per hour of day by channel" });
    const system = within(table).getByRole("row", { name: /^System/ });
    const cells = within(system).getAllByRole("cell").map((c) => c.textContent);
    expect(cells).toHaveLength(24);
    expect(cells[2]).toBe("3");
    expect(cells[0]).toBe("0");
    // The cell grid is decorative for assistive tech; the table carries the values.
    expect(document.querySelector('[data-cell]')!.closest('[aria-hidden="true"]')).not.toBeNull();
  });

  it("says unplaced events are not placed in an hour", () => {
    render(<EvtxChartsView {...props()} />);
    expect(screen.getAllByText(/1 event has no timestamp and is not placed/)).toHaveLength(1);
    expect(
      screen.getAllByText(/1 error or warning has no timestamp and is not placed/),
    ).toHaveLength(1);
    // The unplaced error is not in hour 0.
    const table = screen.getByRole("table", { name: "Errors and warnings per hour of day" });
    const hour0 = within(table).getByRole("row", { name: /^00:00/ });
    expect(within(hour0).getAllByRole("cell").map((c) => c.textContent)).toEqual(["0", "0"]);
  });

  it("shows an empty state instead of empty figures", () => {
    render(<EvtxChartsView {...props({ records: [] })} />);
    expect(screen.getByRole("status")).toHaveTextContent("No events to chart");
    expect(screen.queryAllByRole("figure")).toHaveLength(0);
  });

  describe("update throttle under a live stream", () => {
    const eventsValue = () => Number(screen.getByTestId("kpi-value-events").textContent);
    const batch = (n: number) =>
      Array.from({ length: n }, (_, i) => rec({ eventId: 1000 + i, hour: 1 }));

    it("updates within 75 ms of the first change and at least every 75 ms during a 20 ms stream", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxChartsView {...props({ records: batch(1) })} />);
        expect(eventsValue()).toBe(1);
        const updates: number[] = [];
        let shown = 1;
        let now = 0;
        let count = 1;
        // A change every 20 ms for 1 s, sampled every 5 ms.
        for (now = 5; now <= 1000; now += 5) {
          if (now % 20 === 0) {
            count += 1;
            rerender(<EvtxChartsView {...props({ records: batch(count) })} />);
          }
          act(() => {
            vi.advanceTimersByTime(5);
          });
          const value = eventsValue();
          if (value !== shown) {
            // An update applies the latest value, not the one captured when its wait began.
            expect(value).toBe(count);
            shown = value;
            updates.push(now);
          }
        }
        // The first change happens at t = 20 ms; the first update is no later than 75 ms after it.
        expect(updates[0]).toBeLessThanOrEqual(20 + CHART_DATA_THROTTLE_MS);
        // The charts were never starved: no gap between updates (nor from the last one to the
        // end of the stream) exceeds the interval, plus the 5 ms sampling step.
        const marks = [20, ...updates];
        for (let i = 1; i < marks.length; i += 1) {
          expect(marks[i] - marks[i - 1]).toBeLessThanOrEqual(CHART_DATA_THROTTLE_MS + 5);
        }
        expect(1000 - marks[marks.length - 1]).toBeLessThanOrEqual(CHART_DATA_THROTTLE_MS + 5);
        expect(updates.length).toBeGreaterThan(10);
        // Once the stream ends the last wait applies the final count, and no timer is left.
        act(() => {
          vi.advanceTimersByTime(CHART_DATA_THROTTLE_MS);
        });
        expect(eventsValue()).toBe(count);
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        vi.useRealTimers();
      }
    });

    it("updates once after a single change", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxChartsView {...props({ records: batch(1) })} />);
        rerender(<EvtxChartsView {...props({ records: batch(3) })} />);
        expect(eventsValue()).toBe(1);
        act(() => {
          vi.advanceTimersByTime(CHART_DATA_THROTTLE_MS - 1);
        });
        expect(eventsValue()).toBe(1);
        act(() => {
          vi.advanceTimersByTime(1);
        });
        expect(eventsValue()).toBe(3);
        act(() => {
          vi.advanceTimersByTime(1000);
        });
        expect(eventsValue()).toBe(3);
      } finally {
        vi.useRealTimers();
      }
    });

    it("clears a pending wait on unmount, and a remount shows the current value at once", () => {
      vi.useFakeTimers();
      try {
        const { rerender, unmount } = render(<EvtxChartsView {...props({ records: batch(1) })} />);
        rerender(<EvtxChartsView {...props({ records: batch(2) })} />);
        // The change started a wait; unmounting must not leave it running.
        expect(vi.getTimerCount()).toBe(1);
        unmount();
        expect(vi.getTimerCount()).toBe(0);
        render(<EvtxChartsView {...props({ records: batch(2) })} />);
        expect(eventsValue()).toBe(2);
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe("throttled values that describe the data", () => {
    const advance = (ms: number) => {
      act(() => {
        vi.advanceTimersByTime(ms);
      });
    };
    const eventsValue = () => screen.getByTestId("kpi-value-events").textContent;
    const rows = (n: number) => Array.from({ length: n }, (_, i) => rec({ eventId: 1000 + i, hour: 4 }));
    const utcQualifier = /hour of day, UTC(?![+-])/;
    const localQualifier = /hour of day, UTC[+-]\d\d:\d\d/;

    it("says it is loading, not that there are no events, while a load runs", () => {
      vi.useFakeTimers();
      try {
        // Every other prop is the same object after the flip, so only `loading` changes.
        const base = props({ records: [] });
        const { rerender } = render(<EvtxChartsView {...base} loading />);
        expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
        // A load that ends with zero rows keeps the loading copy until the data settles (accepted cost).
        rerender(<EvtxChartsView {...base} loading={false} />);
        advance(CHART_DATA_THROTTLE_MS - 1);
        expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
        advance(1);
        expect(screen.getByRole("status")).toHaveTextContent("No events to chart");
      } finally {
        vi.useRealTimers();
      }
    });

    it("never says 'No events' between a load ending and its rows being drawn", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxChartsView {...props({ records: [], loading: true })} />);
        expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
        rerender(<EvtxChartsView {...props({ records: rows(3), loading: false })} />);
        expect(screen.queryByText(/No events to chart/)).toBeNull();
        expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
        advance(CHART_DATA_THROTTLE_MS - 1);
        expect(screen.queryByText(/No events to chart/)).toBeNull();
        expect(screen.queryByTestId("kpi-value-events")).toBeNull();
        advance(1);
        expect(screen.queryByText(/No events to chart/)).toBeNull();
        expect(screen.queryByRole("status")).toBeNull();
        expect(eventsValue()).toBe("3");
      } finally {
        vi.useRealTimers();
      }
    });

    it("shows the loading copy again when a new load starts over drawn charts", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxChartsView {...props({ records: rows(2) })} />);
        expect(eventsValue()).toBe("2");
        rerender(<EvtxChartsView {...props({ records: [], loading: true })} />);
        expect(eventsValue()).toBe("2");
        advance(CHART_DATA_THROTTLE_MS);
        expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
        expect(screen.queryByTestId("evtx-charts-view")).toBeNull();
      } finally {
        vi.useRealTimers();
      }
    });

    it("keeps the previous window label over the previous count until both change together", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxChartsView {...props({ records: rows(1), windowLabel: "24 h" })} />);
        expect(screen.getByText("Events (24 h)")).toBeInTheDocument();
        rerender(<EvtxChartsView {...props({ records: rows(3), windowLabel: "7 d" })} />);
        expect(screen.getByText("Events (24 h)")).toBeInTheDocument();
        expect(eventsValue()).toBe("1");
        advance(CHART_DATA_THROTTLE_MS - 1);
        expect(screen.getByText("Events (24 h)")).toBeInTheDocument();
        expect(eventsValue()).toBe("1");
        advance(1);
        expect(screen.getByText("Events (7 d)")).toBeInTheDocument();
        expect(eventsValue()).toBe("3");
      } finally {
        vi.useRealTimers();
      }
    });

    it("applies a window label that changes alone after the throttle", () => {
      vi.useFakeTimers();
      try {
        const base = props({ windowLabel: "24 h" });
        const { rerender } = render(<EvtxChartsView {...base} />);
        rerender(<EvtxChartsView {...base} windowLabel="7 d" />);
        advance(CHART_DATA_THROTTLE_MS - 1);
        expect(screen.getByText("Events (24 h)")).toBeInTheDocument();
        advance(1);
        expect(screen.getByText("Events (7 d)")).toBeInTheDocument();
      } finally {
        vi.useRealTimers();
      }
    });

    it("keeps the previous clock in both qualifiers until the hour buckets change with it", () => {
      vi.useFakeTimers();
      try {
        // Every other prop is the same object after the flip, so only the clock changes.
        const base = props({ timeZoneMode: "utc" });
        const { rerender } = render(<EvtxChartsView {...base} />);
        const heat = () => screen.getByRole("figure", { name: /heat map/ });
        const hourly = () => screen.getByRole("figure", { name: /^Errors and warnings per hour/ });
        expect(heat()).toHaveTextContent(utcQualifier);
        expect(hourly()).toHaveTextContent(utcQualifier);
        rerender(<EvtxChartsView {...base} timeZoneMode="local" />);
        expect(heat()).toHaveTextContent(utcQualifier);
        expect(hourly()).toHaveTextContent(utcQualifier);
        advance(CHART_DATA_THROTTLE_MS - 1);
        expect(heat()).toHaveTextContent(utcQualifier);
        expect(hourly()).toHaveTextContent(utcQualifier);
        advance(1);
        expect(heat()).toHaveTextContent(localQualifier);
        expect(hourly()).toHaveTextContent(localQualifier);
      } finally {
        vi.useRealTimers();
      }
    });

    it("leaves no timer running once a change has settled", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxChartsView {...props({ records: rows(1) })} />);
        expect(vi.getTimerCount()).toBe(0);
        rerender(<EvtxChartsView {...props({ records: rows(2), loading: true, windowLabel: "7 d", timeZoneMode: "local" })} />);
        expect(vi.getTimerCount()).toBe(1);
        advance(CHART_DATA_THROTTLE_MS);
        // A throttled value rebuilt on every render would re-arm the timer forever.
        expect(vi.getTimerCount()).toBe(0);
        advance(10 * CHART_DATA_THROTTLE_MS);
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  it("sizes text from the log list font metrics", () => {
    const { rerender } = render(<EvtxChartsView {...props()} />);
    expect(screen.getByTestId("kpi-value-events").style.fontSize).toBe("22px");
    rerender(<EvtxChartsView {...props({ metrics: getLogListMetrics(16) })} />);
    expect(screen.getByTestId("kpi-value-events").style.fontSize).toBe("25px");
  });

  it("colors bars from the visual tokens", () => {
    const { container } = render(<EvtxChartsView {...props()} />);
    const bars = [...container.querySelectorAll<HTMLElement>('[data-bar="channel"]')];
    // Application ranks first (4 events) but is second in display order.
    expect(bars.map((b) => b.style.background)).toEqual([
      css(lightTokens.channelColor(1)),
      css(lightTokens.channelColor(0)),
    ]);
    for (const bar of container.querySelectorAll<HTMLElement>('[data-bar="top-id"]')) {
      expect(bar.style.background).toBe(css(lightTokens.singleSeries));
    }
    const errorSegment = container.querySelector<HTMLElement>('[data-segment="error"]')!;
    expect(errorSegment.style.background).toBe(css(lightTokens.levels.Error.barColor));
    const warningSegment = container.querySelector<HTMLElement>('[data-segment="warning"]')!;
    expect(warningSegment.style.background).toBe(css(lightTokens.levels.Warning.barColor));
  });

  it("fills non-empty heat cells from the heat steps and empty cells from the empty-cell token", () => {
    const { container } = render(<EvtxChartsView {...props()} />);
    const cells = [...container.querySelectorAll<HTMLElement>("[data-cell]")];
    const empty = cells.filter((c) => c.dataset.cell === "empty");
    const filled = cells.filter((c) => c.dataset.cell !== "empty");
    expect(filled.length).toBe(2);
    expect(empty.length).toBe(cells.length - 2);
    for (const cell of filled) {
      const step = Number(cell.dataset.cell!.replace("step-", ""));
      // Guards the comparison: an unparsed color would read back as "" on both sides.
      expect(css(lightTokens.heatSteps[step])).not.toBe("");
      expect(cell.style.background).toBe(css(lightTokens.heatSteps[step]));
      expect(cell.style.border).toBe("");
    }
    for (const cell of empty) {
      expect(cell.style.border).toContain("dashed");
      expect(cell.style.background).toBe("transparent");
    }
  });
});

/** Resolves one `color-mix(in srgb, <hex> P%, var(--token))` heat step to a hex. */
function resolveHeatStep(step: string, theme: CMTraceTheme): string {
  const match = /^color-mix\(in srgb, (#[0-9a-fA-F]{3,6}) (\d+)%, (var\([^)]*\))\)$/.exec(step);
  if (!match) throw new Error(`Unexpected heat step ${step}`);
  const fg = parseHex(match[1]);
  const bg = parseHex(resolveToken(match[3], theme));
  const p = Number(match[2]) / 100;
  return (
    "#" +
    fg
      .map((c, i) => Math.round(c * p + bg[i] * (1 - p)).toString(16).padStart(2, "0"))
      .join("")
  );
}

describe("heat map empty cell (Adam's acceptance criterion, all themes)", () => {
  it("covers all seven themes", () => {
    expect(themes).toHaveLength(7);
  });

  it("defines the empty cell by an outline, not a fill", () => {
    expect(HEAT_EMPTY_CELL.background).toBe("transparent");
    expect(HEAT_EMPTY_CELL.border).toBe(`1px dashed ${tokens.colorNeutralStrokeAccessible}`);
  });

  it.each(themes.map((t) => [t.id, t] as const))(
    "%s: the empty-cell outline is distinguishable from the faintest step and from the surface",
    (_id, theme) => {
      const visual = buildEvtxVisualTokens(theme);
      const faintest = resolveHeatStep(visual.heatSteps[0], theme);
      const surface = resolveToken(tokens.colorNeutralBackground1, theme);
      const outline = resolveToken(tokens.colorNeutralStrokeAccessible, theme);

      // Graphical-object contrast (WCAG 1.4.11) against both neighbors.
      expect(contrastRatio(outline, faintest)).toBeGreaterThanOrEqual(3);
      expect(contrastRatio(outline, surface)).toBeGreaterThanOrEqual(3);

      // The faintest step is a real fill, not the empty cell's transparent surface.
      expect(faintest.toLowerCase()).not.toBe(surface.toLowerCase());
      expect(HEAT_EMPTY_CELL.background).not.toBe(visual.heatSteps[0]);
    },
  );

  it.each(themes.map((t) => [t.id, t] as const))(
    "%s: the view renders with that theme's tokens",
    (_id, theme) => {
      const visual = buildEvtxVisualTokens(theme);
      const { container } = render(<EvtxChartsView {...props({ visualTokens: visual })} />);
      const filled = container.querySelector<HTMLElement>('[data-cell^="step-"]')!;
      const step = Number(filled.dataset.cell!.replace("step-", ""));
      expect(css(visual.heatSteps[step])).not.toBe("");
      expect(filled.style.background).toBe(css(visual.heatSteps[step]));
      expect(visual.heatSteps).toHaveLength(6);
    },
  );
});
