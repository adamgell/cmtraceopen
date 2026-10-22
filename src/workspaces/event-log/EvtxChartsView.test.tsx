import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { describe, expect, it, vi } from "vitest";
import { contrastRatio, parseHex } from "../../lib/color-contrast";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import type { EvtxChartRecord } from "./evtx-chart-data";
import type { EvtxLevel, EvtxRecord } from "./types";
import {
  compareLoadedFiles,
  computePriorWindow,
  eventIdentityKey,
  resolveFilesPrior,
  type ComparisonOutcome,
  type ComparisonState,
  type PriorWindow,
} from "./evtx-comparison";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import type { ComparisonPresentationInput } from "./evtx-chart-comparison";
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
      // Debounced: the previous derivation stays until the settle time passes.
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
  });

  it("says it is loading, not that there are no events, while a load runs", () => {
    const { rerender } = render(<EvtxChartsView {...props({ records: [], loading: true })} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
    rerender(<EvtxChartsView {...props({ records: [], loading: false })} />);
    expect(screen.getByRole("status")).toHaveTextContent("No events to chart");
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

// ---------------------------------------------------------------------------------------------
// The previous-period comparison (spec 8.10, 8.16, D15)
// ---------------------------------------------------------------------------------------------

describe("the previous-period comparison", () => {
  const NOT_COVERED = "The loaded files do not cover the previous period.";
  const ANCHOR = Date.parse("2026-08-10T12:00:00.000Z");
  const HOUR = 60 * 60 * 1000;
  const ALL_LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

  let nextId = 1;
  function fileRecord(overrides: Partial<EvtxRecord> = {}): EvtxRecord {
    const id = nextId++;
    return {
      id,
      eventRecordId: id,
      timestamp: "2026-08-09T06:00:00.000Z",
      timestampEpoch: ANCHOR - 30 * HOUR,
      provider: "Contoso-Provider",
      channel: "System",
      eventId: 12,
      level: "Information",
      computer: "CONTOSO-PC01",
      message: "synthetic",
      eventData: [],
      rawXml: "<Event/>",
      sourceLabel: "System.evtx",
      ...overrides,
    };
  }

  function priorFor(): PriorWindow {
    const result = computePriorWindow("24h", ANCHOR);
    if (result.status !== "available") throw new Error("expected an available prior window");
    return result.prior;
  }

  const visibility = {
    selectedChannels: new Set(["System"]),
    filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    quickFilter: DEFAULT_QUICK_FILTER,
  };

  /** A real files comparison: two errors and two distinct IDs in the previous 24 h. */
  function filesOutcome(extra: EvtxRecord[] = []): ComparisonOutcome {
    const prior = priorFor();
    return compareLoadedFiles({
      records: [
        fileRecord({ timestampEpoch: prior.fromMs, level: "Error", provider: "A", eventId: 1 }),
        fileRecord({ timestampEpoch: prior.fromMs + HOUR, level: "Error", provider: "A", eventId: 1 }),
        fileRecord({ timestampEpoch: prior.fromMs + 2 * HOUR, level: "Warning", provider: "B", eventId: 2 }),
        fileRecord({ timestampEpoch: prior.toMs }),
        fileRecord({ timestampEpoch: ANCHOR }),
        ...extra,
      ],
      window: "24h",
      anchorEpoch: ANCHOR,
      visibility,
      coverageDetails: [],
      sourceCoverage: [],
    });
  }

  const settled = (outcome: ComparisonOutcome): ComparisonState => ({ phase: "settled", outcome });
  const TALLY = {
    errors: 6,
    distinctIds: new Set([eventIdentityKey("A", 1), eventIdentityKey("C", 3), eventIdentityKey("D", 4)]),
    tailExcluded: 0,
    unplacedRecords: 0,
  };

  function comparisonProps(
    overrides: Partial<ComparisonPresentationInput> = {},
  ) {
    const callbacks = { onCompare: vi.fn(), onRecompare: vi.fn(), onClear: vi.fn() };
    return {
      ...callbacks,
      input: {
        state: { phase: "idle" } as ComparisonState,
        availability: { available: true } as const,
        timeZoneMode: "utc" as const,
        snapshotEpoch: ANCHOR,
        countCurrent: () => TALLY,
        cleared: false,
        ...overrides,
      } satisfies ComparisonPresentationInput,
    };
  }

  const view = (comparison: ReturnType<typeof comparisonProps>, rest: Partial<EvtxChartsViewProps> = {}) =>
    render(<EvtxChartsView {...props({ comparison, ...rest })} />);

  const compareButton = () => screen.queryByRole("button", { name: "Compare with previous period" });
  const clearButton = () => screen.queryByRole("button", { name: "Clear comparison" });
  const errorsText = () => screen.queryByTestId("kpi-sublabel-errors")?.textContent ?? null;
  /** A sublabel's text with the nodes matching `selector` removed. */
  const sublabelWithout = (id: string, selector: string) => {
    const clone = screen.getByTestId(`kpi-sublabel-${id}`).cloneNode(true) as HTMLElement;
    clone.querySelectorAll(selector).forEach((node) => node.remove());
    return clone.textContent;
  };
  /** What a sighted reader sees: the visually hidden direction word is left out. */
  const visibleSublabel = (id: string) => sublabelWithout(id, '[data-testid="kpi-trend-direction"]');
  /** What a screen reader says: the glyph, which is hidden from it, is left out. */
  const spokenSublabel = (id: string) => sublabelWithout(id, '[aria-hidden="true"]');
  const distinctText = () => screen.queryByTestId("kpi-sublabel-distinctIds")?.textContent ?? null;

  describe("not compared", () => {
    it("offers Compare, shows no delta and no status, and starts a comparison on a click", () => {
      const comparison = comparisonProps();
      view(comparison);
      const button = compareButton();
      expect(button).not.toHaveAttribute("aria-disabled", "true");
      fireEvent.click(button!);
      expect(comparison.onCompare).toHaveBeenCalledTimes(1);
      expect(comparison.onRecompare).not.toHaveBeenCalled();
      expect(errorsText()).toBeNull();
      expect(distinctText()).toBeNull();
      expect(screen.getByTestId("comparison-status")).toBeEmptyDOMElement();
      expect(clearButton()).toBeNull();
    });

    it("always has a live status region, so a change of state is announced", () => {
      view(comparisonProps());
      expect(screen.getByTestId("comparison-status")).toHaveAttribute("role", "status");
    });

    it("says a comparison was cleared, in the status region", () => {
      view(comparisonProps({ cleared: true }));
      expect(screen.getByTestId("comparison-status")).toHaveTextContent(
        "The comparison was cleared because what it measured changed.",
      );
    });
  });

  describe("when the prior period cannot be compared", () => {
    const prior = priorFor();
    const records = (overrides: Partial<EvtxRecord>[]) => overrides.map((o) => fileRecord(o));
    const selected = new Set(["System", "Application"]);

    // The reasons come from the comparison itself, so the pins are keyed by its reason code.
    const cases: Array<{
      name: string;
      resolved: ReturnType<typeof resolveFilesPrior>;
      reason: "priorPeriodNotSpanned" | "noTimedRecords";
    }> = [
      {
        name: "the files do not span the previous period",
        resolved: resolveFilesPrior(records([{ timestampEpoch: ANCHOR }]), selected, "24h", ANCHOR),
        reason: "priorPeriodNotSpanned",
      },
      {
        name: "a capture has no timed entry",
        resolved: resolveFilesPrior(
          records([
            { timestampEpoch: prior.fromMs, channel: "Application", sourceLabel: "Application.evtx" },
            { timestampEpoch: prior.toMs, channel: "Application", sourceLabel: "Application.evtx" },
            { timestampEpoch: ANCHOR, channel: "Application", sourceLabel: "Application.evtx" },
            { timestampEpoch: 0 },
          ]),
          selected,
          "24h",
          ANCHOR,
        ),
        reason: "noTimedRecords",
      },
      {
        name: "nothing is loaded for the selected channels",
        resolved: resolveFilesPrior([], selected, "24h", ANCHOR),
        reason: "noTimedRecords",
      },
    ];

    it.each(cases)("$name: shows the comparison's own words, in full, and disables Compare", ({ resolved, reason }) => {
      expect(resolved.status).toBe("unavailable");
      if (resolved.status !== "unavailable") return;
      expect(resolved.reason).toBe(reason);
      const comparison = comparisonProps({
        availability: { available: false, detail: resolved.detail },
      });
      view(comparison);

      const button = compareButton()!;
      expect(button).toHaveAttribute("aria-disabled", "true");
      // Focusable, so a keyboard user reaches the reason; the reason is its accessible description.
      button.focus();
      expect(button).toHaveFocus();
      expect(button).toHaveAccessibleDescription(resolved.detail);
      // Rendered as given, whole: no truncation, nothing added or taken away.
      expect(screen.getByTestId("comparison-disabled-reason").textContent).toBe(resolved.detail);
      fireEvent.click(button);
      expect(comparison.onCompare).not.toHaveBeenCalled();

      // The wording is pinned by the code, never branched on: only a refusal about the period
      // opens with the spec's sentence.
      expect(resolved.detail.startsWith(NOT_COVERED)).toBe(reason === "priorPeriodNotSpanned");
    });

    it("pins the exact words for each reason code", () => {
      const [late, untimed, none] = cases.map((c) => (c.resolved.status === "unavailable" ? c.resolved.detail : ""));
      expect(late).toBe(`${NOT_COVERED} System.evtx (System) does not span it. No selected channel has entries that can be compared.`);
      expect(untimed).toBe(
        "System.evtx (System) has no event with a usable timestamp, so it cannot show whether it covers the previous period. Deselect System to compare the other channels.",
      );
      expect(none).toBe("No entries are loaded for the selected channels.");
    });

    it("wraps a long reason and never clips it", () => {
      const long = `${NOT_COVERED} ${"A-very-long-capture-name.evtx (Channel) ".repeat(12)}does not span it.`;
      view(comparisonProps({ availability: { available: false, detail: long } }));
      const reason = screen.getByTestId("comparison-disabled-reason");
      expect(reason.textContent).toBe(long);
      expect(reason.style.overflowWrap).toBe("anywhere");
      expect(reason.style.whiteSpace).toBe("normal");
      expect(reason.style.textOverflow).toBe("");
      expect(reason.style.width).toBe("");
      expect(reason.style.maxWidth).toBe("100%");
    });

    it("shows the tooltip with the same words when the control takes focus", async () => {
      view(comparisonProps({ availability: { available: false, detail: NOT_COVERED } }));
      fireEvent.focus(compareButton()!);
      const tip = await screen.findByRole("tooltip");
      expect(tip).toHaveTextContent(NOT_COVERED);
    });
  });

  describe("comparing", () => {
    const running: ComparisonState = {
      phase: "running",
      mode: "live",
      requestId: "event-log-compare-1",
      prior: priorFor(),
      channels: ["System"],
      scanned: 1500,
    };

    it("names the period, reports progress, shows no delta, and offers only Clear", () => {
      const comparison = comparisonProps({ state: running });
      view(comparison);
      expect(screen.getByTestId("comparison-label")).toHaveTextContent(
        "Comparing with 2026-08-08 12:00:00.000 to 2026-08-09 11:59:59.999 (UTC)",
      );
      expect(screen.getByTestId("comparison-status")).toHaveTextContent(
        `Reading the previous period: ${(1500).toLocaleString()} events scanned so far.`,
      );
      expect(compareButton()).toBeNull();
      expect(errorsText()).toBeNull();
      expect(distinctText()).toBeNull();
      fireEvent.click(clearButton()!);
      expect(comparison.onClear).toHaveBeenCalledTimes(1);
    });
  });

  describe("complete and current", () => {
    it("shows the deltas on the two tiles, from the comparison's own current period", () => {
      view(comparisonProps({ state: settled(filesOutcome()) }));
      expect(visibleSublabel("errors")).toBe("\u25b2 3\u00d7 vs prior 24 h");
      expect(distinctText()).toBe("2 new vs prior 24 h");
      // The tile's value is the grid's, and is not the comparison's.
      expect(screen.getByTestId("kpi-value-errors")).toHaveTextContent("3");
      expect(screen.getByTestId("comparison-label")).toHaveTextContent(
        "Comparing with 2026-08-08 12:00:00.000 to 2026-08-09 11:59:59.999 (UTC)",
      );
      expect(compareButton()).toBeNull();
    });

    it("gives the arrow an accessible direction and hides the glyph from assistive technology", () => {
      view(comparisonProps({ state: settled(filesOutcome()) }));
      const sublabel = screen.getByTestId("kpi-sublabel-errors");
      // The glyph is hidden from assistive technology; a screen reader says the direction instead.
      expect(sublabel.querySelector('[aria-hidden="true"]')?.textContent?.trim()).toBe("\u25b2");
      expect(within(sublabel).getByTestId("kpi-trend-direction").textContent).toBe("Up ");
      expect(spokenSublabel("errors")).toBe("Up 3\u00d7 vs prior 24 h");
    });

    it("keeps a visible space between the glyph and the ratio, and a spoken space after the direction", () => {
      view(comparisonProps({ state: settled(filesOutcome()) }));
      // What a sighted reader sees, with the visually hidden word left out.
      expect(visibleSublabel("errors")).toBe("\u25b2 3\u00d7 vs prior 24 h");
      expect(visibleSublabel("errors")).not.toMatch(/\u25b2\S/);
      expect(visibleSublabel("errors")).not.toMatch(/\s{2}/);
      // What a screen reader says, with the glyph left out.
      expect(spokenSublabel("errors")).toBe("Up 3\u00d7 vs prior 24 h");
      expect(spokenSublabel("errors")).not.toMatch(/Up\S/);
    });

    it("shows a down arrow and its direction for a decrease", () => {
      view(
        comparisonProps({
          state: settled(filesOutcome()),
          countCurrent: () => ({ ...TALLY, errors: 1 }),
        }),
      );
      expect(visibleSublabel("errors")).toBe("\u25bc 0.5\u00d7 vs prior 24 h");
      expect(spokenSublabel("errors")).toBe("Down 0.5\u00d7 vs prior 24 h");
    });

    it("states the notes, and the tail events left out", () => {
      view(
        comparisonProps({
          state: settled(filesOutcome()),
          countCurrent: () => ({ ...TALLY, tailExcluded: 2 }),
        }),
      );
      expect(screen.getByTestId("comparison-notes")).toHaveTextContent(
        "Left out of the current period: 2 events appended by the live tail.",
      );
    });

    it("clears the comparison on a click", () => {
      const comparison = comparisonProps({ state: settled(filesOutcome()) });
      view(comparison);
      fireEvent.click(clearButton()!);
      expect(comparison.onClear).toHaveBeenCalledTimes(1);
    });
  });

  describe("withheld", () => {
    it("shows no delta, and says why in one sentence", () => {
      view(
        comparisonProps({
          state: settled(filesOutcome()),
          countCurrent: () => ({ ...TALLY, unplacedRecords: 2 }),
        }),
      );
      expect(errorsText()).toBeNull();
      expect(distinctText()).toBeNull();
      expect(screen.getByTestId("comparison-status")).toHaveTextContent(
        "2 loaded entries have no usable timestamp or level and could not be placed in the current period, so no change is shown.",
      );
      expect(clearButton()).not.toBeNull();
    });
  });

  describe("partial", () => {
    it("withholds every delta and lists the comparison's reasons, as written", () => {
      const outcome = filesOutcome([fileRecord({ timestampEpoch: 0 })]);
      expect(outcome.status).toBe("partial");
      view(comparisonProps({ state: settled(outcome) }));
      expect(errorsText()).toBeNull();
      expect(distinctText()).toBeNull();
      expect(screen.getByTestId("comparison-status")).toHaveTextContent(
        "Partial. No change is shown, because the counts for these periods are not complete:",
      );
      const items = within(screen.getByTestId("comparison-reasons")).getAllByRole("listitem");
      expect(items.map((item) => item.textContent)).toEqual(
        outcome.status === "partial" ? outcome.result.gaps : ["unreachable"],
      );
      expect(clearButton()).not.toBeNull();
    });
  });

  describe("unavailable", () => {
    it("states the refusal in the comparison's words and keeps Compare for a retry", () => {
      const detail =
        "Security reached the automatic load's cap of 2,000 events, so the current period is only partly loaded. Deselect Security to compare the other channels.";
      const comparison = comparisonProps({
        state: settled({ status: "unavailable", reason: "currentPeriodIncomplete", detail }),
      });
      view(comparison);
      expect(screen.getByTestId("comparison-status").textContent).toBe(`Comparison unavailable: ${detail}`);
      expect(compareButton()).not.toHaveAttribute("aria-disabled", "true");
      expect(clearButton()).not.toBeNull();
      expect(errorsText()).toBeNull();
    });
  });

  describe("out of date", () => {
    it("shows no delta, says what each side covers, and re-compares on a click", () => {
      const comparison = comparisonProps({
        state: settled(filesOutcome()),
        snapshotEpoch: ANCHOR + 3 * HOUR,
      });
      view(comparison);
      expect(errorsText()).toBeNull();
      expect(distinctText()).toBeNull();
      expect(screen.getByTestId("comparison-status")).toHaveTextContent(
        "Out of date. The comparison covers 2026-08-09 12:00:00.000 to 2026-08-10 12:00:00.000 (UTC); the tiles now show events from 2026-08-09 15:00:00.000 (UTC). No change is shown.",
      );
      fireEvent.click(screen.getByRole("button", { name: "Compare again" }));
      expect(comparison.onRecompare).toHaveBeenCalledTimes(1);
      expect(comparison.onCompare).not.toHaveBeenCalled();
    });

    it("asks a live comparison to refresh first", () => {
      const outcome = filesOutcome();
      if (outcome.status !== "complete") throw new Error("expected complete");
      view(
        comparisonProps({
          state: settled({ status: "complete", result: { ...outcome.result, mode: "live" } }),
          snapshotEpoch: ANCHOR + 3 * HOUR,
        }),
      );
      expect(screen.getByRole("button", { name: "Refresh and compare again" })).not.toHaveAttribute("aria-disabled", "true");
    });
  });

  describe("Clear", () => {
    const outcome = filesOutcome();
    const states: Array<[string, Partial<ComparisonPresentationInput>]> = [
      [
        "running",
        {
          state: {
            phase: "running",
            mode: "live",
            requestId: "event-log-compare-2",
            prior: priorFor(),
            channels: ["System"],
            scanned: 0,
          },
        },
      ],
      ["complete", { state: settled(outcome) }],
      ["partial", { state: settled(filesOutcome([fileRecord({ timestampEpoch: 0 })])) }],
      ["unavailable", { state: settled({ status: "unavailable", reason: "queryFailed", detail: "x" }) }],
      ["out of date", { state: settled(outcome), snapshotEpoch: ANCHOR + 3 * HOUR }],
    ];

    it.each(states)("is offered while %s, and calls onClear once", (_name, overrides) => {
      const comparison = comparisonProps(overrides);
      view(comparison);
      fireEvent.click(clearButton()!);
      expect(comparison.onClear).toHaveBeenCalledTimes(1);
    });

    it("is not offered when nothing is compared", () => {
      view(comparisonProps());
      expect(clearButton()).toBeNull();
    });
  });

  describe("every state", () => {
    const outcome = filesOutcome();
    const everyState: Array<[string, Partial<ComparisonPresentationInput>]> = [
      ["off", {}],
      ["off, cleared", { cleared: true }],
      ["off, disabled", { availability: { available: false, detail: "All time has no previous period." } }],
      ["complete", { state: settled(outcome) }],
      ["partial", { state: settled(filesOutcome([fileRecord({ timestampEpoch: 0 })])) }],
      ["out of date", { state: settled(outcome), snapshotEpoch: ANCHOR + 3 * HOUR }],
      ["out of date, no clock", { state: settled(outcome), snapshotEpoch: Number.NaN }],
      ["withheld", { state: settled(outcome), countCurrent: () => ({ ...TALLY, unplacedRecords: 1 }) }],
      ["unavailable", { state: settled({ status: "unavailable", reason: "queryFailed", detail: "System: failed" }) }],
    ];

    it.each(everyState)("%s: nothing rendered carries an infinity, a NaN, an undefined or a dash", (_name, overrides) => {
      const { container } = view(comparisonProps(overrides));
      expect(container.textContent).not.toMatch(/\u221e|Infinity|NaN|undefined|\[object|\u2013|\u2014/);
    });

    it.each(everyState.filter(([name]) => name !== "complete"))(
      "%s: shows no delta, because only a complete comparison that is still current has one",
      (_name, overrides) => {
        view(comparisonProps(overrides));
        expect(errorsText()).toBeNull();
        expect(distinctText()).toBeNull();
        expect(screen.queryByText(/vs prior/)).toBeNull();
      },
    );
  });

  describe("sizes", () => {
    it("sets its text from the log list font metrics, at two sizes", () => {
      for (const size of [13, 20] as const) {
        const metrics = getLogListMetrics(size);
        const { unmount } = view(
          comparisonProps({
            state: settled(filesOutcome([fileRecord({ timestampEpoch: 0 })])),
            availability: { available: false, detail: "reason" },
          }),
          { metrics },
        );
        const f = metrics.fontSize;
        expect(screen.getByTestId("comparison-label").style.fontSize).toBe(`${Math.max(11, f - 1)}px`);
        expect(screen.getByTestId("comparison-status").style.fontSize).toBe(`${Math.max(11, f - 1)}px`);
        expect(screen.getByTestId("comparison-reasons").style.fontSize).toBe(`${Math.max(10, f - 2)}px`);
        unmount();
      }
    });

    // The three actions (Compare, Compare again, Refresh and compare again) share one button, and
    // Clear comparison is another. Each is rendered in a state that shows it, at two sizes.
    it("sets the text of the action button and of Clear from the font metrics, at two sizes", () => {
      const outcome = filesOutcome();
      if (outcome.status !== "complete") throw new Error("expected complete");
      const live: ComparisonOutcome = {
        status: "complete",
        result: { ...outcome.result, mode: "live" },
      };
      const states: Array<[string, Partial<ComparisonPresentationInput>, string[]]> = [
        ["not compared", {}, ["Compare with previous period"]],
        [
          "refused",
          { state: settled({ status: "unavailable", reason: "queryFailed", detail: "x" }) },
          ["Compare with previous period", "Clear comparison"],
        ],
        [
          "out of date, files",
          { state: settled(outcome), snapshotEpoch: ANCHOR + 3 * HOUR },
          ["Compare again", "Clear comparison"],
        ],
        [
          "out of date, live",
          { state: settled(live), snapshotEpoch: ANCHOR + 3 * HOUR },
          ["Refresh and compare again", "Clear comparison"],
        ],
        ["complete", { state: settled(outcome) }, ["Clear comparison"]],
      ];
      for (const size of [13, 20] as const) {
        const metrics = getLogListMetrics(size);
        const expected = `${Math.max(11, metrics.fontSize - 1)}px`;
        for (const [name, overrides, buttons] of states) {
          const { unmount } = view(comparisonProps(overrides), { metrics });
          for (const label of buttons) {
            const button = screen.getByRole("button", { name: label });
            expect(button.style.fontSize, `${label} (${name}) at ${size}`).toBe(expected);
          }
          unmount();
        }
      }
    });
  });

  describe("contrast, in all seven themes", () => {
    const comparativeToken = tokens.colorNeutralForeground2;
    it("colours a delta, and every new text, with a foreground that passes 4.5:1 on the surface", () => {
      // The third foreground measures 3.37:1 in solarized-dark and 3.03:1 in dracula, so no new text
      // uses it. The text this view adds uses the first and second.
      for (const theme of themes) {
        const surface = resolveToken(tokens.colorNeutralBackground1, theme);
        for (const token of [tokens.colorNeutralForeground1, tokens.colorNeutralForeground2]) {
          expect(contrastRatio(resolveToken(token, theme), surface), `${theme.id} ${token}`).toBeGreaterThanOrEqual(4.5);
        }
      }
    });

    it("gives a comparison delta the second foreground, and leaves the other sublabels theirs", () => {
      view(comparisonProps({ state: settled(filesOutcome()) }));
      expect(screen.getByTestId("kpi-sublabel-errors").style.color).toBe(css(comparativeToken));
      expect(screen.getByTestId("kpi-sublabel-distinctIds").style.color).toBe(css(comparativeToken));
      expect(screen.getByTestId("kpi-sublabel-warnings").style.color).toBe(css(tokens.colorNeutralForeground3));
    });

    it("colours the label, the reasons, the notes and the disabled reason with the second foreground and the status with the first", () => {
      view(
        comparisonProps({
          state: settled(filesOutcome([fileRecord({ timestampEpoch: 0 })])),
          availability: { available: false, detail: "reason" },
        }),
      );
      for (const id of ["comparison-label", "comparison-reasons"]) {
        expect(screen.getByTestId(id).style.color).toBe(css(tokens.colorNeutralForeground2));
      }
      expect(screen.getByTestId("comparison-status").style.color).toBe(css(tokens.colorNeutralForeground1));
    });
  });

  // The two nodes the other colour and size tests never render: the reason beside a disabled
  // Compare, which needs the "off" state, and the notes, which need a complete comparison with
  // tail events left out. Each is measured in its own state, at two font sizes.
  describe("the disabled reason and the notes", () => {
    const measure = (testId: string, node: HTMLElement) => ({
      testId,
      color: node.style.color,
      fontSize: node.style.fontSize,
    });

    it.each([13, 20] as const)(
      "colour them with the second foreground and size them from the font metrics at %i",
      (size) => {
        const metrics = getLogListMetrics(size);
        const small = `${Math.max(10, metrics.fontSize - 2)}px`;

        // Not compared, and the prior period cannot be defined: the reason sits beside Compare.
        const off = view(
          comparisonProps({ availability: { available: false, detail: "All time has no previous period." } }),
          { metrics },
        );
        const reason = measure("comparison-disabled-reason", screen.getByTestId("comparison-disabled-reason"));
        off.unmount();

        // Complete, with a tail event left out: the notes list the count.
        const complete = view(
          comparisonProps({
            state: settled(filesOutcome()),
            countCurrent: () => ({ ...TALLY, tailExcluded: 2 }),
          }),
          { metrics },
        );
        const notes = measure("comparison-notes", screen.getByTestId("comparison-notes"));
        complete.unmount();

        for (const node of [reason, notes]) {
          expect(node.color, `${node.testId} colour at ${size}`).toBe(css(tokens.colorNeutralForeground2));
          expect(node.fontSize, `${node.testId} size at ${size}`).toBe(small);
        }
      },
    );

    it("measure up at 4.5:1 on the surface in all seven themes, as the second foreground does", () => {
      for (const theme of themes) {
        const surface = resolveToken(tokens.colorNeutralBackground1, theme);
        expect(
          contrastRatio(resolveToken(tokens.colorNeutralForeground2, theme), surface),
          theme.id,
        ).toBeGreaterThanOrEqual(4.5);
      }
    });
  });

  describe("the update throttle", () => {
    it("moves the tiles, the delta and the status together, from one snapshot", () => {
      vi.useFakeTimers();
      try {
        const complete = comparisonProps({ state: settled(filesOutcome()) });
        const { rerender } = render(<EvtxChartsView {...props({ comparison: complete })} />);
        expect(errorsText()).not.toBeNull();
        // The operator clears it and the grid changes in the same render.
        const cleared = comparisonProps();
        rerender(<EvtxChartsView {...props({ comparison: cleared, records: records.slice(0, 3) })} />);
        // Nothing has moved yet, so the old delta is still beside the old tile.
        expect(errorsText()).not.toBeNull();
        expect(screen.getByTestId("kpi-value-events").textContent).toBe("7");
        act(() => {
          vi.advanceTimersByTime(CHART_DATA_THROTTLE_MS);
        });
        expect(errorsText()).toBeNull();
        expect(screen.getByTestId("kpi-value-events").textContent).toBe("3");
        expect(compareButton()).not.toBeNull();
      } finally {
        vi.useRealTimers();
      }
    });
  });

  it("offers no control when the grid is empty (the empty state replaces the whole view)", () => {
    view(comparisonProps(), { records: [] });
    expect(compareButton()).toBeNull();
    expect(screen.queryByTestId("comparison-bar")).toBeNull();
  });

  it("offers no comparison when none is supplied", () => {
    render(<EvtxChartsView {...props()} />);
    expect(compareButton()).toBeNull();
    expect(screen.queryByTestId("comparison-bar")).toBeNull();
  });
});
