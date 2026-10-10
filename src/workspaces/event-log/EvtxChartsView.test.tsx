import { render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio, parseHex } from "../../lib/color-contrast";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import type { EvtxChartRecord } from "./evtx-chart-data";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import EvtxChartsViewDefault, {
  EvtxChartsView,
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
    rerender(<EvtxChartsView {...props({ hideRules: [] })} />);
    expect(screen.queryByText(/excluding/)).toBeNull();
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
    expect(
      screen.getAllByText(/1 event has no timestamp and is not placed/),
    ).toHaveLength(2);
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
      expect(filled.style.background).toBe(css(visual.heatSteps[step]));
      expect(visual.heatSteps).toHaveLength(6);
    },
  );
});
