import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The store subscribes to backend events at module scope. Capturing the handlers lets a test
// deliver a channel's batch and its terminal marker exactly as the backend would.
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => undefined);
  }),
}));

import { invoke } from "@tauri-apps/api/core";

import { contrastRatio, parseHex } from "../../lib/color-contrast";
import { getLogListMetrics, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import {
  EvtxGroupedTable,
  EvtxGroupedView,
  GROUPED_DEBOUNCE_MS,
  GROUPED_OVERSCAN,
  groupedRowHeights,
} from "./EvtxGroupedView";
import {
  buildGroupSummaries,
  GROUP_TREND_BINS,
  type GroupSummariesInput,
  type GroupSummariesResult,
} from "./evtx-group-summaries";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

const HOUR = 60 * 60 * 1000;
const DAY_START = Date.UTC(2026, 9, 6);
const NOW = DAY_START + 24 * HOUR;
const THEMES = getAllThemes().map((theme) => [theme.id, theme] as const);
const LEVELS: readonly EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

let nextId = 1;
function rec(partial: Partial<EvtxRecord> & { at?: number } = {}): EvtxRecord {
  const { at, ...rest } = partial;
  const id = nextId++;
  return {
    id,
    eventRecordId: id,
    timestamp: "",
    timestampEpoch: at ?? DAY_START + HOUR,
    provider: "Service Control Manager",
    channel: "System",
    eventId: 7036,
    level: "Information",
    computer: "PC01",
    message: "The service entered the running state.",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "System.evtx",
    ...rest,
  };
}

function summaries(records: EvtxRecord[], overrides: Partial<GroupSummariesInput> = {}) {
  return buildGroupSummaries({
    records,
    loadedRecords: records,
    field: "eventId",
    timeZoneMode: "utc",
    timeWindow: "24h",
    nowMs: NOW,
    sourceMode: "live",
    channelRead: () => "complete",
    ...overrides,
  });
}

/** Twelve 7036 events (Information), two 1000 events (Error), one 4625 (Warning). */
function sampleRecords(): EvtxRecord[] {
  return [
    ...Array.from({ length: 12 }, (_, i) =>
      rec({ eventId: 7036, at: DAY_START + i * HOUR, message: `service message ${i}` }),
    ),
    rec({ eventId: 1000, level: "Error", provider: "Application Error", channel: "Application", message: "Faulting application", at: DAY_START + 3 * HOUR }),
    rec({ eventId: 1000, level: "Error", provider: "Application Error", channel: "Application", message: "Faulting application", at: DAY_START + 9 * HOUR }),
    rec({ eventId: 4625, level: "Warning", provider: "Security-Auditing", message: "Logon failure", at: DAY_START + 2 * HOUR }),
  ];
}

const metrics13 = getLogListMetrics(13);

interface TableProps {
  result?: GroupSummariesResult;
  fontSize?: number;
  theme?: CMTraceTheme;
  onShowAll?: (eventId: number) => void;
  linkedRecordIds?: ReadonlySet<number>;
}

function renderTable({
  result = summaries(sampleRecords()),
  fontSize = 13,
  theme = getAllThemes()[0],
  onShowAll,
  linkedRecordIds,
}: TableProps = {}) {
  return render(
    <div style={{ height: "600px", display: "flex", flexDirection: "column" }}>
      <EvtxGroupedTable
        result={result}
        windowLabel="24 h"
        timeZoneMode="utc"
        metrics={getLogListMetrics(fontSize)}
        theme={theme}
        onShowAll={onShowAll}
        linkedRecordIds={linkedRecordIds}
      />
    </div>,
  );
}

/** jsdom does no layout: give the scroller a viewport so the real virtualizer can size it. */
let restoreLayout: (() => void) | null = null;
function stubScrollerHeight(height: number) {
  const proto = HTMLElement.prototype;
  const originalHeight = Object.getOwnPropertyDescriptor(proto, "offsetHeight");
  const originalWidth = Object.getOwnPropertyDescriptor(proto, "offsetWidth");
  Object.defineProperty(proto, "offsetHeight", {
    configurable: true,
    get(this: HTMLElement) {
      return this.dataset.evtxGroupedScroller !== undefined ? height : 0;
    },
  });
  Object.defineProperty(proto, "offsetWidth", {
    configurable: true,
    get(this: HTMLElement) {
      return this.dataset.evtxGroupedScroller !== undefined ? 1200 : 0;
    },
  });
  restoreLayout = () => {
    if (originalHeight) Object.defineProperty(proto, "offsetHeight", originalHeight);
    if (originalWidth) Object.defineProperty(proto, "offsetWidth", originalWidth);
  };
}

beforeEach(() => stubScrollerHeight(600));

afterEach(() => {
  cleanup();
  restoreLayout?.();
  restoreLayout = null;
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

const groupRows = () => document.querySelectorAll<HTMLElement>('[data-evtx-grouped-row="group"]');
const itemRows = () => document.querySelectorAll<HTMLElement>('[data-evtx-grouped-row="item"]');
const disclosure = (name: RegExp) => screen.getByRole("button", { name });
const styleOf = (element: Element) => (element as HTMLElement).style;

describe("EvtxGroupedTable: summary table (spec 8.8)", () => {
  it("labels the columns in the spec's order, the trend after the window", () => {
    renderTable();
    const table = screen.getByRole("table", { name: /Grouped events/ });
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((header) => header.textContent);
    expect(headers).toEqual([
      "Expand",
      "Level",
      "ID",
      "Provider",
      "Typical message",
      "Count",
      "24 h trend",
      "Last seen",
    ]);
  });

  it("puts the most severe groups first and shows each group's summary cells", () => {
    renderTable();
    const rows = [...groupRows()];
    expect(rows.map((row) => row.dataset.groupValue)).toEqual(["1000", "4625", "7036"]);
    const first = rows[0];
    expect(within(first).getByRole("img", { name: "Error" })).toBeInTheDocument();
    expect(within(first).getByText("1000")).toBeInTheDocument();
    expect(within(first).getByText("Application Error")).toBeInTheDocument();
    expect(within(first).getByText("Faulting application")).toBeInTheDocument();
    expect(within(first).getByText("2")).toBeInTheDocument();
    expect(within(first).getByText("2026-10-06 09:00:00")).toBeInTheDocument();
  });

  it("names the key column after the Group by field when it is neither Event ID nor Provider", () => {
    renderTable({ result: summaries(sampleRecords(), { field: "channel" }) });
    const headers = screen.getAllByRole("columnheader").map((header) => header.textContent);
    expect(headers[3]).toBe("Channel");
    expect(within(groupRows()[0]).getByText("Application")).toBeInTheDocument();
    // Several IDs in one group are counted rather than one of them shown.
    const system = [...groupRows()].find((row) => row.dataset.groupValue === "System");
    expect(system && within(system).getByText("2 IDs")).toBeInTheDocument();
  });

  it("expands a group through a real button with aria-expanded, listing its 8 newest events", () => {
    renderTable({ onShowAll: () => undefined });
    const button = disclosure(/^Event ID 7036/);
    expect(button.tagName).toBe("BUTTON");
    expect(button).toHaveAttribute("type", "button");
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(itemRows()).toHaveLength(0);

    fireEvent.click(button);
    expect(disclosure(/^Event ID 7036/)).toHaveAttribute("aria-expanded", "true");
    const items = [...itemRows()];
    expect(items).toHaveLength(8);
    expect(items.map((row) => within(row).getByTestId("evtx-grouped-item-message").textContent)).toEqual(
      [11, 10, 9, 8, 7, 6, 5, 4].map((i) => `service message ${i}`),
    );
    expect(screen.getByRole("button", { name: "Show all 12 in table" })).toBeInTheDocument();

    fireEvent.click(disclosure(/^Event ID 7036/));
    expect(itemRows()).toHaveLength(0);
  });

  it("styles an expanded group row with Background3 and 600 weight", () => {
    renderTable();
    const row = () => [...groupRows()].find((r) => r.dataset.groupValue === "7036")!;
    expect(styleOf(row()).fontWeight).toBe("400");
    fireEvent.click(disclosure(/^Event ID 7036/));
    expect(styleOf(row()).backgroundColor).toBe(tokens.colorNeutralBackground3);
    expect(styleOf(row()).fontWeight).toBe("600");
  });

  it("does not render another group's items when one group is expanded", () => {
    renderTable({ onShowAll: () => undefined });
    fireEvent.click(disclosure(/^Event ID 1000/));
    const items = [...itemRows()];
    expect(items).toHaveLength(2);
    expect(items.every((row) => row.dataset.groupValue === "1000")).toBe(true);
    for (const row of items) {
      expect(row.textContent).not.toMatch(/service message|Logon failure/);
    }
  });

  it("offers Show all for an Event ID group and hands it the group's ID", () => {
    const onShowAll = vi.fn();
    renderTable({ onShowAll });
    fireEvent.click(disclosure(/^Event ID 1000/));
    fireEvent.click(screen.getByRole("button", { name: "Show all 2 in table" }));
    expect(onShowAll).toHaveBeenCalledWith(1000);
  });

  it("offers no Show all where no existing filter selects exactly the group", () => {
    renderTable({ result: summaries(sampleRecords(), { field: "provider" }), onShowAll: () => undefined });
    fireEvent.click(disclosure(/^Provider Service Control Manager/));
    expect(itemRows()).toHaveLength(8);
    expect(screen.queryByRole("button", { name: /^Show all/ })).toBeNull();
  });

  it("badges an item Linked only when a complete edge index names it", () => {
    const records = sampleRecords();
    const linked = records.find((record) => record.eventId === 1000)!;
    renderTable({ result: summaries(records), linkedRecordIds: new Set([linked.id]) });
    fireEvent.click(disclosure(/^Event ID 1000/));
    expect(screen.getAllByText("Linked")).toHaveLength(1);
    cleanup();
    renderTable({ result: summaries(records) });
    fireEvent.click(disclosure(/^Event ID 1000/));
    expect(screen.queryByText("Linked")).toBeNull();
  });
});

describe("EvtxGroupedTable: keyboard", () => {
  it("moves between groups with the arrow keys and expands and collapses with Right and Left", () => {
    renderTable({ onShowAll: () => undefined });
    const first = disclosure(/^Event ID 1000/);
    expect(first).toHaveAttribute("tabindex", "0");
    expect(disclosure(/^Event ID 4625/)).toHaveAttribute("tabindex", "-1");
    first.focus();

    fireEvent.keyDown(first, { key: "ArrowRight" });
    expect(disclosure(/^Event ID 1000/)).toHaveAttribute("aria-expanded", "true");
    // Down from an expanded group reaches its Show all button, then the next group.
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Show all 2 in table" }));
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 4625/));
    expect(disclosure(/^Event ID 4625/)).toHaveAttribute("tabindex", "0");

    fireEvent.keyDown(document.activeElement!, { key: "ArrowUp" });
    fireEvent.keyDown(document.activeElement!, { key: "ArrowLeft" });
    // Left from Show all returns to its group, and Left again collapses it.
    expect(document.activeElement).toBe(disclosure(/^Event ID 1000/));
    fireEvent.keyDown(document.activeElement!, { key: "ArrowLeft" });
    expect(disclosure(/^Event ID 1000/)).toHaveAttribute("aria-expanded", "false");

    fireEvent.keyDown(document.activeElement!, { key: "End" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 7036/));
    fireEvent.keyDown(document.activeElement!, { key: "Home" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 1000/));
  });
});

describe("EvtxGroupedTable: the trend sparkline", () => {
  it("draws a bar per counted bin, a baseline per read empty bin, and nothing for an unread bin", () => {
    // The cap kept System from 12:00 on: 13 earlier bins were not read.
    const records = [rec({ at: DAY_START + 12 * HOUR + 1 }), rec({ at: DAY_START + 20 * HOUR })];
    const result = summaries(records, { channelRead: () => "newestOnly" });
    renderTable({ result });
    const trend = result.summaries[0].trend;
    const bars = document.querySelectorAll("[data-trend-bar]");
    const zeros = document.querySelectorAll("[data-trend-zero]");
    expect(bars).toHaveLength(trend.filter((bin) => (bin ?? 0) > 0).length);
    expect(zeros).toHaveLength(trend.filter((bin) => bin === 0).length);
    expect(bars.length + zeros.length).toBeLessThan(GROUP_TREND_BINS);
    const drawnBins = new Set(
      [...bars, ...zeros].map((mark) => Number(mark.getAttribute("data-bin"))),
    );
    for (let bin = 0; bin < 12; bin += 1) expect(drawnBins.has(bin), `bin ${bin}`).toBe(false);
    // Unread: the 12 bins before the oldest kept event and the 3 after System's newest event.
    expect(screen.getByText(/24 h trend: 2 of 24 intervals had events, busiest 1; 15 intervals not read/)).toBeInTheDocument();
  });

  it("fills the bars with the group's level bar color", () => {
    const theme = getAllThemes()[0];
    const visual = buildEvtxVisualTokens(theme);
    renderTable({ theme });
    for (const row of groupRows()) {
      const level = within(row).getByRole("img").getAttribute("aria-label") as EvtxLevel;
      for (const bar of row.querySelectorAll<SVGElement>("[data-trend-bar]")) {
        expect(bar.style.fill).toBe(asStyle(visual.levels[level].barColor));
      }
    }
  });
});

describe("EvtxGroupedTable: virtualization", () => {
  function manyGroups(count: number): GroupSummariesResult {
    return summaries(
      Array.from({ length: count }, (_, i) => rec({ eventId: i + 1, at: DAY_START + (i % 24) * HOUR })),
    );
  }

  it("renders a bounded window of 5,000 groups and reaches the last one by scrolling", () => {
    const result = manyGroups(5000);
    renderTable({ result });
    const heights = groupedRowHeights(metrics13);
    const visible = Math.ceil(600 / heights.group);
    const rendered = groupRows().length;
    expect(rendered).toBeGreaterThan(0);
    expect(rendered).toBeLessThanOrEqual(visible + 2 * GROUPED_OVERSCAN + 1);

    const scroller = document.querySelector<HTMLElement>("[data-evtx-grouped-scroller]")!;
    const sizer = scroller.firstElementChild as HTMLElement;
    expect(sizer.style.height).toBe(`${5000 * heights.group}px`);

    act(() => {
      scroller.scrollTop = 5000 * heights.group - 600;
      fireEvent.scroll(scroller);
    });
    const values = [...groupRows()].map((row) => row.dataset.groupValue);
    expect(values).toContain(result.summaries[4999].value);
    expect(values).not.toContain(result.summaries[0].value);
    expect(groupRows().length).toBeLessThanOrEqual(visible + 2 * GROUPED_OVERSCAN + 1);
  });

  it("keeps one tab stop in the DOM after the active control scrolls out of the rendered window", () => {
    const result = manyGroups(5000);
    renderTable({ result });
    const scroller = document.querySelector<HTMLElement>("[data-evtx-grouped-scroller]")!;
    act(() => {
      scroller.scrollTop = 5000 * groupedRowHeights(metrics13).group - 600;
      fireEvent.scroll(scroller);
    });
    const stops = document.querySelectorAll('button[tabindex="0"]');
    expect(stops).toHaveLength(1);
    expect(scroller.contains(stops[0])).toBe(true);
  });

  it("keeps the bound with a group expanded, and renders no other group's items", () => {
    const result = manyGroups(5000);
    renderTable({ result, onShowAll: () => undefined });
    const first = result.summaries[0].value;
    fireEvent.click(disclosure(new RegExp(`^Event ID ${first},`)));
    const items = [...itemRows()];
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((row) => row.dataset.groupValue === first)).toBe(true);
    const rows = document.querySelectorAll('[data-evtx-grouped-row]');
    expect(rows.length).toBeLessThanOrEqual(Math.ceil(600 / groupedRowHeights(metrics13).item) + 2 * GROUPED_OVERSCAN + 1);
  });
});

describe("EvtxGroupedTable: text sizes follow logListFontSize", () => {
  it.each([13, 20])("sizes header, row and last-seen text from a %i px list font", (size) => {
    const f = getLogListMetrics(size).fontSize;
    renderTable({ fontSize: size });
    const header = document.querySelector<HTMLElement>("[data-evtx-grouped-header]")!;
    expect(header.style.fontSize).toBe(`${Math.max(10, f - 2)}px`);
    expect(header.style.fontWeight).toBe("600");
    const row = groupRows()[0];
    expect(row.style.fontSize).toBe(`${Math.max(10, f - 1)}px`);
    expect(row.style.height).toBe(`${groupedRowHeights(getLogListMetrics(size)).group}px`);
    const lastSeen = row.querySelector<HTMLElement>("[data-evtx-grouped-last-seen]")!;
    expect(lastSeen.style.fontSize).toBe(`${Math.max(9, f - 3)}px`);
    const message = row.querySelector<HTMLElement>("[data-evtx-grouped-message]")!;
    expect(message.style.fontFamily).toBe(LOG_MONOSPACE_FONT_FAMILY);
  });
});

// ---------------------------------------------------------------------------------------------
// Contrast, measured from the rendered DOM in all seven themes (Adam's criterion).
// ---------------------------------------------------------------------------------------------

function rgb(hex: string): string {
  const [r, g, b] = parseHex(hex);
  return `rgb(${r}, ${g}, ${b})`;
}

/** The inline-style form of a CSS color string from the token module: `var(...)` or hex. */
function asStyle(css: string): string {
  return css.startsWith("#") ? rgb(css) : css;
}

/** Resolves an inline style color (`rgb(...)` from jsdom, or `var(--token)`) to hex in `theme`. */
function toHex(css: string, theme: CMTraceTheme): string {
  const match = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(css);
  if (match) {
    return `#${[match[1], match[2], match[3]]
      .map((channel) => Number(channel).toString(16).padStart(2, "0"))
      .join("")}`;
  }
  return resolveToken(css, theme);
}

/** The nearest ancestor-or-self background color an element is drawn on. */
function backgroundOf(element: Element, theme: CMTraceTheme): string {
  let node: Element | null = element;
  while (node) {
    const background = (node as HTMLElement).style?.backgroundColor;
    if (background) return toHex(background, theme);
    node = node.parentElement;
  }
  throw new Error("no background found");
}

/** The nearest ancestor-or-self text color. */
function colorOf(element: Element, theme: CMTraceTheme): string {
  let node: Element | null = element;
  while (node) {
    const color = (node as HTMLElement).style?.color;
    if (color) return toHex(color, theme);
    node = node.parentElement;
  }
  throw new Error("no color found");
}

describe.each(THEMES)("contrast in the %s theme", (_id, theme) => {
  /**
   * One group per level, so every level's icon and bars are measured. The Verbose group has no
   * message at all, so the placeholder for a missing typical message is measured too.
   */
  function everyLevel(): GroupSummariesResult {
    return summaries(
      LEVELS.flatMap((level, i) => [
        rec({ eventId: 100 + i, level, at: DAY_START + 2 * HOUR, ...(level === "Verbose" ? { message: "" } : {}) }),
        rec({ eventId: 100 + i, level, at: DAY_START + 5 * HOUR, message: "" }),
      ]),
    );
  }

  function measure(expanded: boolean) {
    const result = everyLevel();
    const linked = new Set(result.summaries.flatMap((summary) => summary.recent.map((r) => r.id)));
    renderTable({ result, theme, onShowAll: () => undefined, linkedRecordIds: linked });
    if (expanded) {
      for (const summary of result.summaries) {
        fireEvent.click(disclosure(new RegExp(`^Event ID ${summary.value}`)));
      }
    }
    const failures: string[] = [];
    const check = (what: string, element: Element, color: string, floor: number) => {
      const background = backgroundOf(element, theme);
      const ratio = contrastRatio(color, background);
      if (ratio < floor) {
        failures.push(`${theme.id} ${what} ${color} on ${background} = ${ratio.toFixed(2)} (< ${floor})`);
      }
    };
    return { failures, check };
  }

  it.each([false, true])("keeps group-row text at 4.5:1 and marks at 3:1 (expanded: %s)", (expanded) => {
    const { failures, check } = measure(expanded);
    for (const row of groupRows()) {
      for (const text of row.querySelectorAll<HTMLElement>("[data-evtx-grouped-text]")) {
        check(`group ${text.dataset.evtxGroupedText}`, text, colorOf(text, theme), 4.5);
      }
      const icon = within(row).getByRole("img");
      check(`level icon ${icon.getAttribute("aria-label")}`, row, colorOf(icon, theme), 3);
      for (const bar of row.querySelectorAll<SVGElement>("[data-trend-bar]")) {
        check("trend bar", row, toHex(bar.style.fill, theme), 3);
      }
      for (const zero of row.querySelectorAll<SVGElement>("[data-trend-zero]")) {
        check("trend zero baseline", row, toHex(zero.style.fill, theme), 3);
      }
    }
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it("keeps the header, item text, the Linked badge and Show all at 4.5:1", () => {
    const { failures, check } = measure(true);
    for (const text of document.querySelectorAll<HTMLElement>('[role="columnheader"]')) {
      check(`header ${text.textContent}`, text, colorOf(text, theme), 4.5);
    }
    expect(itemRows().length).toBeGreaterThan(0);
    for (const row of itemRows()) {
      for (const text of row.querySelectorAll<HTMLElement>("[data-evtx-grouped-text]")) {
        check(`item ${text.dataset.evtxGroupedText}`, text, colorOf(text, theme), 4.5);
      }
    }
    const badges = screen.getAllByText("Linked");
    expect(badges.length).toBeGreaterThan(0);
    for (const badge of badges) check("Linked badge", badge, colorOf(badge, theme), 4.5);
    const showAll = screen.getAllByRole("button", { name: /^Show all/ });
    expect(showAll.length).toBe(LEVELS.length);
    for (const button of showAll) check("Show all", button, colorOf(button, theme), 4.5);
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it("keeps the view's own status text at 4.5:1 on the main surface", () => {
    useEvtxStore.getState().reset();
    useEvtxStore.setState({ isLoading: true });
    useUiStore.setState({ themeId: theme.id });
    render(
      <div style={{ backgroundColor: tokens.colorNeutralBackground1 }}>
        <EvtxGroupedView records={[]} nowEpoch={NOW} />
      </div>,
    );
    const status = screen.getByRole("status");
    const color = colorOf(status, theme);
    const ratio = contrastRatio(color, backgroundOf(status, theme));
    expect(ratio, `${theme.id} status ${color} = ${ratio.toFixed(2)}`).toBeGreaterThanOrEqual(4.5);
  });
});

// ---------------------------------------------------------------------------------------------
// The connected view: store inputs, loading, and Show all through the existing filter state.
// ---------------------------------------------------------------------------------------------

describe("EvtxGroupedView", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    useEvtxLayoutStore.setState({ activeView: "grouped" });
  });

  it("says it is loading rather than showing no groups while records load", () => {
    useEvtxStore.setState({ isLoading: true, records: [] });
    render(<EvtxGroupedView records={[]} nowEpoch={NOW} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading events...");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("says when the filters leave nothing to group", () => {
    useEvtxStore.setState({ records: sampleRecords(), sourceMode: "files", timeWindow: "all" });
    render(<EvtxGroupedView records={[]} nowEpoch={NOW} />);
    expect(screen.getByRole("status")).toHaveTextContent("No records match the current filters.");
  });

  it("groups by the first Group by field and Show all applies an Event ID filter and switches to Table", () => {
    const records = sampleRecords();
    useEvtxStore.setState({
      records,
      sourceMode: "files",
      timeWindow: "all",
      groupBy: [],
      filterEventIds: "1000,7036",
    });
    render(<EvtxGroupedView records={records} nowEpoch={NOW} />);
    expect(screen.getByRole("columnheader", { name: "All loaded trend" })).toBeInTheDocument();
    fireEvent.click(disclosure(/^Event ID 7036/));
    fireEvent.click(screen.getByRole("button", { name: "Show all 12 in table" }));
    expect(useEvtxStore.getState().filterEventIds).toBe("7036");
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
  });

  it("follows the first Group by field", () => {
    const records = sampleRecords();
    useEvtxStore.setState({ records, sourceMode: "files", timeWindow: "all", groupBy: ["level", "provider"] });
    render(<EvtxGroupedView records={records} nowEpoch={NOW} />);
    expect(screen.getAllByRole("columnheader")[3]).toHaveTextContent("Level");
    expect([...groupRows()].map((row) => row.dataset.groupValue)).toEqual([
      "Error",
      "Warning",
      "Information",
    ]);
  });

  it(`applies a stream of changes every ${GROUPED_DEBOUNCE_MS} ms, never waiting for it to go quiet`, () => {
    vi.useFakeTimers();
    try {
      const all = sampleRecords();
      const only = (...ids: number[]) => all.filter((record) => ids.includes(record.eventId));
      useEvtxStore.setState({ records: all, sourceMode: "files", timeWindow: "all" });
      const view = (records: EvtxRecord[]) => (
        <EvtxGroupedView records={records} nowEpoch={NOW} />
      );
      const { rerender } = render(view(only(7036)));
      expect(groupRows()).toHaveLength(1);

      // A change every 50 ms, each inside the previous one's wait.
      rerender(view(only(7036, 1000)));
      act(() => vi.advanceTimersByTime(50));
      rerender(view(only(7036, 1000, 4625)));
      act(() => vi.advanceTimersByTime(30));
      // 80 ms after the first change: the newest value has applied, although the stream went on.
      expect(groupRows()).toHaveLength(3);
      expect(screen.getByRole("table")).toHaveAccessibleName(/^Grouped events, 3 groups/);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------------------------
// The store's own bound note reaches the trend: driven through the real load and reconcile path.
// ---------------------------------------------------------------------------------------------

describe("a channel the store loaded only up to its bound", () => {
  /** The automatic load's per-channel bound (`AUTO_LOAD_MAX_EVENTS` in evtx-store.ts). */
  const BOUND = 2_000;

  /**
   * Security events in hourly bins 17 to 19 and 21 to 23 of the 24 h window ending NOW, none in
   * bin 20. Bin 20 is what tells a read from its oldest kept event (0 there) from a read with a
   * loss at no known time (unknown there).
   */
  function securityEvents(count: number): EvtxRecord[] {
    const windowStart = NOW - 24 * HOUR;
    const half = Math.ceil(count / 2);
    return Array.from({ length: count }, (_, i) => {
      const [from, to, index, size] =
        i < half ? [17.5, 19.9, i, half] : [21.1, 23.9, i - half, count - half];
      return rec({
        eventId: 4624,
        channel: "Security",
        provider: "Microsoft-Windows-Security-Auditing",
        at: windowStart + Math.round((from + ((to - from) * index) / size) * HOUR),
      });
    });
  }

  /** Refreshes the loaded Security channel, the backend replying with `rows` as one batch. */
  async function loadSecurity(rows: EvtxRecord[]): Promise<void> {
    vi.mocked(invoke).mockImplementation(async (_command: string, args?: unknown) => {
      const { channels, requestId } = (args ?? {}) as { channels?: string[]; requestId?: string };
      const channel = channels?.[0] ?? "";
      listeners.get("evtx-record-batch")?.({
        payload: { requestId, channel, sequence: 0, records: rows },
      });
      listeners.get("evtx-record-stream-complete")?.({
        payload: { requestId, channel, sequenceCount: 1, totalRecords: rows.length },
      });
      return {
        records: [],
        channels: [{ name: channel, eventCount: rows.length, sourceType: "live" }],
        totalRecords: rows.length,
        parseErrors: 0,
        errorMessages: [],
      };
    });
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Security", eventCount: 0, sourceType: "live" }],
      loadedChannels: new Set(["Security"]),
      selectedChannels: new Set(["Security"]),
      timeWindow: "24h",
    });
    await useEvtxStore.getState().refreshLoadedChannels();
  }

  beforeEach(() => {
    useEvtxStore.getState().reset();
    vi.mocked(invoke).mockReset();
  });

  afterEach(() => {
    vi.mocked(invoke).mockReset();
    useEvtxStore.getState().reset();
  });

  it("treats a channel that came back at the bound as read from its oldest kept event only", async () => {
    await loadSecurity(securityEvents(BOUND));
    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(BOUND);
    expect(state.coverageGaps.some((gap) => gap.startsWith("Security: "))).toBe(true);

    render(<EvtxGroupedView records={state.records} nowEpoch={NOW} />);
    // The oldest kept event is in bin 17: bins 0 to 16 were not read, and bin 20, after it, was
    // read and is empty.
    expect(
      screen.getByText(/^24 h trend: 6 of 24 intervals had events, busiest \d+; 17 intervals not read$/),
    ).toBeInTheDocument();
    expect(document.querySelector('[data-trend-zero][data-bin="20"]')).not.toBeNull();
  });

  it("treats a channel that came back under the bound as read across the whole window", async () => {
    await loadSecurity(securityEvents(BOUND - 1));
    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(BOUND - 1);
    expect(state.coverageGaps).toEqual([]);

    render(<EvtxGroupedView records={state.records} nowEpoch={NOW} />);
    expect(
      screen.getByText(/^24 h trend: 6 of 24 intervals had events, busiest \d+$/),
    ).toBeInTheDocument();
    expect(document.querySelector('[data-trend-zero][data-bin="0"]')).not.toBeNull();
  });
});
