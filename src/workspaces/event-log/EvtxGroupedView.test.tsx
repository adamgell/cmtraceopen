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
import {
  isNewestOnlyGapReason,
  newestOnlyGapReason,
  useEvtxStore,
  type ChannelReadRecord,
} from "./evtx-store";
import { selectVisibleRecords } from "./evtx-filter";
import { EvtxTimeline } from "./EvtxTimeline";
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

/** The record a time-only load leaves for `channel` when it returned these records. */
function loadReadOf(
  channel: string,
  returned: readonly EvtxRecord[],
  readThrough = NOW,
  serverFiltered = false,
): ChannelReadRecord {
  const placed = returned
    .filter((record) => record.channel === channel)
    .map((record) => record.timestampEpoch)
    .filter((at) => at > 0);
  return {
    readThrough,
    oldestPlacedMs: placed.length > 0 ? Math.min(...placed) : null,
    returnedCount: returned.filter((record) => record.channel === channel).length,
    serverFiltered,
  };
}

/** Live, 24 h to NOW; every channel of `records` in scope, loaded by a time-only read at NOW. */
function summaries(records: EvtxRecord[], overrides: Partial<GroupSummariesInput> = {}) {
  const channels = [...new Set(records.map((record) => record.channel))];
  return buildGroupSummaries({
    records,
    loadedRecords: records,
    field: "eventId",
    timeZoneMode: "utc",
    timeWindow: "24h",
    nowMs: NOW,
    sourceMode: "live",
    channelReads: { kind: () => "complete", unattributedLoss: false },
    scopeChannels: channels,
    loadReads: new Map(channels.map((channel) => [channel, loadReadOf(channel, records)] as const)),
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
  selectedRecordId?: number | null;
  onSelectRecord?: (id: number) => void;
}

function renderTable({
  result = summaries(sampleRecords()),
  fontSize = 13,
  theme = getAllThemes()[0],
  onShowAll,
  linkedRecordIds,
  selectedRecordId,
  onSelectRecord,
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
        selectedRecordId={selectedRecordId}
        onSelectRecord={onSelectRecord}
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
    const table = screen.getByRole("grid", { name: /Grouped events/ });
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
  it("moves through groups, events and Show all with the arrow keys, Right and Left expand and collapse", () => {
    renderTable({ onShowAll: () => undefined });
    const first = disclosure(/^Event ID 1000/);
    expect(first).toHaveAttribute("tabindex", "0");
    expect(disclosure(/^Event ID 4625/)).toHaveAttribute("tabindex", "-1");
    first.focus();

    fireEvent.keyDown(first, { key: "ArrowRight" });
    expect(disclosure(/^Event ID 1000/)).toHaveAttribute("aria-expanded", "true");
    // Down from an expanded group reaches its events, then its Show all button, then the next group.
    const [newest, older] = [...itemRows()];
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(newest);
    expect(newest).toHaveAttribute("tabindex", "0");
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(older);
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Show all 2 in table" }));
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 4625/));
    expect(disclosure(/^Event ID 4625/)).toHaveAttribute("tabindex", "0");

    // Left from an event or from Show all returns to its group, and Left again collapses it.
    fireEvent.keyDown(document.activeElement!, { key: "ArrowUp" });
    fireEvent.keyDown(document.activeElement!, { key: "ArrowUp" });
    expect(document.activeElement).toBe(older);
    fireEvent.keyDown(document.activeElement!, { key: "ArrowLeft" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 1000/));
    fireEvent.keyDown(document.activeElement!, { key: "ArrowLeft" });
    expect(disclosure(/^Event ID 1000/)).toHaveAttribute("aria-expanded", "false");

    fireEvent.keyDown(document.activeElement!, { key: "End" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 7036/));
    fireEvent.keyDown(document.activeElement!, { key: "Home" });
    expect(document.activeElement).toBe(disclosure(/^Event ID 1000/));
  });
});

describe("EvtxGroupedTable: selecting an expanded event (spec 9)", () => {
  function expandedErrors(onSelectRecord = vi.fn(), selectedRecordId: number | null = null) {
    const records = sampleRecords();
    const errors = records
      .filter((record) => record.eventId === 1000)
      .sort((a, b) => b.timestampEpoch - a.timestampEpoch);
    const view = renderTable({ result: summaries(records), onSelectRecord, selectedRecordId });
    fireEvent.click(disclosure(/^Event ID 1000/));
    return { errors, onSelectRecord, view };
  }

  it("selects an event when its row is clicked", () => {
    const { errors, onSelectRecord } = expandedErrors();
    fireEvent.click(itemRows()[1]);
    expect(onSelectRecord).toHaveBeenCalledWith(errors[1].id);
    expect(itemRows()[1]).toHaveAttribute("tabindex", "0");
  });

  it("selects the focused event with Enter or Space, and leaves the buttons' own keys alone", () => {
    const { errors, onSelectRecord } = expandedErrors();
    disclosure(/^Event ID 1000/).focus();
    fireEvent.keyDown(document.activeElement!, { key: "Enter" });
    // Enter on the disclosure button is the button's own: no record is selected.
    expect(onSelectRecord).not.toHaveBeenCalled();
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    fireEvent.keyDown(document.activeElement!, { key: "Enter" });
    expect(onSelectRecord).toHaveBeenLastCalledWith(errors[0].id);
    fireEvent.keyDown(document.activeElement!, { key: "ArrowDown" });
    fireEvent.keyDown(document.activeElement!, { key: " " });
    expect(onSelectRecord).toHaveBeenLastCalledWith(errors[1].id);
    expect(onSelectRecord).toHaveBeenCalledTimes(2);
  });

  it("marks the selected event with the selection triplet and aria-selected", () => {
    const theme = getAllThemes()[0];
    const visual = buildEvtxVisualTokens(theme);
    const records = sampleRecords();
    const selected = records.find((record) => record.eventId === 1000)!;
    renderTable({ result: summaries(records), selectedRecordId: selected.id, theme });
    fireEvent.click(disclosure(/^Event ID 1000/));
    const rows = [...itemRows()];
    const row = rows.find((r) => r.getAttribute("aria-selected") === "true")!;
    expect(rows.filter((r) => r.getAttribute("aria-selected") === "true")).toHaveLength(1);
    expect(within(row).getByTestId("evtx-grouped-item-message")).toHaveTextContent(selected.message);
    expect(row.style.backgroundColor).toBe(visual.selection.background);
    expect(row.style.color).toBe(visual.selection.foreground);
    expect(row.style.boxShadow).toBe(`inset 3px 0 0 ${visual.selection.border}`);
    const other = rows.find((r) => r !== row)!;
    expect(other).toHaveAttribute("aria-selected", "false");
    expect(other.style.boxShadow).toBe("");
  });
});

describe("EvtxGroupedTable: the trend sparkline", () => {
  it("draws a bar per counted bin, a baseline per read empty bin, and nothing for an unread bin", () => {
    // System's oldest kept event is just after 12:00: the 12 earlier bins were not read.
    const records = [rec({ at: DAY_START + 12 * HOUR + 1 }), rec({ at: DAY_START + 20 * HOUR })];
    const result = summaries(records);
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
    expect(screen.getByText(/24 h trend: 2 of 24 intervals had events, busiest 1; 12 intervals not read/)).toBeInTheDocument();
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
    // One expanded event is selected, so its text is measured on the selection background too.
    const selected = result.summaries.find((summary) => summary.level === "Error")!.recent[0];
    renderTable({
      result,
      theme,
      onShowAll: () => undefined,
      linkedRecordIds: linked,
      selectedRecordId: selected.id,
    });
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
    expect([...itemRows()].filter((row) => row.getAttribute("aria-selected") === "true")).toHaveLength(1);
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
      expect(screen.getByRole("grid")).toHaveAccessibleName(/^Grouped events, 3 groups/);
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

  /**
   * The backend answers every channel query with `rows` as one batch, and lists Security. A query
   * takes `readTakesMs`: the clock moves on between the query being sent and its reply.
   */
  function replyWith(rows: EvtxRecord[], readTakesMs = 0): void {
    vi.mocked(invoke).mockImplementation(async (command: string, args?: unknown) => {
      if (command === "evtx_enumerate_channels") {
        return [{ name: "Security", eventCount: 0, sourceType: "live", enabledState: "enabled" }];
      }
      if (readTakesMs > 0) vi.setSystemTime(Date.now() + readTakesMs);
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
  }

  /** Live Security, selected; `loaded` says whether a load already holds it. */
  function liveSecurity(loaded: boolean): void {
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Security", eventCount: 0, sourceType: "live" }],
      loadedChannels: new Set(loaded ? ["Security"] : []),
      selectedChannels: new Set(["Security"]),
      timeWindow: "24h",
    });
  }

  /** Refreshes the loaded Security channel, the backend replying with `rows` as one batch. */
  async function loadSecurity(rows: EvtxRecord[]): Promise<void> {
    replyWith(rows);
    liveSecurity(true);
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

  it("reads a channel that came back under the bound from its oldest kept event too: its log may have wrapped", async () => {
    await loadSecurity(securityEvents(BOUND - 1));
    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(BOUND - 1);
    expect(state.coverageGaps).toEqual([]);

    render(<EvtxGroupedView records={state.records} nowEpoch={NOW} />);
    expect(
      screen.getByText(/^24 h trend: 6 of 24 intervals had events, busiest \d+; 17 intervals not read$/),
    ).toBeInTheDocument();
    expect(document.querySelector('[data-trend-zero][data-bin="0"]')).toBeNull();
    expect(document.querySelector('[data-trend-zero][data-bin="20"]')).not.toBeNull();
  });

  describe("the time each load read through", () => {
    afterEach(() => vi.useRealTimers());

    /** Security events in bins 15 and 20 of the window, none between, all before a load at 21:30. */
    const beforeLoad = () =>
      [15, 15.2, 15.4, 15.6, 15.8, 20, 20.1, 20.2, 20.3, 20.4].map((hour) =>
        rec({ eventId: 4624, channel: "Security", at: NOW - 24 * HOUR + Math.round(hour * HOUR) }),
      );
    const LOAD_AT = NOW - 2.5 * HOUR;
    /** How long each query takes between being sent and its reply. */
    const READ_TAKES = 10 * 60 * 1000;

    /**
     * The clock reads LOAD_AT when the load starts and runs on from there: the store's stream
     * settling waits on real elapsed time, so a frozen clock would never let the load land.
     */
    const clockAtLoad = () => {
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      vi.setSystemTime(LOAD_AT);
    };
    /**
     * The stamp is the time the query was sent, not the time its reply landed: every query here
     * takes READ_TAKES, so a stamp taken after the reply would be at least that late.
     */
    const expectStampedAtSend = () => {
      const stamp = useEvtxStore.getState().channelReadThrough.get("Security")?.readThrough;
      expect(Date.now()).toBeGreaterThanOrEqual(LOAD_AT + READ_TAKES);
      expect(stamp).toBeGreaterThanOrEqual(LOAD_AT);
      expect(stamp).toBeLessThan(LOAD_AT + 60_000);
    };

    it("a refresh stamps the channel with the time its query was sent, and the trend ends there", async () => {
      clockAtLoad();
      replyWith(beforeLoad(), READ_TAKES);
      liveSecurity(true);
      await useEvtxStore.getState().refreshLoadedChannels();
      expectStampedAtSend();

      const state = useEvtxStore.getState();
      render(<EvtxGroupedView records={state.records} nowEpoch={NOW} />);
      // Read from the oldest kept event (bin 15) to 21:30: bin 21 is read only to its middle, and
      // bins 22 and 23 not at all.
      expect(
        screen.getByText(/^24 h trend: 2 of 24 intervals had events, busiest 5; 18 intervals not read$/),
      ).toBeInTheDocument();
      expect(document.querySelector('[data-trend-zero][data-bin="17"]')).not.toBeNull();
      expect(document.querySelector('[data-trend-zero][data-bin="21"]')).toBeNull();
    });

    it("the automatic load stamps the channel with the time its query was sent", async () => {
      clockAtLoad();
      replyWith(beforeLoad(), READ_TAKES);
      await useEvtxStore.getState().enumerateChannels();
      expect(useEvtxStore.getState().loadedChannels.has("Security")).toBe(true);
      expectStampedAtSend();
    });

    it("an explicit Load stamps the channel with the time its query was sent", async () => {
      clockAtLoad();
      replyWith(beforeLoad(), READ_TAKES);
      liveSecurity(false);
      await useEvtxStore.getState().queryChannels(["Security"]);
      expect(useEvtxStore.getState().loadedChannels.has("Security")).toBe(true);
      expectStampedAtSend();
    });

    it("drops a channel's stamp when it is reloaded, until that load lands", async () => {
      await loadSecurity(beforeLoad());
      expect(useEvtxStore.getState().channelReadThrough.has("Security")).toBe(true);
      let answer: (() => void) | undefined;
      vi.mocked(invoke).mockImplementation(
        (_command: string, args?: unknown) =>
          new Promise((resolve) => {
            const { channels, requestId } = (args ?? {}) as { channels?: string[]; requestId?: string };
            answer = () => {
              listeners.get("evtx-record-stream-complete")?.({
                payload: { requestId, channel: channels?.[0] ?? "", sequenceCount: 0, totalRecords: 0 },
              });
              resolve({ records: [], channels: [], totalRecords: 0, parseErrors: 0, errorMessages: [] });
            };
          }),
      );
      const reload = useEvtxStore.getState().queryChannels(["Security"]);
      expect(useEvtxStore.getState().channelReadThrough.has("Security")).toBe(false);
      await vi.waitFor(() => expect(answer).toBeTypeOf("function"));
      answer?.();
      await reload;
    });

    it("drops a channel's stamp when the channel is cleared", async () => {
      await loadSecurity(beforeLoad());
      expect(useEvtxStore.getState().channelReadThrough.has("Security")).toBe(true);
      vi.mocked(invoke).mockImplementation(async (command: string, args?: unknown) =>
        command === "evtx_clear_channel"
          ? { channel: (args as { channel: string }).channel, result: { status: "cleared" } }
          : undefined,
      );
      const outcome = await useEvtxStore.getState().clearChannel("Security", true);
      expect(outcome.status).toBe("cleared");
      expect(useEvtxStore.getState().channelReadThrough.has("Security")).toBe(false);
    });

    it("forgets every stamp when the source changes", async () => {
      await loadSecurity(beforeLoad());
      vi.mocked(invoke).mockResolvedValue({
        records: [],
        channels: [],
        totalRecords: 0,
        parseErrors: 0,
        errorMessages: [],
      });
      await useEvtxStore.getState().parseFiles(["C:/logs/System.evtx"]);
      expect(useEvtxStore.getState().channelReadThrough.size).toBe(0);
    });
  });
});

describe("isNewestOnlyGapReason", () => {
  it.each([1, 2_000, 123_456])("accepts the note the store writes for a bound of %i", (bound) => {
    expect(isNewestOnlyGapReason(newestOnlyGapReason(bound))).toBe(true);
  });

  it.each([
    "3 batches of events were not received",
    "4 of 2000 events did not reach the view",
    "stopped after 2000 events, the channel could not be read further (EvtNext)",
    "newest 2000 events shown",
    "newest 2000 events shown (the channel may hold more) ",
    "Newest 2000 events shown (the channel may hold more)",
    "newest two thousand events shown (the channel may hold more)",
    "kept the newest 2000 events (the channel may hold more)",
    `${newestOnlyGapReason(2000)} and 3 more`,
    "",
  ])("rejects %j", (reason) => {
    expect(isNewestOnlyGapReason(reason)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// Selection is shared with the table, which stays mounted, hidden, while Grouped is active.
// ---------------------------------------------------------------------------------------------

describe("a selection made in the Grouped view with the table mounted", () => {
  function TableAndGrouped() {
    const state = useEvtxStore();
    const visible = selectVisibleRecords({
      records: state.records,
      selectedChannels: state.selectedChannels,
      filterLevels: state.filterLevels,
      filterEventIds: state.filterEventIds,
      filterSearch: state.filterSearch,
      quickFilter: state.quickFilter,
      visibleColumns: state.columnConfig.order,
      timeZoneMode: state.timeZoneMode,
      timeWindow: state.timeWindow,
      nowEpoch: NOW,
    });
    return (
      <>
        <div data-testid="table-view">
          <EvtxTimeline nowEpoch={NOW} />
        </div>
        <EvtxGroupedView records={visible} nowEpoch={NOW} />
      </>
    );
  }

  beforeEach(() => {
    useEvtxStore.getState().reset();
    const records = sampleRecords();
    useEvtxStore.setState({
      records,
      sourceMode: "files",
      timeWindow: "all",
      selectedChannels: new Set(records.map((record) => record.channel)),
      // The table groups by Event ID with 7036 collapsed.
      groupBy: ["eventId"],
      collapsedGroups: new Set(["/eventId=7036"]),
    });
  });

  afterEach(() => useEvtxStore.getState().reset());

  it("holds when the event sits in a group the table has collapsed, and survives a return to Table", () => {
    const view = render(<TableAndGrouped />);
    const grouped = screen.getByRole("grid", { name: /^Grouped events/ });
    fireEvent.click(within(grouped).getByRole("button", { name: /^Event ID 7036/ }));
    const event = [...itemRows()][0];
    fireEvent.click(event);
    const id = useEvtxStore.getState().selectedRecordId;
    expect(id).not.toBeNull();
    expect(useEvtxStore.getState().records.find((record) => record.id === id)?.eventId).toBe(7036);
    // The hidden table ran its effects with 7036 collapsed and left the selection alone.
    expect([...itemRows()][0]).toHaveAttribute("aria-selected", "true");

    // Back on the table: it renders again with the same collapsed group.
    view.rerender(<TableAndGrouped />);
    expect(useEvtxStore.getState().selectedRecordId).toBe(id);
  });

  it("is still cleared when the filters drop the selected event", () => {
    render(<TableAndGrouped />);
    fireEvent.click(screen.getByRole("button", { name: /^Event ID 7036/ }));
    fireEvent.click([...itemRows()][0]);
    expect(useEvtxStore.getState().selectedRecordId).not.toBeNull();
    act(() => useEvtxStore.getState().setFilterEventIds("1000"));
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
// The view's scope wiring: every selected channel, in live mode and in files mode.
// ---------------------------------------------------------------------------------------------

describe("the visible scope the view passes to the trend", () => {
  /** The Grouped view over the store's visible records, as the workspace renders it. */
  function GroupedFromStore() {
    const state = useEvtxStore();
    const visible = selectVisibleRecords({
      records: state.records,
      selectedChannels: state.selectedChannels,
      filterLevels: state.filterLevels,
      filterEventIds: state.filterEventIds,
      filterSearch: state.filterSearch,
      quickFilter: state.quickFilter,
      visibleColumns: state.columnConfig.order,
      timeZoneMode: state.timeZoneMode,
      timeWindow: state.timeWindow,
      nowEpoch: NOW,
    });
    return <EvtxGroupedView records={visible} nowEpoch={NOW} />;
  }

  /** The trend marks drawn on the Error group's row. */
  function errorRowMarks() {
    const row = document.querySelector('[data-evtx-grouped-row="group"][data-group-value="Error"]');
    if (row === null) throw new Error("no Error group row");
    const binsOf = (selector: string) =>
      [...row.querySelectorAll(selector)].map((mark) => Number(mark.getAttribute("data-bin")));
    return { zeros: binsOf("[data-trend-zero]"), bars: binsOf("[data-trend-bar]") };
  }

  /** Application Errors at 03:00, 09:00 and 20:00; its oldest kept event is at 01:00. */
  const application = () => [
    rec({ eventId: 1001, channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START + 1 * HOUR }),
    rec({ eventId: 1000, level: "Error", channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START + 3 * HOUR }),
    rec({ eventId: 1000, level: "Error", channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START + 9 * HOUR }),
    rec({ eventId: 1000, level: "Error", channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START + 20 * HOUR }),
    rec({ eventId: 1001, channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START + 23.5 * HOUR }),
  ];
  /** System Information from 12:00 to 23:00, the newest at 23:00. */
  const system = () =>
    Array.from({ length: 12 }, (_, i) =>
      rec({ eventId: 7036, channel: "System", sourceLabel: "/f/System.evtx", at: DAY_START + (12 + i) * HOUR }),
    );
  const live = (name: string) => ({ name, eventCount: 0, sourceType: "live" as const });

  beforeEach(() => {
    useEvtxStore.getState().reset();
    vi.mocked(invoke).mockReset();
  });
  afterEach(() => {
    vi.mocked(invoke).mockReset();
    useEvtxStore.getState().reset();
  });

  it("live: a second selected loaded channel narrows a group whose events are all in the first", () => {
    useEvtxStore.setState({
      sourceMode: "live",
      timeWindow: "24h",
      groupBy: ["level"],
      records: [...application(), ...system()],
      // Setup is listed but not selected: it is outside the scope and must not blank the trend.
      channels: [live("Application"), live("System"), live("Setup")],
      selectedChannels: new Set(["Application", "System"]),
      loadedChannels: new Set(["Application", "System"]),
      channelReadThrough: new Map([
        ["Application", loadReadOf("Application", application())],
        ["System", loadReadOf("System", system())],
      ]),
    });
    render(<GroupedFromStore />);
    const { zeros, bars } = errorRowMarks();
    expect(bars).toEqual([3, 9, 20]);
    // System proves 12:00 onward only, so nothing before it is drawn as read.
    expect(zeros.every((bin) => bin >= 12)).toBe(true);
    expect(zeros).toContain(12);
    expect(zeros).toContain(22);
  });

  it("live: a selected channel that holds records but is not loaded leaves every empty bin unknown", () => {
    useEvtxStore.setState({
      sourceMode: "live",
      timeWindow: "24h",
      groupBy: ["level"],
      records: [...application(), ...system()],
      channels: [live("Application"), live("System")],
      selectedChannels: new Set(["Application", "System"]),
      // System's load was cancelled: its records are on screen, it is not loaded, it has no stamp.
      loadedChannels: new Set(["Application"]),
      channelReadThrough: new Map([["Application", loadReadOf("Application", application())]]),
    });
    render(<GroupedFromStore />);
    expect(errorRowMarks().zeros).toEqual([]);
  });

  it("files: a second selected file narrows a group whose events are all in the first", () => {
    const day = 24 * HOUR;
    useEvtxStore.setState({
      sourceMode: "files",
      timeWindow: "all",
      groupBy: ["level"],
      // Application from 10-01 to 10-10; System from 10-08 to 10-10.
      records: [
        rec({ eventId: 1000, level: "Error", channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START }),
        rec({ eventId: 1000, level: "Error", channel: "Application", sourceLabel: "/f/Application.evtx", at: DAY_START + 9 * day }),
        rec({ channel: "System", sourceLabel: "/f/System.evtx", at: DAY_START + 7 * day }),
        rec({ channel: "System", sourceLabel: "/f/System.evtx", at: DAY_START + 9 * day }),
      ],
      channels: [
        { name: "Application", eventCount: 2, sourceType: { file: { path: "/f/Application.evtx" } } },
        { name: "System", eventCount: 2, sourceType: { file: { path: "/f/System.evtx" } } },
      ],
      selectedChannels: new Set(["Application", "System"]),
    });
    render(<GroupedFromStore />);
    const { zeros, bars } = errorRowMarks();
    expect(bars).toEqual([0, 23]);
    // Nine days in 24 bins of 9 hours: System's file starts in bin 18, so only 19 to 22 are read.
    expect(zeros).toEqual([19, 20, 21, 22]);
  });
});

// ---------------------------------------------------------------------------------------------
// Store paths that leave a selected channel's records on screen without loading it.
// ---------------------------------------------------------------------------------------------

describe("a selected channel whose load did not finish", () => {
  type Reply = (args: { channels?: string[]; requestId?: string }) => unknown;

  /** System events from 18:00 to 21:00. */
  const systemRows = () =>
    [18, 19, 20, 21].map((hour) => rec({ eventId: 7036, channel: "System", at: DAY_START + hour * HOUR }));
  /** Application Errors at 03:00 and 09:00 and its newest event at 23:00. */
  const applicationRows = () => [
    rec({ eventId: 1000, level: "Error", channel: "Application", at: DAY_START + 3 * HOUR }),
    rec({ eventId: 1000, level: "Error", channel: "Application", at: DAY_START + 9 * HOUR }),
    rec({ eventId: 1001, channel: "Application", at: DAY_START + 23 * HOUR }),
  ];

  /** Delivers `rows` for the asked channel the way the backend streams them. */
  function stream(args: { channels?: string[]; requestId?: string }, rows: EvtxRecord[], complete: boolean) {
    const channel = args.channels?.[0] ?? "";
    if (rows.length > 0) {
      listeners.get("evtx-record-batch")?.({
        payload: { requestId: args.requestId, channel, sequence: 0, records: rows },
      });
    }
    if (complete) {
      listeners.get("evtx-record-stream-complete")?.({
        payload: { requestId: args.requestId, channel, sequenceCount: rows.length > 0 ? 1 : 0, totalRecords: rows.length },
      });
    }
  }
  const ok =
    (rows: EvtxRecord[]): Reply =>
    (args) => {
      stream(args, rows, true);
      const channel = args.channels?.[0] ?? "";
      return { records: [], channels: [{ name: channel, eventCount: rows.length, sourceType: "live" }], totalRecords: rows.length, parseErrors: 0, errorMessages: [] };
    };

  function backend(replies: Record<string, Reply>, enumerate: string[] = []) {
    vi.mocked(invoke).mockImplementation(async (command: string, raw?: unknown) => {
      if (command === "evtx_enumerate_channels") {
        return enumerate.map((name) => ({ name, eventCount: 0, sourceType: "live", enabledState: "enabled" }));
      }
      const args = (raw ?? {}) as { channels?: string[]; requestId?: string };
      const reply = replies[args.channels?.[0] ?? ""];
      if (!reply) throw new Error(`no reply for ${command}`);
      return reply(args);
    });
  }

  /** Application loaded and read through NOW, as the automatic load leaves it. */
  function applicationLoaded(extra: { channels: string[]; selected: string[] }) {
    useEvtxStore.setState({
      sourceMode: "live",
      timeWindow: "24h",
      groupBy: ["level"],
      records: applicationRows(),
      channels: extra.channels.map((name) => ({ name, eventCount: 0, sourceType: "live" as const })),
      selectedChannels: new Set(extra.selected),
      loadedChannels: new Set(["Application"]),
      channelReadThrough: new Map([["Application", loadReadOf("Application", applicationRows())]]),
    });
  }

  function errorZeros() {
    const state = useEvtxStore.getState();
    const visible = state.records.filter((record) => state.selectedChannels.has(record.channel));
    render(<EvtxGroupedView records={visible} nowEpoch={NOW} />);
    const row = document.querySelector('[data-evtx-grouped-row="group"][data-group-value="Error"]')!;
    return row.querySelectorAll("[data-trend-zero]").length;
  }

  beforeEach(() => {
    useEvtxStore.getState().reset();
    vi.mocked(invoke).mockReset();
  });
  afterEach(() => {
    cleanup();
    vi.mocked(invoke).mockReset();
    useEvtxStore.getState().reset();
  });

  it("with System deselected, Application's own read draws its empty bins as 0", () => {
    applicationLoaded({ channels: ["Application", "System"], selected: ["Application"] });
    expect(errorZeros()).toBeGreaterThan(0);
  });

  it("a cancelled Load: System's records stay, it is not loaded, every empty bin is unknown", async () => {
    applicationLoaded({ channels: ["Application", "System"], selected: ["Application", "System"] });
    backend({
      System: (args) => {
        stream(args, systemRows(), true);
        return {
          records: [],
          channels: [{ name: "System", eventCount: 4, sourceType: "live" }],
          totalRecords: 4,
          parseErrors: 0,
          errorMessages: [],
          coverageGaps: [{ source: "System", kind: "cancelled", reason: "the operator stopped the load" }],
        };
      },
    });
    await useEvtxStore.getState().queryChannels(["System"]);
    const state = useEvtxStore.getState();
    expect(state.loadedChannels.has("System")).toBe(false);
    expect(state.records.some((record) => record.channel === "System")).toBe(true);
    expect(errorZeros()).toBe(0);
  });

  it("a failed first Load: System's delivered records stay, every empty bin is unknown", async () => {
    applicationLoaded({ channels: ["Application", "System"], selected: ["Application", "System"] });
    backend({
      System: (args) => {
        stream(args, systemRows(), false);
        throw new Error("RPC server unavailable");
      },
    });
    await useEvtxStore.getState().queryChannels(["System"]);
    const state = useEvtxStore.getState();
    expect(state.loadedChannels.has("System")).toBe(false);
    expect(state.records.some((record) => record.channel === "System")).toBe(true);
    expect(errorZeros()).toBe(0);
  });

  it("a failed refresh: System's delivered records stay, every empty bin is unknown", async () => {
    applicationLoaded({ channels: ["Application", "System"], selected: ["Application", "System"] });
    useEvtxStore.setState({ loadedChannels: new Set(["Application", "System"]) });
    backend({
      Application: ok(applicationRows()),
      System: (args) => {
        stream(args, systemRows(), false);
        throw new Error("RPC server unavailable");
      },
    });
    await useEvtxStore.getState().refreshLoadedChannels();
    const state = useEvtxStore.getState();
    expect(state.loadedChannels.has("Application")).toBe(true);
    expect(state.loadedChannels.has("System")).toBe(false);
    expect(state.records.some((record) => record.channel === "System")).toBe(true);
    expect(errorZeros()).toBe(0);
  });

  it("the automatic load's unusable channel: its records stay, every empty bin is unknown", async () => {
    backend(
      {
        Application: ok(applicationRows()),
        // The reply counts more events than reached the view, so System is unusable.
        System: (args) => {
          stream(args, systemRows(), false);
          listeners.get("evtx-record-stream-complete")?.({
            payload: { requestId: args.requestId, channel: "System", sequenceCount: 1, totalRecords: 9 },
          });
          return { records: [], channels: [{ name: "System", eventCount: 9, sourceType: "live" }], totalRecords: 9, parseErrors: 0, errorMessages: [] };
        },
      },
      ["Application", "System"],
    );
    await useEvtxStore.getState().enumerateChannels();
    useEvtxStore.setState({ groupBy: ["level"] });
    const state = useEvtxStore.getState();
    expect(state.selectedChannels.has("System")).toBe(true);
    expect(state.loadedChannels.has("System")).toBe(false);
    expect(state.records.some((record) => record.channel === "System")).toBe(true);
    expect(errorZeros()).toBe(0);
  });

  it("the automatic load with an empty Setup: Setup proves its span and blanks no trend", async () => {
    backend({ Application: ok(applicationRows()), Setup: ok([]) }, ["Application", "Setup"]);
    await useEvtxStore.getState().enumerateChannels();
    useEvtxStore.setState({ groupBy: ["level"] });
    const state = useEvtxStore.getState();
    expect(state.selectedChannels.has("Setup")).toBe(true);
    expect(state.loadedChannels.has("Setup")).toBe(true);
    expect(state.channelReadThrough.has("Setup")).toBe(true);
    expect(state.records.some((record) => record.channel === "Setup")).toBe(false);
    expect(errorZeros()).toBeGreaterThan(0);
  });

  it("a denied selected channel with no records: every empty bin is unknown", async () => {
    applicationLoaded({ channels: ["Application", "Security"], selected: ["Application", "Security"] });
    backend({
      Security: () => {
        throw new Error("EvtQuery(Security): Access is denied. (0x80070005)");
      },
    });
    await useEvtxStore.getState().queryChannels(["Security"]);
    const state = useEvtxStore.getState();
    expect(state.loadedChannels.has("Security")).toBe(false);
    expect(state.records.some((record) => record.channel === "Security")).toBe(false);
    expect(errorZeros()).toBe(0);
  });
});
