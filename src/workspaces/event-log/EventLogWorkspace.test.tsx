import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { save } from "@tauri-apps/plugin-dialog";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const LEVEL_BADGE_PRESENT_OFFSET = 9;
const LEVEL_BADGE_ABSENT_OFFSET = 5;
const virtualizerState = vi.hoisted(() => ({
  measured: [] as HTMLElement[],
  measuredSizes: new Map<number, number>(),
  items: [] as Array<{ index: number; size: number; start: number; end: number; key: string | number }>,
  initialItems: [] as Array<{ index: number; size: number; start: number; end: number; key: string | number }>,
  totalSize: 0,
  resizedSizes: new Map<number, number>(),
  measureCalls: 0,
  resizeObserverCalls: 0,
  cacheResetCalls: 0,
  resizeItemCalls: 0,
  visibleCount: null as number | null,
  scrollToIndex: vi.fn(),
  recalculate: () => undefined,
  measureElementSize: (element: HTMLElement) => {
    const hasLevelBadge = element.querySelector("[data-evtx-level-badge]") !== null;
    return element.getAttribute("role") === "row" &&
      !element.hasAttribute("data-evtx-marker-key")
      ? Number.parseFloat(element.style.height)
      : Number.parseFloat(element.style.lineHeight) +
          (hasLevelBadge ? LEVEL_BADGE_PRESENT_OFFSET : LEVEL_BADGE_ABSENT_OFFSET);
  },
  resizeItem: (index: number, size: number) => {
    virtualizerState.resizeItemCalls += 1;
    virtualizerState.resizedSizes.set(index, size);
    virtualizerState.measuredSizes.set(index, size);
    virtualizerState.recalculate();
  },
  measure: () => {
    virtualizerState.cacheResetCalls += 1;
    virtualizerState.measuredSizes.clear();
    virtualizerState.resizedSizes.clear();
    virtualizerState.recalculate();
  },
  measureElement: (
    element: HTMLElement | null,
    entry?: { borderBoxSize?: Array<{ blockSize: number }> }
  ) => {
    virtualizerState.measureCalls += 1;
    if (!element) return;
    const index = Number(element.dataset.index);
    const observedSize = entry?.borderBoxSize?.[0]?.blockSize;
    if (observedSize !== undefined) {
      virtualizerState.resizeItem(index, observedSize);
      return;
    }
    if (!virtualizerState.measured.includes(element)) {
      virtualizerState.measured.push(element);
    }
    if (!Object.prototype.hasOwnProperty.call(element, "getBoundingClientRect")) {
      Object.defineProperty(element, "getBoundingClientRect", {
        configurable: true,
        value: () => ({ height: virtualizerState.measureElementSize(element) }),
      });
    }
    virtualizerState.resizeItem(
      index,
      virtualizerState.measureElementSize(element)
    );
  },
  notifyResize: () => {
    for (const element of virtualizerState.measured) {
      virtualizerState.resizeObserverCalls += 1;
      virtualizerState.measureElement(element, {
        borderBoxSize: [
          { blockSize: virtualizerState.measureElementSize(element) },
        ],
      });
    }
  },
}));
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
function configureInvoke() {
  invoke.mockImplementation(async (command: string) => {
    if (command === "load_markers") return null;
    return undefined;
  });
}

// Captured so a test can stream record batches the way the backend does.
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => undefined);
  }),
}));
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({
    count,
    estimateSize,
    getItemKey,
  }: {
    count: number;
    estimateSize: (index: number) => number;
    getItemKey?: (index: number) => string | number;
  }) => {
    const measuredSize = (index: number) =>
      virtualizerState.resizedSizes.get(index) ??
      virtualizerState.measuredSizes.get(index) ??
      estimateSize(index);
    const getTotalSize = () => {
      let totalSize = 0;
      for (let index = 0; index < count; index += 1) totalSize += measuredSize(index);
      virtualizerState.totalSize = totalSize;
      return virtualizerState.totalSize;
    };
    const getVirtualItems = () => {
      let start = 0;
      const visibleCount = virtualizerState.visibleCount ?? count;
      const items = Array.from({ length: Math.min(count, visibleCount) }, (_, index) => {
        const size = measuredSize(index);
        const item = {
          index,
          size,
          start,
          end: start + size,
          key: getItemKey?.(index) ?? index,
        };
        start += size;
        return item;
      });
      if (
        virtualizerState.initialItems.length === 0 &&
        virtualizerState.measuredSizes.size === 0 &&
        virtualizerState.resizedSizes.size === 0
      ) {
        virtualizerState.initialItems = items;
      }
      virtualizerState.items = items;
      return items;
    };
    virtualizerState.recalculate = () => {
      getTotalSize();
      getVirtualItems();
    };
    return {
      getTotalSize,
      getVirtualItems,
      measureElement: virtualizerState.measureElement,
      resizeItem: virtualizerState.resizeItem,
      measure: virtualizerState.measure,
      scrollToIndex: virtualizerState.scrollToIndex,
    };
  },
}));
import {
  getLogDetailsLineHeight,
  getLogListMetrics,
  MAX_LOG_DETAILS_FONT_SIZE,
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_DETAILS_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { deferred } from "../../test-utils/deferred";
import { EVTX_LEVELS } from "./evtx-filter";
import { sourceKeyOf, useEvtxStore } from "./evtx-store";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { defaultColumnConfig, visibleColumns } from "./evtx-columns";
import { EventLogWorkspace } from "./EventLogWorkspace";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxDetailPane } from "./EvtxDetailPane";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxViewBar } from "./EvtxViewBar";
import { EvtxTimeline } from "./EvtxTimeline";
import { SourcePicker } from "./SourcePicker";
import {
  MAX_EXPORT_CHUNK_BYTES,
  MAX_EXPORT_CHUNK_RECORDS,
} from "./evtx-export";
import { eventLogWorkspace } from "./index";
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
  eventData: [{ name: "Detail", value: "Value" }],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

function setListFontSize(fontSize: number) {
  act(() => {
    useUiStore.getState().setLogListFontSize(fontSize);
  });
}

function setDetailsFontSize(fontSize: number) {
  act(() => {
    useUiStore.getState().setLogDetailsFontSize(fontSize);
  });
}

function seedEventLog() {
  useEvtxStore.setState({
    records: [RECORD],
    channels: [
      {
        name: "Application",
        eventCount: 1,
        sourceType: { file: { path: "sample.evtx" } },
      },
    ],
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application"]),
    sourceMode: "files",
    timeWindow: "all",
    selectedRecordId: RECORD.id,
  });
}

function recordGridRows(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>("[data-evtx-marker-key]"));
}

function resetVirtualizerState() {
  virtualizerState.measured.length = 0;
  virtualizerState.items.length = 0;
  virtualizerState.initialItems.length = 0;
  virtualizerState.measuredSizes.clear();
  virtualizerState.visibleCount = null;
  virtualizerState.measureCalls = 0;
  virtualizerState.cacheResetCalls = 0;
  virtualizerState.resizeObserverCalls = 0;
  virtualizerState.resizeItemCalls = 0;
  virtualizerState.scrollToIndex.mockClear();
  virtualizerState.resizedSizes.clear();
  virtualizerState.totalSize = 0;
}

describe("event-viewer shared font metrics", () => {
  beforeEach(() => {
    configureInvoke();
    useEvtxStore.getState().reset();
    resetVirtualizerState();
    useUiStore.getState().resetLogAccessibilityPreferences();
  });

  afterEach(() => {
    cleanup();
  });

  it("uses valid grid ownership for flat and grouped rows with interactive marker controls", () => {
    seedEventLog();
    useEvtxStore.setState({ groupBy: ["level"] });
    const columnCount = visibleColumns(defaultColumnConfig()).length + 1;

    const grouped = render(<EvtxTimeline />);
    const treegrid = grouped.getByRole("treegrid", {
      name: "Event log timeline - 1 records",
    });
    expect(treegrid).toHaveAttribute("aria-rowcount", "2");
    expect(treegrid).toHaveAttribute("aria-colcount", String(columnCount));

    const [groupRow, recordRow] = grouped.getAllByRole("row");
    const [groupCell] = within(groupRow).getAllByRole("gridcell");
    const recordCells = within(recordRow).getAllByRole("gridcell");
    expect(groupRow).toHaveAttribute("aria-rowindex", "1");
    expect(groupRow).toHaveAttribute("aria-level", "1");
    expect(groupRow).toHaveAttribute("aria-expanded", "true");
    expect(groupRow.firstElementChild).toBe(groupCell);
    expect(groupCell).toHaveAttribute("aria-colindex", "1");
    expect(groupCell).toHaveAttribute("aria-colspan", String(columnCount));
    expect(recordRow).toHaveAttribute("aria-rowindex", "2");
    expect(recordRow).toHaveAttribute("aria-level", "2");
    expect(recordRow).toHaveAttribute("aria-selected", "true");
    expect(recordCells).toHaveLength(columnCount);
    recordCells.forEach((cell, index) => {
      expect(cell).toHaveAttribute("aria-colindex", String(index + 1));
    });
    expect(recordRow.firstElementChild).toBe(recordCells[0]);
    expect(recordCells[0]).toContainElement(grouped.getByRole("button", { name: "Tag event" }));
    expect(recordCells[0]).toContainElement(
      grouped.getByRole("button", { name: "Bookmark event" }),
    );

    fireEvent.click(groupRow);
    expect(groupRow).toHaveAttribute("aria-expanded", "false");
    expect(treegrid).toHaveAttribute("aria-rowcount", "1");
    grouped.unmount();

    useEvtxStore.setState({ groupBy: [], selectedRecordId: RECORD.id });
    const flat = render(<EvtxTimeline />);
    const grid = flat.getByRole("grid", {
      name: "Event log timeline - 1 records",
    });
    const flatRow = flat.getByRole("row");
    const flatCells = within(flatRow).getAllByRole("gridcell");
    expect(grid).toHaveAttribute("aria-rowcount", "1");
    expect(grid).toHaveAttribute("aria-colcount", String(columnCount));
    expect(flatRow).toHaveAttribute("aria-rowindex", "1");
    expect(flatRow).toHaveAttribute("aria-selected", "true");
    expect(flatRow).not.toHaveAttribute("aria-level");
    expect(flatCells).toHaveLength(columnCount);
    expect(flatRow.firstElementChild).toBe(flatCells[0]);
  });

  describe("the grid with a transient time range or record scope", () => {
    const events = [1, 2, 3, 4].map(
      (n): EvtxRecord => ({
        ...RECORD,
        id: n,
        eventRecordId: 100 + n,
        timestampEpoch: n * 1000,
        message: `event number ${n}`,
      }),
    );
    const seedFour = () => {
      seedEventLog();
      useEvtxStore.setState({ records: events, selectedRecordId: null });
    };
    const shownMessages = (root: HTMLElement) =>
      recordGridRows(root).map((row) => /event number \d/.exec(row.textContent ?? "")?.[0]);

    it("shows every event without either", () => {
      seedFour();
      const grid = render(<EvtxTimeline />);
      expect(grid.getByRole("grid", { name: "Event log timeline - 4 records" })).toBeInTheDocument();
      expect(shownMessages(grid.container)).toHaveLength(4);
    });

    it("shows only the events in the time range", () => {
      seedFour();
      act(() => {
        useEvtxStore.getState().setTimeRange({ startMs: 2000, endMs: 4000 });
      });
      const grid = render(<EvtxTimeline />);
      expect(grid.getByRole("grid", { name: "Event log timeline - 2 records" })).toBeInTheDocument();
      expect(shownMessages(grid.container)).toEqual(["event number 2", "event number 3"]);
    });

    it("shows only the scoped events, and follows a change of the scope", () => {
      seedFour();
      const scope = (...picked: EvtxRecord[]) => ({
        kind: "finding" as const,
        title: "A finding",
        records: new Set(picked),
        counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
      });
      act(() => {
        useEvtxStore.getState().setRecordScope(scope(events[0], events[3]));
      });
      const grid = render(<EvtxTimeline />);
      expect(shownMessages(grid.container)).toEqual(["event number 1", "event number 4"]);
      act(() => {
        useEvtxStore.getState().setRecordScope(scope(events[2]));
      });
      expect(shownMessages(grid.container)).toEqual(["event number 3"]);
      act(() => {
        useEvtxStore.getState().setRecordScope(null);
      });
      expect(shownMessages(grid.container)).toHaveLength(4);
    });
  });

  it("names channel-folder disclosure and selection controls", () => {
    useEvtxStore.setState({
      channels: [
        {
          name: "Contoso",
          eventCount: 1,
          sourceType: { file: { path: "sample.evtx" } },
        },
        {
          name: "Contoso/Operational",
          eventCount: 1,
          sourceType: { file: { path: "sample.evtx" } },
        },
        {
          name: "Fabrikam/Operational",
          eventCount: 1,
          sourceType: { file: { path: "sample.evtx" } },
        },
      ],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      sourceMode: "files",
    });

    render(<ChannelPicker />);

    const appServicesDisclosure = screen.getByRole("button", {
      name: "Expand Applications and Services Logs",
    });
    expect(appServicesDisclosure).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(appServicesDisclosure);

    const providerDisclosure = screen.getByRole("button", {
      name: "Expand Contoso",
    });
    expect(providerDisclosure).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("checkbox", { name: "Select Contoso" })).not.toBeChecked();

    fireEvent.click(providerDisclosure);
    expect(providerDisclosure).toHaveAccessibleName("Collapse Contoso");
    expect(providerDisclosure).toHaveAttribute("aria-expanded", "true");
  });

  it("keeps row, virtualizer, pickers, filter, and detail metrics aligned at persisted limits", async () => {
    seedEventLog();
    useEvtxStore.setState({ groupBy: ["level"] });

    setListFontSize(MIN_LOG_LIST_FONT_SIZE);
    setDetailsFontSize(MIN_LOG_DETAILS_FONT_SIZE);
    const smallList = getLogListMetrics(MIN_LOG_LIST_FONT_SIZE);
    const smallDetailLineHeight = getLogDetailsLineHeight(MIN_LOG_DETAILS_FONT_SIZE);

    const source = render(<SourcePicker />);
    const sourceHeading = screen.getByText("Event Log Viewer") as HTMLElement;
    expect(sourceHeading.style.fontSize).toBe(`${smallList.fontSize + 5}px`);
    source.unmount();

    const channel = render(<ChannelPicker />);
    const channelTree = screen.getByText("Application").closest("label")!.parentElement as HTMLElement;
    const channelRow = screen.getByText("Application").closest("label") as HTMLElement;
    expect(channelTree.style.fontSize).toBe(`${smallList.fontSize}px`);
    expect(channelRow.style.height).toBe(`${smallList.rowHeight}px`);
    expect(screen.getByPlaceholderText("Filter channels...").style.fontSize).toBe(
      `${smallList.fontSize}px`
    );
    expect(screen.getByRole("button", { name: "Select all" }).style.fontSize).toBe(
      `${smallList.fontSize}px`
    );
    channel.unmount();

    const filter = render(<EvtxFilterBar nowEpoch={Date.now()} />);
    // Spec 7.1: level toggles are f - 2, the other filter controls f - 1.
    expect(screen.getByRole("button", { name: "Toggle Critical events" }).style.fontSize).toBe(
      `${Math.max(10, smallList.fontSize - 2)}px`
    );
    expect(screen.getByRole("textbox", { name: "Search events" }).style.fontSize).toBe(
      `${Math.max(11, smallList.fontSize - 1)}px`
    );
    fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
    const smallPopover = within(await screen.findByRole("dialog", { name: "More filters" }));
    expect(smallPopover.getByPlaceholderText("Event IDs (comma sep.)").style.fontSize).toBe(
      `${Math.max(11, smallList.fontSize - 1)}px`
    );
    expect(smallPopover.getAllByRole("combobox")[0].style.fontSize).toBe(
      `${Math.max(11, smallList.fontSize - 1)}px`
    );
    filter.unmount();
    const timeline = render(<EvtxTimeline />);
    const [groupRow, recordRow] = screen.getAllByRole("row");
    expect(recordRow.style.fontSize).toBe(`${smallList.fontSize}px`);
    expect(recordRow.style.lineHeight).toBe(`${smallList.rowLineHeight}px`);
    expect(virtualizerState.measured).toContain(recordRow);
    expect(virtualizerState.items[1]).toMatchObject({
      index: 1,
      size: smallList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET,
      start: smallList.rowHeight,
    });
    expect(virtualizerState.totalSize).toBe(
      smallList.rowHeight + smallList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );
    expect(groupRow.style.boxSizing).toBe("border-box");
    expect(groupRow.style.height).toBe(`${smallList.rowHeight}px`);
    groupRow.focus();
    fireEvent.keyDown(groupRow, { key: "ArrowDown" });
    expect(recordRow).toHaveFocus();
    timeline.unmount();

    const detail = render(<EvtxDetailPane />);
    const detailRoot = detail.container.firstElementChild as HTMLElement;
    expect(detailRoot.style.fontSize).toBe(`${MIN_LOG_DETAILS_FONT_SIZE}px`);
    // The root no longer scrolls; the body under the fixed header does.
    expect((detailRoot.lastElementChild as HTMLElement).style.overflow).toBe("auto");
    expect(detailRoot.style.lineHeight).toBe(`${smallDetailLineHeight}px`);
    detail.unmount();

    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    setDetailsFontSize(MIN_LOG_DETAILS_FONT_SIZE);
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);

    const sourceLarge = render(<SourcePicker />);
    expect((screen.getByText("Event Log Viewer") as HTMLElement).style.fontSize).toBe(
      `${largeList.fontSize + 5}px`
    );
    sourceLarge.unmount();

    const channelLarge = render(<ChannelPicker />);
    const largeChannelRow = screen.getByText("Application").closest("label") as HTMLElement;
    expect(largeChannelRow.style.height).toBe(`${largeList.rowHeight}px`);
    expect(screen.getByPlaceholderText("Filter channels...").style.fontSize).toBe(
      `${largeList.fontSize}px`
    );
    expect(screen.getByRole("button", { name: "Select all" }).style.fontSize).toBe(
      `${largeList.fontSize}px`
    );
    channelLarge.unmount();

    const filterLarge = render(<EvtxFilterBar nowEpoch={Date.now()} />);
    expect(screen.getByRole("button", { name: "Toggle Critical events" }).style.fontSize).toBe(
      `${Math.max(10, largeList.fontSize - 2)}px`
    );
    expect(screen.getByRole("textbox", { name: "Search events" }).style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
    const largePopover = within(await screen.findByRole("dialog", { name: "More filters" }));
    expect(largePopover.getByPlaceholderText("Event IDs (comma sep.)").style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    expect(largePopover.getAllByRole("combobox")[0].style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    filterLarge.unmount();

    virtualizerState.resizedSizes.clear();
    virtualizerState.measuredSizes.clear();
    virtualizerState.measured.length = 0;
    virtualizerState.items.length = 0;
    const timelineLarge = render(<EvtxTimeline />);
    const [, recordRowLarge] = screen.getAllByRole("row");
    expect(recordRowLarge.style.lineHeight).toBe(`${largeList.rowLineHeight}px`);
    expect(virtualizerState.measured).toContain(recordRowLarge);
    expect(virtualizerState.items[1]).toMatchObject({
      index: 1,
      size: largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET,
      start: largeList.rowHeight,
    });
    const groupRowLarge = screen.getAllByRole("row")[0];
    expect(virtualizerState.totalSize).toBe(
      largeList.rowHeight + largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );
    groupRowLarge.focus();
    fireEvent.keyDown(groupRowLarge, { key: "ArrowDown" });
    expect(recordRowLarge).toHaveFocus();
    timelineLarge.unmount();

    const detailLarge = render(<EvtxDetailPane />);
    const detailRootLarge = detailLarge.container.firstElementChild as HTMLElement;
    expect(detailRootLarge.style.fontSize).toBe(`${MIN_LOG_DETAILS_FONT_SIZE}px`);
    expect(detailRootLarge.style.lineHeight).toBe(`${smallDetailLineHeight}px`);
    expect((detailRootLarge.lastElementChild as HTMLElement).style.overflow).toBe("auto");

    setDetailsFontSize(MAX_LOG_DETAILS_FONT_SIZE);
    expect(detailRootLarge.style.fontSize).toBe(`${MAX_LOG_DETAILS_FONT_SIZE}px`);
    expect(detailRootLarge.style.lineHeight).toBe(
      `${getLogDetailsLineHeight(MAX_LOG_DETAILS_FONT_SIZE)}px`
    );
    expect((detailRootLarge.lastElementChild as HTMLElement).style.overflow).toBe("auto");
    detailLarge.unmount();

    expect(useUiStore.getState().logListFontSize).toBe(MAX_LOG_LIST_FONT_SIZE);
    expect(useUiStore.getState().logDetailsFontSize).toBe(MAX_LOG_DETAILS_FONT_SIZE);
    const persisted = JSON.parse(localStorage.getItem("cmtraceopen-ui-preferences") ?? "{}") as {
      state?: { logListFontSize?: number; logDetailsFontSize?: number };
    };
    expect(persisted.state?.logListFontSize).toBe(MAX_LOG_LIST_FONT_SIZE);
    expect(persisted.state?.logDetailsFontSize).toBe(MAX_LOG_DETAILS_FONT_SIZE);
  });
  it("updates mounted list controls, rows, and virtualizer when persisted list size changes", () => {
    seedEventLog();
    useEvtxStore.setState({ groupBy: ["level"] });
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const channel = render(<ChannelPicker />);
    const channelInput = channel.getByPlaceholderText("Filter channels...") as HTMLInputElement;
    const channelRow = channel.getByText("Application").closest("label") as HTMLElement;
    const filter = render(<EvtxFilterBar nowEpoch={Date.now()} />);
    const filterButton = filter.getByRole("button", { name: "Toggle Critical events" });
    const timeline = render(<EvtxTimeline />);
    const recordRow = recordGridRows(timeline.container)[0];
    const initialMeasureCalls = virtualizerState.measureCalls;
    const smallList = getLogListMetrics(MIN_LOG_LIST_FONT_SIZE);
    expect(virtualizerState.initialItems[1].size).toBe(
      smallList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );

    expect(channelInput.style.fontSize).toBe(`${MIN_LOG_LIST_FONT_SIZE}px`);
    expect(channelRow.style.height).toBe(
      `${getLogListMetrics(MIN_LOG_LIST_FONT_SIZE).rowHeight}px`
    );
    expect(virtualizerState.initialItems[0].size).toBe(smallList.rowHeight);
    const initialResizeObserverCalls = virtualizerState.resizeObserverCalls;
    const initialResizeItemCalls = virtualizerState.resizeItemCalls;
    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    virtualizerState.notifyResize();
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);
    expect(virtualizerState.measureCalls).toBeGreaterThan(initialMeasureCalls);
    expect(virtualizerState.resizeObserverCalls).toBeGreaterThan(initialResizeObserverCalls);
    expect(virtualizerState.resizeItemCalls).toBeGreaterThan(initialResizeItemCalls);

    expect(channel.getByPlaceholderText("Filter channels...")).toBe(channelInput);
    expect(channelInput.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE}px`);
    expect(channelRow.style.height).toBe(`${largeList.rowHeight}px`);
    expect(filter.getByRole("button", { name: "Toggle Critical events" })).toBe(filterButton);
    expect(filterButton.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE - 2}px`);
    expect(recordGridRows(timeline.container)[0]).toBe(recordRow);
    expect(recordRow.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE}px`);
    expect(recordRow.style.lineHeight).toBe(`${largeList.rowLineHeight}px`);
    expect(virtualizerState.resizedSizes.get(0)).toBe(largeList.rowHeight);
    expect(virtualizerState.resizedSizes.get(1)).toBe(
      largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );
    expect(virtualizerState.items[1].start).toBe(largeList.rowHeight);
    expect(virtualizerState.totalSize).toBe(
      largeList.rowHeight + largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );
  });
  it("updates connected rows while estimating offscreen rows after a font change", () => {
    seedEventLog();
    useEvtxStore.setState({
      records: [
        RECORD,
        { ...RECORD, id: 2, eventRecordId: 2, eventId: 43, message: "Second event" },
      ],
      groupBy: ["level"],
    });
    virtualizerState.visibleCount = 2;
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const timeline = render(<EvtxTimeline />);
    expect(recordGridRows(timeline.container)).toHaveLength(1);
    const initialResizeItemCalls = virtualizerState.resizeItemCalls;
    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    virtualizerState.resizedSizes.clear();
    virtualizerState.measuredSizes.clear();
    virtualizerState.items.length = 0;
    virtualizerState.totalSize = 0;
    virtualizerState.notifyResize();
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);
    expect(virtualizerState.resizeItemCalls).toBeGreaterThan(initialResizeItemCalls);
    expect(virtualizerState.resizedSizes.get(0)).toBe(largeList.rowHeight);

    expect(virtualizerState.resizedSizes.get(1)).toBe(
      largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );
    expect(virtualizerState.resizedSizes.has(2)).toBe(false);
    expect(virtualizerState.items).toHaveLength(2);
    expect(virtualizerState.totalSize).toBe(
      largeList.rowHeight +
        (largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET) * 2,
    );
  });
  it("keeps a 100,000-record view addressable with a bounded DOM window", () => {
    seedEventLog();
    const records = Array.from({ length: 100_000 }, (_, index) => ({
      ...RECORD,
      id: index + 1,
      eventRecordId: index + 1,
      timestampEpoch: index + 1,
      message: `Event ${index + 1}`,
    }));
    useEvtxStore.setState({
      records,
      channels: [
        {
          name: "Application",
          eventCount: records.length,
          sourceType: { file: { path: "sample.evtx" } },
        },
      ],
      groupBy: [],
      sortField: "time",
      sortDirection: "asc",
      selectedRecordId: 1,
    });
    virtualizerState.visibleCount = 20;

    const timeline = render(<EvtxTimeline nowEpoch={100_001} />);
    const grid = timeline.getByRole("grid", {
      name: "Event log timeline - 100000 records",
    });
    const rows = recordGridRows(timeline.container);

    expect(grid).toHaveAttribute("aria-rowcount", "100000");
    expect(rows).toHaveLength(20);
    expect(virtualizerState.items).toHaveLength(20);
    expect(rows[0]).toHaveAttribute("data-index", "0");

    fireEvent.keyDown(rows[0], { key: "End" });

    expect(virtualizerState.scrollToIndex).toHaveBeenLastCalledWith(99_999, {
      align: "auto",
    });
    expect(useEvtxStore.getState().selectedRecordId).toBe(100_000);
  });
  it("keeps the virtualizer cache when a clock tick leaves row identities unchanged", () => {
    seedEventLog();
    const timeline = render(<EvtxTimeline nowEpoch={1_000_000} />);
    const initialCacheResetCalls = virtualizerState.cacheResetCalls;

    timeline.rerender(<EvtxTimeline nowEpoch={1_030_000} />);

    expect(virtualizerState.cacheResetCalls).toBe(initialCacheResetCalls);
  });
  it("remeasures a record after a group header shifts its row index", () => {
    seedEventLog();
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const timeline = render(<EvtxTimeline />);
    const recordRow = recordGridRows(timeline.container)[0];
    act(() => {
      useEvtxStore.setState({ groupBy: ["level"] });
    });
    expect(recordGridRows(timeline.container)[0]).toBe(recordRow);
    expect(recordRow.getAttribute("role")).toBe("row");

    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);
    expect(virtualizerState.resizedSizes.get(1)).toBe(
      largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET
    );
    expect(virtualizerState.resizedSizes.get(0)).toBe(largeList.rowHeight);
    timeline.unmount();
  });
  it("clears a measured row cache when that row becomes offscreen", () => {
    seedEventLog();
    useEvtxStore.setState({
      records: [RECORD, { ...RECORD, id: 2, eventRecordId: 2 }],
      groupBy: [],
    });
    virtualizerState.visibleCount = 2;
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const timeline = render(<EvtxTimeline />);
    expect(timeline.getAllByRole("row")).toHaveLength(2);
    expect(virtualizerState.measuredSizes.has(1)).toBe(true);
    const initialCacheResetCalls = virtualizerState.cacheResetCalls;

    virtualizerState.visibleCount = 1;
    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);

    expect(virtualizerState.cacheResetCalls).toBeGreaterThan(initialCacheResetCalls);
    expect(virtualizerState.measuredSizes.has(1)).toBe(false);
    expect(virtualizerState.resizedSizes.has(1)).toBe(false);
    expect(virtualizerState.items).toHaveLength(1);
    expect(virtualizerState.totalSize).toBe(
      (largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET) * 2
    );
    timeline.unmount();
  });
  it("uses the connected DOM height for an empty hidden-level row", () => {
    seedEventLog();
    useEvtxStore.setState((state) => ({
      records: [{ ...RECORD, message: "" }],
      columnConfig: {
        ...state.columnConfig,
        order: state.columnConfig.order.filter((id) => id !== "level"),
      },
      groupBy: [],
    }));
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const timeline = render(<EvtxTimeline />);
    const row = timeline.getByRole("row");
    Object.defineProperty(row, "getBoundingClientRect", {
      configurable: true,
      value: () => ({ height: 5 }),
    });

    setListFontSize(MAX_LOG_LIST_FONT_SIZE);

    expect(virtualizerState.resizedSizes.get(0)).toBe(5);
    expect(virtualizerState.totalSize).toBe(5);
  });
  it("uses the smaller record cache when the level column is hidden", () => {
    seedEventLog();
    useEvtxStore.setState((state) => ({
      columnConfig: {
        ...state.columnConfig,
        order: state.columnConfig.order.filter((id) => id !== "level"),
      },
      groupBy: ["level"],
    }));
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const timeline = render(<EvtxTimeline />);
    expect(recordGridRows(timeline.container)).toHaveLength(1);
    expect(virtualizerState.initialItems[1].size).toBe(
      getLogListMetrics(MIN_LOG_LIST_FONT_SIZE).rowLineHeight + LEVEL_BADGE_ABSENT_OFFSET
    );

    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);

    expect(virtualizerState.resizedSizes.get(0)).toBe(largeList.rowHeight);
    expect(virtualizerState.resizedSizes.get(1)).toBe(
      largeList.rowLineHeight + LEVEL_BADGE_ABSENT_OFFSET
    );
    expect(virtualizerState.totalSize).toBe(
      largeList.rowHeight + largeList.rowLineHeight + LEVEL_BADGE_ABSENT_OFFSET
    );
  });
});

function fixtureRecord(): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 42,
    timestamp: "2026-01-15T12:00:00.000Z",
    timestampEpoch: Date.parse("2026-01-15T12:00:00.000Z"),
    provider: "Application Error",
    channel: "Application",
    eventId: 1000,
    level: "Error",
    computer: "PC01",
    message: "Faulting application name: setup.exe",
    eventData: [{ name: "AppName", value: "setup.exe" }],
    rawXml: "<Event><System><EventID>1000</EventID></System></Event>",
    sourceLabel: "Application.evtx",
  };
}

function seedFixtureEvents() {
  useEvtxStore.setState({
    records: [fixtureRecord()],
    channels: [
      { name: "Application", eventCount: 1, sourceType: "live" },
      { name: "System", eventCount: 0, sourceType: "live" },
      {
        name: "Microsoft-Windows-AAD/Operational",
        eventCount: 0,
        sourceType: "live",
      },
    ],
    sourceMode: "live",
    // A live source whose first load has completed (the store records this as a load ends).
    completedSourceKey: sourceKeyOf({ sourceMode: "live", remoteMachine: null, sourcePaths: [] }),
    isLoading: false,
    loadError: null,
    coverageGaps: [],
    selectedChannels: new Set([
      "Application",
      "System",
      "Microsoft-Windows-AAD/Operational",
    ]),
    loadedChannels: new Set(["Application"]),
    filterLevels: new Set(EVTX_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    timeWindow: "all",
    timeZoneMode: "local",
    columnConfig: defaultColumnConfig(),
    groupBy: [],
    collapsedGroups: new Set(),
    sortField: "time",
    sortDirection: "asc",
    selectedRecordId: null,
  });
}

const exportStatus = () =>
  document.querySelector<HTMLElement>("[data-evtx-export-status]") as HTMLElement;

describe("EventLogWorkspace fixtures", () => {
  beforeEach(() => {
    invoke.mockReset();
    configureInvoke();
    useEvtxStore.getState().reset();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    resetVirtualizerState();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    useEvtxStore.getState().reset();
  });

  it("shows the Windows Logs / Applications tree with select controls", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);

    expect(screen.getByText("Windows Logs")).toBeInTheDocument();
    expect(screen.getByText("Applications and Services Logs")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Filter channels...")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Select all" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deselect all" })).toBeInTheDocument();
    expect(screen.getAllByText("Application").length).toBeGreaterThan(0);
  });

  it("keeps a later source load error visible while prior events remain loaded", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);
    expect(recordGridRows(document.body)).toHaveLength(1);

    const message =
      "No .evtx files were found. Source diagnostics: C:/protected/Security.evtx: Access is denied";
    act(() => {
      useEvtxStore.getState().setLoadError(message);
    });

    expect(screen.getByText(message)).toHaveAttribute("role", "alert");
    expect(recordGridRows(document.body)).toHaveLength(1);
  });

  describe("the transient time range and its Escape key", () => {
    const SEP = "\u2013";
    const RANGE = {
      startMs: Date.parse("2026-01-15T11:00:00.000Z"),
      endMs: Date.parse("2026-01-15T13:00:00.000Z"),
    };
    const pressEscape = (target: Element | Window = document.body) =>
      fireEvent.keyDown(target, { key: "Escape" });
    /** Seeds the fixture, renders the workspace, then sets the range through the store. */
    const renderWithRange = () => {
      seedFixtureEvents();
      useEvtxStore.setState({ timeZoneMode: "utc" });
      const view = render(<EventLogWorkspace />);
      act(() => {
        expect(useEvtxStore.getState().setTimeRange(RANGE)).toBe(true);
      });
      return view;
    };
    const chipText = () =>
      document.querySelector("[data-evtx-chip='timeRange'] span")?.textContent ?? null;

    it("shows the Time chip for the range, in the selected zone", () => {
      renderWithRange();
      expect(chipText()).toBe(`Time: brushed 11:00${SEP}13:00`);
    });

    it("clears the range on Escape, and says it handled the key", () => {
      renderWithRange();
      expect(pressEscape()).toBe(false);
      expect(useEvtxStore.getState().timeRange).toBeNull();
      expect(chipText()).toBeNull();
    });

    it("leaves the key alone when there is no range", () => {
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      expect(pressEscape()).toBe(true);
    });

    it("does not clear the record scope", () => {
      renderWithRange();
      const [first] = useEvtxStore.getState().records;
      act(() => {
        useEvtxStore.getState().setRecordScope({
          kind: "finding",
          title: "A finding",
          records: new Set([first]),
          counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
        });
      });
      pressEscape();
      expect(useEvtxStore.getState().timeRange).toBeNull();
      expect(useEvtxStore.getState().recordScope).not.toBeNull();
      pressEscape();
      expect(useEvtxStore.getState().recordScope).not.toBeNull();
    });

    it("leaves the range alone while a control is being typed into", () => {
      renderWithRange();
      const search = screen.getByRole("textbox", { name: "Search events" });
      search.focus();
      expect(pressEscape(search)).toBe(true);
      expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
    });

    it.each(["combobox", "textbox", "searchbox", "spinbutton"])(
      "leaves the range alone while focus is in an element with the %s role",
      (role) => {
        renderWithRange();
        const control = document.createElement("div");
        control.setAttribute("role", role);
        control.tabIndex = 0;
        document.body.appendChild(control);
        try {
          control.focus();
          expect(control).toHaveFocus();
          expect(pressEscape(control)).toBe(true);
          expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
        } finally {
          control.remove();
        }
      },
    );

    it("leaves the range alone while focus is in a contenteditable element", () => {
      renderWithRange();
      const editor = document.createElement("div");
      editor.setAttribute("contenteditable", "true");
      // jsdom does not compute isContentEditable from the attribute, so state the property it reads.
      Object.defineProperty(editor, "isContentEditable", { value: true });
      document.body.appendChild(editor);
      try {
        expect(pressEscape(editor)).toBe(true);
        expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
      } finally {
        editor.remove();
      }
    });

    it("clears the range when focus is in a button or a link, which are not for typing", () => {
      renderWithRange();
      const button = document.createElement("button");
      document.body.appendChild(button);
      try {
        button.focus();
        pressEscape(button);
      } finally {
        button.remove();
      }
      expect(useEvtxStore.getState().timeRange).toBeNull();
    });

    it("leaves the range alone while a native dialog is open", () => {
      renderWithRange();
      const dialog = document.createElement("dialog");
      dialog.setAttribute("open", "");
      document.body.appendChild(dialog);
      try {
        expect(pressEscape()).toBe(true);
        expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
      } finally {
        dialog.remove();
      }
      // The same dialog closed (no open attribute) no longer holds the key.
      const closed = document.createElement("dialog");
      document.body.appendChild(closed);
      try {
        pressEscape();
      } finally {
        closed.remove();
      }
      expect(useEvtxStore.getState().timeRange).toBeNull();
    });

    it("leaves the range alone while a modal dialog is open", () => {
      renderWithRange();
      const dialog = document.createElement("div");
      dialog.setAttribute("role", "dialog");
      dialog.setAttribute("aria-modal", "true");
      document.body.appendChild(dialog);
      try {
        expect(pressEscape()).toBe(true);
        expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
      } finally {
        dialog.remove();
      }
      pressEscape();
      expect(useEvtxStore.getState().timeRange).toBeNull();
    });

    describe("focus when Escape clears the range under a focused control", () => {
      const search = () => screen.getByRole("textbox", { name: "Search events" });
      const removeTime = () => screen.getByRole("button", { name: `Remove Time: brushed 11:00${SEP}13:00` });
      const scopeIt = () => {
        const [first] = useEvtxStore.getState().records;
        act(() => {
          useEvtxStore.getState().setRecordScope({
            kind: "finding",
            title: "A finding",
            records: new Set([first]),
            counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
          });
        });
      };

      it("moves to the search box when Escape on the Time chip's remove button removes the whole row", () => {
        renderWithRange();
        removeTime().focus();
        expect(removeTime()).toHaveFocus();
        fireEvent.keyDown(removeTime(), { key: "Escape" });
        expect(useEvtxStore.getState().timeRange).toBeNull();
        expect(screen.queryByRole("list", { name: "Active filters" })).toBeNull();
        expect(search()).toHaveFocus();
      });

      it("moves to the next chip's remove button when another chip is left", () => {
        renderWithRange();
        scopeIt();
        removeTime().focus();
        fireEvent.keyDown(removeTime(), { key: "Escape" });
        expect(screen.getByRole("button", { name: "Remove Finding: A finding" })).toHaveFocus();
      });

      it("moves to the search box when Escape on Clear all removes the last clearable chip", () => {
        renderWithRange();
        const clearAll = screen.getByRole("button", { name: "Clear all" });
        clearAll.focus();
        fireEvent.keyDown(clearAll, { key: "Escape" });
        expect(useEvtxStore.getState().timeRange).toBeNull();
        expect(screen.queryByRole("button", { name: "Clear all" })).toBeNull();
        expect(search()).toHaveFocus();
      });

      it("moves to the search box when a cleared channel prunes the focused Finding chip's scope to nothing", async () => {
        renderWithRange();
        act(() => {
          useEvtxStore.getState().setTimeRange(null);
        });
        scopeIt();
        invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
          if (command === "evtx_clear_channel") return { channel: args?.channel, result: { status: "cleared" } };
          if (command === "load_markers") return null;
          return undefined;
        });
        const removeScope = screen.getByRole("button", { name: "Remove Finding: A finding" });
        removeScope.focus();
        expect(removeScope).toHaveFocus();

        await act(async () => {
          await useEvtxStore.getState().clearChannel("Application", true);
        });

        expect(useEvtxStore.getState().recordScope).toBeNull();
        expect(search()).toHaveFocus();
      });
    });

    it("steps aside for an Escape that something else has already used", () => {
      renderWithRange();
      const used = (event: Event) => event.preventDefault();
      document.addEventListener("keydown", used);
      try {
        pressEscape();
        expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
      } finally {
        document.removeEventListener("keydown", used);
      }
      pressEscape();
      expect(useEvtxStore.getState().timeRange).toBeNull();
    });

    it("lets the More filters popover have the first Escape, and clears the range with the next", async () => {
      renderWithRange();
      fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
      const dialog = await screen.findByRole("dialog", { name: "More filters" });

      // The popover handles the key and prevents its default, so the workspace steps aside.
      fireEvent.keyDown(dialog, { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("dialog", { name: "More filters" })).toBeNull());
      expect(useEvtxStore.getState().timeRange).toEqual(RANGE);

      pressEscape();
      expect(useEvtxStore.getState().timeRange).toBeNull();
    });

    it("stops listening when the workspace unmounts", () => {
      const view = renderWithRange();
      view.unmount();
      expect(pressEscape()).toBe(true);
      expect(useEvtxStore.getState().timeRange).toEqual(RANGE);
    });

    it("counts, in the chip's tooltip, the events the range hides for want of a timestamp", () => {
      seedFixtureEvents();
      const untimed = { ...fixtureRecord(), eventRecordId: 43, timestampEpoch: 0, message: "no clock" };
      useEvtxStore.setState({
        timeZoneMode: "utc",
        records: [fixtureRecord(), untimed, { ...untimed, eventRecordId: 44 }],
      });
      render(<EventLogWorkspace />);
      act(() => {
        useEvtxStore.getState().setTimeRange(RANGE);
      });
      expect(screen.getByText(`Time: brushed 11:00${SEP}13:00`)).toHaveAttribute(
        "title",
        `Time: brushed 11:00${SEP}13:00 (UTC)\n2 events without a timestamp are hidden by this range`,
      );
    });
  });

  it("offers CSV, TSV, JSON, and Event XML export of visible events", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);

    fireEvent.click(
      screen.getByTitle(
        "Export the events currently shown, using the same filters as the list"
      )
    );

    expect(screen.getByText("CSV")).toBeInTheDocument();
    expect(screen.getByText("TSV")).toBeInTheDocument();
    expect(screen.getByText("JSON")).toBeInTheDocument();
    expect(screen.getByText("Event XML")).toBeInTheDocument();
  });

  it("exports the records selected by the workspace clock snapshot", async () => {
    const nowEpoch = Date.parse("2026-08-18T13:00:00.000Z");
    const boundaryRecord = {
      ...RECORD,
      timestamp: "2026-08-18T12:00:00.001Z",
      timestampEpoch: nowEpoch - 60 * 60 * 1000 + 1,
    };
    seedEventLog();
    useEvtxStore.setState({ records: [boundaryRecord], timeWindow: "1h" });
    vi.spyOn(Date, "now").mockReturnValue(nowEpoch + 2);
    vi.mocked(save).mockResolvedValue("/tmp/events.json");
    invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "evtx_create_export_session") {
        return {
          sessionId: "export-clock-snapshot",
          nextSequence: 0,
          receivedRecords: 0,
          receivedBytes: 0,
          expectedRecords: args?.expectedRecords,
        };
      }
      if (command === "evtx_append_export_chunk") {
        const payload = atob(args?.payloadBase64 as string);
        return {
          sessionId: "export-clock-snapshot",
          nextSequence: (args?.sequence as number) + 1,
          receivedRecords: payload.split("\n").length - 1,
          receivedBytes: payload.length,
          expectedRecords: 1,
        };
      }
      if (command === "evtx_finalize_export_session") {
        return { sessionId: "export-clock-snapshot", records: 1, bytes: 128 };
      }
      if (command === "load_markers") return null;
      return undefined;
    });

    render(<EvtxViewBar nowEpoch={nowEpoch} />);
    fireEvent.click(
      screen.getByTitle(
        "Export the events currently shown, using the same filters as the list",
      ),
    );
    fireEvent.click(screen.getByText("JSON"));

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith(
        "evtx_append_export_chunk",
        expect.objectContaining({ sequence: 0, payloadBase64: expect.any(String) }),
      ),
    );
    const append = invoke.mock.calls.find(([command]) => command === "evtx_append_export_chunk");
    const transported = JSON.parse(
      atob((append?.[1] as { payloadBase64: string }).payloadBase64).trimEnd(),
    );
    expect(transported).toEqual(boundaryRecord);
    expect(invoke).not.toHaveBeenCalledWith("evtx_export_records", expect.anything());
  });

  it("streams thousands of only the filtered records in visible sort order", async () => {
    const records = Array.from({ length: 2_505 }, (_, index): EvtxRecord => ({
      ...RECORD,
      id: index + 1,
      eventRecordId: index + 1,
      timestampEpoch: index + 1,
      channel: index % 5 === 0 ? "System" : "Application",
      level: index % 7 === 0 ? "Warning" : "Error",
      message: index % 11 === 0 ? `drop-${index}` : `keep-${index}`,
    }));
    const expected = records
      .filter(
        (record) =>
          record.channel === "Application" &&
          record.level === "Error" &&
          record.message.includes("keep"),
      )
      .sort((left, right) => right.timestampEpoch - left.timestampEpoch);
    seedEventLog();
    useEvtxStore.setState({
      records,
      selectedChannels: new Set(["Application"]),
      filterLevels: new Set(["Error"]),
      filterSearch: "keep",
      sortField: "time",
      sortDirection: "desc",
      timeWindow: "all",
    });
    vi.mocked(save).mockResolvedValue("/tmp/events.json");
    let receivedRecords = 0;
    let receivedBytes = 0;
    invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "evtx_create_export_session") {
        return {
          sessionId: "large-visible-export",
          nextSequence: 0,
          receivedRecords: 0,
          receivedBytes: 0,
          expectedRecords: args?.expectedRecords,
        };
      }
      if (command === "evtx_append_export_chunk") {
        const payload = atob(args?.payloadBase64 as string);
        receivedRecords += payload.split("\n").length - 1;
        receivedBytes += payload.length;
        return {
          sessionId: "large-visible-export",
          nextSequence: (args?.sequence as number) + 1,
          receivedRecords,
          receivedBytes,
          expectedRecords: expected.length,
        };
      }
      if (command === "evtx_finalize_export_session") {
        return {
          sessionId: "large-visible-export",
          records: receivedRecords,
          bytes: 9_999,
        };
      }
      if (command === "load_markers") return null;
      return undefined;
    });

    render(<EvtxViewBar nowEpoch={Date.now()} />);
    fireEvent.click(
      screen.getByTitle(
        "Export the events currently shown, using the same filters as the list",
      ),
    );
    fireEvent.click(screen.getByText("JSON"));

    // The visible status; the same text is also announced through a hidden live region.
    await waitFor(() =>
      expect(exportStatus()).toHaveTextContent(
        `Exported ${expected.length.toLocaleString()} events (9,999 bytes)`,
      ),
    );
    const appendCalls = invoke.mock.calls.filter(
      ([command]) => command === "evtx_append_export_chunk",
    );
    expect(appendCalls.length).toBeGreaterThan(1);
    const binary = appendCalls
      .map(([, args]) => atob((args as { payloadBase64: string }).payloadBase64))
      .join("");
    const transported = new TextDecoder()
      .decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)))
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as EvtxRecord);
    expect(transported.map((record) => record.id)).toEqual(
      expected.map((record) => record.id),
    );
    for (const [, args] of appendCalls) {
      const payload = atob((args as { payloadBase64: string }).payloadBase64);
      expect(payload.length).toBeLessThanOrEqual(MAX_EXPORT_CHUNK_BYTES);
      expect(payload.split("\n").length - 1).toBeLessThanOrEqual(
        MAX_EXPORT_CHUNK_RECORDS,
      );
    }
    expect(invoke).not.toHaveBeenCalledWith("evtx_export_records", expect.anything());
  });

  it("advances relative time windows when the loaded records refresh", async () => {
    vi.useFakeTimers();
    const nowEpoch = Date.parse("2026-08-18T13:00:00.000Z");
    vi.setSystemTime(nowEpoch);
    try {
      seedEventLog();
      useEvtxStore.setState({
        records: [
          {
            ...RECORD,
            timestamp: "2026-08-18T12:00:00.001Z",
            timestampEpoch: nowEpoch - 60 * 60 * 1000 + 1,
          },
        ],
        sourceMode: "files",
        timeWindow: "1h",
      });
      render(<EventLogWorkspace />);
      expect(recordGridRows(document.body).length).toBeGreaterThan(0);

      await act(async () => {
        vi.advanceTimersByTime(30_000);
        await Promise.resolve();
      });
      expect(recordGridRows(document.body).length).toBeGreaterThan(0);

      act(() =>
        useEvtxStore.setState((state) => ({ records: [...state.records] })),
      );
      expect(recordGridRows(document.body)).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("gives level filters descriptive state to keyboard and screen-reader users", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);

    const errorToggle = screen.getByRole("button", { name: "Toggle Error events" });
    expect(errorToggle).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(errorToggle);
    expect(errorToggle).toHaveAttribute("aria-pressed", "false");
  });

  // A live re-query empties the records (refreshLoadedChannels). The full-screen spinner belongs to
  // a source's first load only: every later refresh keeps the view bar, the filter row, the chip
  // row, the channel pane and the rail mounted, so the toggle that was just pressed keeps its focus
  // and an open popover stays open.
  describe("a live re-query", () => {
    const pendingQuery = () =>
      invoke.mockImplementation(async (command: string) => {
        if (command === "evtx_query_channels") return new Promise(() => undefined);
        if (command === "load_markers") return null;
        return undefined;
      });

    it("keeps the filter row mounted, and focus on the pressed toggle", async () => {
      pendingQuery();
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      // Toggling Information changes what the service is asked for, so this one re-queries.
      const information = screen.getByRole("button", { name: "Toggle Information events" });
      information.focus();
      expect(information).toHaveFocus();

      fireEvent.click(information);

      await waitFor(() =>
        expect(invoke).toHaveBeenCalledWith("evtx_query_channels", expect.anything()),
      );
      expect(useEvtxStore.getState().isLoading).toBe(true);
      expect(useEvtxStore.getState().records).toEqual([]);
      expect(screen.queryByText("Loading event logs...")).toBeNull();
      expect(screen.getByRole("button", { name: "Toggle Information events" })).toBe(information);
      expect(information).toHaveFocus();
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "true");
      expect(document.querySelector("[data-evtx-region='view-bar']")).not.toBeNull();
      expect(document.querySelector("[data-evtx-region='channels']")).not.toBeNull();
    });

    it("shows the row's busy state once the first batch streams in", async () => {
      pendingQuery();
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      fireEvent.click(screen.getByRole("button", { name: "Toggle Information events" }));
      await waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(true));

      // A batch lands while the query is still running.
      act(() => useEvtxStore.setState({ records: [fixtureRecord()] }));

      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "true");
      expect(screen.getByRole("progressbar", { name: "Reloading events" })).toBeInTheDocument();
      // Counts are unknown, not the batch's partial totals.
      expect(screen.getByRole("button", { name: "Toggle Error events" })).toHaveAccessibleDescription(
        /count not available/i,
      );
      expect(document.querySelector("[data-evtx-filter-count]")).toBeNull();
    });

    it("does not re-query for a toggle that leaves the server filter alone", async () => {
      pendingQuery();
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      const verbose = screen.getByRole("button", { name: "Toggle Verbose events" });
      verbose.focus();
      fireEvent.click(verbose);
      await act(async () => {
        await Promise.resolve();
      });
      expect(invoke).not.toHaveBeenCalledWith("evtx_query_channels", expect.anything());
      expect(useEvtxStore.getState().isLoading).toBe(false);
      expect(verbose).toHaveAttribute("aria-pressed", "false");
      expect(verbose).toHaveFocus();
    });

    it("keeps More filters open while Event IDs are typed, and sends one query when they are committed", async () => {
      pendingQuery();
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
      const dialog = await screen.findByRole("dialog", { name: "More filters" });
      const eventIds = within(dialog).getByRole("textbox", { name: "Event IDs" });
      eventIds.focus();

      for (const typed of ["4", "46", "462", "4624"]) {
        fireEvent.change(eventIds, { target: { value: typed } });
      }
      await act(async () => {
        await Promise.resolve();
      });
      // Nothing is sent per keystroke.
      expect(invoke).not.toHaveBeenCalledWith("evtx_query_channels", expect.anything());
      expect(useEvtxStore.getState().filterEventIds).toBe("");

      fireEvent.keyDown(eventIds, { key: "Enter" });
      await waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(true));

      const calls = invoke.mock.calls.filter(([name]) => name === "evtx_query_channels");
      expect(calls).toHaveLength(1);
      expect(calls[0][1].filter.eventIds).toEqual([{ kind: "single", id: 4624 }]);
      expect(useEvtxStore.getState().filterEventIds).toBe("4624");
      // The popover and the field survived the re-query.
      expect(screen.getByRole("dialog", { name: "More filters" })).toBeInTheDocument();
      expect(screen.getByRole("textbox", { name: "Event IDs" })).toBe(eventIds);
      expect(eventIds).toHaveFocus();
    });

    it("never brings the full-screen spinner back when a change made during the first live load is replayed", async () => {
      // A real first load: Application streams in and finishes while System is still reading, the
      // operator widens the window from the enabled Time window, and the load then ends. The replay
      // starts in the same tick the load ends, and the rows must stay mounted through it.
      const release = deferred<void>();
      let released = false;
      const streamed = (args: { requestId: string; channels: string[] }) => {
        const channel = args.channels[0];
        listeners.get("evtx-record-batch")?.({
          payload: {
            requestId: args.requestId,
            channel,
            sequence: 0,
            records: [{ ...RECORD, id: 1, eventRecordId: 1, channel }],
          },
        });
        listeners.get("evtx-record-stream-complete")?.({
          payload: { requestId: args.requestId, channel, sequenceCount: 1, totalRecords: 1 },
        });
        return {
          records: [],
          channels: [{ name: channel, eventCount: 1, sourceType: "live" as const }],
          totalRecords: 1,
          parseErrors: 0,
          errorMessages: [],
        };
      };
      invoke.mockImplementation(async (command: string, args: { requestId: string; channels: string[] }) => {
        if (command === "load_markers") return null;
        if (command === "evtx_enumerate_channels") {
          return ["Application", "System"].map((name) => ({
            name,
            eventCount: 1,
            sourceType: "live" as const,
            enabledState: "enabled" as const,
          }));
        }
        if (command !== "evtx_query_channels") return undefined;
        const reply = streamed(args);
        if (args.channels[0] === "System" && !released) await release.promise;
        return reply;
      });

      render(<EventLogWorkspace />);
      act(() => {
        void useEvtxStore.getState().enumerateChannels();
      });
      // Application's records have landed, so the rows are mounted while System is still reading.
      const group = await screen.findByRole("group", { name: "Level" });
      expect(useEvtxStore.getState().isLoading).toBe(true);

      let spinnerSeen = false;
      const observer = new MutationObserver(() => {
        if (document.body.textContent?.includes("Loading event logs...")) spinnerSeen = true;
      });
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });

      fireEvent.click(screen.getByRole("combobox", { name: "Time window" }));
      fireEvent.click(await screen.findByRole("option", { name: "Last 7 days" }));
      expect(useEvtxStore.getState().timeWindow).toBe("7d");

      released = true;
      release.resolve();
      await waitFor(() =>
        expect(invoke.mock.calls.filter(([name]) => name === "evtx_query_channels")).toHaveLength(4),
      );
      await waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
      observer.disconnect();

      expect(spinnerSeen).toBe(false);
      expect(screen.getByRole("group", { name: "Level" })).toBe(group);
    });

    it("still shows the full-screen spinner on a source's first load", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        records: [],
        channels: [{ name: "Application", eventCount: 0, sourceType: "live" }],
        isLoading: true,
      });
      render(<EventLogWorkspace />);
      expect(screen.getByText("Loading event logs...")).toBeInTheDocument();
      expect(screen.queryByRole("group", { name: "Level" })).toBeNull();
    });

    it("keeps the rows mounted for a refetch after a first load that found nothing", async () => {
      pendingQuery();
      useEvtxStore.setState({
        sourceMode: "live",
        records: [],
        channels: [{ name: "Application", eventCount: 0, sourceType: "live" }],
        selectedChannels: new Set(["Application"]),
        loadedChannels: new Set<string>(),
        isLoading: true,
      });
      render(<EventLogWorkspace />);
      expect(screen.getByText("Loading event logs...")).toBeInTheDocument();

      // The first load completes: the channel is loaded and holds nothing in the window.
      act(() => useEvtxStore.setState({ isLoading: false, loadedChannels: new Set(["Application"]) }));
      const information = screen.getByRole("button", { name: "Toggle Information events" });
      information.focus();

      // The operator corrects the filter that found nothing: the refetch must not swap the view out.
      fireEvent.click(information);
      await waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(true));
      expect(screen.queryByText("Loading event logs...")).toBeNull();
      expect(screen.getByRole("button", { name: "Toggle Information events" })).toBe(information);
      expect(information).toHaveFocus();
    });

    it("shows the first-load spinner when the source changes in one batch with isLoading", () => {
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      expect(screen.getByRole("group", { name: "Level" })).toBeInTheDocument();

      // What a file parse does to the store at its start: no source and loading, in one set().
      act(() =>
        useEvtxStore.setState({
          sourceMode: null,
          records: [],
          channels: [],
          loadedChannels: new Set<string>(),
          isLoading: true,
        }),
      );
      expect(screen.getByText("Loading event logs...")).toBeInTheDocument();
      expect(screen.queryByRole("group", { name: "Level" })).toBeNull();
    });

    it("goes through the transition the store really makes for a machine change: no source, then a first load", () => {
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      expect(screen.getByRole("group", { name: "Level" })).toBeInTheDocument();

      // enumerateRemoteChannels first clears the source (nothing loading), then enumerateChannels
      // starts the remote load. Two store updates, not one.
      act(() =>
        useEvtxStore.setState({
          remoteMachine: null,
          channels: [],
          records: [],
          sourceMode: null,
          selectedChannels: new Set<string>(),
          loadedChannels: new Set<string>(),
          isLoading: false,
        }),
      );
      expect(screen.queryByRole("group", { name: "Level" })).toBeNull();
      expect(screen.queryByText("Loading event logs...")).toBeNull();

      act(() =>
        useEvtxStore.setState({
          remoteMachine: "SRV01",
          sourceMode: "live",
          channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
          isLoading: true,
        }),
      );
      expect(screen.getByText("Loading event logs...")).toBeInTheDocument();
      expect(screen.queryByRole("group", { name: "Level" })).toBeNull();

      act(() => useEvtxStore.setState({ isLoading: false, loadedChannels: new Set(["Application"]) }));
      expect(screen.getByRole("group", { name: "Level" })).toBeInTheDocument();
    });

    it("pins the source key: a machine change in one batch with isLoading is a new source", () => {
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      expect(screen.getByRole("group", { name: "Level" })).toBeInTheDocument();

      act(() =>
        useEvtxStore.setState({
          remoteMachine: "SRV01",
          records: [],
          loadedChannels: new Set<string>(),
          isLoading: true,
        }),
      );
      expect(screen.getByText("Loading event logs...")).toBeInTheDocument();

      act(() => useEvtxStore.setState({ isLoading: false, loadedChannels: new Set(["Application"]) }));
      expect(screen.getByRole("group", { name: "Level" })).toBeInTheDocument();
      // And the next refetch for this machine keeps it mounted.
      act(() => useEvtxStore.setState({ isLoading: true, records: [], loadedChannels: new Set<string>() }));
      expect(screen.queryByText("Loading event logs...")).toBeNull();
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "true");
    });

    it("goes back to the first-load spinner once the source is reset", async () => {
      seedFixtureEvents();
      render(<EventLogWorkspace />);
      expect(screen.getByRole("group", { name: "Level" })).toBeInTheDocument();

      act(() => useEvtxStore.getState().reset());
      act(() =>
        useEvtxStore.setState({
          sourceMode: "live",
          channels: [{ name: "Application", eventCount: 0, sourceType: "live" }],
          isLoading: true,
        }),
      );

      expect(screen.getByText("Loading event logs...")).toBeInTheDocument();
      expect(screen.queryByRole("group", { name: "Level" })).toBeNull();
    });
  });

  it("mounts the chip row under the filter row with the workspace's visible and loaded counts", () => {
    seedFixtureEvents();
    useEvtxStore.setState({ filterSearch: "no event says this" });
    render(<EventLogWorkspace />);

    const filterRow = document.querySelector("[data-evtx-region='filter-row']")!;
    const chipRow = document.querySelector("[data-evtx-region='chip-row']")!;
    expect(screen.getByRole("button", { name: "Remove Search: no event says this" })).toBeInTheDocument();
    // Directly after the filter row, above the body.
    expect(filterRow.nextElementSibling).toBe(chipRow);
    // The search removes the only loaded event from view: 0 shown of 1 loaded, not a bare 0.
    expect(chipRow.querySelector("[data-evtx-filter-count]")?.textContent).toBe("Showing 0 of 1");

    fireEvent.click(screen.getByRole("button", { name: "Clear all" }));
    expect(document.querySelector("[data-evtx-region='chip-row']")).toBeNull();
  });

  it("identifies invalid ordinary and quick Event ID filters", async () => {
    seedFixtureEvents();
    useEvtxStore.setState((state) => ({
      filterEventIds: "1000,broken",
      quickFilter: {
        ...state.quickFilter,
        mode: "eventIds",
        query: "1000,broken",
      },
    }));
    render(<EvtxFilterBar nowEpoch={Date.now()} />);
    // Event IDs and the quick filter live in the More filters popover, one open away.
    fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
    await screen.findByRole("dialog", { name: "More filters" });

    const eventIds = screen.getByRole("textbox", { name: "Event IDs" });
    expect(eventIds).toHaveAttribute("aria-invalid", "true");
    expect(eventIds).toHaveAccessibleDescription("Invalid Event IDs");

    const quickEventIds = screen.getByRole("textbox", { name: "Quick filter query" });
    expect(quickEventIds).toHaveAttribute("aria-invalid", "true");
    expect(quickEventIds).toHaveAccessibleDescription("Invalid quick Event IDs");

    expect(screen.getByRole("alert", { name: "Invalid Event IDs" })).toBeVisible();
    expect(screen.getByRole("alert", { name: "Invalid quick Event IDs" })).toBeVisible();

    fireEvent.change(eventIds, { target: { value: "1000" } });
    fireEvent.change(quickEventIds, { target: { value: "1000" } });

    expect(eventIds).toHaveAttribute("aria-invalid", "false");
    expect(quickEventIds).toHaveAttribute("aria-invalid", "false");
    expect(screen.queryByRole("alert", { name: "Invalid Event IDs" })).toBeNull();
    expect(screen.queryByRole("alert", { name: "Invalid quick Event IDs" })).toBeNull();
  });

  it("names the sort-direction action that the button will perform", async () => {
    seedFixtureEvents();
    render(<EvtxFilterBar nowEpoch={Date.now()} />);
    fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
    await screen.findByRole("dialog", { name: "More filters" });

    const changeToDescending = screen.getByTitle(
      "Change sort direction to descending",
    );
    expect(changeToDescending).toHaveAttribute(
      "aria-label",
      "Change sort direction to descending",
    );
    fireEvent.click(changeToDescending);

    expect(useEvtxStore.getState().sortDirection).toBe("desc");
    expect(changeToDescending).toHaveAttribute(
      "aria-label",
      "Change sort direction to ascending",
    );
    expect(changeToDescending).toHaveAttribute(
      "title",
      "Change sort direction to ascending",
    );
  });

  it("shows event detail and Event Data in the rail, with the XML on its own sub-tab", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);

    const eventRow = recordGridRows(document.body)[0];
    expect(eventRow).toBeDefined();
    fireEvent.click(eventRow!);

    // A row click switches the rail to Details; the tab now reads "Event {id}".
    expect(screen.getByRole("tab", { name: "Event 1000" })).toHaveAttribute("aria-selected", "true");
    const detail = screen.getByRole("region", { name: "Event log details" });
    expect(within(detail).getByText("Event 1000")).toBeInTheDocument();
    expect(
      within(detail).getAllByText("Faulting application name: setup.exe").length
    ).toBeGreaterThan(0);
    expect(within(detail).getByText("Event Data")).toBeInTheDocument();
    expect(within(detail).getByText("AppName")).toBeInTheDocument();
    expect(within(detail).getAllByText("Application Error").length).toBeGreaterThan(0);

    fireEvent.click(within(detail).getByRole("tab", { name: "XML" }));
    expect(screen.getByText(/<EventID>1000<\/EventID>/)).toBeInTheDocument();
  });

  it("reopens a hidden rail on Details when a row is clicked, even from the Insights tab", () => {
    seedFixtureEvents();
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
    render(<EventLogWorkspace />);
    const rail = document.querySelector<HTMLElement>('[data-evtx-region="rail"]');
    expect(rail).not.toBeVisible();

    fireEvent.click(recordGridRows(document.body)[0]!);

    expect(rail).toBeVisible();
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
  });

  it("re-clicking the selected row keeps it selected and brings Details back, from Insights and from a hidden rail", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);
    const rail = document.querySelector<HTMLElement>('[data-evtx-region="rail"]');
    const firstRow = () => recordGridRows(document.body)[0]!;

    fireEvent.click(firstRow());
    const selectedId = useEvtxStore.getState().selectedRecordId;
    expect(selectedId).not.toBeNull();

    act(() => useEvtxLayoutStore.getState().setRailTab("insights"));
    fireEvent.click(firstRow());
    expect(useEvtxStore.getState().selectedRecordId).toBe(selectedId);
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");

    act(() => {
      useEvtxLayoutStore.getState().setRailTab("insights");
      useEvtxLayoutStore.getState().setPanel("insights", false);
    });
    expect(rail).not.toBeVisible();
    fireEvent.keyDown(firstRow(), { key: "Enter" });
    expect(useEvtxStore.getState().selectedRecordId).toBe(selectedId);
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(rail).toBeVisible();
  });

  it("moves the selection with the arrow keys without switching the rail tab or reopening a hidden rail", () => {
    seedFixtureEvents();
    const [only] = useEvtxStore.getState().records;
    useEvtxStore.setState({
      records: [only, { ...only, id: only.id + 1, eventRecordId: only.eventRecordId + 1 }],
    });
    render(<EventLogWorkspace />);
    fireEvent.click(recordGridRows(document.body)[0]!);
    const first = useEvtxStore.getState().selectedRecordId;
    act(() => {
      useEvtxLayoutStore.getState().setRailTab("insights");
      useEvtxLayoutStore.getState().setPanel("insights", false);
    });

    const row = recordGridRows(document.body)[0]!;
    row.focus();
    fireEvent.keyDown(row, { key: "ArrowDown" });

    expect(useEvtxStore.getState().selectedRecordId).not.toBe(first);
    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(false);
  });

  it("scrolls a selection made outside the grid into view, but not when a live-tail renumber only changes the ids", () => {
    seedFixtureEvents();
    const [only] = useEvtxStore.getState().records;
    const two = [only, { ...only, id: only.id + 1, eventRecordId: only.eventRecordId + 1 }];
    useEvtxStore.setState({ records: two, selectedRecordId: null });
    render(<EventLogWorkspace />);

    // Previous and Next select from outside the grid: the row is brought into view.
    virtualizerState.scrollToIndex.mockClear();
    act(() => useEvtxStore.getState().setSelectedRecordId(1));
    expect(virtualizerState.scrollToIndex).toHaveBeenCalledTimes(1);

    // A tail batch with an older record renumbers every id; the selected record is the same
    // record at a new id, so nothing scrolls.
    virtualizerState.scrollToIndex.mockClear();
    const older = { ...only, eventRecordId: only.eventRecordId - 10, timestampEpoch: only.timestampEpoch - 1000 };
    const renumbered = [older, only, two[1]].map((record, index) => ({ ...record, id: index }));
    act(() => useEvtxStore.setState({ records: renumbered, selectedRecordId: 2 }));
    expect(virtualizerState.scrollToIndex).not.toHaveBeenCalled();
  });

  // The export control has two asynchronous phases before an abort controller exists: the save
  // dialog, and the session the dialog's answer unlocks. These tests drive the real control so the
  // guard is judged by what an operator can make happen, not by reading the ref.
  const selectExportFormat = async (label: string) => {
    fireEvent.click(
      screen.getByTitle("Export the events currently shown, using the same filters as the list"),
    );
    fireEvent.click(await screen.findByRole("menuitem", { name: label }));
  };

  // The shared dialog mock is not reset between tests in this file, and these tests judge the guard
  // by how many dialogs were opened, so each one starts from a clean history.
  const dialogMock = () => {
    const dialog = vi.mocked(save);
    dialog.mockReset();
    return dialog;
  };

  it("opens one save dialog when a second export is asked for before the first resolves", async () => {
    seedEventLog();
    const dialog = Promise.withResolvers<string | null>();
    dialogMock().mockImplementation(() => dialog.promise);
    render(<EvtxViewBar nowEpoch={Date.now()} />);

    await selectExportFormat("JSON");
    await selectExportFormat("JSON");

    expect(save).toHaveBeenCalledTimes(1);

    await act(async () => {
      dialog.resolve(null);
    });
  });

  it("allows another export after the save dialog is dismissed", async () => {
    seedEventLog();
    dialogMock().mockResolvedValue(null);
    render(<EvtxViewBar nowEpoch={Date.now()} />);

    await selectExportFormat("JSON");
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));

    await selectExportFormat("JSON");

    await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  });

  it("allows another export after the save dialog itself fails", async () => {
    seedEventLog();
    dialogMock()
      .mockRejectedValueOnce(new Error("dialog unavailable"))
      .mockResolvedValue(null);
    render(<EvtxViewBar nowEpoch={Date.now()} />);

    await selectExportFormat("JSON");
    await waitFor(() =>
      expect(screen.getByText("Export failed: dialog unavailable")).toBeInTheDocument(),
    );

    await selectExportFormat("JSON");

    await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  });

  it("completes an export after an earlier attempt failed", async () => {
    seedEventLog();
    dialogMock()
      .mockRejectedValueOnce(new Error("dialog unavailable"))
      .mockResolvedValue("/tmp/events.json");
    invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "evtx_create_export_session") {
        return {
          sessionId: "retry-export",
          nextSequence: 0,
          receivedRecords: 0,
          receivedBytes: 0,
          expectedRecords: args?.expectedRecords,
        };
      }
      if (command === "evtx_append_export_chunk") {
        const payload = atob(args?.payloadBase64 as string);
        return {
          sessionId: "retry-export",
          nextSequence: (args?.sequence as number) + 1,
          receivedRecords: payload.split("\n").length - 1,
          receivedBytes: payload.length,
          expectedRecords: 1,
        };
      }
      if (command === "evtx_finalize_export_session") {
        return { sessionId: "retry-export", records: 1, bytes: 128 };
      }
      if (command === "load_markers") return null;
      return undefined;
    });
    render(<EvtxViewBar nowEpoch={Date.now()} />);

    await selectExportFormat("JSON");
    await waitFor(() =>
      expect(screen.getByText("Export failed: dialog unavailable")).toBeInTheDocument(),
    );

    await selectExportFormat("JSON");

    await waitFor(() => expect(exportStatus()).toHaveTextContent(/^Exported /));
  });

  it("keeps a running export as the only one, with the control unavailable while it runs", async () => {
    seedEventLog();
    dialogMock().mockResolvedValue("/tmp/events.json");
    let sessions = 0;
    const held = Promise.withResolvers<never>();
    invoke.mockImplementation(async (command: string) => {
      if (command === "evtx_create_export_session") {
        sessions += 1;
        // Held open: the export never finishes, which is the state the guard exists for.
        return held.promise;
      }
      if (command === "load_markers") return null;
      return undefined;
    });
    render(<EvtxViewBar nowEpoch={Date.now()} />);

    await selectExportFormat("JSON");
    await waitFor(() => expect(sessions).toBe(1));
    await waitFor(() =>
      expect(
        screen.getByTitle("Export the events currently shown, using the same filters as the list"),
      ).toBeDisabled(),
    );

    fireEvent.click(
      screen.getByTitle("Export the events currently shown, using the same filters as the list"),
    );

    expect(save).toHaveBeenCalledTimes(1);
    expect(sessions).toBe(1);
  });
});

describe("Event Log Viewer preview badge", () => {
  beforeEach(() => {
    configureInvoke();
    useEvtxStore.getState().reset();
    resetVirtualizerState();
    useUiStore.getState().resetLogAccessibilityPreferences();
  });

  it("registry labels the workspace as preview", () => {
    expect(eventLogWorkspace.label).toBe("Event Log Viewer (Preview)");
    expect(eventLogWorkspace.statusLabel).toBe("Event Log (Preview)");
  });
  it("shows a Preview badge in the filter bar with events loaded", () => {
    seedEventLog();
    render(<EventLogWorkspace />);

    expect(screen.getByText("Preview")).toBeInTheDocument();
  });
});
