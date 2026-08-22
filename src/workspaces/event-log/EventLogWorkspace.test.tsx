import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
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
  recalculate: () => undefined,
  measureElementSize: (element: HTMLElement) => {
    const hasLevelBadge = Array.from(element.children).some(
      (child) => (child as HTMLElement).hasAttribute("data-evtx-level-badge"),
    );
    return element.getAttribute("role") === "treeitem" &&
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
    if (command === "evtx_build_unified_timeline") {
      return { items: [], unplaced: [], edges: [], coverageGaps: [] };
    }
    if (command === "load_markers") return null;
    return undefined;
  });
}

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
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
      virtualizerState.totalSize = Array.from({ length: count }, (_, index) =>
        measuredSize(index)
      ).reduce((total, size) => total + size, 0);
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
      scrollToIndex: vi.fn(),
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
import { useEvtxStore } from "./evtx-store";
import { defaultColumnConfig } from "./evtx-columns";
import { EventLogWorkspace } from "./EventLogWorkspace";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxDetailPane } from "./EvtxDetailPane";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxTimeline } from "./EvtxTimeline";
import { SourcePicker } from "./SourcePicker";
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

function recordTreeItems(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>("[data-evtx-marker-key]"));
}
describe("event-viewer shared font metrics", () => {
  beforeEach(() => {
    configureInvoke();
    useEvtxStore.getState().reset();
    virtualizerState.measured.length = 0;
    virtualizerState.items.length = 0;
    virtualizerState.initialItems.length = 0;
    virtualizerState.measuredSizes.clear();
    virtualizerState.visibleCount = null;
    virtualizerState.measureCalls = 0;
    virtualizerState.cacheResetCalls = 0;
    virtualizerState.resizeObserverCalls = 0;
    virtualizerState.resizeItemCalls = 0;
    virtualizerState.resizedSizes.clear();
    virtualizerState.totalSize = 0;
    useUiStore.getState().resetLogAccessibilityPreferences();
  });

  afterEach(() => {
    cleanup();
  });

  it("keeps row, virtualizer, pickers, filter, and detail metrics aligned at persisted limits", () => {
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

    const filter = render(<EvtxFilterBar />);
    expect(screen.getByRole("button", { name: "Toggle Critical events" }).style.fontSize).toBe(
      `${Math.max(11, smallList.fontSize - 1)}px`
    );
    expect(screen.getByPlaceholderText("Event IDs (comma sep.)").style.fontSize).toBe(
      `${Math.max(11, smallList.fontSize - 1)}px`
    );
    expect(screen.getAllByRole("combobox")[0].style.fontSize).toBe(
      `${Math.max(11, smallList.fontSize - 1)}px`
    );
    filter.unmount();
    const timeline = render(<EvtxTimeline />);
    const [groupRow, recordRow] = screen.getAllByRole("treeitem");
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
    expect(detailRoot.style.overflow).toBe("auto");
    expect(detailRoot.style.lineHeight).toBe(`${smallDetailLineHeight}px`);
    expect(screen.getByRole("button", { name: "Show Raw XML" }).style.fontSize).toBe(
      `${MIN_LOG_DETAILS_FONT_SIZE}px`
    );
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

    const filterLarge = render(<EvtxFilterBar />);
    expect(screen.getByRole("button", { name: "Toggle Critical events" }).style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    expect(screen.getByPlaceholderText("Event IDs (comma sep.)").style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    expect(screen.getAllByRole("combobox")[0].style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    filterLarge.unmount();

    virtualizerState.resizedSizes.clear();
    virtualizerState.measuredSizes.clear();
    virtualizerState.measured.length = 0;
    virtualizerState.items.length = 0;
    const timelineLarge = render(<EvtxTimeline />);
    const [, recordRowLarge] = screen.getAllByRole("treeitem");
    expect(recordRowLarge.style.lineHeight).toBe(`${largeList.rowLineHeight}px`);
    expect(virtualizerState.measured).toContain(recordRowLarge);
    expect(virtualizerState.items[1]).toMatchObject({
      index: 1,
      size: largeList.rowLineHeight + LEVEL_BADGE_PRESENT_OFFSET,
      start: largeList.rowHeight,
    });
    const groupRowLarge = screen.getAllByRole("treeitem")[0];
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
    expect(detailRootLarge.style.overflow).toBe("auto");

    setDetailsFontSize(MAX_LOG_DETAILS_FONT_SIZE);
    expect(detailRootLarge.style.fontSize).toBe(`${MAX_LOG_DETAILS_FONT_SIZE}px`);
    expect(detailRootLarge.style.lineHeight).toBe(
      `${getLogDetailsLineHeight(MAX_LOG_DETAILS_FONT_SIZE)}px`
    );
    expect(detailRootLarge.style.overflow).toBe("auto");
    expect(screen.getByRole("button", { name: "Show Raw XML" }).style.fontSize).toBe(
      `${MAX_LOG_DETAILS_FONT_SIZE}px`
    );
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
    const filter = render(<EvtxFilterBar />);
    const filterButton = filter.getByRole("button", { name: "Toggle Critical events" });
    const timeline = render(<EvtxTimeline />);
    const recordRow = recordTreeItems(timeline.container)[0];
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
    expect(filterButton.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE - 1}px`);
    expect(recordTreeItems(timeline.container)[0]).toBe(recordRow);
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
    expect(recordTreeItems(timeline.container)).toHaveLength(1);
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
  it("remeasures a record after a group header shifts its row index", () => {
    seedEventLog();
    setListFontSize(MIN_LOG_LIST_FONT_SIZE);

    const timeline = render(<EvtxTimeline />);
    const recordRow = recordTreeItems(timeline.container)[0];
    act(() => {
      useEvtxStore.setState({ groupBy: ["level"] });
    });
    expect(recordTreeItems(timeline.container)[0]).toBe(recordRow);
    expect(recordRow.getAttribute("role")).toBe("treeitem");

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
    expect(timeline.getAllByRole("option")).toHaveLength(2);
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
    const row = timeline.getByRole("option");
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
    expect(recordTreeItems(timeline.container)).toHaveLength(1);
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
    isLoading: false,
    loadError: null,
    coverageGaps: [],
    selectedChannels: new Set([
      "Application",
      "System",
      "Microsoft-Windows-AAD/Operational",
    ]),
    loadedChannels: new Set(["Application"]),
    filterLevels: new Set([
      "Critical",
      "Error",
      "Warning",
      "Information",
      "Verbose",
    ]),
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

describe("EventLogWorkspace fixtures", () => {
  beforeEach(() => {
    invoke.mockReset();
    configureInvoke();
    useEvtxStore.getState().reset();
  });

  afterEach(() => {
    cleanup();
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
    expect(recordTreeItems(document.body)).toHaveLength(1);

    const message =
      "No .evtx files were found. Source diagnostics: C:/protected/Security.evtx: Access is denied";
    act(() => {
      useEvtxStore.getState().setLoadError(message);
    });

    expect(screen.getByText(message)).toHaveAttribute("role", "alert");
    expect(recordTreeItems(document.body)).toHaveLength(1);
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

  it("gives level filters descriptive state to keyboard and screen-reader users", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);

    const errorToggle = screen.getByRole("button", { name: "Toggle Error events" });
    expect(errorToggle).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(errorToggle);
    expect(errorToggle).toHaveAttribute("aria-pressed", "false");
  });

  it("names the sort-direction action that the button will perform", () => {
    seedFixtureEvents();
    render(<EvtxFilterBar />);

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

  it("shows event detail, Event Data, and Show/Hide Raw XML", () => {
    seedFixtureEvents();
    render(<EventLogWorkspace />);

    const eventRow = recordTreeItems(document.body)[0];
    expect(eventRow).toBeDefined();
    fireEvent.click(eventRow!);

    expect(screen.getByText("Event 1000")).toBeInTheDocument();
    expect(
      screen.getAllByText("Faulting application name: setup.exe").length
    ).toBeGreaterThan(0);
    expect(screen.getByText("Event Data")).toBeInTheDocument();
    expect(screen.getByText("AppName")).toBeInTheDocument();
    expect(screen.getAllByText("Application Error").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Show Raw XML" }));
    expect(screen.getByRole("button", { name: "Hide Raw XML" })).toBeInTheDocument();
    expect(screen.getByText(/<EventID>1000<\/EventID>/)).toBeInTheDocument();
  });
});
