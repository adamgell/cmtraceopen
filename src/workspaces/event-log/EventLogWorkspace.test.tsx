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
import { useEvtxStore } from "./evtx-store";
import { defaultColumnConfig, visibleColumns } from "./evtx-columns";
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

function recordGridRows(root: HTMLElement): HTMLElement[] {
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
    virtualizerState.scrollToIndex.mockClear();
    virtualizerState.resizedSizes.clear();
    virtualizerState.totalSize = 0;
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

    const filter = render(<EvtxFilterBar nowEpoch={Date.now()} />);
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

    const filterLarge = render(<EvtxFilterBar nowEpoch={Date.now()} />);
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
    expect(filterButton.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE - 1}px`);
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
    invoke.mockResolvedValue(128);

    render(<EvtxFilterBar nowEpoch={nowEpoch} />);
    fireEvent.click(
      screen.getByTitle(
        "Export the events currently shown, using the same filters as the list",
      ),
    );
    fireEvent.click(screen.getByText("JSON"));

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith(
        "evtx_export_records",
        expect.objectContaining({ records: [boundaryRecord] }),
      ),
    );
  });

  it("ages relative time windows for loaded file sources", async () => {
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

  it("identifies invalid ordinary and quick Event ID filters", () => {
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

  it("names the sort-direction action that the button will perform", () => {
    seedFixtureEvents();
    render(<EvtxFilterBar nowEpoch={Date.now()} />);

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

    const eventRow = recordGridRows(document.body)[0];
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
