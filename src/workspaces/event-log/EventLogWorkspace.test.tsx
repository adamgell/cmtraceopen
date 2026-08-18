import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const virtualizerState = vi.hoisted(() => ({
  measured: [] as HTMLElement[],
  measuredSizes: new Map<number, number>(),
  items: [] as Array<{ index: number; size: number; start: number; end: number; key: string | number }>,
  totalSize: 0,
  remeasure: () => undefined,
  recalculate: () => undefined,
  measureElement: (element: HTMLElement | null) => {
    if (!element) return;
    const index = Number(element.dataset.index);
    const measured =
      element.getAttribute("role") === "treeitem"
        ? Number.parseFloat(element.style.height)
        : Number.parseFloat(element.style.lineHeight) + 5;
    if (!virtualizerState.measured.includes(element)) {
      virtualizerState.measured.push(element);
    }
    virtualizerState.measuredSizes.set(index, measured);
  },
}));
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
    estimateSize: () => number;
    getItemKey?: (index: number) => string | number;
  }) => {
    const measuredSize = (index: number) =>
      virtualizerState.measuredSizes.get(index) ?? estimateSize();
    const getTotalSize = () => {
      virtualizerState.totalSize = Array.from({ length: count }, (_, index) =>
        measuredSize(index)
      ).reduce((total, size) => total + size, 0);
      return virtualizerState.totalSize;
    };
    const getVirtualItems = () => {
      let start = 0;
      const items = Array.from({ length: count }, (_, index) => {
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
      virtualizerState.items = items;
      return items;
    };
    virtualizerState.remeasure = () => {
      for (const element of virtualizerState.measured) {
        virtualizerState.measureElement(element);
      }
    };
    virtualizerState.recalculate = () => {
      getTotalSize();
      getVirtualItems();
    };
    return {
      getTotalSize,
      getVirtualItems,
      measureElement: virtualizerState.measureElement,
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
    sourceMode: "files",
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application"]),
    selectedRecordId: RECORD.id,
  });
}

describe("event-viewer shared font metrics", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    virtualizerState.measured.length = 0;
    virtualizerState.items.length = 0;
    virtualizerState.measuredSizes.clear();
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
    expect(screen.getByRole("button", { name: "Crit" }).style.fontSize).toBe(
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
    const timelineRoot = screen.getByRole("tree");
    const groupRow = screen.getByRole("treeitem");
    act(() => {
      virtualizerState.remeasure();
      virtualizerState.recalculate();
    });
    const recordRow = screen.getByRole("option");
    expect(recordRow.style.fontSize).toBe(`${smallList.fontSize}px`);
    expect(recordRow.style.lineHeight).toBe(`${smallList.rowLineHeight}px`);
    expect(virtualizerState.measured).toContain(recordRow);
    expect(virtualizerState.items[1]).toMatchObject({
      index: 1,
      size: smallList.rowHeight + 2,
      start: smallList.rowHeight,
    });
    expect(virtualizerState.totalSize).toBe(smallList.rowHeight + smallList.rowHeight + 2);
    expect(groupRow.style.height).toBe(`${smallList.rowHeight}px`);
    fireEvent.keyDown(timelineRoot, { key: "ArrowDown" });
    expect(timelineRoot).toHaveFocus();
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
    expect(screen.getByRole("button", { name: "Crit" }).style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    expect(screen.getByPlaceholderText("Event IDs (comma sep.)").style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    expect(screen.getAllByRole("combobox")[0].style.fontSize).toBe(
      `${Math.max(11, largeList.fontSize - 1)}px`
    );
    filterLarge.unmount();

    virtualizerState.measured.length = 0;
    virtualizerState.items.length = 0;
    virtualizerState.measuredSizes.clear();
    const timelineLarge = render(<EvtxTimeline />);
    const timelineRootLarge = screen.getByRole("tree");
    const recordRowLarge = screen.getByRole("option");
    act(() => {
      virtualizerState.remeasure();
      virtualizerState.recalculate();
    });
    expect(recordRowLarge.style.fontSize).toBe(`${largeList.fontSize}px`);
    expect(recordRowLarge.style.lineHeight).toBe(`${largeList.rowLineHeight}px`);
    expect(virtualizerState.measured).toContain(recordRowLarge);
    expect(virtualizerState.items[1]).toMatchObject({
      index: 1,
      size: largeList.rowHeight + 2,
      start: largeList.rowHeight,
    });
    const groupRowLarge = screen.getByRole("treeitem");
    expect(groupRowLarge.style.height).toBe(`${largeList.rowHeight}px`);
    expect(virtualizerState.totalSize).toBe(
      largeList.rowHeight + largeList.rowHeight + 2
    );
    fireEvent.keyDown(timelineRootLarge, { key: "ArrowDown" });
    expect(timelineRootLarge).toHaveFocus();
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
    const filterButton = filter.getByRole("button", { name: "Crit" });
    const timeline = render(<EvtxTimeline />);
    const recordRow = timeline.getByRole("option");

    expect(channelInput.style.fontSize).toBe(`${MIN_LOG_LIST_FONT_SIZE}px`);
    expect(channelRow.style.height).toBe(
      `${getLogListMetrics(MIN_LOG_LIST_FONT_SIZE).rowHeight}px`
    );
    expect(filterButton.style.fontSize).toBe(`${MIN_LOG_LIST_FONT_SIZE}px`);
    expect(recordRow.style.fontSize).toBe(`${MIN_LOG_LIST_FONT_SIZE}px`);

    setListFontSize(MAX_LOG_LIST_FONT_SIZE);
    act(() => {
      virtualizerState.remeasure();
      virtualizerState.recalculate();
    });
    const largeList = getLogListMetrics(MAX_LOG_LIST_FONT_SIZE);

    expect(channel.getByPlaceholderText("Filter channels...")).toBe(channelInput);
    expect(channelInput.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE}px`);
    expect(channelRow.style.height).toBe(`${largeList.rowHeight}px`);
    expect(filter.getByRole("button", { name: "Crit" })).toBe(filterButton);
    expect(filterButton.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE - 1}px`);
    expect(timeline.getByRole("option")).toBe(recordRow);
    expect(recordRow.style.fontSize).toBe(`${MAX_LOG_LIST_FONT_SIZE}px`);
    expect(recordRow.style.lineHeight).toBe(`${largeList.rowLineHeight}px`);
    expect(virtualizerState.items[1].start).toBe(largeList.rowHeight);
    expect(virtualizerState.totalSize).toBe(
      largeList.rowHeight + largeList.rowHeight + 2
    );
  });
});
