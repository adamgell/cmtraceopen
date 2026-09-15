import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LogListView } from "./LogListView";
import { useFilterStore } from "../../stores/filter-store";
import { useLogStore } from "../../stores/log-store";
import { useMarkerStore } from "../../stores/marker-store";
import { useUiStore } from "../../stores/ui-store";
import type { LogEntry, LogSource } from "../../types/log";

const calcAutoFitWidthMock = vi.fn();

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({
    count,
    estimateSize,
  }: {
    count: number;
    estimateSize: () => number;
  }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        size: estimateSize(),
        start: index * estimateSize(),
      })),
    scrollToIndex: vi.fn(),
  }),
}));

vi.mock("../../lib/column-config", async () => {
  const actual = await vi.importActual<typeof import("../../lib/column-config")>(
    "../../lib/column-config"
  );

  return {
    ...actual,
    calcAutoFitWidth: (...args: Parameters<typeof actual.calcAutoFitWidth>) =>
      calcAutoFitWidthMock(...args),
  };
});

vi.mock("./LogRow", () => ({
  LogRow: ({
    entry,
    rowDomId,
    onToggleMarker,
  }: {
    entry: LogEntry;
    rowDomId: string;
    onToggleMarker?: (filePath: string, lineId: number) => void;
  }) => (
    <div id={rowDomId} className="log-row">
      <button
        aria-label={`Toggle marker ${entry.id}`}
        onClick={() => onToggleMarker?.(entry.filePath, entry.id)}
      />
      {entry.message}
    </div>
  ),
}));

vi.mock("./SectionDividerRow", () => ({
  SectionDividerRow: ({ entry }: { entry: LogEntry }) => <div>{entry.message}</div>,
}));

vi.mock("./MergeLegendBar", () => ({
  MergeLegendBar: () => null,
}));

vi.mock("../../hooks/use-context-menu", () => ({
  useContextMenu: () => ({
    showContextMenu: vi.fn(),
  }),
}));

function makeEntry(id: number, filePath: string, message = "log entry"): LogEntry {
  return {
    id,
    lineNumber: id,
    message,
    component: null,
    timestamp: 0,
    timestampDisplay: "2026-07-10 00:00:00",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped",
    filePath,
    timezoneOffset: null,
  };
}

function getSourcePath(source: LogSource): string {
  return source.kind === "known" ? source.defaultPath : source.path;
}

function setLogViewState(
  source: LogSource,
  entries: LogEntry[],
  mode: "single-file" | "aggregate-folder"
) {
  const sourcePath = getSourcePath(source);

  useLogStore.setState({
    activeSource: source,
    sourceOpenMode: mode,
    openFilePath: mode === "single-file" ? sourcePath : null,
    selectedSourceFilePath: mode === "single-file" ? sourcePath : null,
    entries,
    activeColumns: ["severity", "dateTime", "message"],
    correlatedEntries: [],
    mergedTabState: null,
    selectedId: null,
    highlightText: "",
    highlightCaseSensitive: false,
    isPaused: false,
    findMatchIds: [],
    pendingScrollTarget: null,
  });
}

describe("LogListView", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    calcAutoFitWidthMock.mockReset();
    localStorage.clear();

    useLogStore.getState().clear();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useFilterStore.setState(useFilterStore.getInitialState(), true);
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(),
      createdTimestamps: new Map(),
      loadMarkers: vi.fn().mockResolvedValue(undefined),
      saveMarkers: vi.fn().mockResolvedValue(undefined),
      toggleMarker: vi.fn(),
      setMarkerCategory: vi.fn(),
    });

    useUiStore.setState({
      showDetails: true,
      columnWidths: {},
      columnOrder: null,
    });
  });

  afterEach(() => {
    cleanup();
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  it("retries auto-sizing when a pending timer is cancelled by a dependency change", () => {
    calcAutoFitWidthMock.mockReturnValue(920);

    setLogViewState(
      { kind: "file", path: "/logs/alpha.log" },
      [makeEntry(1, "/logs/alpha.log", "first message")],
      "single-file"
    );

    render(<LogListView />);

    act(() => {
      useUiStore.setState({ logListFontSize: useUiStore.getState().logListFontSize + 1 });
    });

    act(() => {
      vi.advanceTimersByTime(100);
    });

    expect(calcAutoFitWidthMock).toHaveBeenCalledTimes(1);
    expect(useUiStore.getState().columnWidths.message).toBe(920);
  });

  it("treats each aggregate folder load as a distinct auto-size attempt", () => {
    calcAutoFitWidthMock.mockReturnValueOnce(920).mockReturnValueOnce(980);

    render(<LogListView />);

    act(() => {
      setLogViewState(
        { kind: "folder", path: "/logs/folder-a" },
        [makeEntry(1, "/logs/folder-a/a.log", "folder a")],
        "aggregate-folder"
      );
    });

    act(() => {
      vi.advanceTimersByTime(100);
    });

    expect(useUiStore.getState().columnWidths.message).toBe(920);

    act(() => {
      useUiStore.getState().resetColumnWidths();
      setLogViewState(
        { kind: "folder", path: "/logs/folder-b" },
        [makeEntry(2, "/logs/folder-b/b.log", "folder b")],
        "aggregate-folder"
      );
    });

    expect(useUiStore.getState().columnWidths.message).toBeUndefined();

    act(() => {
      vi.advanceTimersByTime(100);
    });

    expect(calcAutoFitWidthMock).toHaveBeenCalledTimes(2);
    expect(useUiStore.getState().columnWidths.message).toBe(980);
  });

  it("flushes a dirty marker when the view unmounts before the debounce", () => {
    const filePath = "/logs/unmount.log";
    const saveMarkers = vi.fn().mockResolvedValue(undefined);
    useMarkerStore.setState({ saveMarkers });
    setLogViewState(
      { kind: "file", path: filePath },
      [makeEntry(1, filePath)],
      "single-file",
    );

    const view = render(<LogListView />);
    fireEvent.click(view.getByRole("button", { name: "Toggle marker 1" }));
    expect(saveMarkers).not.toHaveBeenCalled();

    view.unmount();

    expect(saveMarkers).toHaveBeenCalledTimes(1);
    expect(saveMarkers).toHaveBeenCalledWith(filePath);
  });

  it("coalesces marker edits and does not save the flushed file again on unmount", () => {
    const filePath = "/logs/coalesced.log";
    const saveMarkers = vi.fn().mockResolvedValue(undefined);
    useMarkerStore.setState({ saveMarkers });
    setLogViewState(
      { kind: "file", path: filePath },
      [makeEntry(1, filePath)],
      "single-file",
    );

    const view = render(<LogListView />);
    const toggle = view.getByRole("button", { name: "Toggle marker 1" });
    fireEvent.click(toggle);
    fireEvent.click(toggle);
    act(() => vi.advanceTimersByTime(1_000));

    expect(saveMarkers).toHaveBeenCalledTimes(1);
    expect(saveMarkers).toHaveBeenCalledWith(filePath);
    view.unmount();
    expect(saveMarkers).toHaveBeenCalledTimes(1);
  });

  it("flushes each dirty marker file once when the view unmounts", () => {
    const firstPath = "/logs/first.log";
    const secondPath = "/logs/second.log";
    const saveMarkers = vi.fn().mockResolvedValue(undefined);
    useMarkerStore.setState({ saveMarkers });
    setLogViewState(
      { kind: "folder", path: "/logs" },
      [makeEntry(1, firstPath), makeEntry(2, secondPath)],
      "aggregate-folder",
    );

    const view = render(<LogListView />);
    fireEvent.click(view.getByRole("button", { name: "Toggle marker 1" }));
    fireEvent.click(view.getByRole("button", { name: "Toggle marker 2" }));
    view.unmount();

    expect(saveMarkers).toHaveBeenCalledTimes(2);
    expect(saveMarkers).toHaveBeenNthCalledWith(1, firstPath);
    expect(saveMarkers).toHaveBeenNthCalledWith(2, secondPath);
  });
});
