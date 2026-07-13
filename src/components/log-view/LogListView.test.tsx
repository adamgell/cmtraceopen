import { act, cleanup, render } from "@testing-library/react";
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
  }: {
    entry: LogEntry;
    rowDomId: string;
  }) => (
    <div id={rowDomId} className="log-row">
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

describe("LogListView auto-size effect", () => {
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
});
