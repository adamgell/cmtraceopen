import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LogListView } from "./LogListView";
import { useFilterStore } from "../../stores/filter-store";
import { useLogStore } from "../../stores/log-store";
import { useMarkerStore } from "../../stores/marker-store";
import { useUiStore } from "../../stores/ui-store";
import type { LogEntry } from "../../types/log";

const scrollToIndex = vi.fn();

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        size: estimateSize(),
        start: index * estimateSize(),
      })),
    scrollToIndex,
  }),
}));

vi.mock("../../hooks/use-context-menu", () => ({
  useContextMenu: () => ({ showContextMenu: vi.fn() }),
}));

function makeEntry(id: number, message = `Policy evaluation ${id} completed`): LogEntry {
  return {
    id,
    lineNumber: id * 10,
    message,
    component: "AppEnforce",
    timestamp: Date.parse("2026-07-26T12:00:00Z") + id * 1000,
    timestampDisplay: `2026-07-26 12:00:${String(id).padStart(2, "0")}.000`,
    severity: id === 3 ? "Error" : "Info",
    thread: 1000 + id,
    threadDisplay: String(1000 + id),
    sourceFile: null,
    format: "Ccm",
    filePath: "C:/Windows/CCM/Logs/AppEnforce.log",
    timezoneOffset: null,
  };
}

function seedEntries(count = 5) {
  useLogStore.setState({
    activeSource: { kind: "file", path: "C:/Windows/CCM/Logs/AppEnforce.log" },
    sourceOpenMode: "single-file",
    openFilePath: "C:/Windows/CCM/Logs/AppEnforce.log",
    selectedSourceFilePath: "C:/Windows/CCM/Logs/AppEnforce.log",
    entries: Array.from({ length: count }, (_, i) => makeEntry(i + 1)),
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

describe("LogListView selection and jump fixtures", () => {
  beforeEach(() => {
    scrollToIndex.mockReset();
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
    useUiStore.setState({ showDetails: true, showInfoPane: true, columnWidths: {}, columnOrder: null });
    seedEntries();
  });

  afterEach(() => {
    cleanup();
  });

  it("virtualizes rows and selects a clicked entry", () => {
    render(<LogListView />);
    fireEvent.click(screen.getByText("Policy evaluation 2 completed"));
    expect(useLogStore.getState().selectedId).toBe(2);
    expect(screen.getByText("Policy evaluation 2 completed").closest("[role='option']")).toHaveAttribute(
      "data-selected",
      "true",
    );
  });

  it("toggles additive selection with Ctrl/Cmd+click and ranges with Shift+click", () => {
    render(<LogListView />);
    fireEvent.click(screen.getByText("Policy evaluation 1 completed"));
    fireEvent.click(screen.getByText("Policy evaluation 3 completed"), { metaKey: true });
    expect(screen.getByText("Policy evaluation 1 completed").closest("[role='option']")).toHaveStyle({
      outline: "1px solid rgba(59, 130, 246, 0.5)",
    });
    fireEvent.click(screen.getByText("Policy evaluation 5 completed"), { shiftKey: true });
    expect(screen.getByText("Policy evaluation 4 completed").closest("[role='option']")).toHaveStyle({
      outline: "1px solid rgba(59, 130, 246, 0.5)",
    });
  });

  it("selects every displayed row on Ctrl/Cmd+A", () => {
    render(<LogListView />);
    const list = screen.getByRole("listbox", { name: "Log entries" });
    fireEvent.keyDown(list, { key: "a", metaKey: true });
    for (const id of [1, 2, 3, 4, 5]) {
      expect(screen.getByText(`Policy evaluation ${id} completed`).closest("[role='option']")).toHaveStyle({
        outline: "1px solid rgba(59, 130, 246, 0.5)",
      });
    }
  });

  it("consumes a matching pending scroll target and selects the first line at or after the target", () => {
    render(<LogListView />);
    act(() => {
      useLogStore.getState().setPendingScrollTarget({
        filePath: "C:/Windows/CCM/Logs/AppEnforce.log",
        lineNumber: 25,
      });
    });
    expect(useLogStore.getState().selectedId).toBe(3);
    expect(useLogStore.getState().pendingScrollTarget).toBeNull();
  });

  it("follows live tail to the last row when not paused", () => {
    render(<LogListView />);
    act(() => {
      useLogStore.setState({
        entries: [...useLogStore.getState().entries, makeEntry(6)],
      });
    });
    expect(scrollToIndex).toHaveBeenCalledWith(5, { align: "end" });
  });
});
