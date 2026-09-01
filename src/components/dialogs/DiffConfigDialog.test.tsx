import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCachedTabSnapshot, clearAllTabSnapshots } from "../../stores/log-store";
import type { TabState } from "../../stores/ui-store";
import { useUiStore } from "../../stores/ui-store";
import type { LogEntry } from "../../types/log";
import { DiffConfigDialog } from "./DiffConfigDialog";

function tab(filePath: string): TabState {
  return {
    id: filePath,
    filePath,
    fileName: filePath.split(/[\\/]/).pop() ?? filePath,
    scrollPosition: 0,
    selectedLineId: null,
    sourceContext: null,
    fileKind: "log",
  };
}

function entry(id: number, filePath: string): LogEntry {
  return {
    id,
    lineNumber: id,
    message: `line ${id}`,
    component: null,
    timestamp: id,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath,
    timezoneOffset: null,
  };
}

describe("DiffConfigDialog (LOG-017)", () => {
  beforeEach(() => {
    clearAllTabSnapshots();
    useUiStore.setState({ openTabs: [] });
  });

  afterEach(() => {
    cleanup();
  });

  it("requires two different log tabs before Compare is enabled", () => {
    const onCompare = vi.fn();
    const a = "C:/logs/before.log";
    const b = "C:/logs/after.log";
    useUiStore.setState({ openTabs: [tab(a), tab(b)] });
    setCachedTabSnapshot(a, {
      entries: [entry(1, a)],
      formatDetected: "Plain",
      parserSelection: null,
      totalLines: 1,
      byteOffset: 0,
      selectedSourceFilePath: a,
      sourceOpenMode: "single-file",
      activeColumns: [],
    });
    setCachedTabSnapshot(b, {
      entries: [entry(1, b), entry(2, b)],
      formatDetected: "Plain",
      parserSelection: null,
      totalLines: 2,
      byteOffset: 0,
      selectedSourceFilePath: b,
      sourceOpenMode: "single-file",
      activeColumns: [],
    });

    render(<DiffConfigDialog isOpen onClose={() => {}} onCompare={onCompare} />);

    expect(screen.getByRole("dialog", { name: "Compare Log Files" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Compare" })).toBeDisabled();

    const selects = screen.getAllByRole("combobox");
    fireEvent.change(selects[0], { target: { value: a } });
    fireEvent.change(selects[1], { target: { value: b } });
    expect(screen.getByRole("button", { name: "Compare" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(onCompare).toHaveBeenCalledWith(
      { filePath: a, label: "before.log" },
      { filePath: b, label: "after.log" },
    );
  });
});
