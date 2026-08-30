import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { classifyEntries } from "../../lib/diff-entries";
import { useLogStore } from "../../stores/log-store";
import type { LogEntry } from "../../types/log";
import { createTestVirtualizer } from "../../test-utils/virtualizer";
import { DiffView } from "./DiffView";

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: { count: number }) => createTestVirtualizer(options),
}));

function entry(id: number, message: string, filePath: string): LogEntry {
  return {
    id,
    lineNumber: id,
    message,
    component: "CIAgent",
    timestamp: id,
    timestampDisplay: "2026-08-29 12:00:00.000",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

describe("DiffView (LOG-017)", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows common/only-A/only-B counts and switches to unified", () => {
    const entriesA = [
      entry(1, "only in A", "C:/logs/a.log"),
      entry(2, "shared line", "C:/logs/a.log"),
    ];
    const entriesB = [
      entry(10, "only in B", "C:/logs/b.log"),
      entry(11, "shared line", "C:/logs/b.log"),
    ];
    const classified = classifyEntries(entriesA, entriesB);
    useLogStore.setState({
      diffState: {
        mode: "two-file",
        sourceA: { filePath: "C:/logs/a.log", label: "a.log" },
        sourceB: { filePath: "C:/logs/b.log", label: "b.log" },
        displayMode: "side-by-side",
        entriesA,
        entriesB,
        ...classified,
      },
    });

    render(<DiffView />);

    expect(screen.getByText(/Diff: a.log vs b.log/)).toBeVisible();
    expect(screen.getByText("1 common")).toBeVisible();
    expect(screen.getByText("1 only A")).toBeVisible();
    expect(screen.getByText("1 only B")).toBeVisible();
    expect(screen.getByRole("button", { name: "Side-by-side" })).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("button", { name: "Unified" }));
    expect(useLogStore.getState().diffState?.displayMode).toBe("unified");

    fireEvent.click(screen.getByRole("button", { name: "Close diff" }));
    expect(useLogStore.getState().diffState).toBeNull();
  });
});
