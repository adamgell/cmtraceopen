import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LogEntry } from "../../types/log";
import { useLogStore } from "../../stores/log-store";
import { FindBar } from "./FindBar";

function entry(id: number, message: string): LogEntry {
  return {
    id,
    lineNumber: id,
    message,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath: "/test.log",
    timezoneOffset: null,
  };
}

describe("FindBar (CHROME-007)", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
  });

  afterEach(() => {
    cleanup();
  });

  it("focuses the find field and exposes match-case and regex toggles", () => {
    render(<FindBar onClose={() => {}} />);

    expect(screen.getByPlaceholderText("Find...")).toHaveFocus();
    expect(screen.getByRole("button", { name: "Match case" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("button", { name: "Use regular expression" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("shows match index, no-results, and invalid regex status", () => {
    useLogStore.setState({
      findQuery: "error",
      findMatchIds: [1, 2, 3],
      findCurrentIndex: 0,
      findRegexError: null,
    });
    const { rerender } = render(<FindBar onClose={() => {}} />);
    expect(screen.getByText("1 of 3")).toBeVisible();

    useLogStore.setState({
      findQuery: "zzz",
      findMatchIds: [],
      findCurrentIndex: -1,
      findRegexError: null,
    });
    rerender(<FindBar onClose={() => {}} />);
    expect(screen.getByText("No results")).toBeVisible();

    useLogStore.setState({
      findQuery: "[",
      findUseRegex: true,
      findMatchIds: [],
      findCurrentIndex: -1,
      findRegexError: "Invalid regular expression",
    });
    rerender(<FindBar onClose={() => {}} />);
    expect(screen.getByText("Invalid regex")).toBeVisible();
  });

  it("Enter/F3 find next, Shift+Enter previous, Escape closes", () => {
    const onClose = vi.fn();
    useLogStore.setState({
      entries: [entry(1, "error one"), entry(2, "error two")],
      findQuery: "error",
      findMatchIds: [1, 2],
      findCurrentIndex: 0,
      selectedId: 1,
    });

    render(<FindBar onClose={onClose} />);
    const input = screen.getByPlaceholderText("Find...");

    fireEvent.keyDown(input, { key: "Enter" });
    expect(useLogStore.getState().findCurrentIndex).toBe(1);
    expect(useLogStore.getState().selectedId).toBe(2);

    fireEvent.keyDown(input, { key: "F3", shiftKey: true });
    expect(useLogStore.getState().findCurrentIndex).toBe(0);
    expect(useLogStore.getState().selectedId).toBe(1);

    fireEvent.keyDown(input, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("toggles match case from the toolbar", () => {
    render(<FindBar onClose={() => {}} />);
    const matchCase = screen.getByRole("button", { name: "Match case" });
    fireEvent.click(matchCase);
    expect(useLogStore.getState().findCaseSensitive).toBe(true);
    expect(matchCase).toHaveAttribute("aria-pressed", "true");
  });
});
