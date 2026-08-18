import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MergeLegendBar } from "./MergeLegendBar";
import { useLogStore } from "../../stores/log-store";
import type { LogEntry } from "../../types/log";

function entry(id: number, filePath: string): LogEntry {
  return {
    id,
    lineNumber: id,
    message: `line ${id}`,
    component: "CIAgent",
    timestamp: id,
    timestampDisplay: "2026-07-26 12:00:00.000",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

describe("MergeLegendBar", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
    const app = "C:/Windows/CCM/Logs/AppEnforce.log";
    const ci = "C:/Windows/CCM/Logs/CIAgent.log";
    useLogStore.setState({
      entries: [entry(1, app), entry(2, ci), entry(3, app)],
      correlationWindowMs: 1000,
      autoCorrelate: true,
      mergedTabState: {
        sourceFilePaths: [app, ci],
        colorAssignments: { [app]: "#ef4444", [ci]: "#3b82f6" },
        fileVisibility: { [app]: true, [ci]: true },
        mergedEntries: [entry(1, app), entry(2, ci), entry(3, app)],
        cacheKey: `${app}:2|${ci}:1`,
      },
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("toggles file chips, All/None, correlation windows, and Auto", () => {
    render(<MergeLegendBar />);
    expect(screen.getByText("AppEnforce.log")).toBeInTheDocument();
    expect(screen.getByText("CIAgent.log")).toBeInTheDocument();
    expect(screen.getByText("3 merged")).toBeInTheDocument();

    fireEvent.click(screen.getByText("AppEnforce.log"));
    expect(useLogStore.getState().mergedTabState?.fileVisibility["C:/Windows/CCM/Logs/AppEnforce.log"]).toBe(
      false,
    );

    fireEvent.click(screen.getByRole("button", { name: "None" }));
    expect(
      Object.values(useLogStore.getState().mergedTabState?.fileVisibility ?? {}).every((visible) => !visible),
    ).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "All" }));
    expect(
      Object.values(useLogStore.getState().mergedTabState?.fileVisibility ?? {}).every(Boolean),
    ).toBe(true);

    fireEvent.change(screen.getByDisplayValue("1s"), { target: { value: "500" } });
    expect(useLogStore.getState().correlationWindowMs).toBe(500);

    fireEvent.click(screen.getByRole("button", { name: "Auto" }));
    expect(useLogStore.getState().autoCorrelate).toBe(false);
  });
});
