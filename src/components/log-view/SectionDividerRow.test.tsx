import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SectionDividerRow } from "./SectionDividerRow";
import type { LogEntry } from "../../types/log";

function sectionEntry(): LogEntry {
  return {
    id: 12,
    lineNumber: 120,
    message: "Section: AppEnforce",
    component: null,
    timestamp: Date.parse("2026-07-26T12:00:00Z"),
    timestampDisplay: "2026-07-26 12:00:00.000",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath: "C:/Windows/CCM/Logs/AppEnforce.log",
    timezoneOffset: null,
    entryKind: "Section",
    sectionName: "AppEnforce",
    sectionColor: "#3b82f6",
  };
}

describe("SectionDividerRow", () => {
  it("renders a section banner and selects the row on click", () => {
    const onClick = vi.fn();
    render(
      <SectionDividerRow
        entry={sectionEntry()}
        resolvedColor="#3b82f6"
        listFontSize={13}
        rowLineHeight={18}
        onClick={onClick}
      />,
    );
    fireEvent.click(screen.getByRole("option"));
    expect(onClick).toHaveBeenCalledWith(12);
    expect(screen.getByText("Section: AppEnforce")).toBeInTheDocument();
  });

  it("shows the iteration caption on Iteration banners", () => {
    render(
      <SectionDividerRow
        entry={{ ...sectionEntry(), entryKind: "Iteration", iteration: "Pass 2", message: "Iteration" }}
        resolvedColor="#22c55e"
        listFontSize={13}
        rowLineHeight={18}
        onClick={vi.fn()}
      />,
    );
    expect(screen.getByText("Pass 2")).toBeInTheDocument();
  });
});
