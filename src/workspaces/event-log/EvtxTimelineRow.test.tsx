import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Marker } from "../../types/markers";
import { defaultColumnConfig, visibleColumns } from "./evtx-columns";
import { EvtxTimelineRow } from "./EvtxTimelineRow";
import type { EvtxRecord } from "./types";

function record(): EvtxRecord {
  return {
    id: 4,
    eventRecordId: 42,
    timestamp: "2026-08-18 12:00:00",
    timestampEpoch: 1_000,
    provider: "Provider",
    channel: "Application",
    eventId: 100,
    level: "Error",
    computer: "PC01",
    message: "setup failure happened",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "Application.evtx",
  };
}

function renderRow(overrides: Partial<React.ComponentProps<typeof EvtxTimelineRow>> = {}) {
  return render(
    <EvtxTimelineRow
      record={record()}
      dataIndex={0}
      isSelected={false}
      fontSize={13}
      smallFontSize={10}
      monoFontSize={12}
      lineHeight="18px"
      columnConfig={defaultColumnConfig()}
      columns={visibleColumns(defaultColumnConfig())}
      timeZoneMode="local"
      onSelect={vi.fn()}
      {...overrides}
    />
  );
}

const tagged: Marker = {
  lineId: 5,
  category: "investigate",
  color: "#60a5fa",
  added: "2026-08-18T12:00:00Z",
};

describe("EvtxTimelineRow triage state", () => {
  it("renders text and ARIA metadata when the quick-filter match is enabled", () => {
    renderRow({
      quickFilter: {
        mode: "oneString",
        query: "failure",
        scope: "allColumns",
        action: "show",
        caseSensitive: false,
        highlight: true,
      },
      quickFilterMatch: true,
    });

    expect(screen.getAllByLabelText("Quick-filter match").length).toBeGreaterThan(0);
    expect(screen.getByRole("option")).toHaveAttribute("data-quick-filter-match", "true");
    expect(screen.getByRole("option")).toHaveAttribute("aria-description", expect.stringContaining("Quick-filter match"));
  });

  it("keeps selected state ahead of marker state and exposes tag/bookmark actions", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ marker: tagged, isSelected: true, onTag, onBookmark });

    const row = screen.getByRole("option");
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(row).toHaveAttribute("data-marker-category", "investigate");
    fireEvent.click(screen.getByRole("button", { name: "Remove event tag" }));
    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    fireEvent.keyDown(row, { key: "b" });
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
  });

  it("does not render highlight markup when the control is off", () => {
    renderRow({
      quickFilter: {
        mode: "oneString",
        query: "failure",
        scope: "allColumns",
        action: "show",
        caseSensitive: false,
        highlight: false,
      },
      quickFilterMatch: true,
    });

    expect(screen.queryByLabelText("Quick-filter match")).not.toBeInTheDocument();
    expect(screen.getByRole("option")).toHaveAttribute("data-quick-filter-match", "false");
  });
});
