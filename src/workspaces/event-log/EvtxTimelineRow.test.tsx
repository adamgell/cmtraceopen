import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Marker } from "../../types/markers";
import { defaultColumnConfig, visibleColumns } from "./evtx-columns";
import { EvtxTimelineRow, resolveEvtxRowVisualState } from "./EvtxTimelineRow";
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
  it("applies selected, marker, severity, match, and default precedence deterministically", () => {
    expect(resolveEvtxRowVisualState({
      isSelected: true,
      marker: tagged,
      level: "Error",
      quickFilterMatch: true,
    })).toBe("selected");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: tagged,
      level: "Error",
      quickFilterMatch: true,
    })).toBe("marker");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: null,
      level: "Error",
      quickFilterMatch: true,
    })).toBe("severity");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: null,
      level: null,
      quickFilterMatch: true,
    })).toBe("match");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: null,
      level: null,
      quickFilterMatch: false,
    })).toBe("default");
  });
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
    expect(screen.getByRole("row")).toHaveAttribute("data-quick-filter-match", "true");
    expect(screen.getByRole("row")).toHaveAttribute(
      "aria-description",
      expect.stringContaining("Quick-filter match"),
    );
    expect(screen.getByText("Match")).toBeInTheDocument();
  });

  it("keeps selected state ahead of marker state and exposes tag/bookmark actions", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ marker: tagged, isSelected: true, onTag, onBookmark });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(row).toHaveAttribute("aria-rowindex", "1");
    expect(row).toHaveAttribute("data-marker-category", "investigate");
    const tagButton = screen.getByRole("button", { name: "Remove event tag" });
    const bookmarkButton = screen.getByRole("button", { name: "Bookmark event" });
    const cells = screen.getAllByRole("gridcell");
    const columns = visibleColumns(defaultColumnConfig());
    expect(cells).toHaveLength(columns.length + 1);
    cells.forEach((cell, index) => {
      expect(cell).toHaveAttribute("aria-colindex", String(index + 1));
    });
    expect(cells[0]).toHaveAccessibleName("Event markers");
    columns.forEach((column, index) => {
      expect(cells[index + 1]).toHaveAccessibleName(
        new RegExp(`^${column.label}: `),
      );
    });
    expect(cells[0]).toContainElement(tagButton);
    expect(cells[0]).toContainElement(bookmarkButton);
    expect(tagButton).toHaveAttribute("aria-pressed", "true");
    expect(bookmarkButton).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(tagButton);
    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    fireEvent.keyDown(row, { key: "b" });
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
  });

  it("disables marker controls when EventRecordID is unavailable", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({
      record: {
        ...record(),
        eventRecordId: 0,
        eventRecordIdText: "0",
      },
      onTag,
      onBookmark,
    });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute(
      "aria-description",
      expect.stringContaining("Markers unavailable: EventRecordID is missing")
    );
    const tag = screen.getByRole("button", {
      name: "EventRecordID unavailable; tagging is disabled",
    });
    const bookmark = screen.getByRole("button", {
      name: "EventRecordID unavailable; bookmarking is disabled",
    });
    expect(tag).toBeDisabled();
    expect(bookmark).toBeDisabled();
    fireEvent.click(tag);
    fireEvent.click(bookmark);
    expect(onTag).not.toHaveBeenCalled();
    expect(onBookmark).not.toHaveBeenCalled();
  });

  it("keeps marker shortcuts on the roving row when grouped", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ grouped: true, onTag, onBookmark, tabIndex: 0 });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("aria-level", "1");
    expect(screen.getByRole("button", { name: "Bookmark event" })).toHaveAttribute("tabindex", "-1");
    row.focus();
    fireEvent.keyDown(row, { key: "t" });
    fireEvent.keyDown(row, { key: "b" });

    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    expect(row).toHaveFocus();
  });

  it.each([
    ["Control", { ctrlKey: true }],
    ["Alt", { altKey: true }],
    ["Shift", { shiftKey: true }],
    ["Meta", { metaKey: true }],
  ])("does not run marker shortcuts when the %s modifier is held", (_label, modifier) => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ onTag, onBookmark });

    const row = screen.getByRole("row");
    fireEvent.keyDown(row, { key: "t", ...modifier });
    fireEvent.keyDown(row, { key: "b", ...modifier });

    expect(onTag).not.toHaveBeenCalled();
    expect(onBookmark).not.toHaveBeenCalled();
  });

  it("keeps ungrouped marker controls out of the nested tab order", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ onTag, onBookmark, tabIndex: 0 });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("tabindex", "0");
    expect(row).not.toHaveAttribute("aria-level");
    expect(screen.getByRole("button", { name: "Tag event" })).toHaveAttribute("tabindex", "-1");
    expect(screen.getByRole("button", { name: "Bookmark event" })).toHaveAttribute("tabindex", "-1");

    row.focus();
    expect(row).toHaveFocus();
    fireEvent.keyDown(row, { key: "t" });
    fireEvent.keyDown(row, { key: "b" });
    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
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
    expect(screen.getByRole("row")).toHaveAttribute("data-quick-filter-match", "false");
    expect(screen.getByRole("row")).toHaveAttribute("data-evtx-filter-match", "true");
    expect(screen.getByText("Match")).toBeInTheDocument();
  });

  it("highlights only substrings matched by the quick-filter regular expression", () => {
    renderRow({
      record: {
        ...record(),
        provider: "é",
        channel: "Å",
        message: "é",
      },
      quickFilter: {
        mode: "oneString",
        query: "e",
        scope: "allColumns",
        action: "show",
        caseSensitive: false,
        highlight: true,
      },
      quickFilterMatch: true,
    });

    expect(screen.queryByLabelText("Quick-filter match")).not.toBeInTheDocument();
  });
});
