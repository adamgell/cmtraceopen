import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { LogRow } from "./LogRow";
import { getColumnDef } from "../../lib/column-config";
import { themeSeverityPalettes } from "../../lib/themes/palettes";
import { DEFAULT_CATEGORIES } from "../../types/markers";
import type { LogEntry } from "../../types/log";

const severityColumn = getColumnDef("severity");
const messageColumn = getColumnDef("message");
if (!severityColumn || !messageColumn) {
  throw new Error("LogRow story requires severity and message column definitions");
}
const visibleColumns = [severityColumn, messageColumn];

function makeEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: 4,
    lineNumber: 40,
    message: "Install failed 0x80070005 for app {aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb}",
    component: "AppEnforce",
    timestamp: Date.parse("2026-07-26T12:00:03Z"),
    timestampDisplay: "2026-07-26 12:00:03.000",
    severity: "Error",
    thread: 1004,
    threadDisplay: "1004",
    sourceFile: "appexecmgr.cpp",
    format: "Ccm",
    filePath: "C:/Windows/CCM/Logs/AppEnforce.log",
    timezoneOffset: null,
    errorCodeSpans: [
      {
        start: 15,
        end: 25,
        codeHex: "0x80070005",
        codeDecimal: "2147942405",
        description: "Access is denied.",
        category: "Win32",
      },
    ],
    ...overrides,
  };
}

function renderRow(overrides: Partial<Parameters<typeof LogRow>[0]> = {}) {
  const onClick = vi.fn();
  const onContextMenu = vi.fn();
  const onErrorCodeClick = vi.fn();
  const onToggleMarker = vi.fn();
  const onSetMarkerCategory = vi.fn();
  render(
    <LogRow
      entry={makeEntry()}
      rowDomId="row-4"
      isSelected={false}
      isFindMatch={false}
      visibleColumns={visibleColumns}
      gridTemplateColumns="40px 1fr"
      listFontSize={13}
      rowLineHeight={18}
      severityPalette={themeSeverityPalettes.light}
      highlightText=""
      highlightCaseSensitive={false}
      onClick={onClick}
      onContextMenu={onContextMenu}
      onErrorCodeClick={onErrorCodeClick}
      onToggleMarker={onToggleMarker}
      onSetMarkerCategory={onSetMarkerCategory}
      markerCategories={DEFAULT_CATEGORIES}
      {...overrides}
    />,
  );
  return { onClick, onContextMenu, onErrorCodeClick, onToggleMarker, onSetMarkerCategory };
}

describe("LogRow error codes and markers", () => {
  it("underlines an HRESULT and stops row selection when the span is activated", () => {
    const { onClick, onErrorCodeClick } = renderRow();
    const code = screen.getByRole("button", { name: "0x80070005" });
    expect(code).toHaveStyle({ textDecoration: "underline dotted" });
    fireEvent.click(code);
    expect(onErrorCodeClick).toHaveBeenCalledWith(
      expect.objectContaining({ codeHex: "0x80070005", description: "Access is denied." }),
    );
    expect(onClick).not.toHaveBeenCalled();
    fireEvent.keyDown(code, { key: "Enter" });
    expect(onErrorCodeClick).toHaveBeenCalledTimes(2);
  });

  it("toggles the active marker from the gutter and offers Bug / Investigate / Confirmed / Remove", () => {
    const { onClick, onToggleMarker, onSetMarkerCategory } = renderRow({
      marker: { lineId: 4, category: "bug", color: "#ef4444", added: "2026-07-26T12:00:00Z" },
    });
    const gutter = screen.getByRole("option").firstElementChild as HTMLElement;
    fireEvent.click(gutter);
    expect(onToggleMarker).toHaveBeenCalledWith("C:/Windows/CCM/Logs/AppEnforce.log", 4);
    expect(onClick).not.toHaveBeenCalled();

    fireEvent.contextMenu(gutter);
    expect(screen.getByText("Bug")).toBeInTheDocument();
    expect(screen.getByText("Investigate")).toBeInTheDocument();
    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Investigate"));
    expect(onSetMarkerCategory).toHaveBeenCalledWith(
      "C:/Windows/CCM/Logs/AppEnforce.log",
      4,
      "investigate",
    );
    fireEvent.contextMenu(gutter);
    fireEvent.click(screen.getByText("Remove Marker"));
    expect(onToggleMarker).toHaveBeenCalledTimes(2);
  });
});
