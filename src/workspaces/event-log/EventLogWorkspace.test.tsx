/**
 * Event Log workspace fixtures. Mock Tauri before importing evtx-store:
 * the store registers event listeners at module scope.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxRecord } from "./types";
import { createTestVirtualizer } from "../../test-utils/virtualizer";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: Parameters<typeof createTestVirtualizer>[0]) =>
    createTestVirtualizer(options),
}));

const { EventLogWorkspace } = await import("./EventLogWorkspace");
const { useEvtxStore } = await import("./evtx-store");
const { defaultColumnConfig } = await import("./evtx-columns");

function record(): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 42,
    timestamp: "2026-01-15T12:00:00.000Z",
    timestampEpoch: Date.parse("2026-01-15T12:00:00.000Z"),
    provider: "Application Error",
    channel: "Application",
    eventId: 1000,
    level: "Error",
    computer: "PC01",
    message: "Faulting application name: setup.exe",
    eventData: [{ name: "AppName", value: "setup.exe" }],
    rawXml: "<Event><System><EventID>1000</EventID></System></Event>",
    sourceLabel: "Application.evtx",
  };
}

function seedEvents() {
  useEvtxStore.setState({
    records: [record()],
    channels: [
      { name: "Application", eventCount: 1, sourceType: "live" },
      { name: "System", eventCount: 0, sourceType: "live" },
      {
        name: "Microsoft-Windows-AAD/Operational",
        eventCount: 0,
        sourceType: "live",
      },
    ],
    sourceMode: "files",
    isLoading: false,
    loadError: null,
    coverageGaps: [],
    selectedChannels: new Set(["Application", "System", "Microsoft-Windows-AAD/Operational"]),
    loadedChannels: new Set(["Application"]),
    filterLevels: new Set(["Critical", "Error", "Warning", "Information", "Verbose"]),
    filterEventIds: "",
    filterSearch: "",
    timeWindow: "24h",
    timeZoneMode: "local",
    columnConfig: defaultColumnConfig(),
    groupBy: [],
    collapsedGroups: new Set(),
    sortField: "time",
    sortDirection: "asc",
    selectedRecordId: null,
  });
}

afterEach(() => {
  cleanup();
  useEvtxStore.getState().reset();
});

beforeEach(() => {
  invoke.mockReset();
  useEvtxStore.getState().reset();
});

describe("EventLogWorkspace fixtures", () => {
  it("EVTX-003 shows the Windows Logs / Applications tree with select controls", () => {
    seedEvents();
    render(<EventLogWorkspace />);

    expect(screen.getByText("Windows Logs")).toBeInTheDocument();
    expect(screen.getByText("Applications and Services Logs")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Filter channels...")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Select all" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deselect all" })).toBeInTheDocument();
    expect(screen.getAllByText("Application").length).toBeGreaterThan(0);
  });

  it("EVTX-006 offers CSV, TSV, JSON, and Event XML export of visible events", () => {
    seedEvents();
    render(<EventLogWorkspace />);

    fireEvent.click(
      screen.getByTitle(
        "Export the events currently shown, using the same filters as the list",
      ),
    );

    expect(screen.getByText("CSV")).toBeInTheDocument();
    expect(screen.getByText("TSV")).toBeInTheDocument();
    expect(screen.getByText("JSON")).toBeInTheDocument();
    expect(screen.getByText("Event XML")).toBeInTheDocument();
  });
  it("EVTX-004 gives level filters descriptive state to keyboard and screen-reader users", () => {
    seedEvents();
    render(<EventLogWorkspace />);

    const errorToggle = screen.getByRole("button", { name: "Toggle Error events" });
    expect(errorToggle).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(errorToggle);
    expect(errorToggle).toHaveAttribute("aria-pressed", "false");
  });

  it("EVTX-007 shows event detail, Event Data, and Show/Hide Raw XML", () => {
    seedEvents();
    render(<EventLogWorkspace />);

    fireEvent.click(screen.getByRole("option"));

    expect(screen.getByText("Event 1000")).toBeInTheDocument();
    expect(
      screen.getAllByText("Faulting application name: setup.exe").length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("Event Data")).toBeInTheDocument();
    expect(screen.getByText("AppName")).toBeInTheDocument();
    expect(screen.getAllByText("Application Error").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Show Raw XML" }));
    expect(screen.getByRole("button", { name: "Hide Raw XML" })).toBeInTheDocument();
    expect(screen.getByText(/<EventID>1000<\/EventID>/)).toBeInTheDocument();
  });
});
