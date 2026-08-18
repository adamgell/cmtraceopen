import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SysmonWorkspace } from "./SysmonWorkspace";
import { useSysmonStore } from "./sysmon-store";
import type { SysmonAnalysisResult, SysmonEvent } from "./types";

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    commandState: { canRefresh: false },
    refreshActiveSource: vi.fn(),
  }),
}));

vi.mock("../../lib/commands", () => ({
  analyzeSysmonLogs: vi.fn(),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: index,
        start: index * 28,
        size: 28,
      })),
    getTotalSize: () => count * 28,
    measureElement: vi.fn(),
    scrollToIndex: vi.fn(),
  }),
}));

function event(): SysmonEvent {
  return {
    id: 1,
    eventId: 1,
    eventType: "ProcessCreate",
    eventTypeDisplay: "Process Create",
    severity: "Info",
    timestamp: "2026-01-15T12:00:00.000Z",
    timestampMs: Date.parse("2026-01-15T12:00:00.000Z"),
    computer: "PC01",
    recordId: 1,
    image: "C:\\Windows\\System32\\cmd.exe",
    message: "Process Create",
    sourceFile: "Sysmon.evtx",
  };
}

function analysis(): SysmonAnalysisResult {
  return {
    events: [event()],
    summary: {
      totalEvents: 1,
      eventTypeCounts: [],
      uniqueProcesses: 1,
      uniqueComputers: 1,
      earliestTimestamp: null,
      latestTimestamp: null,
      sourceFiles: ["Sysmon.evtx"],
      parseErrors: 0,
    },
    config: {
      schemaVersion: "4.90",
      hashAlgorithms: "SHA256",
      found: true,
      lastConfigChange: null,
      configurationXml: "<Sysmon schemaversion=\"4.90\" />",
      sysmonVersion: "15.14",
      activeEventTypes: [],
    },
    dashboard: {
      timelineMinute: [],
      timelineHourly: [],
      timelineDaily: [],
      topProcesses: [],
      topDestinations: [],
      topPorts: [],
      topDnsQueries: [],
      securityEvents: {
        totalWarnings: 0,
        totalErrors: 0,
        eventsByType: [],
      },
      topTargetFiles: [],
      topRegistryKeys: [],
    },
    sourcePath: "C:\\temp\\Sysmon.evtx",
  };
}

afterEach(() => {
  cleanup();
  useSysmonStore.getState().clear();
});

beforeEach(() => {
  useSysmonStore.getState().clear();
});

describe("SysmonWorkspace fixtures", () => {
  it("SYSMON-001 shows the empty analyze state then dashboard after a result", () => {
    render(<SysmonWorkspace />);

    expect(screen.getByText("Sysmon Log Viewer")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open .evtx files..." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "This computer" })).toBeInTheDocument();

    cleanup();
    useSysmonStore.getState().setResults(analysis());
    render(<SysmonWorkspace />);

    expect(screen.getByRole("tab", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.getByText("Total Events")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("SYSMON-002 switches Dashboard, Events, Summary, and Configuration", () => {
    useSysmonStore.getState().setResults(analysis());
    render(<SysmonWorkspace />);

    expect(screen.getByRole("tab", { name: "Dashboard" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByText("Total Events")).toBeInTheDocument();
    expect(screen.getByText("Security Alerts")).toBeInTheDocument();
    expect(screen.getByText("Top Processes")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /Events/ }));
    expect(screen.getByLabelText("Search events")).toBeInTheDocument();
    expect(screen.getByText(/Type:/)).toBeInTheDocument();
    expect(screen.getByText(/Severity:/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Summary" }));
    expect(screen.getByText("Sysmon Analysis Summary")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Configuration" }));
    expect(screen.getByText("Sysmon Configuration")).toBeInTheDocument();
    expect(screen.getByText("Schema Version")).toBeInTheDocument();
    expect(screen.getByText("Configuration Details (from Event ID 16)")).toBeInTheDocument();
  });
});
