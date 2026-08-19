import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NewIntuneWorkspace } from "./NewIntuneWorkspace";
import { useIntuneStore } from "./intune-store";
import type { IntuneResultMetadata } from "./types";
import { createTestVirtualizer } from "../../test-utils/virtualizer";
import {
  ANALYZED_PATH,
  APPWORKLOAD_PATH,
  DIAGNOSTIC,
  DOWNLOAD_NAME,
  EVENT_LOG_ANALYSIS,
  FAILED_EVENT_NAME,
  LIVE_EMPTY_EVENT_LOG_ANALYSIS,
  STORY_DOWNLOADS,
  STORY_EVENTS,
  STORY_SOURCE_FILES,
  SUMMARY,
} from "./intune-story-fixtures";

const openKnownSourceById = vi.fn();
const openSourceFileDialog = vi.fn();
const openSourceFolderDialog = vi.fn();
const refreshActiveSource = vi.fn();

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    commandState: {
      canOpenSources: true,
      canOpenKnownSources: true,
      canRefresh: true,
    },
    openKnownSourceById,
    openSourceFileDialog,
    openSourceFolderDialog,
    refreshActiveSource,
  }),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: Parameters<typeof createTestVirtualizer>[0]) =>
    createTestVirtualizer(options),
}));

function seedReadyResults(metadata?: Partial<IntuneResultMetadata>) {
  act(() => {
    useIntuneStore.getState().beginAnalysis(ANALYZED_PATH, "folder");
    useIntuneStore.getState().setResults(
      STORY_EVENTS,
      STORY_DOWNLOADS,
      SUMMARY,
      [DIAGNOSTIC],
      ANALYZED_PATH,
      STORY_SOURCE_FILES,
      metadata,
    );
  });
}

afterEach(() => {
  cleanup();
  useIntuneStore.getState().clear();
});

beforeEach(() => {
  useIntuneStore.getState().clear();
  openKnownSourceById.mockReset();
  openSourceFileDialog.mockReset();
  openSourceFolderDialog.mockReset();
  refreshActiveSource.mockReset();
});

describe("INTUNE-011 New Intune surfaces and reset", () => {
  it("renders Overview, Event evidence, Download evidence, Event log evidence, Reset, and Refresh", () => {
    seedReadyResults({ eventLogAnalysis: EVENT_LOG_ANALYSIS });
    render(<NewIntuneWorkspace />);

    expect(screen.getByRole("tab", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Event evidence" })).not.toBeDisabled();
    expect(screen.getByRole("tab", { name: "Download evidence" })).not.toBeDisabled();
    expect(screen.getByRole("tab", { name: /Event log evidence/ })).not.toBeDisabled();
    expect(screen.getByRole("tab", { name: /Event log evidence/ })).toHaveTextContent("1");
    expect(screen.getByRole("button", { name: "Reset investigation" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh analysis" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Event evidence" }));
    expect(screen.getAllByText(FAILED_EVENT_NAME).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("tab", { name: "Download evidence" }));
    expect(screen.getByText(DOWNLOAD_NAME)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Refresh analysis" }));
    expect(refreshActiveSource).toHaveBeenCalled();
  });

  it("clears type, status, file scope, and selected event on Reset investigation", () => {
    seedReadyResults();
    render(<NewIntuneWorkspace />);

    act(() => {
      useIntuneStore.getState().setFilterEventType("Win32App");
      useIntuneStore.getState().setFilterStatus("Failed");
      useIntuneStore.getState().setTimelineFileScope(APPWORKLOAD_PATH);
      useIntuneStore.getState().selectEvent(1);
    });

    expect(screen.getByText("Type Win32 app")).toBeInTheDocument();
    expect(screen.getByText("Status Failed")).toBeInTheDocument();
    expect(screen.getByText("Scoped to AppWorkload.log")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Reset investigation" }));

    expect(useIntuneStore.getState().filterEventType).toBe("All");
    expect(useIntuneStore.getState().filterStatus).toBe("All");
    expect(useIntuneStore.getState().timelineScope.filePath).toBeNull();
    expect(useIntuneStore.getState().selectedEventId).toBeNull();
    expect(screen.queryByText("Type Win32 app")).not.toBeInTheDocument();
    expect(screen.queryByText("Status Failed")).not.toBeInTheDocument();
  });
});

describe("INTUNE-012 New Intune overview triage", () => {
  it("shows triage metrics, priority issues, failure patterns, coverage, and correlated event-log jump", () => {
    seedReadyResults({ eventLogAnalysis: EVENT_LOG_ANALYSIS });
    render(<NewIntuneWorkspace />);

    const metrics = screen.getByRole("region", { name: "Analysis metrics" });
    expect(within(metrics).getByText("Active issues")).toBeInTheDocument();
    expect(within(metrics).getByText("Repeated failures")).toBeInTheDocument();
    expect(within(metrics).getByText("Evidence confidence")).toBeInTheDocument();
    expect(within(metrics).getByText("Dominant source")).toBeInTheDocument();
    expect(within(metrics).getByText("Event log signals")).toBeInTheDocument();
    expect(within(metrics).getByText("Content downloads")).toBeInTheDocument();
    expect(within(metrics).getByText("AppWorkload.log")).toBeInTheDocument();

    expect(screen.getByText("Priority issues")).toBeInTheDocument();
    expect(screen.getByText("Win32 content download failed")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Show related events" }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Scope source" }).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Open downloads" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /event log signal/ })).toBeInTheDocument();
    expect(screen.getByText("Failure patterns")).toBeInTheDocument();
    expect(screen.getByText("Source coverage")).toBeInTheDocument();
    expect(screen.getByText("AppWorkload")).toBeInTheDocument();
    expect(screen.getByText("Correlated event log evidence")).toBeInTheDocument();
    expect(
      screen.getByText("Intune Management Extension reported a content download failure."),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open downloads" }));
    expect(screen.getByText(DOWNLOAD_NAME)).toBeInTheDocument();
  });
});

describe("INTUNE-013 New Intune event-log evidence", () => {
  it("filters live event-log rows and jumps back to the correlated IME event", () => {
    seedReadyResults({ eventLogAnalysis: EVENT_LOG_ANALYSIS });
    render(<NewIntuneWorkspace />);

    fireEvent.click(screen.getByRole("tab", { name: /Event log evidence/ }));
    expect(screen.getByText("All channels (1)")).toBeInTheDocument();
    expect(screen.getByText("All severities")).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: /DeviceManagement-Enterprise-Diagnostics-Provider\/Admin/,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Intune Management Extension reported a content download failure."),
    ).toBeInTheDocument();
    expect(screen.getByText("linked")).toBeInTheDocument();

    fireEvent.click(
      screen.getByText("Intune Management Extension reported a content download failure."),
    );
    expect(screen.getByText("Related IME Evidence")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View in Timeline" }));
    expect(useIntuneStore.getState().selectedEventId).toBe(1);
    expect(screen.getAllByText(FAILED_EVENT_NAME).length).toBeGreaterThan(0);
  });

  it("shows per-channel live query status when no entries return", () => {
    seedReadyResults({ eventLogAnalysis: LIVE_EMPTY_EVENT_LOG_ANALYSIS });
    render(<NewIntuneWorkspace />);

    fireEvent.click(screen.getByRole("tab", { name: /Event log evidence/ }));
    expect(screen.getByText("Live Windows Event Log query completed.")).toBeInTheDocument();
    expect(
      screen.getByText("No matching entries were returned from 2 queried channels."),
    ).toBeInTheDocument();
    expect(screen.getByText("1 channel query failed.")).toBeInTheDocument();
    expect(screen.getByText("Empty")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("Access is denied.")).toBeInTheDocument();
  });
});
