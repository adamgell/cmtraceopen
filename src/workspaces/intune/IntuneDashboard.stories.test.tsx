import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DownloadStats } from "./DownloadStats";
import { IntuneDashboard } from "./IntuneDashboard";
import { IntuneSidebar } from "./IntuneSidebar";
import { useIntuneStore } from "./intune-store";
import type { IntuneResultMetadata } from "./types";
import {
  ANALYZED_PATH,
  APP_GUID,
  APPWORKLOAD_PATH,
  DOWNLOAD_NAME,
  FAILED_EVENT_NAME,
  GRAPH_APP_NAME,
  GRAPH_GUID_REGISTRY,
  GUID_ONLY_EVENT,
  SCRIPT_BODY,
  SCRIPT_EVENT_NAME,
  STORY_DOWNLOADS,
  STORY_EVENTS,
  STORY_SOURCE_FILES,
  SUMMARY,
  DIAGNOSTIC,
} from "./intune-story-fixtures";

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    commandState: {
      canOpenSources: true,
      canOpenKnownSources: true,
      canRefresh: true,
    },
    openSourceFileDialog: vi.fn(),
    openSourceFolderDialog: vi.fn(),
  }),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({
    count,
    estimateSize,
    getItemKey,
  }: {
    count: number;
    estimateSize: (index: number) => number;
    getItemKey?: (index: number) => string | number;
  }) => ({
    getTotalSize: () => {
      let total = 0;
      for (let index = 0; index < count; index += 1) {
        total += estimateSize(index);
      }
      return total;
    },
    getVirtualItems: () => {
      let start = 0;
      return Array.from({ length: count }, (_, index) => {
        const size = estimateSize(index);
        const item = {
          index,
          key: getItemKey?.(index) ?? index,
          size,
          start,
        };
        start += size;
        return item;
      });
    },
    scrollToIndex: vi.fn(),
    measureElement: vi.fn(),
  }),
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

function tabButton(label: string) {
  return screen.getByRole("button", { name: new RegExp(`^${label}\\d*$`) });
}

function expectVisibleName(name: string) {
  expect(screen.getAllByText(name).length).toBeGreaterThan(0);
}

afterEach(() => {
  cleanup();
  useIntuneStore.getState().clear();
});

beforeEach(() => {
  useIntuneStore.getState().clear();
  vi.mocked(writeText).mockReset();
});

describe("INTUNE-002 classic Timeline / Downloads / Summary tabs", () => {
  it("renders Timeline, Downloads, and Summary and switches among them", () => {
    seedReadyResults();
    render(<IntuneDashboard />);

    expect(tabButton("Timeline")).not.toBeDisabled();
    expect(tabButton("Downloads")).not.toBeDisabled();
    expect(tabButton("Summary")).not.toBeDisabled();
    expectVisibleName(FAILED_EVENT_NAME);

    fireEvent.click(tabButton("Downloads"));
    expect(screen.getByText(DOWNLOAD_NAME)).toBeInTheDocument();
    expect(screen.queryByText(FAILED_EVENT_NAME)).not.toBeInTheDocument();

    fireEvent.click(tabButton("Summary"));
    expect(screen.getByText("Intune Diagnostics Summary")).toBeInTheDocument();
    expect(screen.queryByText(DOWNLOAD_NAME)).not.toBeInTheDocument();
  });

  it("disables empty surfaces and falls back when the active tab has no data", () => {
    act(() => {
      useIntuneStore.getState().beginAnalysis(ANALYZED_PATH, "folder");
      useIntuneStore.getState().setResults(
        STORY_EVENTS,
        [],
        { ...SUMMARY, totalDownloads: 0, successfulDownloads: 0 },
        [DIAGNOSTIC],
        ANALYZED_PATH,
        STORY_SOURCE_FILES,
      );
      useIntuneStore.getState().setActiveTab("downloads");
    });

    render(<IntuneDashboard />);

    expect(tabButton("Downloads")).toBeDisabled();
    expectVisibleName(FAILED_EVENT_NAME);
    expect(useIntuneStore.getState().activeTab).toBe("timeline");
  });

  it("disables tabs while analyzing", () => {
    seedReadyResults();
    act(() => {
      useIntuneStore.setState({ isAnalyzing: true });
    });
    render(<IntuneDashboard />);

    expect(tabButton("Timeline")).toBeDisabled();
    expect(tabButton("Downloads")).toBeDisabled();
    expect(tabButton("Summary")).toBeDisabled();
  });
});

describe("INTUNE-003 time window filter", () => {
  it("offers All Activity / Last Hour / Last 6 Hours / Last Day / Last 7 Days", () => {
    seedReadyResults();
    render(<IntuneDashboard />);

    const windowSelect = screen.getByDisplayValue("All Activity");
    expect(within(windowSelect).getByRole("option", { name: "All Activity" })).toBeInTheDocument();
    expect(within(windowSelect).getByRole("option", { name: "Last Hour" })).toBeInTheDocument();
    expect(within(windowSelect).getByRole("option", { name: "Last 6 Hours" })).toBeInTheDocument();
    expect(within(windowSelect).getByRole("option", { name: "Last Day" })).toBeInTheDocument();
    expect(within(windowSelect).getByRole("option", { name: "Last 7 Days" })).toBeInTheDocument();
  });

  it("anchors the window to the latest event and leaves summary diagnostics unwindowed", () => {
    seedReadyResults();
    render(<IntuneDashboard />);

    expect(screen.getByText(SCRIPT_EVENT_NAME)).toBeInTheDocument();
    fireEvent.change(screen.getByDisplayValue("All Activity"), {
      target: { value: "last-day" },
    });

    expect(screen.getByDisplayValue("Last Day")).toBeInTheDocument();
    expectVisibleName(FAILED_EVENT_NAME);
    expect(screen.queryByText(SCRIPT_EVENT_NAME)).not.toBeInTheDocument();

    fireEvent.click(tabButton("Summary"));
    expect(
      screen.getByText(
        /Diagnostics guidance, confidence, and repeated-failure analysis still reflect the full analyzed source set/,
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Win32 content download failed").length).toBeGreaterThan(0);
  });
});

describe("INTUNE-004 timeline type/status/sort/activity", () => {
  it("filters by type and status, resets, sorts, and switches list vs activity", () => {
    seedReadyResults();
    render(<IntuneDashboard />);

    const typeSelect = screen.getByDisplayValue("All Types");
    expect(within(typeSelect).getByRole("option", { name: "Win32" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "WinGet" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "Script" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "Remediation" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "ESP" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "Sync" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "Policy" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "Download" })).toBeInTheDocument();
    expect(within(typeSelect).getByRole("option", { name: "Other" })).toBeInTheDocument();

    const statusSelect = screen.getByDisplayValue("All Statuses");
    expect(within(statusSelect).getByRole("option", { name: "Success" })).toBeInTheDocument();
    expect(within(statusSelect).getByRole("option", { name: "Failed" })).toBeInTheDocument();
    expect(within(statusSelect).getByRole("option", { name: "In Progress" })).toBeInTheDocument();
    expect(within(statusSelect).getByRole("option", { name: "Pending" })).toBeInTheDocument();
    expect(within(statusSelect).getByRole("option", { name: "Timeout" })).toBeInTheDocument();
    expect(within(statusSelect).getByRole("option", { name: "Unknown" })).toBeInTheDocument();

    fireEvent.change(typeSelect, { target: { value: "PowerShellScript" } });
    expect(screen.getByText(SCRIPT_EVENT_NAME)).toBeInTheDocument();
    expect(screen.queryByText(FAILED_EVENT_NAME)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    expectVisibleName(FAILED_EVENT_NAME);

    fireEvent.change(screen.getByDisplayValue("All Statuses"), {
      target: { value: "Failed" },
    });
    expect(screen.getAllByText(FAILED_EVENT_NAME).length).toBeGreaterThan(0);
    expect(screen.queryByText(SCRIPT_EVENT_NAME)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    const sortSelect = screen.getByDisplayValue("Time");
    expect(within(sortSelect).getByRole("option", { name: "Name" })).toBeInTheDocument();
    expect(within(sortSelect).getByRole("option", { name: "Type" })).toBeInTheDocument();
    expect(within(sortSelect).getByRole("option", { name: "Status" })).toBeInTheDocument();
    expect(within(sortSelect).getByRole("option", { name: "Duration" })).toBeInTheDocument();
    fireEvent.change(sortSelect, { target: { value: "name" } });
    expect(useIntuneStore.getState().sortField).toBe("name");

    fireEvent.click(screen.getByRole("button", { name: "Activity" }));
    expect(screen.getByRole("tree", { name: /Activity groups/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "List" }));
    expect(screen.getByRole("listbox", { name: /Intune event timeline/ })).toBeInTheDocument();
  });
});

describe("INTUNE-005 scope timeline to one included file", () => {
  it("scopes from the sidebar and clears from the nav chip", () => {
    seedReadyResults();
    render(
      <>
        <IntuneSidebar />
        <IntuneDashboard />
      </>,
    );

    fireEvent.click(screen.getByRole("button", { name: /AppWorkload\.log/ }));
    expect(screen.getByText("Scoped")).toBeInTheDocument();
    expect(screen.getByText(/Timeline scoped to AppWorkload\.log/)).toBeInTheDocument();
    expectVisibleName(FAILED_EVENT_NAME);
    expect(screen.queryByText(SCRIPT_EVENT_NAME)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Clear Scope" }));
    expect(screen.queryByText("Scoped")).not.toBeInTheDocument();
    expect(screen.getByText(SCRIPT_EVENT_NAME)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /AppWorkload\.log/ }));
    fireEvent.click(screen.getByRole("button", { name: /AppWorkload\.log/ }));
    expect(useIntuneStore.getState().timelineScope.filePath).toBeNull();
  });
});

describe("INTUNE-006 inspect and copy an IME event", () => {
  it("expands a failed event and copies error context plus script body", async () => {
    seedReadyResults();
    render(<IntuneDashboard />);

    fireEvent.click(screen.getAllByRole("option", { name: /Win32 App Install Failed/ })[0]);
    expect(screen.getByText("Failure context")).toBeInTheDocument();
    expect(screen.getByText(/AppWorkload context:/)).toBeInTheDocument();
    expect(screen.getByText(`${APPWORKLOAD_PATH.split("/").pop()}:12`)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy error + context" }));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("Error: 0x87D30067"));

    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    fireEvent.change(screen.getByDisplayValue("All Types"), {
      target: { value: "PowerShellScript" },
    });
    fireEvent.click(screen.getByRole("option", { name: /Inventory Collection/ }));
    expect(screen.getByText(/Collect inventory/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith(SCRIPT_BODY);
  });
});

describe("INTUNE-007 download statistics table", () => {
  it("shows sortable headers, aggregates, and the download row", () => {
    seedReadyResults();
    render(<IntuneDashboard />);
    fireEvent.click(tabButton("Downloads"));

    expect(screen.getByText("1 files")).toBeInTheDocument();
    expect(screen.getByText(/Success:/)).toBeInTheDocument();
    expect(screen.getByText(/Failure:/)).toBeInTheDocument();
    expect(screen.getByText(/Transferred:/)).toBeInTheDocument();
    expect(screen.getAllByText("1.0 MB").length).toBeGreaterThan(0);
    expect(screen.getByRole("columnheader", { name: "Status" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Content/ })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Size/ })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Speed/ })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /DO %/ })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Dur\./ })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Timestamp/ })).toBeInTheDocument();
    expect(screen.getByText(DOWNLOAD_NAME)).toBeInTheDocument();
    expect(screen.getByText("72.5%")).toBeInTheDocument();
  });

  it("shows the empty download copy when no content events exist", () => {
    render(<DownloadStats downloads={[]} />);
    expect(
      screen.getByText("No content download events were found in this analysis."),
    ).toBeInTheDocument();
  });
});

describe("INTUNE-008 summary findings, coverage, confidence", () => {
  it("renders conclusions, coverage, confidence, remediation, and activity metrics", () => {
    seedReadyResults();
    render(<IntuneDashboard />);
    fireEvent.click(tabButton("Summary"));

    expect(screen.getByText("Conclusions")).toBeInTheDocument();
    expect(screen.getByText("Diagnostics Coverage")).toBeInTheDocument();
    expect(screen.getAllByText("Confidence").length).toBeGreaterThan(0);
    expect(screen.getByText("Repeated Failures")).toBeInTheDocument();
    expect(screen.getByText("Remediation Assistant")).toBeInTheDocument();
    expect(screen.getByText("Activity Metrics")).toBeInTheDocument();
    expect(screen.getByText("Files")).toBeInTheDocument();
    expect(screen.getByText("Families")).toBeInTheDocument();
    expect(screen.getByText("Rotated")).toBeInTheDocument();
    expect(screen.getByText("Dominant")).toBeInTheDocument();
    expect(screen.getByText(/Timestamp Bounds:/)).toBeInTheDocument();
    expect(screen.getByText("AppWorkload")).toBeInTheDocument();
    expect(screen.getByText("AgentExecutor")).toBeInTheDocument();
    expect(screen.getByText("Total Events")).toBeInTheDocument();
    expect(screen.getByText("Win32 Apps")).toBeInTheDocument();
  });
});

describe("INTUNE-009 Graph GUID name enrichment", () => {
  it("shows GraphApi names in activity view and has no Graph panel", () => {
    act(() => {
      useIntuneStore.getState().beginAnalysis(ANALYZED_PATH, "folder");
      useIntuneStore.getState().setResults(
        [GUID_ONLY_EVENT],
        STORY_DOWNLOADS,
        { ...SUMMARY, totalEvents: 1, win32Apps: 0, scripts: 0, succeeded: 0, failed: 1 },
        [],
        ANALYZED_PATH,
        [APPWORKLOAD_PATH],
        { guidRegistry: GRAPH_GUID_REGISTRY },
      );
    });
    render(<IntuneDashboard />);

    fireEvent.click(screen.getByRole("button", { name: "Activity" }));
    expect(screen.getByRole("tree", { name: /Activity groups/ })).toBeInTheDocument();
    expect(useIntuneStore.getState().guidRegistry[APP_GUID]?.source).toBe("GraphApi");
    expect(screen.getByTitle(GRAPH_APP_NAME)).toBeInTheDocument();
    expect(screen.queryByText(/Graph API/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/device picker/i)).not.toBeInTheDocument();
  });
});
