import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DsregcmdSidebar } from "./DsregcmdSidebar";
import { DsregcmdWorkspace } from "./DsregcmdWorkspace";
import { useDsregcmdStore } from "./dsregcmd-store";
import { analysisResult, sourceContext } from "./dsregcmd-test-fixtures";
import { useUiStore } from "../../stores/ui-store";

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    openSourceFileDialog: vi.fn(),
    openSourceFolderDialog: vi.fn(),
    pasteDsregcmdSource: vi.fn(),
    captureDsregcmdSource: vi.fn(),
    commandState: { canRefresh: false },
    refreshActiveSource: vi.fn(),
  }),
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

function seedReady(mdmEnrolled: boolean | null = true) {
  const result = analysisResult();
  result.derived.mdmEnrolled = mdmEnrolled;
  useDsregcmdStore
    .getState()
    .setResults("AzureAdJoined : YES", result, sourceContext());
}

afterEach(() => {
  cleanup();
  useDsregcmdStore.getState().clear();
});

beforeEach(() => {
  useUiStore.setState({ currentPlatform: "windows" });
  useDsregcmdStore.getState().clear();
});

/** Matches any button the removed header row used to carry, including the old "Capture" label and the toolbar's "Capture now". */
const NO_HEADER_BUTTONS = /^(Capture|Paste|Open (Text File|Evidence Folder))/;

describe("DsregcmdWorkspace fixtures", () => {
  it.each([
    { mdmEnrolled: false, label: "Not enrolled" },
    { mdmEnrolled: null, label: "Unknown" },
  ])(
    "shows $label on the MDM Signals card when mdmEnrolled is $mdmEnrolled",
    ({ mdmEnrolled, label }) => {
      seedReady(mdmEnrolled);
      render(<DsregcmdWorkspace />);

      const factsCard = screen.getByText("MDM Signals").parentElement;
      expect(factsCard).toHaveTextContent(label);
    },
  );

  it("DSREG-003 shows health cards and the issues overview", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.getAllByText("Join Type").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Current Stage").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Capture Confidence").length).toBeGreaterThan(0);
    expect(screen.getByText("PRT State")).toBeInTheDocument();
    expect(screen.getByText("MDM Signals")).toBeInTheDocument();
    const factsCard = screen.getByText("MDM Signals").parentElement;
    expect(factsCard).toHaveTextContent("Present");
    expect(screen.getByText("NGC")).toBeInTheDocument();
    expect(screen.getAllByText("Certificate").length).toBeGreaterThan(0);
    expect(screen.getByText("90 days")).toBeInTheDocument();
    expect(screen.getByText("Issues Overview")).toBeInTheDocument();
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    expect(screen.getByText("Next checks")).toBeInTheDocument();
    expect(screen.getByText("Suggested fixes")).toBeInTheDocument();
    expect(screen.getAllByText("PRT may need a refresh").length).toBeGreaterThan(0);
  });

  it("DSREG-004 shows fact groups including Policy Evidence, timeline, and flows", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.getByText("Facts by Group")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Show not reported fields" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Policy Evidence")).toBeInTheDocument();
    expect(screen.getByText("Join State")).toBeInTheDocument();
    expect(screen.getByText("Operating System")).toBeInTheDocument();
    expect(screen.getByText("Proxy Configuration")).toBeInTheDocument();
    expect(screen.getByText("Enrollment Status")).toBeInTheDocument();
    expect(screen.getByText("SCP Configuration")).toBeInTheDocument();
    expect(screen.getByText("Endpoint Connectivity")).toBeInTheDocument();
    expect(screen.getByText("Timeline")).toBeInTheDocument();
    expect(screen.getByText("Flows")).toBeInTheDocument();
  });

  it("DSREG-005 shows the Event Logs surface with channel and severity filters", () => {
    seedReady();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );

    fireEvent.click(screen.getByRole("link", { name: /Event logs/ }));

    expect(screen.getByText("Channel:")).toBeInTheDocument();
    expect(screen.getByText("Severity:")).toBeInTheDocument();
    expect(screen.getByText("1 of 1 entries")).toBeInTheDocument();
    expect(screen.getAllByText("AAD Operational").length).toBeGreaterThan(0);
    expect(screen.getByText("PRT refresh failed")).toBeInTheDocument();
  });

  it("renders no Analysis | Event Logs tab strip", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.queryByRole("button", { name: /^Analysis/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Event Logs/ })).toBeNull();
    expect(document.getElementById("dsregcmd-section-overview")).not.toBeNull();
  });

  it("renders no workspace header row when results are loaded", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.queryByText("dsregcmd Workspace")).toBeNull();
    expect(screen.queryByRole("button", { name: NO_HEADER_BUTTONS })).toBeNull();
  });

  it("renders no workspace header row in the empty state", () => {
    useDsregcmdStore.getState().clear();
    render(<DsregcmdWorkspace />);

    expect(screen.queryByText("dsregcmd Workspace")).toBeNull();
    expect(screen.queryByRole("button", { name: NO_HEADER_BUTTONS })).toBeNull();
    expect(screen.getByText("No dsregcmd source loaded")).toBeInTheDocument();
  });

  it("DSREG-006 shows export controls for JSON, status, summary, and raw input", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.getByText("Export")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy JSON" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy status text" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy summary" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save JSON..." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save summary..." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show raw input" })).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Export boundary (issue #556)
// ---------------------------------------------------------------------------

/// The clipboard is one of the three egress points issue #556 names. The raw
/// `dsregcmd /status` text has no projected form upstream of the workspace, so
/// the copy path must ask the backend to project it; everything else the
/// workspace copies is already projected by the crate before it arrives.
const CLEARTEXT_STATUS = ` TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 Thumbprint : 8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D
 User Identity : adele.vance@contoso.onmicrosoft.com
`;
const CLEARTEXT_STATUS_UPN = "adele.vance@contoso.onmicrosoft.com";
const PROJECTED_STATUS = ` TenantId : [tenant:2f1b8a6d5c4e3f20]
 DeviceId : [device:9c0f4b2a7e6d5c31]
 Thumbprint : [thumbprint:4d7a1e9b2c8f6035]
 User Identity : [upn:7b3e5a1c9f2d4806]
`;

describe("DsregcmdWorkspace export boundary", () => {
  it("DSREG-007 projects the raw status text before it reaches the clipboard", async () => {
    useDsregcmdStore
      .getState()
      .setResults(CLEARTEXT_STATUS, analysisResult(), sourceContext());
    vi.mocked(invoke).mockResolvedValue(PROJECTED_STATUS);
    render(<DsregcmdWorkspace />);

    fireEvent.click(screen.getByRole("button", { name: "Copy status text" }));

    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const calls = vi.mocked(writeText).mock.calls;
    const copied = calls[calls.length - 1]?.[0] ?? "";
    expect(copied).not.toContain(CLEARTEXT_STATUS_UPN);
    expect(vi.mocked(invoke)).toHaveBeenCalledWith("redact_dsregcmd_status_text", {
      input: CLEARTEXT_STATUS,
    });
  });
});
