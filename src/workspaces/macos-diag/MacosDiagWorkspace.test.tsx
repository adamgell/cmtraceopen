import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MacosDiagWorkspace } from "./MacosDiagWorkspace";
import { useMacosDiagStore } from "./macos-diag-store";
import type {
  MacosDefenderResult,
  MacosDiagEnvironment,
  MacosIntuneLogScanResult,
  MacosPackagesResult,
  MacosProfilesResult,
  MacosUnifiedLogResult,
} from "./types";
import { createTestVirtualizer } from "../../test-utils/virtualizer";

vi.mock("../../lib/commands", () => ({
  macosScanEnvironment: vi.fn(),
  macosScanIntuneLogs: vi.fn(),
  macosListProfiles: vi.fn(),
  macosInspectDefender: vi.fn(),
  macosListPackages: vi.fn(),
  macosGetPackageInfo: vi.fn(),
  macosGetPackageFiles: vi.fn(),
  macosQueryUnifiedLog: vi.fn(),
  openLogFile: vi.fn(),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: Parameters<typeof createTestVirtualizer>[0]) =>
    createTestVirtualizer(options),
}));

function environment(
  fullDiskAccess: MacosDiagEnvironment["fullDiskAccess"] = "granted",
): MacosDiagEnvironment {
  return {
    macosVersion: "15.3",
    macosBuild: "24D70",
    fullDiskAccess,
    tools: {
      profiles: true,
      mdatp: true,
      pkgutil: true,
      logCommand: true,
    },
    directories: {
      intuneSystemLogs: true,
      intuneUserLogs: true,
      companyPortalLogs: true,
      intuneScriptsLogs: true,
      defenderLogs: true,
      defenderDiag: true,
    },
    summary: "macOS diagnostics ready",
  };
}

function intuneLogs(): MacosIntuneLogScanResult {
  return {
    files: [
      {
        path: "/Library/Logs/Microsoft/Intune/IntuneMDMDaemon.log",
        fileName: "IntuneMDMDaemon.log",
        sizeBytes: 2048,
        modifiedUnixMs: Date.parse("2026-01-15T12:00:00.000Z"),
        sourceDirectory: "/Library/Logs/Microsoft/Intune",
      },
    ],
    scannedDirectories: ["/Library/Logs/Microsoft/Intune"],
    totalSizeBytes: 2048,
  };
}

function profiles(): MacosProfilesResult {
  return {
    profiles: [
      {
        profileIdentifier: "com.contoso.mdm",
        profileDisplayName: "Contoso MDM",
        profileOrganization: "Contoso",
        profileType: "Configuration",
        profileUuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        installDate: null,
        payloads: [],
        isManaged: true,
        verificationState: null,
        description: null,
        source: null,
        removalDisallowed: null,
      },
    ],
    enrollmentStatus: {
      enrolled: true,
      mdmServer: "https://manage.microsoft.com",
      enrollmentType: "Device",
      rawOutput: "",
    },
    rawOutput: "",
  };
}

function defender(): MacosDefenderResult {
  return {
    health: {
      healthy: true,
      healthIssues: [],
      realTimeProtectionEnabled: true,
      definitionsStatus: "Up to date",
      engineVersion: "1.1",
      appVersion: "101.25012.0",
      rawOutput: "",
    },
    logFiles: [],
    diagFiles: [],
  };
}

function packages(): MacosPackagesResult {
  return {
    packages: [
      {
        packageId: "com.microsoft.wdav",
        version: "101.25012.0",
        volume: "/",
        location: null,
        installTime: "1700000000",
      },
    ],
    totalCount: 1,
    microsoftCount: 1,
  };
}

function unifiedLog(): MacosUnifiedLogResult {
  return {
    entries: [
      {
        timestamp: "2026-01-15T12:00:00.000Z",
        process: "mdmclient",
        subsystem: "com.apple.ManagedClient",
        category: "mdm",
        level: "info",
        message: "MDM check-in completed",
        pid: 100,
        tid: 1,
      },
    ],
    totalMatched: 1,
    capped: false,
    resultCap: 5000,
    predicateUsed: "process == \"mdmclient\"",
    timeRange: null,
  };
}

function seedReadyEnvironment() {
  useMacosDiagStore.setState({
    environment: environment("granted"),
    environmentPhase: "ready",
    environmentError: null,
    intuneLogScan: intuneLogs(),
    intuneLogScanLoading: false,
    profilesResult: profiles(),
    profilesLoading: false,
    defenderResult: defender(),
    defenderLoading: false,
    packagesResult: packages(),
    packagesLoading: false,
    unifiedLogResult: unifiedLog(),
    unifiedLogLoading: false,
    activeTab: "intune-logs",
  });
}

afterEach(() => {
  cleanup();
  useMacosDiagStore.getState().clear();
});

beforeEach(() => {
  useMacosDiagStore.getState().clear();
});

describe("MacosDiagWorkspace fixtures", () => {
  it("MACDIAG-001 shows the FDA gate when Full Disk Access is not granted", () => {
    useMacosDiagStore.setState({
      environment: environment("notGranted"),
      environmentPhase: "ready",
      environmentError: null,
    });
    render(<MacosDiagWorkspace />);

    expect(screen.getByText("Full Disk Access Required")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Re-check FDA status" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Open System Settings..." }),
    ).toBeInTheDocument();
  });

  it("MACDIAG-001 shows the ready banner with version, FDA pill, tools, and Refresh all", () => {
    seedReadyEnvironment();
    render(<MacosDiagWorkspace />);

    expect(screen.getByText("macOS Diagnostics")).toBeInTheDocument();
    expect(screen.getByText("macOS 15.3 (24D70)")).toBeInTheDocument();
    expect(screen.getByText("Full Disk Access")).toBeInTheDocument();
    expect(screen.getByText("profiles")).toBeInTheDocument();
    expect(screen.getByText("mdatp")).toBeInTheDocument();
    expect(screen.getByText("pkgutil")).toBeInTheDocument();
    expect(screen.getByText("log")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh all" })).toBeInTheDocument();
  });

  it("MACDIAG-002 shows Intune, Profiles, Defender, Packages, and Unified Log tabs", () => {
    seedReadyEnvironment();
    render(<MacosDiagWorkspace />);

    expect(screen.getByRole("button", { name: /Intune Logs/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Profiles & MDM/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Defender/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Packages/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Unified Log/ })).toBeInTheDocument();

    expect(screen.getByText("Discovered Log Files")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open in log viewer" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Profiles & MDM/ }));
    expect(screen.getByText(/Installed Configuration Profiles/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy all" })).toBeInTheDocument();
    expect(screen.getByText(/Enrolled via Device/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Defender/ }));
    expect(screen.getByText("Defender Health: OK")).toBeInTheDocument();
    expect(screen.getByText("Real-time Protection")).toBeInTheDocument();
    expect(screen.getByText("Definitions")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Packages/ }));
    expect(screen.getByText("Microsoft Packages")).toBeInTheDocument();
    expect(screen.getAllByText("com.microsoft.wdav").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Unified Log/ }));
    expect(screen.getByText("Hide NSURLSession noise")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Query" })).toBeInTheDocument();
    expect(screen.getByText("MDM Client (mdmclient)")).toBeInTheDocument();
  });
});
