import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  captureSccmDiagnostics,
  authorizeSccmAdvancedCapture,
  cancelSccmAdvancedCapture,
  captureSccmAdvancedDiagnostics,
  discoverSccmEnvironment,
  revealInFileManager,
} from "../../lib/commands";
import { open } from "@tauri-apps/plugin-dialog";
import { SccmWorkspace } from "./SccmWorkspace";
import { useSccmStore } from "./sccm-store";
import type {
  SccmCaptureResult,
  SccmEnvironmentDiscovery,
  SccmSourceStatus,
} from "./types";

vi.mock("../../lib/commands", () => ({
  authorizeSccmAdvancedCapture: vi.fn(),
  cancelSccmAdvancedCapture: vi.fn(),
  captureSccmAdvancedDiagnostics: vi.fn(),
  captureSccmDiagnostics: vi.fn(),
  discoverSccmEnvironment: vi.fn(),
  revealInFileManager: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const COVERAGE_ROWS: SccmSourceStatus[] = [
  {
    role: "client",
    sourceId: "client-policy-current",
    rotation: "current",
    state: "captured",
    retainedBytes: 2048,
  },
  {
    role: "client",
    sourceId: "client-policy-absent",
    rotation: "current",
    state: "absent",
    retainedBytes: 0,
  },
  {
    role: "client",
    sourceId: "client-policy-denied",
    rotation: "loUnderscore",
    state: "accessDenied",
    retainedBytes: 0,
    detailCode: "accessDenied",
  },
  {
    role: "managementPoint",
    sourceId: "mp-capped",
    rotation: "numbered",
    state: "capped",
    retainedBytes: 16_777_216,
    detailCode: "byteLimitExceeded",
  },
  {
    role: "distributionPoint",
    sourceId: "dp-skipped",
    rotation: "timestamped",
    state: "skipped",
    retainedBytes: 0,
  },
  {
    role: "softwareUpdatePoint",
    sourceId: "sup-unsupported",
    rotation: "unknown",
    state: "unsupported",
    retainedBytes: 0,
    detailCode: "unsupportedPlatform",
  },
  {
    role: "siteServer",
    sourceId: "site-malformed",
    rotation: "unknown",
    state: "parseFailed",
    retainedBytes: 0,
    detailCode: "malformedRotation",
  },
];

const DISCOVERY: SccmEnvironmentDiscovery = {
  supported: true,
  configmgrVersion: "5.00.9128.1000",
  roles: [
    { role: "client", basis: "service" },
    { role: "managementPoint", basis: "cim" },
  ],
  sources: COVERAGE_ROWS,
  issues: [{ code: "registryAccessDenied", role: "client" }],
  advancedSources: [],
};

const ROLELESS_DISCOVERY: SccmEnvironmentDiscovery = {
  supported: true,
  configmgrVersion: null,
  roles: [],
  sources: [],
  issues: [],
  advancedSources: [],
};

const CAPTURE: SccmCaptureResult = {
  bundleRoot: "C:\\Users\\TEST\\AppData\\Local\\cmtrace-open\\sccm\\bundle-id",
  capturedAtUtc: "2026-08-04T14:30:00Z",
  roles: ["client", "managementPoint"],
  sources: COVERAGE_ROWS,
  artifactCount: 4,
  retainedBytes: 16_779_264,
};

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  useSccmStore.getState().reset();
  vi.mocked(cancelSccmAdvancedCapture).mockResolvedValue(undefined);
});

describe("SccmWorkspace", () => {
  it("starts with a read-only environment discovery action", () => {
    render(<SccmWorkspace />);

    expect(screen.getByText("Read-only environment discovery")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    ).toBeEnabled();
    expect(
      screen.queryByRole("button", { name: "Capture diagnostic bundle" }),
    ).not.toBeInTheDocument();
  });

  it("renders discovered roles and every explicit source coverage state", async () => {
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(DISCOVERY);
    render(<SccmWorkspace />);

    fireEvent.click(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    );

    expect(await screen.findAllByText("Management Point")).toHaveLength(2);
    for (const label of [
      "Captured",
      "Absent",
      "Access denied",
      "Capped",
      "Skipped",
      "Unsupported",
      "Parse failed",
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByText("Registry access denied")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Capture diagnostic bundle" }),
    ).toBeEnabled();
  });

  it("keeps capture unavailable when discovery finds no SCCM roles", async () => {
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(ROLELESS_DISCOVERY);
    vi.mocked(captureSccmDiagnostics).mockResolvedValue(CAPTURE);
    render(<SccmWorkspace />);

    fireEvent.click(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    );

    expect(await screen.findByText("No SCCM roles detected")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This host is supported, but discovery found no Configuration Manager roles to collect.",
      ),
    ).toBeInTheDocument();
    const capture = screen.getByRole("button", {
      name: "Capture diagnostic bundle",
    });
    expect(capture).toBeDisabled();

    fireEvent.click(capture);

    expect(captureSccmDiagnostics).not.toHaveBeenCalled();
    expect(screen.queryByText("Bundle retained")).not.toBeInTheDocument();
  });

  it("disables capture while native work is in flight", async () => {
    let finishCapture: ((result: SccmCaptureResult) => void) | undefined;
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(DISCOVERY);
    vi.mocked(captureSccmDiagnostics).mockImplementation(
      () =>
        new Promise((resolve) => {
          finishCapture = resolve;
        }),
    );
    render(<SccmWorkspace />);

    fireEvent.click(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    );
    const capture = await screen.findByRole("button", {
      name: "Capture diagnostic bundle",
    });
    fireEvent.click(capture);

    expect(
      screen.getByRole("button", { name: "Capturing diagnostic bundle" }),
    ).toBeDisabled();

    finishCapture?.(CAPTURE);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Capture diagnostic bundle" }),
      ).toBeEnabled(),
    );
  });

  it("keeps the previous discovery visible when capture fails", async () => {
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(DISCOVERY);
    vi.mocked(captureSccmDiagnostics).mockRejectedValue(
      new Error("Capture destination is unavailable."),
    );
    render(<SccmWorkspace />);

    fireEvent.click(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Capture diagnostic bundle" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Capture destination is unavailable.",
    );
    expect(screen.getByText("client-policy-current")).toBeInTheDocument();
    expect(screen.getAllByText("Management Point")).toHaveLength(2);
  });

  it("reports retained counts and reveals a successful capture", async () => {
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(DISCOVERY);
    vi.mocked(captureSccmDiagnostics).mockResolvedValue(CAPTURE);
    vi.mocked(revealInFileManager).mockResolvedValue(undefined);
    render(<SccmWorkspace />);

    fireEvent.click(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Capture diagnostic bundle" }),
    );

    expect(await screen.findByText("4 artifacts")).toBeInTheDocument();
    expect(screen.getByText("16.0 MiB retained")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Reveal bundle" }));
    await waitFor(() =>
      expect(revealInFileManager).toHaveBeenCalledWith(CAPTURE.bundleRoot),
    );
  });

  it("runs picker consent authorization and single-use advanced capture", async () => {
    const advancedDiscovery: SccmEnvironmentDiscovery = {
      ...DISCOVERY,
      advancedSources: [
        {
          cardId: "reporting",
          cardVersion: "1.0.0",
          sourceId: "advanced-reporting",
          roleScopes: ["reportingServicesPoint"],
          pathClasses: ["configuredRoleLogRoot", "reportServerLogs"],
          sourceVersion: "5.00.9128.1000",
          availability: "operatorDeclaredCandidate",
          maxBytes: 4_194_304,
          maxFiles: 2,
          rotations: ["current", "lo_"],
        },
      ],
    };
    const capability = {
      capabilityHandle: `cmtraceopen.capture-capability.sha256.v1:${"a".repeat(64)}`,
      cardId: "reporting",
      cardVersion: "1.0.0",
      sourceId: "advanced-reporting",
      roleScope: "reportingServicesPoint",
      pathClass: "configuredRoleLogRoot",
      sourceVersion: "5.00.9128.1000",
    };
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(advancedDiscovery);
    vi.mocked(open).mockResolvedValue("C:\\private-root");
    vi.spyOn(window, "confirm").mockReturnValueOnce(true).mockReturnValueOnce(true);
    vi.mocked(authorizeSccmAdvancedCapture).mockResolvedValue(capability);
    vi.mocked(captureSccmAdvancedDiagnostics).mockResolvedValue(CAPTURE);
    render(<SccmWorkspace />);

    fireEvent.click(screen.getByRole("button", { name: "Discover SCCM environment" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Authorize Reporting services bounded capture",
      }),
    );

    expect(screen.getByText("4.0 MiB total / source")).toBeInTheDocument();
    await waitFor(() =>
      expect(open).toHaveBeenCalledWith({ directory: true, multiple: false }),
    );
    expect(authorizeSccmAdvancedCapture).toHaveBeenCalledWith({
      cardId: "reporting",
      cardVersion: "1.0.0",
      sourceId: "advanced-reporting",
      roleScope: "reportingServicesPoint",
      pathClass: "configuredRoleLogRoot",
      expectedSourceVersion: "5.00.9128.1000",
      selectedRoot: "C:\\private-root",
    });
    await waitFor(() =>
      expect(captureSccmAdvancedDiagnostics).toHaveBeenCalledWith(
        capability.capabilityHandle,
      ),
    );
    expect(cancelSccmAdvancedCapture).not.toHaveBeenCalled();
    expect(useSccmStore.getState().advancedCapability).toBeNull();
  });

  it("cancels a capability when final consent is declined", async () => {
    const advancedDiscovery: SccmEnvironmentDiscovery = {
      ...DISCOVERY,
      advancedSources: [
        {
          cardId: "client-notification-bgb",
          cardVersion: "1.0.0",
          sourceId: "advanced-client-notification-bgb",
          roleScopes: ["clientNotificationServer", "managementPoint"],
          pathClasses: ["configuredRoleLogRoot", "siteServerLogs"],
          sourceVersion: null,
          availability: "observed",
          maxBytes: 4_194_304,
          maxFiles: 2,
          rotations: ["current", "lo_"],
        },
      ],
    };
    const capability = {
      capabilityHandle: `cmtraceopen.capture-capability.sha256.v1:${"b".repeat(64)}`,
      cardId: "client-notification-bgb",
      cardVersion: "1.0.0",
      sourceId: "advanced-client-notification-bgb",
      roleScope: "managementPoint",
      pathClass: "configuredRoleLogRoot",
      sourceVersion: null,
    };
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(advancedDiscovery);
    vi.mocked(open).mockResolvedValue("C:\\private-root");
    vi.spyOn(window, "confirm").mockReturnValueOnce(true).mockReturnValueOnce(false);
    vi.mocked(authorizeSccmAdvancedCapture).mockResolvedValue(capability);
    render(<SccmWorkspace />);

    fireEvent.click(screen.getByRole("button", { name: "Discover SCCM environment" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Authorize Client notification / BGB bounded capture",
      }),
    );

    await waitFor(() =>
      expect(cancelSccmAdvancedCapture).toHaveBeenCalledWith(
        capability.capabilityHandle,
      ),
    );
    expect(captureSccmAdvancedDiagnostics).not.toHaveBeenCalled();
    expect(useSccmStore.getState().advancedCapability).toBeNull();
  });

  it("cancels a late authorization after unmount without writing stale state", async () => {
    const advancedDiscovery: SccmEnvironmentDiscovery = {
      ...DISCOVERY,
      advancedSources: [
        {
          cardId: "reporting",
          cardVersion: "1.0.0",
          sourceId: "advanced-reporting",
          roleScopes: ["reportingServicesPoint"],
          pathClasses: ["configuredRoleLogRoot", "reportServerLogs"],
          sourceVersion: null,
          availability: "operatorDeclaredCandidate",
          maxBytes: 4_194_304,
          maxFiles: 2,
          rotations: ["current", "lo_"],
        },
      ],
    };
    const capability = {
      capabilityHandle: `cmtraceopen.capture-capability.sha256.v1:${"c".repeat(64)}`,
      cardId: "reporting",
      cardVersion: "1.0.0",
      sourceId: "advanced-reporting",
      roleScope: "reportingServicesPoint",
      pathClass: "configuredRoleLogRoot",
      sourceVersion: null,
    };
    let resolveAuthorization:
      | ((value: typeof capability) => void)
      | undefined;
    vi.mocked(discoverSccmEnvironment).mockResolvedValue(advancedDiscovery);
    vi.mocked(open).mockResolvedValue("C:\\private-root");
    vi.spyOn(window, "confirm").mockReturnValueOnce(true);
    vi.mocked(authorizeSccmAdvancedCapture).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveAuthorization = resolve;
        }),
    );
    const { unmount } = render(<SccmWorkspace />);

    fireEvent.click(
      screen.getByRole("button", { name: "Discover SCCM environment" }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Authorize Reporting services bounded capture",
      }),
    );
    await waitFor(() =>
      expect(authorizeSccmAdvancedCapture).toHaveBeenCalledOnce(),
    );

    unmount();
    expect(useSccmStore.getState()).toMatchObject({
      phase: "ready",
      advancedCapability: null,
    });
    resolveAuthorization?.(capability);

    await waitFor(() =>
      expect(cancelSccmAdvancedCapture).toHaveBeenCalledWith(
        capability.capabilityHandle,
      ),
    );
    expect(captureSccmAdvancedDiagnostics).not.toHaveBeenCalled();
    expect(useSccmStore.getState()).toMatchObject({
      phase: "ready",
      advancedCapability: null,
      capture: null,
    });
  });
});
