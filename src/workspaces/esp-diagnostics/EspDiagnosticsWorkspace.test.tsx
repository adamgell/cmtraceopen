import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../../stores/ui-store";
import { ActionCenter } from "./ActionCenter";
import { EvidenceSections } from "./EvidenceSections";
import { EspDiagnosticsWorkspace } from "./EspDiagnosticsWorkspace";
import { EspPhaseProgress } from "./EspPhaseProgress";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import { EspWorkloadTable } from "./EspWorkloadTable";
import { GraphEnrichmentPanel } from "./GraphEnrichmentPanel";
import { LiveActivity } from "./LiveActivity";
import { createEspGraphCoordinator } from "./use-esp-session-updates";
import type {
  EspDiagnosticFinding,
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspInstallerCorrelation,
  EspNormalizedStatus,
  EspProcessObservation,
  EspRawEvidenceRecord,
  EspRegistrationEvent,
  EspScenario,
  EspTimelineEntry,
  EspTrackedKind,
  EspWorkload,
} from "./types";

const GRAPH_MANAGED_DEVICE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GRAPH_MANAGED_DEVICE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function timestamp(rawText: string) {
  return {
    rawText,
    originalOffset: "+00:00",
    normalizedUtc: rawText,
    kind: "utc" as const,
  };
}

function notRequestedGraphStatus() {
  return {
    status: "skipped" as const,
    requiredScope: null,
    apiVersion: "notRequested" as const,
    data: null,
    error: null,
  };
}

function unnormalizedTimestamp(
  rawText: string,
  originalOffset: string | null = null,
) {
  return {
    rawText,
    originalOffset,
    normalizedUtc: null,
    kind:
      originalOffset === null ? ("unspecified" as const) : ("offset" as const),
  };
}

function processObservation(
  pid: number,
  overrides: Partial<EspProcessObservation> = {},
): EspProcessObservation {
  return {
    context: {
      evidenceRef: {
        evidenceId: `ev-process-${pid}`,
        sourceArtifactId: "process-sample",
      },
      provenance: {
        sourceKind: "process",
        sourceArtifactId: "process-sample",
        filePath: null,
        lineNumber: null,
        recordNumber: pid,
        registry: null,
        event: null,
      },
      sourceTimestamp: timestamp("2026-07-15T20:07:30Z"),
      observedAtUtc: "2026-07-15T20:07:30Z",
      sensitivity: "public",
      parseState: "parsed",
      accessState: "available",
    },
    pid,
    processStartTime: timestamp("2026-07-15T20:07:15Z"),
    parentPid: 4120,
    executableName: "msiexec.exe",
    sanitizedCommandLine:
      'msiexec.exe /i ContosoVPN.msi TOKEN=super-secret /L*V "C:\\Windows\\Temp\\ContosoVPN.log"',
    referencedLogPath: "C:\\Windows\\Temp\\ContosoVPN.log",
    appId: "app-vpn-raw-guid",
    productCode: "{11111111-2222-3333-4444-555555555555}",
    ...overrides,
  };
}

function exactCorrelation(): EspInstallerCorrelation {
  return {
    correlationId: "corr-exact",
    workloadId: "workload-vpn",
    confidence: "exact",
    reason: "MSI log path matches the active AppWorkload record.",
    candidateWorkloadIds: ["workload-vpn"],
    processObservations: [processObservation(8044)],
    evidence: [
      { evidenceId: "ev-msi-1", sourceArtifactId: "ime-app-workload" },
    ],
  };
}

function makeSnapshot(
  overrides: Partial<EspDiagnosticsSnapshot> = {},
): EspDiagnosticsSnapshot {
  return {
    schemaVersion: 1,
    scenario: "autopilotV1",
    phase: "deviceSetup",
    generatedAtUtc: "2026-07-15T20:08:05Z",
    elevation: {
      isElevated: false,
      restartSupported: true,
      restrictedSources: [
        "HKLM Enrollment Status Tracking registry",
        "DeviceManagement-Enterprise-Diagnostics-Provider/Admin event log",
        "SYSTEM profile temporary installer logs",
      ],
    },
    identity: {
      deviceName: "ESP-LAB-042",
      managedDeviceId: "managed-device-raw-guid",
      entraDeviceId: "entra-device-raw-guid",
      entdmId: { value: "entdm-sensitive", sensitivity: "sensitive" },
      tenantId: { value: "tenant-sensitive", sensitivity: "sensitive" },
      tenantDomain: { value: "contoso.example", sensitivity: "public" },
      userPrincipalName: {
        value: "operator@contoso.example",
        sensitivity: "restricted",
      },
      serialNumber: { value: "SERIAL-042", sensitivity: "sensitive" },
      evidence: [],
    },
    profile: null,
    enrollments: [],
    sessions: [
      {
        sessionId: "session-current",
        kind: "classic",
        scope: "device",
        userSid: null,
        startedAt: timestamp("2026-07-15T20:00:00Z"),
        endedAt: null,
        phase: "deviceSetup",
        isLatest: true,
        workloadIds: ["workload-vpn"],
        evidence: [],
      },
    ],
    workloads: [
      {
        workloadId: "workload-vpn",
        sessionId: "session-current",
        kind: "win32App",
        scope: "device",
        rawIdentifier: "app-vpn-raw-guid",
        displayName: "Contoso VPN Client",
        status: {
          raw: 3,
          normalized: "installing",
          display: "Installing",
          detail: null,
        },
        timestamps: {
          firstObserved: timestamp("2026-07-15T20:05:00Z"),
          started: timestamp("2026-07-15T20:07:15Z"),
          ended: null,
          lastUpdated: timestamp("2026-07-15T20:08:00Z"),
        },
        exitCode: null,
        enforcementErrorCode: null,
        blocking: true,
        evidence: [],
      },
    ],
    installerCorrelations: [exactCorrelation()],
    nodeCache: [],
    registrationEvents: [],
    deliveryOptimization: null,
    hardware: null,
    activity: [],
    findings: [],
    coverage: [
      {
        artifactId: "ime-app-workload",
        family: "IME workload logs",
        status: "available",
        detail: null,
        observedAtUtc: "2026-07-15T20:08:00Z",
        evidence: [],
      },
      {
        artifactId: "esp-registry",
        family: "ESP registry",
        status: "permissionDenied",
        detail: "Administrator rights required",
        observedAtUtc: "2026-07-15T20:08:00Z",
        evidence: [],
      },
      {
        artifactId: "mdm-events",
        family: "MDM event log",
        status: "available",
        detail: null,
        observedAtUtc: "2026-07-15T20:08:00Z",
        evidence: [],
      },
    ],
    rawEvidence: [],
    graph: null,
    ...overrides,
  };
}

const workloadStateLabels: Array<[EspNormalizedStatus, string]> = [
  ["notStarted", "Not started"],
  ["notInstalled", "Not installed"],
  ["initialized", "Initialized"],
  ["pending", "Pending"],
  ["downloading", "Downloading"],
  ["downloaded", "Downloaded"],
  ["installing", "Installing"],
  ["inProgress", "In progress"],
  ["processed", "Processed"],
  ["succeeded", "Succeeded"],
  ["failed", "Failed"],
  ["skipped", "Skipped"],
  ["uninstalled", "Uninstalled"],
  ["rebootRequired", "Reboot required"],
  ["cancelled", "Cancelled"],
  ["unknown", "Unknown (wire-status-99)"],
];

function makeWorkload(
  workloadId: string,
  kind: EspTrackedKind,
  normalized: EspNormalizedStatus,
  display: string,
  overrides: Partial<EspWorkload> = {},
): EspWorkload {
  return {
    workloadId,
    sessionId: "session-current",
    kind,
    scope: "device",
    rawIdentifier: `raw-${workloadId}`,
    displayName: `${kind} ${workloadId}`,
    status: {
      raw: normalized === "unknown" ? "wire-status-99" : normalized,
      normalized,
      display,
      detail: null,
    },
    timestamps: {
      firstObserved: timestamp("2026-07-15T20:05:00Z"),
      started: null,
      ended: null,
      lastUpdated: timestamp("2026-07-15T20:08:00Z"),
    },
    exitCode: null,
    enforcementErrorCode: null,
    blocking: true,
    evidence: [
      {
        evidenceId: `ev-${workloadId}`,
        sourceArtifactId: "ime-app-workload",
      },
    ],
    ...overrides,
  };
}

function makeFinding(): EspDiagnosticFinding {
  return {
    findingId: "finding-blocker",
    severity: "blocker",
    confidence: "high",
    title: "Required Win32 application is still failing",
    summary: "Exit code 1603 has repeated during the active device phase.",
    recommendedChecks: [
      "Inspect the referenced MSI log around Return value 3.",
      "Verify the requirement and detection rules in Intune.",
    ],
    evidence: [
      { evidenceId: "ev-finding-1", sourceArtifactId: "ime-app-workload" },
    ],
    coverageGapIds: ["coverage-system-temp"],
  };
}

function makeActivity(entryId: string, observedAt: string): EspTimelineEntry {
  return {
    entryId,
    timestamp: timestamp(observedAt),
    kind: "workload",
    title: "Installer retry observed",
    detail: `Occurrence ${entryId}`,
    status: {
      raw: 3,
      normalized: "installing",
      display: "Installing",
      detail: null,
    },
    evidence: [
      { evidenceId: `ev-${entryId}`, sourceArtifactId: "ime-app-workload" },
    ],
  };
}

function makeRawRecord(
  index: number,
  evidenceId = `ev-raw-${index}`,
): EspRawEvidenceRecord {
  return {
    recordId: `raw-record-${index}`,
    provenance: {
      sourceKind: "imeLog",
      sourceArtifactId: "ime-app-workload",
      filePath:
        "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
      lineNumber: index + 1,
      recordNumber: index,
      registry: null,
      event: null,
    },
    sourceTimestamp: timestamp(
      `2026-07-15T20:07:${String(index % 60).padStart(2, "0")}Z`,
    ),
    observedAtUtc: `2026-07-15T20:07:${String(index % 60).padStart(2, "0")}Z`,
    rawValue: { text: `Raw record ${index}` },
    sensitivity: "public",
    parseState: "parsed",
    accessState: "available",
    evidence: [{ evidenceId, sourceArtifactId: "ime-app-workload" }],
  };
}

function makeGraphOverlay(appId: string, displayName: string): EspGraphOverlay {
  const skipped = {
    status: "skipped" as const,
    requiredScope: null,
    apiVersion: "notRequested" as const,
    data: null,
    error: null,
  };
  return {
    requestId: "graph-panel",
    requestedAtUtc: "2026-07-15T20:08:00Z",
    deviceMatch: skipped,
    autopilotIdentity: skipped,
    deploymentProfile: skipped,
    intendedDeploymentProfile: skipped,
    profileAssignments: skipped,
    autopilotEvents: skipped,
    enrollmentConfiguration: skipped,
    apps: {
      status: "available",
      requiredScope: "DeviceManagementApps.Read.All",
      apiVersion: "v1.0",
      data: [
        {
          appId,
          displayName,
          trackedOnEnrollmentStatus: true,
          status: null,
          intentState: notRequestedGraphStatus(),
          assignments: [],
          evidence: [],
        },
      ],
      error: null,
    },
    policies: skipped,
    scripts: skipped,
  };
}

function showSnapshot(
  snapshot = makeSnapshot(),
  options: {
    phase?: "live" | "ready";
    graphPhase?: "ready" | "partial";
  } = {},
) {
  act(() => {
    useEspDiagnosticsStore.setState({
      phase: options.phase ?? "ready",
      requestId: options.phase === "live" ? "live-request" : null,
      sessionId: options.phase === "live" ? "session-current" : null,
      snapshot,
      graphPhase: options.graphPhase ?? "ready",
      graphUnavailableReason: null,
      error: null,
    });
  });
}

beforeEach(() => {
  vi.mocked(invoke).mockReset();
  useEspDiagnosticsStore.setState(
    useEspDiagnosticsStore.getInitialState(),
    true,
  );
  useUiStore.setState({ currentPlatform: "windows" });
});

describe("ESP diagnostic cockpit frame", () => {
  it("keeps admin guidance plus explicit empty, analyzing, and error states inside the full-width workspace", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      isElevated: false,
      restartSupported: true,
      restrictedSources: [],
    });
    render(<EspDiagnosticsWorkspace />);

    expect(
      screen.getByRole("heading", { name: "ESP Diagnostics", level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText("Waiting for evidence")).toBeInTheDocument();
    expect(screen.getByText("Scenario not detected")).toBeInTheDocument();
    expect(screen.getByText("No evidence loaded")).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    expect(
      await screen.findByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).toBeInTheDocument();
    expect(vi.mocked(invoke)).toHaveBeenCalledWith(
      "get_esp_elevation_state",
      undefined,
    );

    act(() => {
      useEspDiagnosticsStore.setState({ phase: "analyzing" });
    });
    expect(screen.getByText("Analyzing captured evidence")).toBeInTheDocument();
    expect(screen.getByText("Reading local artifacts…")).toBeInTheDocument();

    act(() => {
      useEspDiagnosticsStore.setState({
        phase: "error",
        error: "The evidence archive is malformed.",
      });
    });
    expect(screen.getByText("Evidence analysis failed")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "The evidence archive is malformed.",
    );
  });

  it("does not recommend elevation when the entry probe reports administrator", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      isElevated: true,
      restartSupported: true,
      restrictedSources: [],
    });

    render(<EspDiagnosticsWorkspace />);

    await waitFor(() =>
      expect(vi.mocked(invoke)).toHaveBeenCalledWith(
        "get_esp_elevation_state",
        undefined,
      ),
    );
    expect(
      screen.queryByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).not.toBeInTheDocument();
  });

  it("fails safely toward admin guidance when the entry probe is unavailable", async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error("probe unavailable"));

    render(<EspDiagnosticsWorkspace />);

    expect(
      await screen.findByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).toBeInTheDocument();
  });

  it.each<[EspScenario, string]>([
    ["unknown", "Scenario not detected"],
    ["autopilotV1", "Classic Autopilot ESP"],
    ["existingDeviceJson", "Autopilot for existing devices"],
    ["espOnly", "ESP only"],
    ["autopilotDevicePreparationV2", "Autopilot Device Preparation"],
  ])("labels the %s scenario as %s", (scenario, label) => {
    showSnapshot(makeSnapshot({ scenario }));
    render(<EspDiagnosticsWorkspace />);

    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("reports live state, phase, elapsed time, partial coverage, and partial Graph independently", () => {
    showSnapshot(makeSnapshot(), { phase: "live", graphPhase: "partial" });
    render(<EspDiagnosticsWorkspace />);

    expect(screen.getByText("Local collection live")).toBeInTheDocument();
    expect(screen.getByText("Device setup")).toBeInTheDocument();
    expect(screen.getByText("8m 05s")).toBeInTheDocument();
    expect(screen.getByText("2 / 3 sources")).toBeInTheDocument();
    expect(
      screen.getByText("Partial", { selector: "strong" }),
    ).toBeInTheDocument();

    act(() => {
      useEspDiagnosticsStore.setState({ phase: "ready", graphPhase: "ready" });
    });
    expect(screen.getByText("Analysis ready")).toBeInTheDocument();
    expect(
      screen.getByText("Connected", { selector: "strong" }),
    ).toBeInTheDocument();
  });

  it("computes elapsed time deterministically across multiple latest sessions", () => {
    const base = makeSnapshot();
    const deviceSession = base.sessions[0];
    const userSession = {
      ...deviceSession,
      sessionId: "session-user-current",
      scope: "user" as const,
      startedAt: timestamp("2026-07-15T20:04:00Z"),
      workloadIds: [],
    };
    showSnapshot(
      makeSnapshot({
        sessions: [userSession, deviceSession],
      }),
    );

    render(<EspDiagnosticsWorkspace />);

    expect(screen.getByText("8m 05s")).toBeInTheDocument();
    expect(screen.queryByText("4m 05s")).not.toBeInTheDocument();
  });
});

describe("optional Graph enrichment presentation", () => {
  function renderGraphPanel(
    snapshot: EspDiagnosticsSnapshot,
    controls: {
      onRefresh?: () => void | Promise<void>;
      onCancel?: () => void | Promise<void>;
      onSelectDevice?: (managedDeviceId: string) => void | Promise<void>;
    } = {},
  ) {
    return render(<GraphEnrichmentPanel snapshot={snapshot} {...controls} />);
  }

  it("keeps disabled and connecting states local-only and requires an explicit refresh after connection", async () => {
    const onRefresh = vi.fn();
    const onCancel = vi.fn();
    const snapshot = makeSnapshot();
    useUiStore.setState({
      graphApiEnabled: false,
      graphApiStatus: "idle",
    });
    useEspDiagnosticsStore.setState({
      snapshot,
      graphPhase: "disabled",
      graphUnavailableReason: "graphDisabled",
    });

    renderGraphPanel(snapshot, { onRefresh, onCancel });

    const panel = screen.getByRole("region", {
      name: "Microsoft Graph enrichment",
    });
    expect(panel).toHaveTextContent("Graph enrichment is off");
    expect(
      within(panel).getByRole("button", { name: "Refresh Graph data" }),
    ).toBeDisabled();
    expect(within(panel).queryByText("Sign in with Windows")).toBeNull();
    expect(within(panel).queryByText("Sign out")).toBeNull();

    act(() => {
      useUiStore.setState({
        graphApiEnabled: true,
        graphApiStatus: "connecting",
      });
      useEspDiagnosticsStore
        .getState()
        .setGraphUnavailable("graphNotConnected");
    });
    expect(panel).toHaveTextContent("GraphNotConnected");
    expect(panel).toHaveTextContent("never opens Windows sign-in");
    expect(
      within(panel).getByRole("button", { name: "Refresh Graph data" }),
    ).toBeDisabled();
    expect(onRefresh).not.toHaveBeenCalled();

    act(() => {
      useUiStore.setState({ graphApiStatus: "connected" });
      useEspDiagnosticsStore.setState({
        graphPhase: "idle",
        graphUnavailableReason: null,
      });
    });
    expect(panel).toHaveTextContent("Ready for explicit refresh");
    fireEvent.click(
      within(panel).getByRole("button", { name: "Refresh Graph data" }),
    );
    expect(onRefresh).toHaveBeenCalledOnce();

    act(() => {
      useEspDiagnosticsStore.setState({
        graphPhase: "loading",
        graphRequestId: "graph-loading",
      });
    });
    fireEvent.click(
      within(panel).getByRole("button", { name: "Cancel Graph query" }),
    );
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it("shows independent partial, denied, offline, throttled, cancelled, and beta section states", () => {
    const overlay = makeGraphOverlay(
      "assignment-only-app",
      "Assignment-only application",
    );
    overlay.deviceMatch = {
      status: "notFound",
      requiredScope: "DeviceManagementManagedDevices.Read.All",
      apiVersion: "v1.0",
      data: null,
      error: null,
    };
    overlay.autopilotIdentity = {
      status: "permissionDenied",
      requiredScope: "DeviceManagementServiceConfig.Read.All",
      apiVersion: "beta",
      data: null,
      error: {
        code: "Forbidden",
        message: "Autopilot identity permission is unavailable",
        requestId: "request-denied",
        blockedBy: null,
        retryAfterSeconds: null,
      },
    };
    overlay.deploymentProfile = {
      status: "failed",
      requiredScope: "DeviceManagementServiceConfig.Read.All",
      apiVersion: "beta",
      data: null,
      error: {
        code: "Offline",
        message: "Microsoft Graph is unreachable",
        requestId: null,
        blockedBy: null,
        retryAfterSeconds: null,
      },
    };
    overlay.profileAssignments = {
      status: "failed",
      requiredScope: "DeviceManagementServiceConfig.Read.All",
      apiVersion: "beta",
      data: null,
      error: {
        code: "TooManyRequests",
        message: "Microsoft Graph throttled this section",
        requestId: "request-throttled",
        blockedBy: null,
        retryAfterSeconds: 12,
      },
    };
    overlay.apps = {
      status: "available",
      requiredScope: "DeviceManagementApps.Read.All",
      apiVersion: "v1.0",
      data: [
        {
          appId: "assignment-only-app",
          displayName: "Assignment-only application",
          trackedOnEnrollmentStatus: false,
          status: null,
          intentState: notRequestedGraphStatus(),
          assignments: [
            {
              assignmentId: "assignment-required",
              targetId: "group-required",
              filterId: "filter-required",
              intent: "required",
              targetKind: "group",
              targeting: "declared",
              evidence: [],
            },
          ],
          evidence: [],
        },
        {
          appId: "app-vpn-raw-guid",
          displayName: "Contoso VPN from Graph",
          trackedOnEnrollmentStatus: true,
          status: {
            raw: "installing",
            normalized: "installing",
            display: "Installing",
            detail: null,
          },
          intentState: notRequestedGraphStatus(),
          assignments: [],
          evidence: [],
        },
      ],
      error: null,
    };
    overlay.autopilotEvents = {
      status: "available",
      requiredScope: "DeviceManagementServiceConfig.Read.All",
      apiVersion: "beta",
      data: [
        {
          eventId: "event-policy-status",
          managedDeviceId: "managed-device-raw-guid",
          enrollmentConfigurationId: null,
          eventTime: timestamp("2026-07-15T20:06:00Z"),
          deploymentState: {
            raw: "inProgress",
            normalized: "inProgress",
            display: "In progress",
            detail: null,
          },
          policyStatusDetails: [
            {
              statusDetailId: "detail-app-vpn",
              relatedObjectId: "app-vpn-raw-guid",
              displayName: "Contoso VPN event status",
              kind: "app",
              trackedOnEnrollmentStatus: true,
              status: {
                raw: "installing",
                normalized: "installing",
                display: "Installing",
                detail: null,
              },
              correlationConfidence: "exact",
              evidence: [],
            },
          ],
          evidence: [],
        },
      ],
      error: null,
    };
    overlay.policies = {
      status: "permissionDenied",
      requiredScope: "DeviceManagementConfiguration.Read.All",
      apiVersion: "v1.0",
      data: null,
      error: {
        code: "Forbidden",
        message: "Policy permission is unavailable",
        requestId: "request-policy",
        blockedBy: null,
        retryAfterSeconds: null,
      },
    };
    overlay.scripts = {
      status: "cancelled",
      requiredScope: "DeviceManagementScripts.Read.All",
      apiVersion: "beta",
      data: null,
      error: {
        code: "Cancelled",
        message: "Script query cancelled",
        requestId: null,
        blockedBy: null,
        retryAfterSeconds: null,
      },
    };
    const snapshot = makeSnapshot({ graph: overlay });
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });
    useEspDiagnosticsStore.setState({
      snapshot,
      graphPhase: "partial",
      graphUnavailableReason: null,
    });

    renderGraphPanel(snapshot);

    const panel = screen.getByRole("region", {
      name: "Microsoft Graph enrichment",
    });
    expect(panel).toHaveTextContent("Partial enrichment");
    expect(panel).toHaveTextContent("No managed device match");
    expect(panel).toHaveTextContent("Permission denied");
    expect(panel).toHaveTextContent("Microsoft Graph is unreachable");
    expect(panel).toHaveTextContent("Retry after 12 seconds");
    expect(panel).toHaveTextContent("Cancelled");
    expect(within(panel).getAllByText("Beta").length).toBeGreaterThan(0);

    const applications = within(panel).getByRole("article", {
      name: "Graph section Applications",
    });
    expect(applications).toHaveTextContent(
      "Declared targeting · Required · group · group-required",
    );
    expect(applications).toHaveTextContent("Filter · filter-required");
    expect(applications).toHaveTextContent(
      "Effective · local ESP tracking observed",
    );
    expect(applications).toHaveTextContent(
      "Effective device status · Installing",
    );
    const assignmentOnly = within(applications).getByTestId(
      "graph-record-assignment-only-app",
    );
    expect(assignmentOnly).toHaveTextContent("Declared targeting");
    expect(assignmentOnly).not.toHaveTextContent("Effective");

    const events = within(panel).getByRole("article", {
      name: "Graph section Autopilot events",
    });
    expect(events).toHaveTextContent(
      "Effective Autopilot status · Contoso VPN event status · Installing",
    );
  });

  it("renders an accessible API version for dependency-blocked sections that were not requested", () => {
    const overlay = makeGraphOverlay(
      "app-vpn-raw-guid",
      "Contoso VPN from Graph",
    );
    overlay.autopilotIdentity = {
      status: "skipped",
      requiredScope: "DeviceManagementServiceConfig.Read.All",
      apiVersion: "notRequested",
      data: null,
      error: {
        code: "Blocked",
        message: "Select a managed device first",
        requestId: "request-blocked",
        blockedBy: "deviceMatch",
        retryAfterSeconds: null,
      },
    };
    const snapshot = makeSnapshot({ graph: overlay });
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });
    useEspDiagnosticsStore.setState({
      snapshot,
      graphPhase: "partial",
      graphUnavailableReason: null,
    });

    renderGraphPanel(snapshot);

    const autopilotIdentity = screen.getByRole("article", {
      name: "Graph section Autopilot identity",
    });
    expect(within(autopilotIdentity).getByText("Not requested")).toBeVisible();
  });

  it("requires explicit selection for ambiguous managed-device candidates", () => {
    const onSelectDevice = vi.fn();
    const overlay = makeGraphOverlay(
      "app-vpn-raw-guid",
      "Contoso VPN from Graph",
    );
    const candidates = [
      {
        managedDeviceId: GRAPH_MANAGED_DEVICE_A,
        entraDeviceId: "entra-candidate-a",
        serialNumber: null,
        deviceName: "ESP-LAB-A",
        userId: null,
        userPrincipalName: null,
        tenantId: null,
        evidence: [],
      },
      {
        managedDeviceId: GRAPH_MANAGED_DEVICE_B,
        entraDeviceId: "entra-candidate-b",
        serialNumber: null,
        deviceName: "ESP-LAB-B",
        userId: null,
        userPrincipalName: null,
        tenantId: null,
        evidence: [],
      },
    ];
    overlay.deviceMatch = {
      status: "available",
      requiredScope: "DeviceManagementManagedDevices.Read.All",
      apiVersion: "v1.0",
      data: {
        selected: null,
        candidates,
        matchBasis: "serialNumber",
        confidence: "temporal",
        evidence: [],
      },
      error: null,
    };
    const snapshot = makeSnapshot({ graph: overlay });
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });
    useEspDiagnosticsStore.setState({
      snapshot,
      graphPhase: "partial",
      graphUnavailableReason: null,
    });

    const view = renderGraphPanel(snapshot, { onSelectDevice });

    const panel = screen.getByRole("region", {
      name: "Microsoft Graph enrichment",
    });
    expect(panel).toHaveTextContent(
      "Selection is required before dependent queries can continue",
    );
    fireEvent.click(
      within(panel).getByRole("button", {
        name: `Select Graph device ${GRAPH_MANAGED_DEVICE_B}`,
      }),
    );
    expect(onSelectDevice).toHaveBeenCalledWith(GRAPH_MANAGED_DEVICE_B);

    overlay.deviceMatch.data = {
      selected: candidates[1],
      candidates,
      matchBasis: "managedDeviceId",
      confidence: "exact",
      evidence: [],
    };
    const selectedSnapshot = makeSnapshot({ graph: overlay });
    act(() => {
      useEspDiagnosticsStore.setState({ snapshot: selectedSnapshot });
    });
    view.rerender(
      <GraphEnrichmentPanel
        snapshot={selectedSnapshot}
        onSelectDevice={onSelectDevice}
      />,
    );
    expect(panel).toHaveTextContent("Selected device · ESP-LAB-B");
    expect(panel).toHaveTextContent(GRAPH_MANAGED_DEVICE_B);
  });

  it("sends an explicit candidate through the coordinator request contract", async () => {
    const snapshot = makeSnapshot();
    const fetchGraph = vi.fn(async (request) => ({
      ...makeGraphOverlay("app-vpn-raw-guid", "Contoso VPN from Graph"),
      requestId: request.requestId,
    }));
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });
    useEspDiagnosticsStore.setState({
      snapshot,
      graphPhase: "idle",
      graphUnavailableReason: null,
    });
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-explicit-candidate",
    });

    await coordinator.refresh(GRAPH_MANAGED_DEVICE_B);

    expect(fetchGraph).toHaveBeenCalledWith(
      expect.objectContaining({
        requestId: "graph-explicit-candidate",
        selectedManagedDeviceId: GRAPH_MANAGED_DEVICE_B,
      }),
    );
    coordinator.dispose();
  });

  it("cancels a manual coordinator query and ignores its late overlay", async () => {
    const snapshot = makeSnapshot();
    let resolveGraph!: (overlay: EspGraphOverlay) => void;
    const fetchGraph = vi.fn(
      () =>
        new Promise<EspGraphOverlay>((resolve) => {
          resolveGraph = resolve;
        }),
    );
    const cancelGraph = vi.fn(async () => undefined);
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });
    useEspDiagnosticsStore.setState({
      snapshot,
      graphPhase: "idle",
      graphUnavailableReason: null,
    });
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => "graph-manual-cancel",
    });

    const pendingRefresh = coordinator.refresh();
    await waitFor(() => expect(fetchGraph).toHaveBeenCalledOnce());
    await coordinator.cancel();

    expect(cancelGraph).toHaveBeenCalledWith("graph-manual-cancel");
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("cancelled");
    resolveGraph({
      ...makeGraphOverlay("app-vpn-raw-guid", "Late Graph name"),
      requestId: "graph-manual-cancel",
    });
    await pendingRefresh;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    coordinator.dispose();
  });

  it("keeps local IDs and evidence visible after a remote query error", () => {
    const snapshot = makeSnapshot();
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot,
      graphPhase: "error",
      graphUnavailableReason: null,
      graphError: "Microsoft Graph is offline",
    });

    render(<EspDiagnosticsWorkspace />);

    expect(
      screen.getByRole("region", { name: "Microsoft Graph enrichment" }),
    ).toHaveTextContent("Microsoft Graph is offline");
    expect(
      screen.getByRole("region", { name: "Tracked workloads" }),
    ).toHaveTextContent("app-vpn-raw-guid");
    expect(screen.getByRole("region", { name: "ESP evidence" })).toBeVisible();
  });
});

describe("ESP elevation recommendation", () => {
  it("lists exact restricted evidence, states the numeric coverage impact, and invokes explicit relaunch", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      launched: true,
      reason: "launched",
    });
    showSnapshot();
    render(<EspDiagnosticsWorkspace />);

    const recommendation = screen.getByRole("region", {
      name: "Administrator coverage recommendation",
    });
    expect(recommendation).toHaveTextContent(
      "3 restricted evidence sources are unavailable",
    );
    expect(recommendation).toHaveTextContent(
      "HKLM Enrollment Status Tracking registry",
    );
    expect(recommendation).toHaveTextContent(
      "DeviceManagement-Enterprise-Diagnostics-Provider/Admin event log",
    );
    expect(recommendation).toHaveTextContent(
      "SYSTEM profile temporary installer logs",
    );
    expect(
      screen.getByText("Standard user", { selector: "strong" }),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Restart as administrator" }),
    );
    await waitFor(() =>
      expect(vi.mocked(invoke)).toHaveBeenCalledWith(
        "restart_esp_as_administrator",
        undefined,
      ),
    );
    expect(
      screen.getByText("Administrator restart requested."),
    ).toBeInTheDocument();
  });

  it("keeps the recommendation persistent when relaunch is unsupported", () => {
    showSnapshot(
      makeSnapshot({
        elevation: {
          isElevated: false,
          restartSupported: false,
          restrictedSources: ["Protected process command lines"],
        },
      }),
    );
    render(<EspDiagnosticsWorkspace />);

    expect(
      screen.queryByRole("button", { name: "Restart as administrator" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Close CMTrace Open and relaunch it explicitly as administrator.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Protected process command lines"),
    ).toBeInTheDocument();
  });

  it("reports full administrator coverage without showing a recommendation", () => {
    showSnapshot(
      makeSnapshot({
        elevation: {
          isElevated: true,
          restartSupported: false,
          restrictedSources: [],
        },
      }),
    );
    render(<EspDiagnosticsWorkspace />);

    expect(
      screen.getByText("Elevated", { selector: "strong" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).not.toBeInTheDocument();
  });
});

describe("current MSIEXEC activity", () => {
  it("makes absence explicit when no installer process is observed", () => {
    showSnapshot(makeSnapshot({ installerCorrelations: [] }));
    render(<EspDiagnosticsWorkspace />);

    expect(screen.getByText("0 active processes")).toBeInTheDocument();
    expect(
      screen.getByText("No active MSI installer process observed"),
    ).toBeInTheDocument();
  });

  it("shows an exact single-process correlation, raw IDs, redacted command, log, and evidence actions", () => {
    showSnapshot();
    render(<EspDiagnosticsWorkspace />);

    const installer = screen.getByRole("region", {
      name: "What MSIEXEC is doing now",
    });
    expect(installer).toHaveTextContent("1 active process");
    expect(installer).toHaveTextContent("Exact match");
    expect(installer).toHaveTextContent("Contoso VPN Client");
    expect(installer).toHaveTextContent("app-vpn-raw-guid");
    expect(installer).toHaveTextContent("PID 8044");
    expect(installer).toHaveTextContent("Parent PID 4120");
    expect(installer).toHaveTextContent("TOKEN=[REDACTED]");
    expect(installer).not.toHaveTextContent("super-secret");
    expect(installer).toHaveTextContent("C:\\Windows\\Temp\\ContosoVPN.log");
    expect(
      screen.getByRole("link", { name: "Open evidence ev-msi-1" }),
    ).toHaveAttribute("href", "#evidence-ev-msi-1");
  });

  it("distinguishes temporal and ambiguous correlations across multiple processes", () => {
    const temporal: EspInstallerCorrelation = {
      ...exactCorrelation(),
      correlationId: "corr-temporal",
      workloadId: "workload-vpn",
      confidence: "temporal",
      reason: "Only active workload inside the ±120 second window.",
      processObservations: [
        processObservation(9055, {
          sanitizedCommandLine: "msiexec.exe /i ContosoVPN.msi /qn",
          referencedLogPath: null,
        }),
      ],
    };
    const ambiguous: EspInstallerCorrelation = {
      correlationId: "corr-ambiguous",
      workloadId: null,
      confidence: "uncorrelated",
      reason: "Multiple active workloads match the observation window.",
      candidateWorkloadIds: ["workload-vpn", "workload-office"],
      processObservations: [
        processObservation(9177, {
          appId: null,
          productCode: null,
          sanitizedCommandLine: "msiexec.exe /i unknown.msi /qn",
          referencedLogPath: null,
        }),
      ],
      evidence: [],
    };
    showSnapshot(
      makeSnapshot({ installerCorrelations: [temporal, ambiguous] }),
    );
    render(<EspDiagnosticsWorkspace />);

    expect(screen.getByText("2 active processes")).toBeInTheDocument();
    expect(screen.getByText("Temporal match")).toBeInTheDocument();
    expect(screen.getByText("Ambiguous — 2 candidates")).toBeInTheDocument();
    expect(screen.getAllByText("No active MSI log referenced")).toHaveLength(2);
  });
});

describe("actionable read-only findings", () => {
  it("shows severity, confidence, recommended checks, provenance, and no remediation controls", () => {
    render(<ActionCenter findings={[makeFinding()]} />);

    const actionCenter = screen.getByRole("region", { name: "Action center" });
    expect(actionCenter).toHaveTextContent("Blocker · High confidence");
    expect(actionCenter).toHaveTextContent(
      "Required Win32 application is still failing",
    );
    expect(actionCenter).toHaveTextContent(
      "Inspect the referenced MSI log around Return value 3.",
    );
    expect(actionCenter).toHaveTextContent(
      "Verify the requirement and detection rules in Intune.",
    );
    expect(
      within(actionCenter).getByRole("link", {
        name: "Open evidence ev-finding-1",
      }),
    ).toHaveAttribute("href", "#evidence-ev-finding-1");
    expect(actionCenter).toHaveTextContent("coverage-system-temp");
    expect(within(actionCenter).queryByRole("button")).not.toBeInTheDocument();
  });
});

describe("scenario-aware phase progress", () => {
  it("keeps classic ESP and Device Preparation phase rules visibly distinct", () => {
    const view = render(
      <EspPhaseProgress
        snapshot={makeSnapshot({
          scenario: "autopilotV1",
          phase: "deviceSetup",
        })}
      />,
    );

    const progress = screen.getByRole("region", { name: "ESP phase progress" });
    expect(progress).toHaveTextContent("Classic ESP phases");
    expect(progress).toHaveTextContent("Device setup · Current");
    expect(progress).toHaveTextContent("Account setup · Pending");

    view.rerender(
      <EspPhaseProgress
        snapshot={makeSnapshot({
          scenario: "autopilotDevicePreparationV2",
          phase: "devicePreparation",
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              kind: "devicePreparationV2",
              phase: "devicePreparation",
            },
          ],
        })}
      />,
    );
    expect(progress).toHaveTextContent("Device Preparation phases");
    expect(progress).toHaveTextContent("Agent bootstrap · Current");
    expect(progress).not.toHaveTextContent("Classic ESP phases");
  });

  it("keeps not-started stages pending for both classic and Device Preparation", () => {
    const view = render(
      <EspPhaseProgress
        snapshot={makeSnapshot({
          phase: "notStarted",
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              phase: "notStarted",
            },
          ],
        })}
      />,
    );

    const progress = screen.getByRole("region", { name: "ESP phase progress" });
    expect(within(progress).getAllByText(/· Pending$/)).toHaveLength(3);
    expect(progress).not.toHaveTextContent("· Current");
    expect(progress).not.toHaveTextContent("· Complete");
    expect(progress).not.toHaveTextContent("· Failed");

    view.rerender(
      <EspPhaseProgress
        snapshot={makeSnapshot({
          scenario: "autopilotDevicePreparationV2",
          phase: "notStarted",
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              kind: "devicePreparationV2",
              phase: "notStarted",
            },
          ],
        })}
      />,
    );
    expect(within(progress).getAllByText(/· Pending$/)).toHaveLength(4);
    expect(progress).not.toHaveTextContent("· Current");
    expect(progress).not.toHaveTextContent("· Failed");
  });

  it("does not invent a failing stage when the snapshot only reports failure", () => {
    const view = render(
      <EspPhaseProgress
        snapshot={makeSnapshot({
          phase: "failed",
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              phase: "failed",
            },
          ],
        })}
      />,
    );

    const progress = screen.getByRole("region", { name: "ESP phase progress" });
    expect(progress).toHaveTextContent("Failing stage not identified");
    expect(progress).not.toHaveTextContent("Account setup · Failed");

    view.rerender(
      <EspPhaseProgress
        snapshot={makeSnapshot({
          scenario: "autopilotDevicePreparationV2",
          phase: "failed",
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              kind: "devicePreparationV2",
              phase: "failed",
            },
          ],
        })}
      />,
    );
    expect(progress).not.toHaveTextContent("Completion · Failed");
  });
});

describe("independent live activity", () => {
  it("retains repeated occurrences and updates without replacing workload state", () => {
    const workload = makeWorkload(
      "persistent-row",
      "win32App",
      "installing",
      "Installing",
      { displayName: "Workload row persists" },
    );
    const first = makeSnapshot({
      installerCorrelations: [],
      workloads: [workload],
      activity: [makeActivity("activity-a", "2026-07-15T20:07:00Z")],
    });
    const view = render(
      <>
        <LiveActivity entries={first.activity} />
        <EspWorkloadTable snapshot={first} />
      </>,
    );

    const activity = screen.getByRole("region", { name: "Live activity" });
    expect(
      within(activity).getAllByText("Installer retry observed"),
    ).toHaveLength(1);

    view.rerender(
      <>
        <LiveActivity
          entries={[
            makeActivity("activity-a", "2026-07-15T20:07:00Z"),
            makeActivity("activity-b", "2026-07-15T20:07:30Z"),
          ]}
        />
        <EspWorkloadTable
          snapshot={{
            ...first,
          }}
        />
      </>,
    );
    expect(
      within(activity).getAllByText("Installer retry observed"),
    ).toHaveLength(2);
    expect(
      within(
        screen.getByRole("region", { name: "Tracked workloads" }),
      ).getByText("Workload row persists"),
    ).toBeInTheDocument();
  });

  it("keeps raw timestamps verbatim and orders only normalized UTC timestamps", () => {
    const rawActivity = {
      ...makeActivity("raw-activity", "2026-07-15T01:00:00Z"),
      timestamp: unnormalizedTimestamp("2026-07-15T01:00:00"),
    };
    const normalizedActivity = makeActivity(
      "normalized-activity",
      "2026-07-15T04:00:00Z",
    );
    const rawWorkload = makeWorkload(
      "raw-workload",
      "win32App",
      "pending",
      "Pending",
      {
        timestamps: {
          firstObserved: unnormalizedTimestamp("2026-07-15T01:00:00"),
          started: null,
          ended: null,
          lastUpdated: null,
        },
      },
    );
    const normalizedWorkload = makeWorkload(
      "normalized-workload",
      "win32App",
      "installing",
      "Installing",
      {
        timestamps: {
          firstObserved: timestamp("2026-07-15T04:00:00Z"),
          started: null,
          ended: null,
          lastUpdated: null,
        },
      },
    );

    render(
      <>
        <LiveActivity entries={[rawActivity, normalizedActivity]} />
        <EspWorkloadTable
          snapshot={makeSnapshot({
            installerCorrelations: [],
            activity: [],
            workloads: [rawWorkload, normalizedWorkload],
            sessions: [
              {
                ...makeSnapshot().sessions[0],
                workloadIds: [
                  rawWorkload.workloadId,
                  normalizedWorkload.workloadId,
                ],
              },
            ],
          })}
        />
      </>,
    );

    const activityEntries = within(
      screen.getByRole("region", { name: "Live activity" }),
    ).getAllByTestId("esp-activity-entry");
    expect(activityEntries[0]).toHaveTextContent("normalized-activity");
    expect(activityEntries[1]).toHaveTextContent("raw-activity");
    expect(activityEntries[1]).toHaveTextContent("2026-07-15T01:00:00");

    const workloadRows = within(
      screen.getByRole("region", { name: "Tracked workloads" }),
    ).getAllByTestId("esp-workload-row");
    expect(workloadRows[0]).toHaveTextContent("normalized-workload");
    expect(workloadRows[1]).toHaveTextContent("raw-workload");
  });

  it("moves from a clamped page using the visible window after entries shrink", () => {
    const entries = Array.from({ length: 200 }, (_, index) =>
      makeActivity(
        `page-${index}`,
        `2026-07-15T20:${String(index % 60).padStart(2, "0")}:00Z`,
      ),
    );
    const view = render(<LiveActivity entries={entries} />);
    const activity = screen.getByRole("region", { name: "Live activity" });

    fireEvent.click(within(activity).getByRole("button", { name: "Older" }));
    fireEvent.click(within(activity).getByRole("button", { name: "Older" }));
    view.rerender(<LiveActivity entries={entries.slice(0, 100)} />);
    expect(activity).toHaveTextContent("Showing 21–100 of 100 occurrences");

    fireEvent.click(within(activity).getByRole("button", { name: "Newer" }));
    expect(activity).toHaveTextContent("Showing 1–80 of 100 occurrences");
  });
});

describe("workload table", () => {
  it("uses nested status detail for visual severity and shows both wire statuses", () => {
    const workload = makeWorkload(
      "nested-failure",
      "win32App",
      "succeeded",
      "Outer processing succeeded",
      {
        status: {
          raw: "outer-success",
          normalized: "succeeded",
          display: "Outer processing succeeded",
          detail: {
            raw: "inner-failure-1603",
            normalized: "failed",
            display: "Installer failed",
          },
        },
      },
    );
    render(
      <EspWorkloadTable snapshot={makeSnapshot({ workloads: [workload] })} />,
    );

    const row = screen.getByRole("row", { name: /nested-failure/i });
    expect(row).toHaveTextContent("Outer processing succeeded");
    expect(row).toHaveTextContent("Detail · Installer failed");
    expect(row).toHaveTextContent("Raw · outer-success");
    expect(row).toHaveTextContent("Detail raw · inner-failure-1603");
    expect(
      within(row).getByTestId("esp-workload-effective-status"),
    ).toHaveTextContent("Installer failed");
    expect(
      within(row).getByTestId("esp-workload-effective-status"),
    ).not.toHaveTextContent("Outer processing succeeded");
    expect(
      row.querySelector('[data-effective-status="failed"]'),
    ).toBeInTheDocument();
  });

  it("renders every workload kind and wire state with scope, codes, unknowns, and additive Graph names", () => {
    const kinds: EspTrackedKind[] = [
      "msi",
      "office",
      "modernApp",
      "win32App",
      "policy",
      "scepCertificate",
      "platformScript",
      "devicePreparationWorkload",
    ];
    const workloads = workloadStateLabels.map(([state, display], index) =>
      makeWorkload(
        `state-${index}`,
        kinds[index % kinds.length],
        state,
        display,
        {
          scope: index % 2 === 0 ? "device" : "user",
          rawIdentifier:
            index === 0 ? "graph-app-raw-guid" : `raw-state-${index}`,
          displayName:
            index === 0
              ? "Contoso VPN local name"
              : state === "unknown"
                ? null
                : `${kinds[index % kinds.length]} workload ${index}`,
          blocking: state === "unknown" ? null : index % 2 === 0,
          exitCode:
            index === 0
              ? { raw: "1603", decimal: 1603, hex: "0x00000643" }
              : null,
          enforcementErrorCode:
            index === 0
              ? {
                  raw: "-2016330855",
                  decimal: -2016330855,
                  hex: "0x87D30019",
                }
              : null,
        },
      ),
    );
    render(
      <EspWorkloadTable
        snapshot={makeSnapshot({
          installerCorrelations: [],
          workloads,
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              workloadIds: workloads.map((workload) => workload.workloadId),
            },
          ],
          graph: makeGraphOverlay(
            "graph-app-raw-guid",
            "Contoso VPN Graph name",
          ),
        })}
      />,
    );

    const table = screen.getByRole("region", { name: "Tracked workloads" });
    for (const label of [
      "MSI",
      "Microsoft 365 Apps",
      "Modern app",
      "Win32 app",
      "Policy",
      "SCEP certificate",
      "Platform script",
      "Device Preparation workload",
    ]) {
      expect(within(table).getAllByText(label).length).toBeGreaterThan(0);
    }
    for (const [, label] of workloadStateLabels) {
      expect(within(table).getAllByText(label).length).toBeGreaterThan(0);
    }
    expect(table).toHaveTextContent("Contoso VPN local name");
    expect(table).toHaveTextContent("Graph · Contoso VPN Graph name");
    expect(table).toHaveTextContent("graph-app-raw-guid");
    expect(table).toHaveTextContent("Device scope");
    expect(table).toHaveTextContent("User scope");
    expect(table).toHaveTextContent("1603 · 0x00000643");
    expect(table).toHaveTextContent("-2016330855 · 0x87D30019");
    expect(table).toHaveTextContent("Blocking unknown");
    expect(table).toHaveTextContent("Exit code unknown");
    expect(table).toHaveTextContent("Enforcement code unknown");
  });

  it("defaults to latest sessions, preserves retry rows, and sorts all sessions chronologically", () => {
    const oldRetry = makeWorkload("retry-old", "win32App", "failed", "Failed", {
      sessionId: "session-old",
      rawIdentifier: "same-app-raw-guid",
      displayName: "Contoso VPN retry 1",
      timestamps: {
        firstObserved: timestamp("2026-07-15T19:00:00Z"),
        started: timestamp("2026-07-15T19:01:00Z"),
        ended: timestamp("2026-07-15T19:02:00Z"),
        lastUpdated: timestamp("2026-07-15T19:02:00Z"),
      },
    });
    const currentRetry = makeWorkload(
      "retry-current",
      "win32App",
      "installing",
      "Installing",
      {
        sessionId: "session-current",
        rawIdentifier: "same-app-raw-guid",
        displayName: "Contoso VPN retry 2",
        timestamps: {
          firstObserved: timestamp("2026-07-15T20:05:00Z"),
          started: timestamp("2026-07-15T20:06:00Z"),
          ended: null,
          lastUpdated: timestamp("2026-07-15T20:08:00Z"),
        },
      },
    );
    render(
      <EspWorkloadTable
        snapshot={makeSnapshot({
          installerCorrelations: [],
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              sessionId: "session-old",
              isLatest: false,
              workloadIds: [oldRetry.workloadId],
            },
            {
              ...makeSnapshot().sessions[0],
              sessionId: "session-current",
              isLatest: true,
              workloadIds: [currentRetry.workloadId],
            },
          ],
          workloads: [currentRetry, oldRetry],
        })}
      />,
    );

    const table = screen.getByRole("region", { name: "Tracked workloads" });
    expect(table).toHaveTextContent("Latest sessions · 1 of 2 workloads");
    expect(table).toHaveTextContent("Contoso VPN retry 2");
    expect(table).not.toHaveTextContent("Contoso VPN retry 1");

    fireEvent.click(
      within(table).getByRole("checkbox", { name: "Show all sessions" }),
    );
    expect(table).toHaveTextContent("All sessions · 2 workloads");
    expect(table).toHaveTextContent("Contoso VPN retry 1");
    expect(table).toHaveTextContent("Contoso VPN retry 2");
    expect(within(table).getAllByText("same-app-raw-guid")).toHaveLength(2);

    const rowText = within(table)
      .getAllByRole("row")
      .map((row) => row.textContent ?? "");
    expect(rowText.findIndex((text) => text.includes("retry 1"))).toBeLessThan(
      rowText.findIndex((text) => text.includes("retry 2")),
    );
    expect(within(table).getAllByText("View full values")).toHaveLength(2);
    expect(
      within(table).queryAllByTestId("esp-workload-full-values"),
    ).toHaveLength(0);

    fireEvent.click(within(table).getAllByText("View full values")[0]);
    expect(
      within(table).getAllByTestId("esp-workload-full-values"),
    ).toHaveLength(1);
    expect(table).toHaveTextContent("ev-retry-old");
  });

  it("bounds large workload volumes, lazily mounts full values, and keeps every session record reachable", () => {
    const currentWorkloads = Array.from({ length: 130 }, (_, index) =>
      makeWorkload(
        `current-${String(index).padStart(3, "0")}`,
        "win32App",
        "installing",
        "Installing",
        {
          displayName: `Current workload ${String(index).padStart(3, "0")}`,
          timestamps: {
            firstObserved: timestamp("2026-07-15T20:00:00Z"),
            started: null,
            ended: null,
            lastUpdated: null,
          },
        },
      ),
    );
    const historicWorkloads = Array.from({ length: 75 }, (_, index) =>
      makeWorkload(
        `historic-${String(index).padStart(3, "0")}`,
        "win32App",
        "failed",
        "Failed",
        {
          sessionId: "session-old",
          displayName: `Historic workload ${String(index).padStart(3, "0")}`,
          timestamps: {
            firstObserved: timestamp("2026-07-15T19:00:00Z"),
            started: null,
            ended: null,
            lastUpdated: null,
          },
        },
      ),
    );
    render(
      <EspWorkloadTable
        snapshot={makeSnapshot({
          installerCorrelations: [],
          sessions: [
            {
              ...makeSnapshot().sessions[0],
              sessionId: "session-old",
              isLatest: false,
              workloadIds: historicWorkloads.map(
                (workload) => workload.workloadId,
              ),
            },
            {
              ...makeSnapshot().sessions[0],
              workloadIds: currentWorkloads.map(
                (workload) => workload.workloadId,
              ),
            },
          ],
          workloads: [...currentWorkloads, ...historicWorkloads],
        })}
      />,
    );

    const table = screen.getByRole("region", { name: "Tracked workloads" });
    expect(table).toHaveTextContent("Showing 1–80 of 130 workloads");
    expect(within(table).getAllByTestId("esp-workload-row")).toHaveLength(80);
    expect(
      within(table).queryAllByTestId("esp-workload-full-values"),
    ).toHaveLength(0);
    expect(table).not.toHaveTextContent("Current workload 129");

    fireEvent.click(
      within(table).getByRole("button", { name: "Next workloads" }),
    );
    expect(table).toHaveTextContent("Showing 81–130 of 130 workloads");
    const lastCurrentRow = within(table).getByRole("row", {
      name: /Current workload 129/i,
    });
    fireEvent.click(within(lastCurrentRow).getByText("View full values"));
    expect(
      within(table).getAllByTestId("esp-workload-full-values"),
    ).toHaveLength(1);
    expect(lastCurrentRow).toHaveTextContent("ev-current-129");
    fireEvent.click(within(lastCurrentRow).getByText("View full values"));
    expect(
      within(table).queryAllByTestId("esp-workload-full-values"),
    ).toHaveLength(0);

    fireEvent.click(
      within(table).getByRole("checkbox", { name: "Show all sessions" }),
    );
    expect(table).toHaveTextContent("All sessions · 205 workloads");
    expect(table).toHaveTextContent("Showing 1–80 of 205 workloads");
    expect(table).toHaveTextContent("Historic workload 000");
    expect(within(table).getAllByTestId("esp-workload-row")).toHaveLength(80);

    fireEvent.click(
      within(table).getByRole("button", { name: "Next workloads" }),
    );
    fireEvent.click(
      within(table).getByRole("button", { name: "Next workloads" }),
    );
    expect(table).toHaveTextContent("Showing 161–205 of 205 workloads");
    expect(table).toHaveTextContent("Current workload 129");
    expect(within(table).getAllByTestId("esp-workload-row")).toHaveLength(45);
  });
});

describe("complete single-page evidence composition", () => {
  it("keeps blockers and workloads before the collapsed evidence families", () => {
    showSnapshot(makeSnapshot({ findings: [makeFinding()] }));
    render(<EspDiagnosticsWorkspace />);

    const actionCenter = screen.getByRole("region", { name: "Action center" });
    const workloads = screen.getByRole("region", { name: "Tracked workloads" });
    const evidence = screen.getByRole("region", { name: "ESP evidence" });

    expect(
      actionCenter.compareDocumentPosition(workloads) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      workloads.compareDocumentPosition(evidence) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    for (const sectionTitle of [
      "Identity and profile",
      "OOBE flags",
      "ESP configuration",
      "Enrollment and sessions",
      "Apps",
      "Scripts",
      "Policies",
      "Certificates",
      "Join and registration",
      "Delivery Optimization",
      "Hardware",
      "NodeCache",
      "Source coverage",
      "Raw provenance",
    ]) {
      expect(within(evidence).getByText(sectionTitle)).toBeInTheDocument();
    }
  });

  it("keeps sensitive values masked by default and never reveals restricted values", () => {
    showSnapshot();
    render(<EspDiagnosticsWorkspace />);

    const evidence = screen.getByRole("region", { name: "ESP evidence" });
    expect(evidence).toHaveTextContent(
      "Sensitive values are masked by default",
    );
    expect(evidence).toHaveTextContent(
      "Copy remains unavailable for restricted values",
    );

    fireEvent.click(within(evidence).getByText("Identity and profile"));
    expect(evidence).toHaveTextContent("Sensitive value · masked");
    expect(evidence).toHaveTextContent("Restricted value · reveal unavailable");
    expect(evidence).not.toHaveTextContent("tenant-sensitive");
    expect(evidence).not.toHaveTextContent("operator@contoso.example");

    fireEvent.click(
      within(evidence).getByRole("button", { name: "Reveal sensitive values" }),
    );
    expect(evidence).toHaveTextContent("tenant-sensitive");
    expect(evidence).toHaveTextContent("SERIAL-042");
    expect(evidence).not.toHaveTextContent("operator@contoso.example");
    expect(
      within(evidence).getByRole("button", { name: "Mask sensitive values" }),
    ).toHaveAttribute("aria-pressed", "true");
  });

  it("does not mount evidence item bodies until their disclosure is opened", () => {
    render(<EvidenceSections snapshot={makeSnapshot()} />);

    const evidence = screen.getByRole("region", { name: "ESP evidence" });
    expect(evidence).not.toHaveTextContent("managed-device-raw-guid");
    expect(within(evidence).queryAllByTestId("esp-evidence-item")).toHaveLength(
      0,
    );

    fireEvent.click(within(evidence).getByText("Identity and profile"));

    expect(evidence).toHaveTextContent("managed-device-raw-guid");
    expect(
      within(evidence).getAllByTestId("esp-evidence-item").length,
    ).toBeGreaterThan(0);
  });

  it("bounds high-volume activity and raw-evidence DOM across live snapshot updates", () => {
    const activity = Array.from({ length: 600 }, (_, index) =>
      makeActivity(
        `bulk-${index}`,
        `2026-07-15T20:${String(index % 60).padStart(2, "0")}:00Z`,
      ),
    );
    const rawEvidence = Array.from({ length: 600 }, (_, index) =>
      makeRawRecord(index),
    );
    const initial = makeSnapshot({ activity, rawEvidence });
    showSnapshot(initial, { phase: "live" });
    render(<EspDiagnosticsWorkspace />);

    const live = screen.getByRole("region", { name: "Live activity" });
    const evidence = screen.getByRole("region", { name: "ESP evidence" });
    expect(live).toHaveTextContent("600 occurrences");
    expect(
      within(live).getAllByTestId("esp-activity-entry").length,
    ).toBeLessThanOrEqual(80);
    expect(within(evidence).queryAllByTestId("esp-evidence-item")).toHaveLength(
      0,
    );

    fireEvent.click(within(evidence).getByText("Raw provenance"));
    const rawDisclosure = within(evidence)
      .getByText("Raw provenance")
      .closest("details");
    expect(rawDisclosure).not.toBeNull();
    expect(
      within(rawDisclosure as HTMLElement).getAllByTestId("esp-evidence-item")
        .length,
    ).toBeLessThanOrEqual(80);
    expect(rawDisclosure).toHaveTextContent("Showing 1–80 of 600 records");

    act(() => {
      useEspDiagnosticsStore.setState({
        snapshot: {
          ...initial,
          activity: [
            ...activity,
            makeActivity("bulk-600", "2026-07-15T21:00:00Z"),
          ],
          rawEvidence: [...rawEvidence, makeRawRecord(600)],
        },
      });
    });

    expect(live).toHaveTextContent("601 occurrences");
    expect(
      within(live).getAllByTestId("esp-activity-entry").length,
    ).toBeLessThanOrEqual(80);
    expect(rawDisclosure).toHaveTextContent("601 records");
    expect(
      within(rawDisclosure as HTMLElement).getAllByTestId("esp-evidence-item")
        .length,
    ).toBeLessThanOrEqual(80);
    expect(useEspDiagnosticsStore.getState().snapshot?.activity).toHaveLength(
      601,
    );
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence,
    ).toHaveLength(601);
  });

  it("navigates duplicate evidence references to one canonical raw target", async () => {
    const sharedEvidenceId = "ev-shared-canonical";
    const finding = {
      ...makeFinding(),
      evidence: [
        { evidenceId: sharedEvidenceId, sourceArtifactId: "ime-app-workload" },
      ],
    };
    const workload = makeWorkload(
      "shared-evidence-workload",
      "win32App",
      "failed",
      "Failed",
      {
        evidence: [
          {
            evidenceId: sharedEvidenceId,
            sourceArtifactId: "ime-app-workload",
          },
        ],
      },
    );
    showSnapshot(
      makeSnapshot({
        findings: [finding],
        workloads: [workload],
        rawEvidence: [makeRawRecord(1, sharedEvidenceId)],
      }),
    );
    render(<EspDiagnosticsWorkspace />);

    expect(
      document.querySelectorAll(`#evidence-${sharedEvidenceId}`),
    ).toHaveLength(0);
    fireEvent.click(
      within(screen.getByRole("region", { name: "Action center" })).getByRole(
        "link",
        { name: `Open evidence ${sharedEvidenceId}` },
      ),
    );

    await waitFor(() =>
      expect(
        document.querySelectorAll(`#evidence-${sharedEvidenceId}`),
      ).toHaveLength(1),
    );
    const target = document.getElementById(`evidence-${sharedEvidenceId}`);
    expect(target).not.toBeNull();
    expect(target).toHaveFocus();
    expect(target?.closest("details")).toHaveAttribute("open");
    expect(
      target?.closest('[data-evidence-item-id="raw-record-1"]'),
    ).not.toBeNull();
    const ids = Array.from(document.querySelectorAll<HTMLElement>("[id]"))
      .map((element) => element.id)
      .filter(Boolean);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("navigates orphan process evidence to an explicit reference-only target", async () => {
    showSnapshot();
    render(<EspDiagnosticsWorkspace />);

    const installer = screen.getByRole("region", {
      name: "What MSIEXEC is doing now",
    });
    fireEvent.click(
      within(installer).getByRole("link", {
        name: "Open evidence ev-process-8044",
      }),
    );

    await waitFor(() =>
      expect(
        document.getElementById("evidence-ev-process-8044"),
      ).not.toBeNull(),
    );
    const target = document.getElementById("evidence-ev-process-8044");
    expect(target).toHaveFocus();
    expect(target?.closest("details")).toHaveAttribute("open");
    expect(
      target?.closest(
        '[data-evidence-item-id="reference-only-ev-process-8044"]',
      ),
    ).toHaveTextContent("Raw record not included in this snapshot");
  });

  it("navigates an orphan finding coverage gap to a canonical placeholder", async () => {
    showSnapshot(makeSnapshot({ findings: [makeFinding()] }));
    render(<EspDiagnosticsWorkspace />);

    const actionCenter = screen.getByRole("region", { name: "Action center" });
    fireEvent.click(
      within(actionCenter).getByRole("link", {
        name: "Coverage gap · coverage-system-temp",
      }),
    );

    await waitFor(() =>
      expect(
        document.getElementById("coverage-coverage-system-temp"),
      ).not.toBeNull(),
    );
    const target = document.getElementById("coverage-coverage-system-temp");
    expect(target).toHaveFocus();
    expect(target?.closest("details")).toHaveAttribute("open");
    expect(target).toHaveTextContent("Referenced coverage gap");
    expect(target).toHaveTextContent("no source coverage record was included");
    expect(
      document.querySelectorAll("#coverage-coverage-system-temp"),
    ).toHaveLength(1);
  });

  it("keeps duplicate null-record registration events unique and navigable", async () => {
    const registrationEvents: EspRegistrationEvent[] = [
      {
        eventId: 75,
        recordId: null,
        status: {
          raw: "0x0",
          normalized: "succeeded",
          display: "Registration succeeded",
          detail: null,
        },
        message: "First registration occurrence",
        timestamp: timestamp("2026-07-15T19:59:00Z"),
        namedData: [],
        evidence: [
          { evidenceId: "ev-registration-a", sourceArtifactId: "mdm-events" },
        ],
      },
      {
        eventId: 75,
        recordId: null,
        status: {
          raw: "0x0",
          normalized: "succeeded",
          display: "Registration succeeded",
          detail: null,
        },
        message: "Second registration occurrence",
        timestamp: timestamp("2026-07-15T20:00:00Z"),
        namedData: [],
        evidence: [
          { evidenceId: "ev-registration-b", sourceArtifactId: "mdm-events" },
        ],
      },
    ];
    const finding = {
      ...makeFinding(),
      evidence: [registrationEvents[1].evidence[0]],
      coverageGapIds: [],
    };
    showSnapshot(
      makeSnapshot({
        findings: [finding],
        registrationEvents,
      }),
    );
    render(<EspDiagnosticsWorkspace />);

    fireEvent.click(
      within(screen.getByRole("region", { name: "Action center" })).getByRole(
        "link",
        { name: "Open evidence ev-registration-b" },
      ),
    );

    await waitFor(() =>
      expect(
        document.getElementById("evidence-ev-registration-b"),
      ).not.toBeNull(),
    );
    const target = document.getElementById("evidence-ev-registration-b");
    expect(target).toHaveFocus();
    expect(target?.closest("details")).toHaveAttribute("open");
    expect(
      target?.closest('[data-evidence-item-id^="registration-75-"]'),
    ).toHaveTextContent("Second registration occurrence");
    const registrationItems = Array.from(
      target
        ?.closest("details")
        ?.querySelectorAll<HTMLElement>(
          '[data-evidence-item-id^="registration-75-"]',
        ) ?? [],
    );
    expect(registrationItems).toHaveLength(2);
    expect(
      new Set(registrationItems.map((item) => item.dataset.evidenceItemId))
        .size,
    ).toBe(2);
  });

  it("exposes responsive panel and installer reflow hooks", () => {
    showSnapshot();
    render(<EspDiagnosticsWorkspace />);

    expect(screen.getByRole("main")).toHaveClass("esp-diagnostics-workspace");
    expect(document.querySelectorAll(".esp-cockpit-panel-grid")).toHaveLength(
      2,
    );

    const installer = screen.getByRole("region", {
      name: "What MSIEXEC is doing now",
    });
    expect(installer).toHaveClass("esp-msi-status");

    const row = within(installer).getByTestId("esp-installer-row");
    expect(row).toHaveClass("esp-msi-row");
    expect(row.querySelectorAll(":scope > .esp-msi-cell")).toHaveLength(3);
    expect(row.querySelector(".esp-msi-log-path")).not.toBeNull();

    const evidence = screen.getByRole("region", { name: "ESP evidence" });
    expect(
      evidence.querySelectorAll("summary.esp-evidence-summary"),
    ).not.toHaveLength(0);
  });

  it("does not render diagnostic labels below ten pixels", () => {
    showSnapshot();
    const { container } = render(<EspDiagnosticsWorkspace />);

    const undersizedLabels = Array.from(
      container.querySelectorAll<HTMLElement>("*"),
    )
      .filter((element) => {
        const fontSize = Number.parseFloat(
          window.getComputedStyle(element).fontSize,
        );
        return Number.isFinite(fontSize) && fontSize > 0 && fontSize < 10;
      })
      .map((element) => element.textContent?.trim().slice(0, 80));

    expect(undersizedLabels).toEqual([]);
  });
});
