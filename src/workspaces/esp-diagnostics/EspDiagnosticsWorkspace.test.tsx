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
import { EspDiagnosticsWorkspace } from "./EspDiagnosticsWorkspace";
import { EspPhaseProgress } from "./EspPhaseProgress";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import { EspWorkloadTable } from "./EspWorkloadTable";
import { LiveActivity } from "./LiveActivity";
import type {
  EspDiagnosticFinding,
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspInstallerCorrelation,
  EspNormalizedStatus,
  EspProcessObservation,
  EspScenario,
  EspTimelineEntry,
  EspTrackedKind,
  EspWorkload,
} from "./types";

function timestamp(rawText: string) {
  return {
    rawText,
    originalOffset: "+00:00",
    normalizedUtc: rawText,
    kind: "utc" as const,
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

function makeActivity(
  entryId: string,
  observedAt: string,
): EspTimelineEntry {
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

function makeGraphOverlay(appId: string, displayName: string): EspGraphOverlay {
  const skipped = {
    status: "skipped" as const,
    requiredScope: null,
    apiVersion: "v1.0" as const,
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
  useEspDiagnosticsStore.setState(useEspDiagnosticsStore.getInitialState(), true);
  useUiStore.setState({ currentPlatform: "windows" });
});

describe("ESP diagnostic cockpit frame", () => {
  it("keeps explicit empty, analyzing, and error states inside the full-width workspace", () => {
    render(<EspDiagnosticsWorkspace />);

    expect(
      screen.getByRole("heading", { name: "ESP Diagnostics", level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText("Waiting for evidence")).toBeInTheDocument();
    expect(screen.getByText("Scenario not detected")).toBeInTheDocument();
    expect(screen.getByText("No evidence loaded")).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();

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
    expect(screen.getByText("Partial", { selector: "strong" })).toBeInTheDocument();

    act(() => {
      useEspDiagnosticsStore.setState({ phase: "ready", graphPhase: "ready" });
    });
    expect(screen.getByText("Analysis ready")).toBeInTheDocument();
    expect(screen.getByText("Connected", { selector: "strong" })).toBeInTheDocument();
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
    expect(screen.getByText("Standard user", { selector: "strong" })).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Restart as administrator" }),
    );
    await waitFor(() =>
      expect(vi.mocked(invoke)).toHaveBeenCalledWith(
        "restart_esp_as_administrator",
        undefined,
      ),
    );
    expect(screen.getByText("Administrator restart requested.")).toBeInTheDocument();
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
    expect(screen.getByText("Protected process command lines")).toBeInTheDocument();
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

    expect(screen.getByText("Elevated", { selector: "strong" })).toBeInTheDocument();
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
    expect(installer).toHaveTextContent(
      "C:\\Windows\\Temp\\ContosoVPN.log",
    );
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
        snapshot={makeSnapshot({ scenario: "autopilotV1", phase: "deviceSetup" })}
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
      within(screen.getByRole("region", { name: "Tracked workloads" })).getByText(
        "Workload row persists",
      ),
    ).toBeInTheDocument();
  });
});

describe("workload table", () => {
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
      makeWorkload(`state-${index}`, kinds[index % kinds.length], state, display, {
        scope: index % 2 === 0 ? "device" : "user",
        rawIdentifier: index === 0 ? "graph-app-raw-guid" : `raw-state-${index}`,
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
      }),
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
        graph: makeGraphOverlay("graph-app-raw-guid", "Contoso VPN Graph name"),
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
    const oldRetry = makeWorkload(
      "retry-old",
      "win32App",
      "failed",
      "Failed",
      {
        sessionId: "session-old",
        rawIdentifier: "same-app-raw-guid",
        displayName: "Contoso VPN retry 1",
        timestamps: {
          firstObserved: timestamp("2026-07-15T19:00:00Z"),
          started: timestamp("2026-07-15T19:01:00Z"),
          ended: timestamp("2026-07-15T19:02:00Z"),
          lastUpdated: timestamp("2026-07-15T19:02:00Z"),
        },
      },
    );
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
    expect(table).toHaveTextContent("ev-retry-old");
    expect(table).toHaveTextContent("ev-retry-current");
  });
});
