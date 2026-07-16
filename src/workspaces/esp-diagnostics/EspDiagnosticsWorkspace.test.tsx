import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../../stores/ui-store";
import { EspDiagnosticsWorkspace } from "./EspDiagnosticsWorkspace";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import type {
  EspDiagnosticsSnapshot,
  EspInstallerCorrelation,
  EspProcessObservation,
  EspScenario,
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
