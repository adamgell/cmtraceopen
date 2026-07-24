import espFixture from "./demo/esp-diagnostics.json" with { type: "json" };
import type {
  EspDiagnosticsSnapshot,
  EspEvidenceRef,
  EspIdentityEvidence,
  EspRawEvidenceRecord,
  EspTimestamp,
  EspWorkload,
} from "../../src/workspaces/esp-diagnostics/types";

const GENERATED_AT_UTC = "2026-07-15T20:08:00Z";
const DEVICE_PREPARATION_ARTIFACT = "device-preparation-v2";

const baseSnapshot =
  espFixture.baseSnapshot as unknown as EspDiagnosticsSnapshot;
const devicePreparationVariant = espFixture.variants
  .devicePreparationV2 as unknown as {
  scenario: EspDiagnosticsSnapshot["scenario"];
  phase: EspDiagnosticsSnapshot["phase"];
  mixedWorkloads: Array<{
    workloadId: string;
    kind: EspWorkload["kind"];
    rawIdentifier: string;
    displayName: string;
    normalizedStatus: EspWorkload["status"]["normalized"];
    displayStatus: string;
  }>;
};
const sparseVariant = espFixture.variants.sparseBundle as unknown as Pick<
  EspDiagnosticsSnapshot,
  | "scenario"
  | "phase"
  | "elevation"
  | "activity"
  | "findings"
  | "coverage"
  | "rawEvidence"
>;

function timestamp(iso: string): EspTimestamp {
  return {
    rawText: iso,
    originalOffset: "+00:00",
    normalizedUtc: iso,
    kind: "utc",
  };
}

function emptyIdentity(): EspIdentityEvidence {
  return {
    deviceName: null,
    managedDeviceId: null,
    entraDeviceId: null,
    entdmId: null,
    tenantId: null,
    tenantDomain: null,
    userPrincipalName: null,
    serialNumber: null,
    evidence: [],
  };
}

function devicePreparationEvidenceRef(index: number): EspEvidenceRef {
  return {
    evidenceId: `ev-device-preparation-${index + 1}`,
    sourceArtifactId: DEVICE_PREPARATION_ARTIFACT,
  };
}

export function buildBaseEspSnapshot(): EspDiagnosticsSnapshot {
  return structuredClone(baseSnapshot);
}

export function buildElevatedEspSnapshot(): EspDiagnosticsSnapshot {
  const snapshot = buildBaseEspSnapshot();
  const registryEvidence: EspEvidenceRef = {
    evidenceId: "ev-esp-registry",
    sourceArtifactId: "esp-registry",
  };

  snapshot.elevation = {
    isElevated: true,
    restartSupported: true,
    restrictedSources: [],
  };
  snapshot.coverage = snapshot.coverage.map((source) =>
    source.artifactId === "esp-registry"
      ? {
          ...source,
          status: "available",
          detail: null,
          evidence: [registryEvidence],
        }
      : source,
  );
  snapshot.rawEvidence = [
    ...snapshot.rawEvidence,
    {
      recordId: "raw-esp-registry",
      provenance: {
        sourceKind: "registry",
        sourceArtifactId: "esp-registry",
        filePath: null,
        lineNumber: null,
        recordNumber: 1,
        registry: {
          hive: "HKLM",
          key: "SOFTWARE\\Microsoft\\Enrollments\\Status\\Device",
          valueName: "TrackingEnabled",
        },
        event: null,
      },
      sourceTimestamp: timestamp(GENERATED_AT_UTC),
      observedAtUtc: GENERATED_AT_UTC,
      rawValue: { boolean: true },
      sensitivity: "public",
      parseState: "parsed",
      accessState: "available",
      evidence: [registryEvidence],
    },
  ];
  snapshot.findings = snapshot.findings.map((finding) => ({
    ...finding,
    coverageGapIds: finding.coverageGapIds.filter(
      (artifactId) => artifactId !== "esp-registry",
    ),
  }));

  return snapshot;
}

export function buildDevicePreparationSnapshot(): EspDiagnosticsSnapshot {
  const workloadTimes = [
    "2026-07-15T20:07:15Z",
    "2026-07-15T20:07:30Z",
    "2026-07-15T20:07:45Z",
  ];
  const workloadEvidence = devicePreparationVariant.mixedWorkloads.map(
    (_, index) => devicePreparationEvidenceRef(index),
  );
  const workloads = devicePreparationVariant.mixedWorkloads.map(
    (workload, index): EspWorkload => {
      const observed = timestamp(workloadTimes[index] ?? GENERATED_AT_UTC);
      const evidence = [workloadEvidence[index]];
      return {
        workloadId: workload.workloadId,
        sessionId: "session-device-preparation",
        kind: workload.kind,
        scope: "device",
        rawIdentifier: workload.rawIdentifier,
        displayName: workload.displayName,
        status: {
          raw: workload.normalizedStatus,
          normalized: workload.normalizedStatus,
          display: workload.displayStatus,
          detail: null,
        },
        timestamps: {
          firstObserved: observed,
          started: index === 0 ? observed : null,
          ended: null,
          lastUpdated: observed,
        },
        exitCode: null,
        enforcementErrorCode: null,
        blocking: true,
        evidence,
      };
    },
  );
  const rawEvidence = workloads.map(
    (workload, index): EspRawEvidenceRecord => ({
      recordId: `raw-device-preparation-${index + 1}`,
      provenance: {
        sourceKind: "json",
        sourceArtifactId: DEVICE_PREPARATION_ARTIFACT,
        filePath: null,
        lineNumber: null,
        recordNumber: index + 1,
        registry: null,
        event: null,
      },
      sourceTimestamp: workload.timestamps.firstObserved,
      observedAtUtc:
        workload.timestamps.firstObserved.normalizedUtc ?? GENERATED_AT_UTC,
      rawValue: {
        text:
          index === 0
            ? "Device Preparation bootstrap is in progress; agent timeout 300 seconds; page timeout 3600 seconds; diagnostics enabled"
            : `${workload.displayName} is ${workload.status.display.toLowerCase()}`,
      },
      sensitivity: "public",
      parseState: "parsed",
      accessState: "available",
      evidence: workload.evidence,
    }),
  );

  return {
    schemaVersion: 1,
    scenario: devicePreparationVariant.scenario,
    phase: devicePreparationVariant.phase,
    generatedAtUtc: GENERATED_AT_UTC,
    elevation: {
      isElevated: true,
      restartSupported: true,
      restrictedSources: [],
    },
    identity: emptyIdentity(),
    profile: {
      profileName: "Contoso Device Preparation",
      deploymentProfileId: null,
      correlationId: null,
      tenantDomain: null,
      tenantId: null,
      oobeConfig: null,
      profileDownloadTime: timestamp("2026-07-15T20:07:15Z"),
      joinMode: null,
      odjApplied: null,
      skipDomainConnectivityCheck: null,
      devicePreparation: {
        agentDownloadTimeoutSeconds: 300,
        pageTimeoutSeconds: 3_600,
        allowSkipOnFailure: false,
        allowDiagnostics: true,
        scriptIds: workloads
          .filter((workload) => workload.kind === "platformScript")
          .map((workload) => workload.rawIdentifier),
        evidence: [workloadEvidence[0]],
      },
      evidence: [workloadEvidence[0]],
    },
    enrollments: [],
    sessions: [
      {
        sessionId: "session-device-preparation",
        kind: "devicePreparationV2",
        scope: "device",
        userSid: null,
        startedAt: timestamp("2026-07-15T20:07:15Z"),
        endedAt: null,
        phase: "devicePreparation",
        isLatest: true,
        workloadIds: workloads.map((workload) => workload.workloadId),
        evidence: workloadEvidence,
      },
    ],
    workloads,
    installerCorrelations: [],
    nodeCache: [],
    registrationEvents: [],
    deliveryOptimization: null,
    hardware: null,
    activity: workloads.map((workload, index) => ({
      entryId: `activity-device-preparation-${index + 1}`,
      timestamp: workload.timestamps.firstObserved,
      kind: "workload",
      title:
        index === 0
          ? "Device Preparation bootstrap is installing"
          : `${workload.displayName} is pending`,
      detail:
        index === 0
          ? "Required apps, scripts, and certificates are being evaluated."
          : null,
      status: workload.status,
      evidence: workload.evidence,
    })),
    findings: [],
    coverage: [
      {
        artifactId: DEVICE_PREPARATION_ARTIFACT,
        family: "Device Preparation v2",
        status: "available",
        detail: null,
        observedAtUtc: GENERATED_AT_UTC,
        evidence: workloadEvidence,
      },
    ],
    rawEvidence,
    graph: null,
  };
}

export function buildSparseBundleSnapshot(): EspDiagnosticsSnapshot {
  const capturedProfileEvidence: EspEvidenceRef = {
    evidenceId: "ev-captured-profile",
    sourceArtifactId: "captured-profile",
  };

  return {
    schemaVersion: 1,
    scenario: sparseVariant.scenario,
    phase: sparseVariant.phase,
    generatedAtUtc: GENERATED_AT_UTC,
    elevation: structuredClone(sparseVariant.elevation),
    identity: emptyIdentity(),
    profile: {
      profileName: "Captured Autopilot profile",
      deploymentProfileId: null,
      correlationId: null,
      tenantDomain: null,
      tenantId: null,
      oobeConfig: null,
      profileDownloadTime: timestamp(GENERATED_AT_UTC),
      joinMode: null,
      odjApplied: null,
      skipDomainConnectivityCheck: null,
      devicePreparation: null,
      evidence: [capturedProfileEvidence],
    },
    enrollments: [],
    sessions: [],
    workloads: [],
    installerCorrelations: [],
    nodeCache: [],
    registrationEvents: [],
    deliveryOptimization: null,
    hardware: null,
    activity: structuredClone(sparseVariant.activity),
    findings: structuredClone(sparseVariant.findings),
    coverage: structuredClone(sparseVariant.coverage),
    rawEvidence: structuredClone(sparseVariant.rawEvidence),
    graph: null,
  };
}
