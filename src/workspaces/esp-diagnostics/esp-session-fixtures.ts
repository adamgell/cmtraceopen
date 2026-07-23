import type {
  EspDiagnosticsSnapshot,
  EspGraphAppRecord,
  EspGraphOverlay,
  EspWorkload,
  GraphSection,
} from "./types";

// Typed factories for building valid ESP snapshots/overlays in tests. Every
// object here satisfies the wire validators in esp-wire-validation.ts, so a
// snapshot from makeEspSnapshot() round-trips through the capture format and
// loads into the store exactly like a real one. Shared by the capture and
// replay test suites.

function utcTimestamp(value: string): EspWorkload["timestamps"]["firstObserved"] {
  return {
    rawText: value,
    originalOffset: "Z",
    normalizedUtc: value,
    kind: "utc",
  };
}

/** A "skipped" section carrying no data, contextually typed to its slot. */
function emptySection<T>(): GraphSection<T> {
  return {
    status: "skipped",
    requiredScope: null,
    apiVersion: "v1.0",
    data: null,
    error: null,
  };
}

/** An "available" apps section, for exercising Graph name resolution. */
export function makeEspAppsSection(
  apps: EspGraphAppRecord[],
): GraphSection<EspGraphAppRecord[]> {
  return {
    status: "available",
    requiredScope: null,
    apiVersion: "v1.0",
    data: apps,
    error: null,
  };
}

export function makeEspGraphApp(
  overrides: Partial<EspGraphAppRecord> = {},
): EspGraphAppRecord {
  return {
    appId: "a7c420db-0fa1-4c26-aca5-467e1a4dee73",
    displayName: "Contoso VPN",
    trackedOnEnrollmentStatus: true,
    status: null,
    intentState: emptySection(),
    assignments: [],
    evidence: [],
    ...overrides,
  };
}

export function makeEspGraphOverlay(
  overrides: Partial<EspGraphOverlay> = {},
): EspGraphOverlay {
  return {
    requestId: "graph-req-1",
    requestedAtUtc: "2026-07-23T21:00:00Z",
    deviceMatch: emptySection(),
    autopilotIdentity: emptySection(),
    deploymentProfile: emptySection(),
    intendedDeploymentProfile: emptySection(),
    profileAssignments: emptySection(),
    autopilotEvents: emptySection(),
    enrollmentConfiguration: emptySection(),
    apps: emptySection(),
    policies: emptySection(),
    scripts: emptySection(),
    ...overrides,
  };
}

export function makeEspWorkload(
  overrides: Partial<EspWorkload> = {},
): EspWorkload {
  return {
    workloadId: "workload-1",
    sessionId: "session-1",
    kind: "win32App",
    scope: "device",
    rawIdentifier: "Win32App_a7c420db-0fa1-4c26-aca5-467e1a4dee73_1",
    displayName: null,
    status: {
      raw: "pending",
      normalized: "pending",
      display: "Pending",
      detail: null,
    },
    timestamps: {
      firstObserved: utcTimestamp("2026-07-23T20:00:00Z"),
      started: null,
      ended: null,
      lastUpdated: null,
    },
    exitCode: null,
    enforcementErrorCode: null,
    blocking: null,
    evidence: [],
    ...overrides,
  };
}

export function makeEspSnapshot(
  overrides: Partial<EspDiagnosticsSnapshot> = {},
): EspDiagnosticsSnapshot {
  return {
    schemaVersion: 1,
    scenario: "espOnly",
    phase: "deviceSetup",
    generatedAtUtc: "2026-07-23T21:00:00Z",
    elevation: {
      isElevated: false,
      restartSupported: true,
      restrictedSources: [],
    },
    identity: {
      deviceName: null,
      managedDeviceId: null,
      entraDeviceId: null,
      entdmId: null,
      tenantId: null,
      tenantDomain: null,
      userPrincipalName: null,
      serialNumber: null,
      evidence: [],
    },
    profile: null,
    enrollments: [],
    sessions: [],
    workloads: [],
    installerCorrelations: [],
    nodeCache: [],
    registrationEvents: [],
    deliveryOptimization: null,
    hardware: null,
    activity: [],
    findings: [],
    coverage: [],
    rawEvidence: [],
    graph: null,
    ...overrides,
  };
}
