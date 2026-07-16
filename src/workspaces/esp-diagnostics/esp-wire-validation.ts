import type { EspDiagnosticsSnapshot, EspGraphOverlay } from "./types";

type Guard = (value: unknown) => boolean;

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const hasOwn = (value: object, key: PropertyKey): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);
const string: Guard = (value) => typeof value === "string";
const number: Guard = (value) =>
  typeof value === "number" && Number.isFinite(value);
const integer: Guard = (value) =>
  typeof value === "number" && Number.isSafeInteger(value);
const unsignedInteger: Guard = (value) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const boolean: Guard = (value) => typeof value === "boolean";
const nullable =
  (guard: Guard): Guard =>
  (value) =>
    value === null || guard(value);
const array =
  (guard: Guard): Guard =>
  (value) =>
    Array.isArray(value) && value.every(guard);
const values = (...allowed: string[]): Guard => {
  const set = new Set(allowed);
  return (value) => typeof value === "string" && set.has(value);
};
const fields =
  (shape: Record<string, Guard>): Guard =>
  (value) =>
    record(value) &&
    Object.entries(shape).every(
      ([key, guard]) => hasOwn(value, key) && guard(value[key]),
    );

const sensitivity = values("public", "sensitive", "restricted");
const timestampKind = values(
  "utc",
  "offset",
  "local",
  "unspecified",
  "invalid",
);
const normalizedStatus = values(
  "notStarted",
  "notInstalled",
  "initialized",
  "pending",
  "downloading",
  "downloaded",
  "installing",
  "inProgress",
  "processed",
  "succeeded",
  "failed",
  "skipped",
  "uninstalled",
  "rebootRequired",
  "cancelled",
  "unknown",
);
const sourceKind = values(
  "registry",
  "json",
  "eventLog",
  "imeLog",
  "deploymentLog",
  "process",
  "system",
  "deliveryOptimization",
  "graph",
  "coverage",
);
const parseState = values("parsed", "raw", "malformed", "unsupported");
const accessState = values(
  "available",
  "missing",
  "permissionDenied",
  "failed",
  "unsupported",
);

const evidenceRef = fields({ evidenceId: string, sourceArtifactId: string });
const evidenceRefs = array(evidenceRef);
const classifiedString = fields({ value: string, sensitivity });
const timestamp = fields({
  rawText: string,
  originalOffset: nullable(string),
  normalizedUtc: nullable(string),
  kind: timestampKind,
});
const namedValue = fields({ name: string, value: string });
const registryProvenance = fields({
  hive: string,
  key: string,
  valueName: nullable(string),
});
const eventProvenance = fields({
  channel: string,
  eventId: unsignedInteger,
  recordId: nullable(unsignedInteger),
  namedData: array(namedValue),
});
const provenance = fields({
  sourceKind,
  sourceArtifactId: string,
  filePath: nullable(string),
  lineNumber: nullable(unsignedInteger),
  recordNumber: nullable(unsignedInteger),
  registry: nullable(registryProvenance),
  event: nullable(eventProvenance),
});
const observationContext = fields({
  evidenceRef,
  provenance,
  sourceTimestamp: nullable(timestamp),
  observedAtUtc: string,
  sensitivity,
  parseState,
  accessState,
});
const rawStatus: Guard = (value) => string(value) || integer(value);
const statusDetail = fields({
  raw: rawStatus,
  normalized: normalizedStatus,
  display: string,
});
const status = fields({
  raw: rawStatus,
  normalized: normalizedStatus,
  display: string,
  detail: nullable(statusDetail),
});
const errorCode = fields({
  raw: string,
  decimal: nullable(integer),
  hex: nullable(string),
});
const elevation = fields({
  isElevated: boolean,
  restartSupported: boolean,
  restrictedSources: array(string),
});
const identity = fields({
  deviceName: nullable(string),
  managedDeviceId: nullable(string),
  entraDeviceId: nullable(string),
  entdmId: nullable(classifiedString),
  tenantId: nullable(classifiedString),
  tenantDomain: nullable(classifiedString),
  userPrincipalName: nullable(classifiedString),
  serialNumber: nullable(classifiedString),
  evidence: evidenceRefs,
});
const oobeConfig = fields({
  rawMask: unsignedInteger,
  skipKeyboard: boolean,
  enablePatchDownload: boolean,
  skipWindowsUpgradeUx: boolean,
  aadTpmRequired: boolean,
  aadDeviceAuthentication: boolean,
  tpmAttestation: boolean,
  skipEula: boolean,
  skipOemRegistration: boolean,
  skipExpressSettings: boolean,
  disallowAdmin: boolean,
});
const devicePreparation = fields({
  agentDownloadTimeoutSeconds: nullable(unsignedInteger),
  pageTimeoutSeconds: nullable(unsignedInteger),
  allowSkipOnFailure: nullable(boolean),
  allowDiagnostics: nullable(boolean),
  scriptIds: array(string),
  evidence: evidenceRefs,
});
const profile = fields({
  profileName: nullable(string),
  deploymentProfileId: nullable(string),
  correlationId: nullable(string),
  tenantDomain: nullable(classifiedString),
  tenantId: nullable(classifiedString),
  oobeConfig: nullable(oobeConfig),
  profileDownloadTime: nullable(timestamp),
  joinMode: nullable(string),
  odjApplied: nullable(boolean),
  skipDomainConnectivityCheck: nullable(boolean),
  devicePreparation: nullable(devicePreparation),
  evidence: evidenceRefs,
});
const enrollmentSettings = fields({
  deviceEspEnabled: nullable(boolean),
  userEspEnabled: nullable(boolean),
  timeoutSeconds: nullable(unsignedInteger),
  blocking: nullable(boolean),
  allowReset: nullable(boolean),
  allowRetry: nullable(boolean),
  continueAnyway: nullable(boolean),
});
const enrollment = fields({
  enrollmentId: string,
  providerId: nullable(string),
  tenantId: nullable(classifiedString),
  userPrincipalName: nullable(classifiedString),
  entdmId: nullable(classifiedString),
  settings: enrollmentSettings,
  evidence: evidenceRefs,
});
const session = fields({
  sessionId: string,
  kind: values("classic", "devicePreparationV2"),
  scope: values("device", "user"),
  userSid: nullable(classifiedString),
  startedAt: nullable(timestamp),
  endedAt: nullable(timestamp),
  phase: values(
    "notStarted",
    "devicePreparation",
    "deviceSetup",
    "accountSetup",
    "completed",
    "failed",
    "unknown",
  ),
  isLatest: boolean,
  workloadIds: array(string),
  evidence: evidenceRefs,
});
const workload = fields({
  workloadId: string,
  sessionId: string,
  kind: values(
    "msi",
    "office",
    "modernApp",
    "win32App",
    "policy",
    "scepCertificate",
    "platformScript",
    "devicePreparationWorkload",
  ),
  scope: values("device", "user"),
  rawIdentifier: string,
  displayName: nullable(string),
  status,
  timestamps: fields({
    firstObserved: timestamp,
    started: nullable(timestamp),
    ended: nullable(timestamp),
    lastUpdated: nullable(timestamp),
  }),
  exitCode: nullable(errorCode),
  enforcementErrorCode: nullable(errorCode),
  blocking: nullable(boolean),
  evidence: evidenceRefs,
});
const processObservation = fields({
  context: observationContext,
  pid: unsignedInteger,
  processStartTime: timestamp,
  parentPid: nullable(unsignedInteger),
  executableName: string,
  sanitizedCommandLine: nullable(string),
  referencedLogPath: nullable(string),
  appId: nullable(string),
  productCode: nullable(string),
});
const installerCorrelation = fields({
  correlationId: string,
  workloadId: nullable(string),
  confidence: values("exact", "strong", "temporal", "uncorrelated"),
  reason: string,
  candidateWorkloadIds: array(string),
  processObservations: array(processObservation),
  evidence: evidenceRefs,
});
const nodeCacheEntry = fields({
  index: unsignedInteger,
  nodeUri: string,
  expectedValue: nullable(string),
  sensitivity,
  evidence: evidenceRefs,
});
const registrationEvent = fields({
  eventId: unsignedInteger,
  recordId: nullable(unsignedInteger),
  status,
  message: string,
  timestamp,
  namedData: array(namedValue),
  evidence: evidenceRefs,
});
const doTransfer = fields({
  transferId: string,
  kind: values("downloadStarted", "downloadCompleted"),
  contentId: nullable(string),
  appId: nullable(string),
  timestamp,
  evidence: evidenceRefs,
});
const deliveryOptimization = fields({
  downloadHttpBytes: unsignedInteger,
  downloadLanBytes: unsignedInteger,
  downloadCacheHostBytes: unsignedInteger,
  peerSharePercent: nullable(number),
  connectedCacheSharePercent: nullable(number),
  transfers: array(doTransfer),
  evidence: evidenceRefs,
});
const hardware = fields({
  osVersion: nullable(string),
  osBuild: nullable(string),
  manufacturer: nullable(string),
  model: nullable(string),
  serialNumber: nullable(classifiedString),
  tpmVersion: nullable(string),
  evidence: evidenceRefs,
});
const timelineEntry = fields({
  entryId: string,
  timestamp,
  kind: values(
    "profileDownload",
    "offlineDomainJoin",
    "registration",
    "workload",
    "deliveryOptimization",
    "coverage",
    "process",
    "other",
  ),
  title: string,
  detail: nullable(string),
  status: nullable(status),
  evidence: evidenceRefs,
});
const finding = fields({
  findingId: string,
  severity: values("info", "warning", "error", "blocker"),
  confidence: values("low", "medium", "high"),
  title: string,
  summary: string,
  recommendedChecks: array(string),
  evidence: evidenceRefs,
  coverageGapIds: array(string),
});
const coverage = fields({
  artifactId: string,
  family: string,
  status: values(
    "available",
    "missing",
    "permissionDenied",
    "parseFailed",
    "unsupported",
  ),
  detail: nullable(string),
  observedAtUtc: string,
  evidence: evidenceRefs,
});
const observationValue: Guard = (value) => {
  if (!record(value) || Object.keys(value).length !== 1) return false;
  if (hasOwn(value, "text")) return string(value.text);
  if (hasOwn(value, "integer")) return integer(value.integer);
  if (hasOwn(value, "unsigned")) return unsignedInteger(value.unsigned);
  if (hasOwn(value, "boolean")) return boolean(value.boolean);
  return hasOwn(value, "stringList") && array(string)(value.stringList);
};
const rawEvidence = fields({
  recordId: string,
  provenance,
  sourceTimestamp: nullable(timestamp),
  observedAtUtc: string,
  rawValue: observationValue,
  sensitivity,
  parseState,
  accessState,
  evidence: evidenceRefs,
});

const graphError = fields({
  code: string,
  message: string,
  requestId: nullable(string),
  blockedBy: nullable(string),
  retryAfterSeconds: nullable(unsignedInteger),
});
const assignment = fields({
  assignmentId: string,
  targetId: nullable(string),
  filterId: nullable(string),
  intent: string,
  targetKind: string,
  targeting: values("declared", "effective"),
  evidence: evidenceRefs,
});
const managedDevice = fields({
  managedDeviceId: string,
  entraDeviceId: nullable(string),
  serialNumber: nullable(classifiedString),
  deviceName: nullable(string),
  userId: nullable(string),
  userPrincipalName: nullable(classifiedString),
  tenantId: nullable(classifiedString),
  evidence: evidenceRefs,
});
const deviceMatch = fields({
  selected: nullable(managedDevice),
  candidates: array(managedDevice),
  matchBasis: nullable(string),
  confidence: values("exact", "strong", "temporal", "uncorrelated"),
  evidence: evidenceRefs,
});
const autopilotIdentity = fields({
  autopilotDeviceId: string,
  entraDeviceId: nullable(string),
  serialNumber: nullable(classifiedString),
  deploymentProfileId: nullable(string),
  groupTag: nullable(string),
  evidence: evidenceRefs,
});
const deploymentProfile = fields({
  profileId: string,
  displayName: nullable(string),
  joinMode: nullable(string),
  selectedMobileAppIds: array(string),
  evidence: evidenceRefs,
});
const policyStatusDetail = fields({
  statusDetailId: string,
  relatedObjectId: nullable(string),
  displayName: nullable(string),
  kind: string,
  status,
  correlationConfidence: values("exact", "strong", "temporal", "uncorrelated"),
  evidence: evidenceRefs,
});
const autopilotEvent = fields({
  eventId: string,
  managedDeviceId: nullable(string),
  eventTime: nullable(timestamp),
  deploymentState: status,
  policyStatusDetails: array(policyStatusDetail),
  evidence: evidenceRefs,
});
const enrollmentConfiguration = fields({
  configurationId: string,
  displayName: nullable(string),
  deviceEspEnabled: nullable(boolean),
  userEspEnabled: nullable(boolean),
  timeoutMinutes: nullable(unsignedInteger),
  selectedMobileAppIds: array(string),
  assignments: array(assignment),
  evidence: evidenceRefs,
});
const graphApp = fields({
  appId: string,
  displayName: nullable(string),
  trackedOnEnrollmentStatus: nullable(boolean),
  status: nullable(status),
  assignments: array(assignment),
  evidence: evidenceRefs,
});
const graphPolicy = fields({
  policyId: string,
  displayName: nullable(string),
  kind: string,
  status: nullable(status),
  assignments: array(assignment),
  evidence: evidenceRefs,
});
const graphScript = fields({
  scriptId: string,
  displayName: nullable(string),
  kind: string,
  status: nullable(status),
  assignments: array(assignment),
  evidence: evidenceRefs,
});
const graphSection = (data: Guard): Guard =>
  fields({
    status: string,
    requiredScope: nullable(string),
    apiVersion: string,
    data: nullable(data),
    error: nullable(graphError),
  });

const graphOverlay: Guard = fields({
  requestId: string,
  requestedAtUtc: string,
  deviceMatch: graphSection(deviceMatch),
  autopilotIdentity: graphSection(autopilotIdentity),
  deploymentProfile: graphSection(deploymentProfile),
  intendedDeploymentProfile: graphSection(deploymentProfile),
  profileAssignments: graphSection(array(assignment)),
  autopilotEvents: graphSection(array(autopilotEvent)),
  enrollmentConfiguration: graphSection(enrollmentConfiguration),
  apps: graphSection(array(graphApp)),
  policies: graphSection(array(graphPolicy)),
  scripts: graphSection(array(graphScript)),
});

export function isEspGraphOverlay(value: unknown): value is EspGraphOverlay {
  return graphOverlay(value);
}

export function isEspDiagnosticsSnapshot(
  value: unknown,
): value is EspDiagnosticsSnapshot {
  return fields({
    schemaVersion: (candidate) => candidate === 1,
    scenario: values(
      "unknown",
      "autopilotV1",
      "existingDeviceJson",
      "espOnly",
      "autopilotDevicePreparationV2",
    ),
    phase: values(
      "notStarted",
      "devicePreparation",
      "deviceSetup",
      "accountSetup",
      "completed",
      "failed",
      "unknown",
    ),
    generatedAtUtc: string,
    elevation,
    identity,
    profile: nullable(profile),
    enrollments: array(enrollment),
    sessions: array(session),
    workloads: array(workload),
    installerCorrelations: array(installerCorrelation),
    nodeCache: array(nodeCacheEntry),
    registrationEvents: array(registrationEvent),
    deliveryOptimization: nullable(deliveryOptimization),
    hardware: nullable(hardware),
    activity: array(timelineEntry),
    findings: array(finding),
    coverage: array(coverage),
    rawEvidence: array(rawEvidence),
    graph: nullable(graphOverlay),
  })(value);
}
