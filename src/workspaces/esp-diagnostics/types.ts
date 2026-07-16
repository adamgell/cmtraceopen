export type EspScenario =
  | "unknown"
  | "autopilotV1"
  | "existingDeviceJson"
  | "espOnly"
  | "autopilotDevicePreparationV2";

export type EspPhase =
  | "notStarted"
  | "devicePreparation"
  | "deviceSetup"
  | "accountSetup"
  | "completed"
  | "failed"
  | "unknown";

export type EspTrackedKind =
  | "msi"
  | "office"
  | "modernApp"
  | "win32App"
  | "policy"
  | "scepCertificate"
  | "platformScript"
  | "devicePreparationWorkload";

export type EspNormalizedStatus =
  | "notStarted"
  | "notInstalled"
  | "initialized"
  | "pending"
  | "downloading"
  | "downloaded"
  | "installing"
  | "inProgress"
  | "processed"
  | "succeeded"
  | "failed"
  | "skipped"
  | "uninstalled"
  | "rebootRequired"
  | "cancelled"
  | "unknown";

export type EspArtifactStatus =
  | "available"
  | "missing"
  | "permissionDenied"
  | "parseFailed"
  | "unsupported";

export type EspCorrelationConfidence =
  | "exact"
  | "strong"
  | "temporal"
  | "uncorrelated";

export type EspSensitivity = "none" | "sensitive" | "secret";
export type EspParseState = "parsed" | "unknown" | "malformed";
export type EspSourceKind =
  | "registry"
  | "json"
  | "eventLog"
  | "ime"
  | "deploymentLog"
  | "process"
  | "system"
  | "deliveryOptimization"
  | "graph"
  | "coverage";

export interface EspEvidenceRef {
  id: string;
  sourceKind: EspSourceKind;
  sourceArtifactId: string;
  path: string | null;
  lineNumber: number | null;
  recordNumber: number | null;
  registryHive: string | null;
  registryKey: string | null;
  registryValue: string | null;
  eventChannel: string | null;
  eventId: number | null;
  eventRecordId: number | null;
}

export interface EspElevationState {
  supported: boolean;
  isElevated: boolean;
  error: string | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspIdentityEvidence {
  tenantDomain: string | null;
  tenantId: string | null;
  correlationId: string | null;
  entDmId: string | null;
  userPrincipalName: string | null;
  enrollmentIds: string[];
  managedDeviceId: string | null;
  entraDeviceId: string | null;
  serialNumber: string | null;
  hostName: string | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspOobeSettings {
  rawMask: number | null;
  skipCortana: boolean | null;
  oobeUserNotLocalAdmin: boolean | null;
  skipExpressSettings: boolean | null;
  skipOemRegistration: boolean | null;
  skipEula: boolean | null;
  skipKeyboardSelection: boolean | null;
  skipPrivacySettings: boolean | null;
  skipRegionSelection: boolean | null;
  skipWifi: boolean | null;
  skipEulaServer: boolean | null;
}

export interface EspProfileEvidence {
  profileName: string | null;
  profileId: string | null;
  downloadedAtUtc: string | null;
  joinMode: "entra" | "hybrid" | "unknown";
  odjApplied: boolean | null;
  skipDomainConnectivityCheck: boolean | null;
  oobe: EspOobeSettings;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspSettingsEvidence {
  enabled: boolean | null;
  timeoutMinutes: number | null;
  blockDeviceUse: boolean | null;
  allowReset: boolean | null;
  allowRetry: boolean | null;
  allowContinue: boolean | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspEnrollmentEvidence {
  id: string;
  providerId: string | null;
  scope: "device" | "user";
  userSid: string | null;
  startedAtUtc: string | null;
  settings: EspSettingsEvidence | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspSession {
  id: string;
  enrollmentId: string | null;
  scope: "device" | "user";
  scenario: EspScenario;
  phase: EspPhase;
  startedAtUtc: string | null;
  completedAtUtc: string | null;
  isLatest: boolean;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspWorkload {
  id: string;
  sessionId: string | null;
  kind: EspTrackedKind;
  scope: "device" | "user";
  rawId: string | null;
  displayName: string | null;
  rawStatus: string | number | null;
  status: EspNormalizedStatus;
  startedAtUtc: string | null;
  completedAtUtc: string | null;
  exitCode: string | null;
  enforcementErrorCode: string | null;
  isBlocking: boolean | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspProcessObservation {
  processId: number;
  parentProcessId: number | null;
  imageName: string;
  startedAtUtc: string;
  commandLineSummary: string | null;
  logPath: string | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspInstallerCorrelation {
  id: string;
  process: EspProcessObservation;
  workloadId: string | null;
  productCode: string | null;
  applicationId: string | null;
  activeLogPath: string | null;
  confidence: EspCorrelationConfidence;
  reason: string;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspNodeCacheEntry {
  key: number;
  value: string;
  sensitivity: EspSensitivity;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspRegistrationEvent {
  id: string;
  eventId: number;
  status: EspNormalizedStatus;
  rawStatus: string | number | null;
  timestampUtc: string | null;
  message: string | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspDeliveryOptimizationEvidence {
  httpBytes: number | null;
  lanBytes: number | null;
  cacheBytes: number | null;
  totalBytes: number | null;
  events: EspTimelineEntry[];
  evidenceRefs: EspEvidenceRef[];
}

export interface EspHardwareEvidence {
  osVersion: string | null;
  osBuild: string | null;
  manufacturer: string | null;
  model: string | null;
  serialNumber: string | null;
  tpmVersion: string | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspTimelineEntry {
  id: string;
  timestampUtc: string | null;
  originalTimestamp: string | null;
  originalOffset: string | null;
  kind: string;
  title: string;
  detail: string | null;
  status: EspNormalizedStatus | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspDiagnosticFinding {
  findingId: string;
  severity: "info" | "warning" | "error";
  confidence: EspCorrelationConfidence;
  title: string;
  explanation: string;
  recommendedCheck: string;
  evidenceRefs: EspEvidenceRef[];
  coverageGapRefs: string[];
}

export interface EspArtifactCoverage {
  artifactId: string;
  family: string;
  status: EspArtifactStatus;
  detail: string | null;
  evidenceRefs: EspEvidenceRef[];
}

export interface EspRawEvidenceRecord {
  id: string;
  sourceKind: EspSourceKind;
  sourceArtifactId: string;
  observedAtUtc: string;
  sourceTimestamp: string | null;
  originalOffset: string | null;
  normalizedTimestampUtc: string | null;
  rawValue: string;
  sensitivity: EspSensitivity;
  parseState: EspParseState;
  accessState: EspArtifactStatus;
  evidenceRefs: EspEvidenceRef[];
}

export type GraphApiVersion = "v1" | "beta";
export type GraphSectionStatus =
  | "available"
  | "notFound"
  | "permissionDenied"
  | "failed"
  | "skipped"
  | "cancelled";

export interface GraphSectionError {
  code: string;
  message: string;
  graphRequestId: string | null;
  blockedBy: string | null;
}

export interface GraphSection<T> {
  status: GraphSectionStatus;
  requiredScope: string | null;
  apiVersion: GraphApiVersion;
  data: T | null;
  error: GraphSectionError | null;
}

export interface EspGraphDeviceCandidate {
  managedDeviceId: string;
  displayName: string | null;
  entraDeviceId: string | null;
  serialNumber: string | null;
}

export interface EspGraphDeviceMatch {
  managedDeviceId: string | null;
  matchBasis: "managedDeviceId" | "entraDeviceId" | "serialNumber" | "hostTenantUser" | "none";
  confidence: EspCorrelationConfidence;
  candidates: EspGraphDeviceCandidate[];
  evidenceRefs: EspEvidenceRef[];
}

export interface EspGraphObject {
  id: string;
  displayName: string | null;
  rawState: string | null;
  declaredTargetIds: string[];
  evidenceRefs: EspEvidenceRef[];
}

export interface EspGraphOverlay {
  requestId: string;
  fetchedAtUtc: string;
  deviceMatch: GraphSection<EspGraphDeviceMatch>;
  managedDevice: GraphSection<EspGraphObject>;
  autopilotIdentity: GraphSection<EspGraphObject>;
  deploymentProfile: GraphSection<EspGraphObject>;
  autopilotEvents: GraphSection<EspGraphObject[]>;
  espConfiguration: GraphSection<EspGraphObject>;
  apps: GraphSection<EspGraphObject[]>;
  policies: GraphSection<EspGraphObject[]>;
  certificates: GraphSection<EspGraphObject[]>;
  scripts: GraphSection<EspGraphObject[]>;
  remediations: GraphSection<EspGraphObject[]>;
}

export interface EspDiagnosticsSnapshot {
  schemaVersion: number;
  scenario: EspScenario;
  phase: EspPhase;
  generatedAtUtc: string;
  elevation: EspElevationState;
  identity: EspIdentityEvidence;
  profile: EspProfileEvidence | null;
  enrollments: EspEnrollmentEvidence[];
  sessions: EspSession[];
  workloads: EspWorkload[];
  installerCorrelations: EspInstallerCorrelation[];
  nodeCache: EspNodeCacheEntry[];
  registrationEvents: EspRegistrationEvent[];
  deliveryOptimization: EspDeliveryOptimizationEvidence | null;
  hardware: EspHardwareEvidence | null;
  activity: EspTimelineEntry[];
  findings: EspDiagnosticFinding[];
  coverage: EspArtifactCoverage[];
  rawEvidence: EspRawEvidenceRecord[];
  graph: EspGraphOverlay | null;
}

export type EspSessionState =
  | "starting"
  | "live"
  | "stopping"
  | "stopped"
  | "completed"
  | "expired"
  | "error";

export type EspUpdateReason =
  | "initialSnapshot"
  | "evidenceChanged"
  | "sourceAttached"
  | "sourceReset"
  | "stopped"
  | "expired"
  | "error";

export interface EspSessionEnvelope {
  sessionId: string;
  requestId: string;
  sequence: number;
  state: EspSessionState;
  snapshot: EspDiagnosticsSnapshot;
}

export interface EspSessionUpdate extends EspSessionEnvelope {
  reason: EspUpdateReason;
  emittedAtUtc: string;
}

export interface EspGraphRequest {
  requestId: string;
  identity: EspIdentityEvidence;
  workloadIds: string[];
  selectedManagedDeviceId: string | null;
}

export interface EspRelaunchResult {
  launched: boolean;
  reason: "launched" | "alreadyElevated" | "elevationCancelled" | "unsupportedPlatform";
}
