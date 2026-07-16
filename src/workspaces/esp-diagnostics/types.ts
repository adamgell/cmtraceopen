// Wire types mirrored from crates/cmtraceopen-parser/src/esp/models.rs.

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
  "available" | "missing" | "permissionDenied" | "parseFailed" | "unsupported";

export type EspCorrelationConfidence =
  "exact" | "strong" | "temporal" | "uncorrelated";

export type EspTimestampKind =
  "utc" | "offset" | "local" | "unspecified" | "invalid";

export type EspSourceKind =
  | "registry"
  | "json"
  | "eventLog"
  | "imeLog"
  | "deploymentLog"
  | "process"
  | "system"
  | "deliveryOptimization"
  | "graph"
  | "coverage";

export type EspSensitivity = "public" | "sensitive" | "restricted";
export type EspParseState = "parsed" | "raw" | "malformed" | "unsupported";
export type EspSourceAccessState =
  "available" | "missing" | "permissionDenied" | "failed" | "unsupported";
export type EspScope = "device" | "user";
export type EspSessionKind = "classic" | "devicePreparationV2";
export type EspJoinMode = "entra" | "hybridEntra" | (string & {});
export type EspFindingSeverity = "info" | "warning" | "error" | "blocker";
export type EspFindingConfidence = "low" | "medium" | "high";
export type EspTimelineKind =
  | "profileDownload"
  | "offlineDomainJoin"
  | "registration"
  | "workload"
  | "deliveryOptimization"
  | "coverage"
  | "process"
  | "other";
export type EspGraphAssignmentIntent =
  "required" | "available" | "uninstall" | (string & {});
export type EspGraphTargetKind =
  "allDevices" | "allUsers" | "group" | "filter" | (string & {});
export type EspGraphTargeting = "declared" | "effective";
export type EspGraphPolicyKind =
  | "deviceConfiguration"
  | "compliance"
  | "configurationPolicy"
  | "scepCertificate"
  | (string & {});
export type EspGraphScriptKind =
  "platformScript" | "remediation" | (string & {});
export type EspGraphObservationSection =
  | "managedDevice"
  | "autopilotIdentity"
  | "deploymentProfile"
  | "enrollmentConfiguration"
  | "app"
  | "policy"
  | "script"
  | (string & {});
export type EspGraphPolicyStatusDetailKind = "app" | "policy" | (string & {});
export type EspDeliveryOptimizationEventKind =
  "downloadStarted" | "downloadCompleted";

export type EspRawStatus =
  | number
  | string
  | boolean
  | null
  | EspRawStatus[]
  | { [key: string]: EspRawStatus };
export type EspObservationValue =
  | { text: string }
  | { integer: number }
  | { unsigned: number }
  | { boolean: boolean }
  | { stringList: string[] };

export interface EspClassifiedString {
  value: string;
  sensitivity: EspSensitivity;
}

export interface EspTimestamp {
  rawText: string;
  originalOffset: string | null;
  normalizedUtc: string | null;
  kind: EspTimestampKind;
}

export interface EspEvidenceRef {
  evidenceId: string;
  sourceArtifactId: string;
}

export interface EspRegistryProvenance {
  hive: string;
  key: string;
  valueName: string | null;
}

export interface EspNamedValue {
  name: string;
  value: string;
}

export interface EspEventProvenance {
  channel: string;
  eventId: number;
  recordId: number | null;
  namedData: EspNamedValue[];
}

export interface EspEvidenceProvenance {
  sourceKind: EspSourceKind;
  sourceArtifactId: string;
  filePath: string | null;
  lineNumber: number | null;
  recordNumber: number | null;
  registry: EspRegistryProvenance | null;
  event: EspEventProvenance | null;
}

export interface EspObservationContext {
  evidenceRef: EspEvidenceRef;
  provenance: EspEvidenceProvenance;
  sourceTimestamp: EspTimestamp | null;
  observedAtUtc: string;
  sensitivity: EspSensitivity;
  parseState: EspParseState;
  accessState: EspSourceAccessState;
}

export interface EspStatusDetail {
  raw: EspRawStatus;
  normalized: EspNormalizedStatus;
  display: string;
}

export interface EspStatus {
  raw: EspRawStatus;
  normalized: EspNormalizedStatus;
  display: string;
  detail: EspStatusDetail | null;
}

export interface EspErrorCode {
  raw: string;
  decimal: number | null;
  hex: string | null;
}

export interface EspElevationState {
  isElevated: boolean;
  restartSupported: boolean;
  restrictedSources: string[];
}

export interface EspIdentityEvidence {
  deviceName: string | null;
  managedDeviceId: string | null;
  entraDeviceId: string | null;
  entdmId: EspClassifiedString | null;
  tenantId: EspClassifiedString | null;
  tenantDomain: EspClassifiedString | null;
  userPrincipalName: EspClassifiedString | null;
  serialNumber: EspClassifiedString | null;
  evidence: EspEvidenceRef[];
}

export interface EspOobeConfig {
  rawMask: number;
  skipKeyboard: boolean;
  enablePatchDownload: boolean;
  skipWindowsUpgradeUx: boolean;
  aadTpmRequired: boolean;
  aadDeviceAuthentication: boolean;
  tpmAttestation: boolean;
  skipEula: boolean;
  skipOemRegistration: boolean;
  skipExpressSettings: boolean;
  disallowAdmin: boolean;
}

export interface EspDevicePreparationEvidence {
  agentDownloadTimeoutSeconds: number | null;
  pageTimeoutSeconds: number | null;
  allowSkipOnFailure: boolean | null;
  allowDiagnostics: boolean | null;
  scriptIds: string[];
  evidence: EspEvidenceRef[];
}

export interface EspProfileEvidence {
  profileName: string | null;
  deploymentProfileId: string | null;
  correlationId: string | null;
  tenantDomain: EspClassifiedString | null;
  tenantId: EspClassifiedString | null;
  oobeConfig: EspOobeConfig | null;
  profileDownloadTime: EspTimestamp | null;
  joinMode: EspJoinMode | null;
  odjApplied: boolean | null;
  skipDomainConnectivityCheck: boolean | null;
  devicePreparation: EspDevicePreparationEvidence | null;
  evidence: EspEvidenceRef[];
}

export interface EspEnrollmentSettings {
  deviceEspEnabled: boolean | null;
  userEspEnabled: boolean | null;
  timeoutSeconds: number | null;
  blocking: boolean | null;
  allowReset: boolean | null;
  allowRetry: boolean | null;
  continueAnyway: boolean | null;
}

export interface EspEnrollmentEvidence {
  enrollmentId: string;
  providerId: string | null;
  tenantId: EspClassifiedString | null;
  userPrincipalName: EspClassifiedString | null;
  entdmId: EspClassifiedString | null;
  settings: EspEnrollmentSettings;
  evidence: EspEvidenceRef[];
}

export interface EspSession {
  sessionId: string;
  kind: EspSessionKind;
  scope: EspScope;
  userSid: EspClassifiedString | null;
  startedAt: EspTimestamp | null;
  endedAt: EspTimestamp | null;
  phase: EspPhase;
  isLatest: boolean;
  workloadIds: string[];
  evidence: EspEvidenceRef[];
}

export interface EspWorkloadTimestamps {
  firstObserved: EspTimestamp;
  started: EspTimestamp | null;
  ended: EspTimestamp | null;
  lastUpdated: EspTimestamp | null;
}

export interface EspWorkload {
  workloadId: string;
  sessionId: string;
  kind: EspTrackedKind;
  scope: EspScope;
  rawIdentifier: string;
  displayName: string | null;
  status: EspStatus;
  timestamps: EspWorkloadTimestamps;
  exitCode: EspErrorCode | null;
  enforcementErrorCode: EspErrorCode | null;
  blocking: boolean | null;
  evidence: EspEvidenceRef[];
}

export interface EspNodeCacheEntry {
  index: number;
  nodeUri: string;
  expectedValue: string | null;
  sensitivity: EspSensitivity;
  evidence: EspEvidenceRef[];
}

export interface EspRegistrationEvent {
  eventId: number;
  recordId: number | null;
  status: EspStatus;
  message: string;
  timestamp: EspTimestamp;
  namedData: EspNamedValue[];
  evidence: EspEvidenceRef[];
}

export interface EspDeliveryOptimizationTransfer {
  transferId: string;
  kind: EspDeliveryOptimizationEventKind;
  contentId: string | null;
  appId: string | null;
  timestamp: EspTimestamp;
  evidence: EspEvidenceRef[];
}

export interface EspDeliveryOptimizationEvidence {
  downloadHttpBytes: number;
  downloadLanBytes: number;
  downloadCacheHostBytes: number;
  peerSharePercent: number | null;
  connectedCacheSharePercent: number | null;
  transfers: EspDeliveryOptimizationTransfer[];
  evidence: EspEvidenceRef[];
}

export interface EspHardwareEvidence {
  osVersion: string | null;
  osBuild: string | null;
  manufacturer: string | null;
  model: string | null;
  serialNumber: EspClassifiedString | null;
  tpmVersion: string | null;
  evidence: EspEvidenceRef[];
}

export interface EspTimelineEntry {
  entryId: string;
  timestamp: EspTimestamp;
  kind: EspTimelineKind;
  title: string;
  detail: string | null;
  status: EspStatus | null;
  evidence: EspEvidenceRef[];
}

export interface EspDiagnosticFinding {
  findingId: string;
  severity: EspFindingSeverity;
  confidence: EspFindingConfidence;
  title: string;
  summary: string;
  recommendedChecks: string[];
  evidence: EspEvidenceRef[];
  coverageGapIds: string[];
}

export interface EspArtifactCoverage {
  artifactId: string;
  family: string;
  status: EspArtifactStatus;
  detail: string | null;
  observedAtUtc: string;
  evidence: EspEvidenceRef[];
}

export interface EspRawEvidenceRecord {
  recordId: string;
  provenance: EspEvidenceProvenance;
  sourceTimestamp: EspTimestamp | null;
  observedAtUtc: string;
  rawValue: EspObservationValue;
  sensitivity: EspSensitivity;
  parseState: EspParseState;
  accessState: EspSourceAccessState;
  evidence: EspEvidenceRef[];
}

export interface EspRegistryObservation {
  context: EspObservationContext;
  hive: string;
  key: string;
  valueName: string;
  value: EspObservationValue;
}

export interface EspJsonObservation {
  context: EspObservationContext;
  documentType: string;
  jsonPointer: string;
  value: EspObservationValue;
}

export interface EspEventLogObservation {
  context: EspObservationContext;
  channel: string;
  eventId: number;
  recordId: number | null;
  namedData: EspNamedValue[];
  message: string | null;
}

export interface EspImeObservation {
  context: EspObservationContext;
  component: string | null;
  message: string;
  appId: string | null;
  status: EspStatus | null;
}

export interface EspDeploymentLogObservation {
  context: EspObservationContext;
  component: string | null;
  message: string;
  productCode: string | null;
  logPath: string | null;
  status: EspStatus | null;
}

export interface EspProcessObservation {
  context: EspObservationContext;
  pid: number;
  processStartTime: EspTimestamp;
  parentPid: number | null;
  executableName: string;
  sanitizedCommandLine: string | null;
  referencedLogPath: string | null;
  appId: string | null;
  productCode: string | null;
}

export type EspSystemFact =
  | { osVersion: string }
  | { osBuild: string }
  | { manufacturer: string }
  | { model: string }
  | { serialNumber: string }
  | { tpmVersion: string }
  | { hostname: string }
  | { elevation: EspElevationState };

export interface EspSystemObservation {
  context: EspObservationContext;
  fact: EspSystemFact;
}

export interface EspDeliveryOptimizationObservation {
  context: EspObservationContext;
  kind: EspDeliveryOptimizationEventKind;
  contentId: string | null;
  appId: string | null;
  httpBytes: number | null;
  lanBytes: number | null;
  cacheHostBytes: number | null;
}

type RawPreservingString<Known extends string> =
  Known | (string & Record<never, never>);

export type GraphApiVersion = RawPreservingString<
  "v1.0" | "beta" | "notRequested"
>;
export type GraphSectionStatus = RawPreservingString<
  | "available"
  | "notFound"
  | "permissionDenied"
  | "failed"
  | "skipped"
  | "cancelled"
>;

export interface EspGraphObservation {
  context: EspObservationContext;
  section: EspGraphObservationSection;
  apiVersion: GraphApiVersion;
  recordId: string;
  displayName: string | null;
  status: EspStatus | null;
}

export interface EspInstallerCorrelation {
  correlationId: string;
  workloadId: string | null;
  confidence: EspCorrelationConfidence;
  reason: string;
  candidateWorkloadIds: string[];
  processObservations: EspProcessObservation[];
  evidence: EspEvidenceRef[];
}

export interface GraphSectionError {
  code: string;
  message: string;
  requestId: string | null;
  blockedBy: string | null;
  retryAfterSeconds: number | null;
}

export interface GraphSection<T> {
  status: GraphSectionStatus;
  requiredScope: string | null;
  apiVersion: GraphApiVersion;
  data: T | null;
  error: GraphSectionError | null;
}

export interface EspGraphManagedDevice {
  managedDeviceId: string;
  entraDeviceId: string | null;
  serialNumber: EspClassifiedString | null;
  deviceName: string | null;
  userId: string | null;
  userPrincipalName: EspClassifiedString | null;
  tenantId: EspClassifiedString | null;
  evidence: EspEvidenceRef[];
}

export interface EspGraphDeviceMatch {
  selected: EspGraphManagedDevice | null;
  candidates: EspGraphManagedDevice[];
  matchBasis: string | null;
  confidence: EspCorrelationConfidence;
  evidence: EspEvidenceRef[];
}

export interface EspGraphAutopilotIdentity {
  autopilotDeviceId: string;
  entraDeviceId: string | null;
  serialNumber: EspClassifiedString | null;
  deploymentProfileId: string | null;
  groupTag: string | null;
  evidence: EspEvidenceRef[];
}

export interface EspGraphDeploymentProfile {
  profileId: string;
  displayName: string | null;
  joinMode: EspJoinMode | null;
  selectedMobileAppIds: string[];
  evidence: EspEvidenceRef[];
}

export interface EspGraphAssignment {
  assignmentId: string;
  targetId: string | null;
  filterId: string | null;
  intent: EspGraphAssignmentIntent;
  targetKind: EspGraphTargetKind;
  targeting: EspGraphTargeting;
  evidence: EspEvidenceRef[];
}

export interface EspGraphPolicyStatusDetail {
  statusDetailId: string;
  relatedObjectId: string | null;
  displayName: string | null;
  kind: EspGraphPolicyStatusDetailKind;
  status: EspStatus;
  trackedOnEnrollmentStatus: boolean | null;
  correlationConfidence: EspCorrelationConfidence;
  evidence: EspEvidenceRef[];
}

export interface EspGraphAutopilotEvent {
  eventId: string;
  managedDeviceId: string | null;
  enrollmentConfigurationId: string | null;
  eventTime: EspTimestamp | null;
  deploymentState: EspStatus;
  policyStatusDetails: EspGraphPolicyStatusDetail[];
  evidence: EspEvidenceRef[];
}

export interface EspGraphEnrollmentConfiguration {
  configurationId: string;
  displayName: string | null;
  showInstallationProgress: boolean | null;
  deviceEspEnabled: boolean | null;
  userEspEnabled: boolean | null;
  disableUserStatusTrackingAfterFirstUser: boolean | null;
  timeoutMinutes: number | null;
  selectedMobileAppIds: string[];
  assignments: EspGraphAssignment[];
  evidence: EspEvidenceRef[];
}

export interface EspGraphAppRecord {
  appId: string;
  displayName: string | null;
  trackedOnEnrollmentStatus: boolean | null;
  status: EspStatus | null;
  intentState: GraphSection<EspStatus>;
  assignments: EspGraphAssignment[];
  evidence: EspEvidenceRef[];
}

export interface EspGraphPolicyRecord {
  policyId: string;
  displayName: string | null;
  kind: EspGraphPolicyKind;
  status: EspStatus | null;
  assignments: EspGraphAssignment[];
  evidence: EspEvidenceRef[];
}

export interface EspGraphScriptRecord {
  scriptId: string;
  displayName: string | null;
  kind: EspGraphScriptKind;
  status: EspStatus | null;
  assignments: EspGraphAssignment[];
  evidence: EspEvidenceRef[];
}

export interface EspGraphOverlay {
  requestId: string;
  requestedAtUtc: string;
  deviceMatch: GraphSection<EspGraphDeviceMatch>;
  autopilotIdentity: GraphSection<EspGraphAutopilotIdentity>;
  deploymentProfile: GraphSection<EspGraphDeploymentProfile>;
  intendedDeploymentProfile: GraphSection<EspGraphDeploymentProfile>;
  profileAssignments: GraphSection<EspGraphAssignment[]>;
  autopilotEvents: GraphSection<EspGraphAutopilotEvent[]>;
  enrollmentConfiguration: GraphSection<EspGraphEnrollmentConfiguration>;
  apps: GraphSection<EspGraphAppRecord[]>;
  policies: GraphSection<EspGraphPolicyRecord[]>;
  scripts: GraphSection<EspGraphScriptRecord[]>;
}

export interface EspGraphPolicyReference {
  id: string;
  kind: EspGraphPolicyKind;
}

export interface EspGraphScriptReference {
  id: string;
  kind: EspGraphScriptKind;
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
  evidenceWindowStartUtc: string | null;
  evidenceWindowEndUtc: string | null;
  enrollmentConfigurationIds: string[];
  appIds: string[];
  policyReferences: EspGraphPolicyReference[];
  scriptReferences: EspGraphScriptReference[];
}

export interface EspRelaunchResult {
  launched: boolean;
  reason:
    | "launched"
    | "alreadyElevated"
    | "elevationCancelled"
    | "unsupportedPlatform";
}
