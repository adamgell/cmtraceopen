export type DsregcmdSeverity = "Info" | "Warning" | "Error";
export type DsregcmdJoinType =
  | "HybridEntraIdJoined"
  | "EntraIdJoined"
  | "NotJoined"
  | "Unknown";

export type DsregcmdDiagnosticPhase =
  | "precheck"
  | "discover"
  | "auth"
  | "join"
  | "post_join"
  | "unknown";

export type DsregcmdCaptureConfidence = "high" | "medium" | "low";

export type DsregcmdEvidenceSource =
  | "dsregcmd"
  | "policy_manager_current"
  | "policy_manager_provider"
  | "policy_manager_comparison"
  | "windows_policy_machine"
  | "windows_policy_user";

export interface DsregcmdPolicyEvidenceValue {
  displayValue: boolean | null;
  currentValue: boolean | null;
  providerValue: boolean | null;
  source: DsregcmdEvidenceSource | null;
  note: string | null;
}

export interface DsregcmdWhfbPolicyEvidence {
  policyEnabled: DsregcmdPolicyEvidenceValue;
  postLogonEnabled: DsregcmdPolicyEvidenceValue;
  pinRecoveryEnabled: DsregcmdPolicyEvidenceValue;
  requireSecurityDevice: DsregcmdPolicyEvidenceValue;
  useCertificateForOnPremAuth: DsregcmdPolicyEvidenceValue;
  useCloudTrustForOnPremAuth: DsregcmdPolicyEvidenceValue;
  artifactPaths: string[];
}

export interface DsregcmdJoinState {
  azureAdJoined: boolean | null;
  domainJoined: boolean | null;
  workplaceJoined: boolean | null;
  enterpriseJoined: boolean | null;
}

export interface DsregcmdDeviceDetails {
  deviceId: string | null;
  thumbprint: string | null;
  deviceCertificateValidity: string | null;
  keyContainerId: string | null;
  keyProvider: string | null;
  tpmProtected: boolean | null;
  deviceAuthStatus: string | null;
}

export interface DsregcmdTenantDetails {
  tenantId: string | null;
  tenantName: string | null;
  domainName: string | null;
  idp: string | null;
}

export interface DsregcmdManagementDetails {
  mdmUrl: string | null;
  mdmComplianceUrl: string | null;
  mdmTouUrl: string | null;
  settingsUrl: string | null;
  deviceManagementSrvVer: string | null;
  deviceManagementSrvUrl: string | null;
  deviceManagementSrvId: string | null;
}

export interface DsregcmdServiceEndpoints {
  authCodeUrl: string | null;
  accessTokenUrl: string | null;
  joinSrvVersion: string | null;
  joinSrvUrl: string | null;
  joinSrvId: string | null;
  keySrvVersion: string | null;
  keySrvUrl: string | null;
  keySrvId: string | null;
  webAuthnSrvVersion: string | null;
  webAuthnSrvUrl: string | null;
  webAuthnSrvId: string | null;
}

export interface DsregcmdUserState {
  ngcSet: boolean | null;
  ngcKeyId: string | null;
  canReset: string | null;
  wamDefaultSet: boolean | null;
  wamDefaultAuthority: string | null;
  wamDefaultId: string | null;
  wamDefaultGuid: string | null;
  isDeviceJoined: boolean | null;
  isUserAzureAd: boolean | null;
  policyEnabled: boolean | null;
  postLogonEnabled: boolean | null;
  deviceEligible: boolean | null;
  sessionIsNotRemote: boolean | null;
}

export interface DsregcmdSsoState {
  azureAdPrt: boolean | null;
  azureAdPrtAuthority: string | null;
  azureAdPrtUpdateTime: string | null;
  acquirePrtDiagnostics: string | null;
  enterprisePrt: boolean | null;
  enterprisePrtUpdateTime: string | null;
  enterprisePrtExpiryTime: string | null;
  enterprisePrtAuthority: string | null;
  onPremTgt: boolean | null;
  cloudTgt: boolean | null;
  adfsRefreshToken: boolean | null;
  adfsRaIsReady: boolean | null;
  kerbTopLevelNames: string | null;
}

export interface DsregcmdDiagnosticFields {
  previousPrtAttempt: string | null;
  attemptStatus: string | null;
  userIdentity: string | null;
  credentialType: string | null;
  correlationId: string | null;
  endpointUri: string | null;
  httpMethod: string | null;
  httpError: string | null;
  httpStatus: number | null;
  requestId: string | null;
  diagnosticsReference: string | null;
  userContext: string | null;
  clientTime: string | null;
}

export interface DsregcmdPreJoinTests {
  adConnectivityTest: string | null;
  adConfigurationTest: string | null;
  drsDiscoveryTest: string | null;
  drsConnectivityTest: string | null;
  tokenAcquisitionTest: string | null;
  fallbackToSyncJoin: string | null;
}

export interface DsregcmdRegistrationState {
  previousRegistration: string | null;
  errorPhase: string | null;
  certEnrollment: string | null;
  logonCertTemplateReady: string | null;
  preReqResult: string | null;
  clientErrorCode: string | null;
  serverErrorCode: string | null;
  serverMessage: string | null;
  serverErrorDescription: string | null;
}

export interface DsregcmdPostJoinDiagnostics {
  aadRecoveryEnabled: boolean | null;
  keySignTest: string | null;
}

export interface DsregcmdFacts {
  joinState: DsregcmdJoinState;
  deviceDetails: DsregcmdDeviceDetails;
  tenantDetails: DsregcmdTenantDetails;
  managementDetails: DsregcmdManagementDetails;
  serviceEndpoints: DsregcmdServiceEndpoints;
  userState: DsregcmdUserState;
  ssoState: DsregcmdSsoState;
  diagnostics: DsregcmdDiagnosticFields;
  preJoinTests: DsregcmdPreJoinTests;
  registration: DsregcmdRegistrationState;
  postJoinDiagnostics: DsregcmdPostJoinDiagnostics;
}

export interface DsregcmdDerived {
  joinType: DsregcmdJoinType;
  joinTypeLabel: string;
  dominantPhase: DsregcmdDiagnosticPhase;
  phaseSummary: string;
  captureConfidence: DsregcmdCaptureConfidence;
  captureConfidenceReason: string;
  mdmEnrolled: boolean | null;
  missingMdm: boolean | null;
  complianceUrlPresent: boolean | null;
  missingComplianceUrl: boolean | null;
  azureAdPrtPresent: boolean | null;
  stalePrt: boolean | null;
  prtLastUpdate: string | null;
  prtReferenceTime: string | null;
  prtAgeHours: number | null;
  tpmProtected: boolean | null;
  certificateValidFrom: string | null;
  certificateValidTo: string | null;
  certificateExpiringSoon: boolean | null;
  certificateDaysRemaining: number | null;
  networkErrorCode: string | null;
  hasNetworkError: boolean;
  remoteSessionSystem: boolean | null;
}

export interface DsregcmdDiagnosticInsight {
  id: string;
  severity: DsregcmdSeverity;
  category: string;
  title: string;
  summary: string;
  evidence: string[];
  nextChecks: string[];
  suggestedFixes: string[];
}

export interface DsregcmdOsVersionEvidence {
  currentBuild: string | null;
  displayVersion: string | null;
  productName: string | null;
  ubr: number | null;
  editionId: string | null;
}

export interface DsregcmdProxyEvidence {
  proxyEnabled: boolean | null;
  proxyServer: string | null;
  proxyOverride: string | null;
  autoConfigUrl: string | null;
  wpadDetected: boolean;
  winhttpProxy: string | null;
}

export interface DsregcmdEnrollmentEntry {
  guid: string | null;
  upn: string | null;
  providerId: string | null;
  enrollmentState: number | null;
}

export interface DsregcmdEnrollmentEvidence {
  enrollmentCount: number;
  enrollments: DsregcmdEnrollmentEntry[];
}

export interface DsregcmdConnectivityResult {
  endpoint: string;
  reachable: boolean;
  statusCode: number | null;
  latencyMs: number | null;
  errorMessage: string | null;
  timestamp: string;
}

export interface DsregcmdScpQueryResult {
  scpFound: boolean;
  tenantDomain: string | null;
  azureadId: string | null;
  keywords: string[];
  domainController: string | null;
  error: string | null;
}

export interface DsregcmdActiveEvidence {
  connectivityTests: DsregcmdConnectivityResult[];
  scpQuery: DsregcmdScpQueryResult | null;
}

export interface DsregcmdScheduledTaskEvidence {
  enterpriseMgmtGuids: string[];
}

export interface DsregcmdAnalysisResult {
  facts: DsregcmdFacts;
  derived: DsregcmdDerived;
  diagnostics: DsregcmdDiagnosticInsight[];
  policyEvidence: DsregcmdWhfbPolicyEvidence;
  osVersion: DsregcmdOsVersionEvidence | null;
  proxyEvidence: DsregcmdProxyEvidence | null;
  enrollmentEvidence: DsregcmdEnrollmentEvidence | null;
  activeEvidence: DsregcmdActiveEvidence | null;
  scheduledTaskEvidence: DsregcmdScheduledTaskEvidence | null;
  eventLogAnalysis: import("./event-log").EventLogAnalysis | null;
}

export interface DsregcmdCaptureResult {
  input: string;
  bundlePath: string | null;
  evidenceFilePath: string | null;
}

export interface DsregcmdResolvedSource {
  input: string;
  bundlePath: string | null;
  resolvedPath: string | null;
  evidenceFilePath: string | null;
}

export type DsregcmdSourceKind = "file" | "folder" | "clipboard" | "capture" | "text";

export type DsregcmdSourceDescriptor =
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string }
  | { kind: "clipboard" }
  | { kind: "capture" }
  | { kind: "text"; label: string };

export interface DsregcmdSourceContext {
  source: DsregcmdSourceDescriptor | null;
  requestedPath: string | null;
  resolvedPath: string | null;
  bundlePath: string | null;
  displayLabel: string;
  evidenceFilePath: string | null;
  rawLineCount: number;
  rawCharCount: number;
}

export type DsregcmdAnalysisPhase = "idle" | "analyzing" | "ready" | "error";

export interface DsregcmdAnalysisState {
  phase: DsregcmdAnalysisPhase;
  message: string;
  detail: string | null;
  requestedKind: DsregcmdSourceKind | null;
  requestedPath: string | null;
  lastError: string | null;
}
