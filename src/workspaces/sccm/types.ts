export type SccmRole =
  | "client"
  | "siteServer"
  | "managementPoint"
  | "distributionPoint"
  | "softwareUpdatePoint"
  | "wsUs"
  | "provider"
  | "adminService"
  | "distributionPointPxe"
  | "certificateRegistrationPoint"
  | "reportingServicesPoint"
  | "cloudManagementGatewayConnectionPoint"
  | "serviceConnectionPoint"
  | "clientNotificationServer"
  | "unclassified";

export type SccmDiscoveryBasis = "registry" | "service" | "cim";

export type SccmRotationCategory =
  | "current"
  | "loUnderscore"
  | "numbered"
  | "timestamped"
  | "unknown";

export type SccmCoverageState =
  | "captured"
  | "absent"
  | "accessDenied"
  | "capped"
  | "skipped"
  | "unsupported"
  | "parseFailed";

export type SccmSourceDetailCode =
  | "accessDenied"
  | "byteLimitExceeded"
  | "fileLimitExceeded"
  | "malformedRotation"
  | "readFailed"
  | "unsafePath"
  | "unsupportedPlatform";

export type SccmDiscoveryIssueCode =
  | "unsupportedPlatform"
  | "registryAccessDenied"
  | "cimAccessDenied"
  | "discoveryFailed";

export interface SccmDetectedRole {
  role: SccmRole;
  basis: SccmDiscoveryBasis;
}

export interface SccmSourceStatus {
  role: SccmRole;
  sourceId: string;
  rotation: SccmRotationCategory;
  state: SccmCoverageState;
  retainedBytes: number;
  detailCode?: SccmSourceDetailCode;
}

export interface SccmDiscoveryIssue {
  code: SccmDiscoveryIssueCode;
  role?: SccmRole;
}

export interface SccmEnvironmentDiscovery {
  supported: boolean;
  configmgrVersion: string | null;
  roles: SccmDetectedRole[];
  sources: SccmSourceStatus[];
  issues: SccmDiscoveryIssue[];
  advancedSources: SccmAdvancedSourceOption[];
}

export type SccmAdvancedSourceAvailability =
  | "observed"
  | "operatorDeclaredCandidate"
  | "blocked";

export interface SccmAdvancedSourceOption {
  cardId: string;
  cardVersion: string;
  sourceId: string;
  roleScopes: string[];
  pathClasses: string[];
  sourceVersion: string | null;
  availability: SccmAdvancedSourceAvailability;
  maxBytes: number;
  maxFiles: number;
  rotations: ["current", "lo_"];
}

export interface SccmAdvancedCaptureAuthorizationRequest {
  cardId: string;
  cardVersion: string;
  sourceId: string;
  roleScope: string;
  pathClass: string;
  expectedSourceVersion: string | null;
  selectedRoot: string;
}

export interface SccmAdvancedCaptureCapability {
  capabilityHandle: string;
  cardId: string;
  cardVersion: string;
  sourceId: string;
  roleScope: string;
  pathClass: string;
  sourceVersion: string | null;
}

export interface SccmCaptureResult {
  bundleRoot: string;
  capturedAtUtc: string;
  roles: SccmRole[];
  sources: SccmSourceStatus[];
  artifactCount: number;
  retainedBytes: number;
}
