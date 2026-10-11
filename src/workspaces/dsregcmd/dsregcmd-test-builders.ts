import type {
  DsregcmdAnalysisResult,
  DsregcmdDerived,
  DsregcmdDiagnosticInsight,
  DsregcmdEnrollmentEntry,
  DsregcmdFacts,
  DsregcmdPolicyEvidenceValue,
  DsregcmdWhfbPolicyEvidence,
} from "./types";

/**
 * Typed test builders. Every field of the shared shapes is spelled out, so a
 * reshape of `DsregcmdDerived`, `DsregcmdFacts` or the diagnostic fails
 * `tsc --noEmit` here instead of being hidden behind a cast.
 */

const unreportedPolicy = (): DsregcmdPolicyEvidenceValue => ({
  displayValue: null,
  currentValue: null,
  providerValue: null,
  source: null,
  note: null,
});

export function buildPolicyEvidence(): DsregcmdWhfbPolicyEvidence {
  return {
    policyEnabled: unreportedPolicy(),
    postLogonEnabled: unreportedPolicy(),
    pinRecoveryEnabled: unreportedPolicy(),
    requireSecurityDevice: unreportedPolicy(),
    useCertificateForOnPremAuth: unreportedPolicy(),
    useCloudTrustForOnPremAuth: unreportedPolicy(),
    artifactPaths: [],
  };
}

export function buildFacts(
  managementDetails: Partial<DsregcmdFacts["managementDetails"]> = {},
): DsregcmdFacts {
  return {
    joinState: {
      azureAdJoined: null,
      domainJoined: null,
      workplaceJoined: null,
      enterpriseJoined: null,
    },
    deviceDetails: {
      deviceId: null,
      thumbprint: null,
      deviceCertificateValidity: null,
      keyContainerId: null,
      keyProvider: null,
      tpmProtected: null,
      deviceAuthStatus: null,
    },
    tenantDetails: { tenantId: null, tenantName: null, domainName: null, idp: null },
    managementDetails: {
      mdmUrl: null,
      mdmComplianceUrl: null,
      mdmTouUrl: null,
      settingsUrl: null,
      deviceManagementSrvVer: null,
      deviceManagementSrvUrl: null,
      deviceManagementSrvId: null,
      ...managementDetails,
    },
    serviceEndpoints: {
      authCodeUrl: null,
      accessTokenUrl: null,
      joinSrvVersion: null,
      joinSrvUrl: null,
      joinSrvId: null,
      keySrvVersion: null,
      keySrvUrl: null,
      keySrvId: null,
      webAuthnSrvVersion: null,
      webAuthnSrvUrl: null,
      webAuthnSrvId: null,
    },
    userState: {
      ngcSet: null,
      ngcKeyId: null,
      canReset: null,
      wamDefaultSet: null,
      wamDefaultAuthority: null,
      wamDefaultId: null,
      wamDefaultGuid: null,
      isDeviceJoined: null,
      isUserAzureAd: null,
      policyEnabled: null,
      postLogonEnabled: null,
      deviceEligible: null,
      sessionIsNotRemote: null,
    },
    ssoState: {
      azureAdPrt: null,
      azureAdPrtAuthority: null,
      azureAdPrtUpdateTime: null,
      acquirePrtDiagnostics: null,
      enterprisePrt: null,
      enterprisePrtUpdateTime: null,
      enterprisePrtExpiryTime: null,
      enterprisePrtAuthority: null,
      onPremTgt: null,
      cloudTgt: null,
      adfsRefreshToken: null,
      adfsRaIsReady: null,
      kerbTopLevelNames: null,
    },
    diagnostics: {
      previousPrtAttempt: null,
      attemptStatus: null,
      userIdentity: null,
      credentialType: null,
      correlationId: null,
      endpointUri: null,
      httpMethod: null,
      httpError: null,
      httpStatus: null,
      requestId: null,
      diagnosticsReference: null,
      userContext: null,
      clientTime: null,
    },
    preJoinTests: {
      adConnectivityTest: null,
      adConfigurationTest: null,
      drsDiscoveryTest: null,
      drsConnectivityTest: null,
      tokenAcquisitionTest: null,
      fallbackToSyncJoin: null,
    },
    registration: {
      previousRegistration: null,
      errorPhase: null,
      certEnrollment: null,
      logonCertTemplateReady: null,
      preReqResult: null,
      clientErrorCode: null,
      serverErrorCode: null,
      serverMessage: null,
      serverErrorDescription: null,
    },
    postJoinDiagnostics: { aadRecoveryEnabled: null, keySignTest: null },
  };
}

/** Every value unreported: the MDM fields default to "could not be determined". */
export function buildDerived(overrides: Partial<DsregcmdDerived> = {}): DsregcmdDerived {
  return {
    joinType: "Unknown",
    joinTypeLabel: "Unknown",
    dominantPhase: "unknown",
    phaseSummary: "",
    captureConfidence: "low",
    captureConfidenceReason: "",
    mdmEnrolled: null,
    mdmUrlsPresent: null,
    missingMdm: null,
    complianceUrlPresent: null,
    missingComplianceUrl: null,
    azureAdPrtPresent: null,
    stalePrt: null,
    prtLastUpdate: null,
    prtReferenceTime: null,
    prtAgeHours: null,
    tpmProtected: null,
    certificateValidFrom: null,
    certificateValidTo: null,
    certificateExpiringSoon: null,
    certificateDaysRemaining: null,
    networkErrorCode: null,
    hasNetworkError: false,
    remoteSessionSystem: false,
    ...overrides,
  };
}

export function buildDiagnostic(
  overrides: Partial<DsregcmdDiagnosticInsight> & Pick<DsregcmdDiagnosticInsight, "id">,
): DsregcmdDiagnosticInsight {
  return {
    severity: "Info",
    category: "test",
    title: `Title of ${overrides.id}`,
    summary: "",
    evidence: [],
    nextChecks: [],
    suggestedFixes: [],
    relatedErrorCodes: [],
    ...overrides,
  };
}

export function buildEnrollmentEntry(
  overrides: Partial<DsregcmdEnrollmentEntry> = {},
): DsregcmdEnrollmentEntry {
  return { guid: null, upn: null, providerId: null, enrollmentState: null, ...overrides };
}

export function buildAnalysisResult(
  overrides: Partial<DsregcmdAnalysisResult> = {},
): DsregcmdAnalysisResult {
  return {
    facts: buildFacts(),
    derived: buildDerived(),
    diagnostics: [],
    policyEvidence: buildPolicyEvidence(),
    osVersion: null,
    proxyEvidence: null,
    enrollmentEvidence: null,
    activeEvidence: null,
    scheduledTaskEvidence: null,
    eventLogAnalysis: null,
    ...overrides,
  };
}
