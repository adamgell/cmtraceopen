import type {
  DsregcmdAnalysisResult,
  DsregcmdFacts,
  DsregcmdPolicyEvidenceValue,
  DsregcmdSourceContext,
  DsregcmdWhfbPolicyEvidence,
} from "./types";
import type { EventLogAnalysis, EventLogEntry } from "../../types/event-log";

/** Synthetic dsregcmd fixtures shared by the workspace and sidebar tests. */

function policyValue(
  overrides: Partial<DsregcmdPolicyEvidenceValue> = {},
): DsregcmdPolicyEvidenceValue {
  return {
    displayValue: true,
    currentValue: true,
    providerValue: true,
    source: "windows_policy_machine",
    note: null,
    ...overrides,
  };
}

function fixtureFacts(): DsregcmdFacts {
  return {
    joinState: {
      azureAdJoined: true,
      domainJoined: true,
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
      deviceAuthStatus: "SUCCESS",
    },
    tenantDetails: {
      tenantId: null,
      tenantName: null,
      domainName: null,
      idp: null,
    },
    managementDetails: {
      mdmUrl: null,
      mdmComplianceUrl: null,
      mdmTouUrl: null,
      settingsUrl: null,
      deviceManagementSrvVer: null,
      deviceManagementSrvUrl: null,
      deviceManagementSrvId: null,
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
      ngcSet: true,
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
      azureAdPrt: true,
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
    postJoinDiagnostics: {
      aadRecoveryEnabled: null,
      keySignTest: null,
    },
  };
}

function policyEvidence(): DsregcmdWhfbPolicyEvidence {
  return {
    policyEnabled: policyValue(),
    postLogonEnabled: policyValue(),
    pinRecoveryEnabled: policyValue({ displayValue: false }),
    requireSecurityDevice: policyValue(),
    useCertificateForOnPremAuth: policyValue({ displayValue: false }),
    useCloudTrustForOnPremAuth: policyValue(),
    artifactPaths: ["HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork"],
  };
}

export function eventLogAnalysis(): EventLogAnalysis {
  const entry: EventLogEntry = {
    id: 1,
    channel: "AadOperational",
    channelDisplay: "AAD Operational",
    provider: "Microsoft-Windows-AAD",
    eventId: 1098,
    severity: "Error",
    timestamp: "2026-01-15T12:00:00.000Z",
    computer: "PC01",
    message: "PRT refresh failed",
    correlationActivityId: null,
    sourceFile: "AAD.evtx",
  };
  return {
    sourceKind: "Bundle",
    entries: [entry],
    channelSummaries: [
      {
        channel: "AadOperational",
        channelDisplay: "AAD Operational",
        entryCount: 1,
        errorCount: 1,
        warningCount: 0,
        timestampBounds: null,
        sourceFile: "AAD.evtx",
      },
    ],
    correlationLinks: [],
    parsedFileCount: 1,
    totalEntryCount: 1,
    errorEntryCount: 1,
    warningEntryCount: 0,
    timestampBounds: null,
    liveQuery: {
      attemptedChannelCount: 2,
      successfulChannelCount: 1,
      channelsWithResultsCount: 1,
      failedChannelCount: 1,
      perChannelEntryLimit: 500,
      channels: [],
    },
  };
}

export function analysisResult(): DsregcmdAnalysisResult {
  return {
    facts: fixtureFacts(),
    derived: {
      joinType: "HybridEntraIdJoined",
      joinTypeLabel: "Hybrid Entra ID joined",
      dominantPhase: "auth",
      phaseSummary: "Authentication is the current problem phase.",
      captureConfidence: "high",
      captureConfidenceReason: "Live capture includes dsregcmd and registry evidence.",
      mdmEnrolled: true,
      missingMdm: false,
      complianceUrlPresent: true,
      missingComplianceUrl: false,
      azureAdPrtPresent: true,
      stalePrt: false,
      prtLastUpdate: null,
      prtReferenceTime: null,
      prtAgeHours: 1,
      tpmProtected: null,
      certificateValidFrom: null,
      certificateValidTo: null,
      certificateExpiringSoon: false,
      certificateDaysRemaining: 90,
      networkErrorCode: null,
      hasNetworkError: false,
      remoteSessionSystem: false,
    },
    diagnostics: [
      {
        id: "prt-stale",
        severity: "Warning",
        category: "SSO",
        title: "PRT may need a refresh",
        summary: "Primary Refresh Token age is approaching the stale threshold.",
        evidence: ["azureAdPrt=YES"],
        nextChecks: ["dsregcmd /status"],
        suggestedFixes: ["Sign out and sign in again"],
      },
    ],
    policyEvidence: policyEvidence(),
    osVersion: {
      currentBuild: "26100",
      displayVersion: "24H2",
      productName: "Windows 11",
      ubr: 1,
      editionId: "Enterprise",
    },
    proxyEvidence: {
      proxyEnabled: false,
      proxyServer: null,
      proxyOverride: null,
      autoConfigUrl: null,
      wpadDetected: false,
    },
    enrollmentEvidence: {
      enrollmentCount: 1,
      enrollments: [
        {
          guid: "11111111-1111-1111-1111-111111111111",
          upn: "user@contoso.com",
          providerId: "MS DM Server",
          enrollmentState: 1,
        },
      ],
    },
    activeEvidence: {
      connectivityTests: [
        {
          endpoint: "https://login.microsoftonline.com",
          reachable: true,
          statusCode: 200,
          latencyMs: 40,
          errorMessage: null,
          timestamp: "2026-01-15T12:00:00.000Z",
        },
      ],
      scpQuery: {
        scpFound: true,
        tenantDomain: "contoso.com",
        azureadId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        keywords: ["aADDomainName"],
        domainController: "dc01.contoso.com",
        error: null,
      },
    },
    scheduledTaskEvidence: { enterpriseMgmtGuids: [] },
    eventLogAnalysis: eventLogAnalysis(),
  };
}

export function sourceContext(): DsregcmdSourceContext {
  return {
    source: { kind: "file", path: "C:\\temp\\dsregcmd.txt" },
    requestedPath: "C:\\temp\\dsregcmd.txt",
    resolvedPath: "C:\\temp\\dsregcmd.txt",
    bundlePath: null,
    displayLabel: "dsregcmd.txt",
    evidenceFilePath: "C:\\temp\\dsregcmd.txt",
    rawLineCount: 40,
    rawCharCount: 800,
  };
}
