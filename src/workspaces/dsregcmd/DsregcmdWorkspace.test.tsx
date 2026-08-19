import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DsregcmdSidebar } from "./DsregcmdSidebar";
import { DsregcmdWorkspace } from "./DsregcmdWorkspace";
import { useDsregcmdStore } from "./dsregcmd-store";
import type {
  DsregcmdAnalysisResult,
  DsregcmdFacts,
  DsregcmdPolicyEvidenceValue,
  DsregcmdSourceContext,
  DsregcmdWhfbPolicyEvidence,
} from "./types";
import type { EventLogAnalysis, EventLogEntry } from "../../types/event-log";
import { createTestVirtualizer } from "../../test-utils/virtualizer";

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    openSourceFileDialog: vi.fn(),
    openSourceFolderDialog: vi.fn(),
    pasteDsregcmdSource: vi.fn(),
    captureDsregcmdSource: vi.fn(),
    commandState: { canRefresh: false },
    refreshActiveSource: vi.fn(),
  }),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: Parameters<typeof createTestVirtualizer>[0]) =>
    createTestVirtualizer(options),
}));

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

function nullFacts(): DsregcmdFacts {
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

function eventLogAnalysis(): EventLogAnalysis {
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

function analysisResult(): DsregcmdAnalysisResult {
  return {
    facts: nullFacts(),
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
      winhttpProxy: null,
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

function sourceContext(): DsregcmdSourceContext {
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

function seedReady() {
  useDsregcmdStore
    .getState()
    .setResults("AzureAdJoined : YES", analysisResult(), sourceContext());
}

afterEach(() => {
  cleanup();
  useDsregcmdStore.getState().clear();
});

beforeEach(() => {
  useDsregcmdStore.getState().clear();
});

describe("DsregcmdWorkspace fixtures", () => {
  it("DSREG-003 shows health cards, issues overview, and sidebar findings", () => {
    seedReady();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );

    expect(screen.getAllByText("Join Type").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Current Stage").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Capture Confidence").length).toBeGreaterThan(0);
    expect(screen.getByText("PRT State")).toBeInTheDocument();
    expect(screen.getByText("MDM Signals")).toBeInTheDocument();
    expect(screen.getByText("NGC")).toBeInTheDocument();
    expect(screen.getAllByText("Certificate").length).toBeGreaterThan(0);
    expect(screen.getByText("90 days")).toBeInTheDocument();
    expect(screen.getByText("Issues Overview")).toBeInTheDocument();
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    expect(screen.getByText("Next checks")).toBeInTheDocument();
    expect(screen.getByText("Suggested fixes")).toBeInTheDocument();
    expect(screen.getByText("Top Findings")).toBeInTheDocument();
    expect(screen.getAllByText("PRT may need a refresh").length).toBeGreaterThan(0);
  });

  it("DSREG-004 shows fact groups including Policy Evidence, timeline, and flows", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.getByText("Facts by Group")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Show not reported fields" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Policy Evidence")).toBeInTheDocument();
    expect(screen.getByText("Join State")).toBeInTheDocument();
    expect(screen.getByText("Operating System")).toBeInTheDocument();
    expect(screen.getByText("Proxy Configuration")).toBeInTheDocument();
    expect(screen.getByText("Enrollment Status")).toBeInTheDocument();
    expect(screen.getByText("SCP Configuration")).toBeInTheDocument();
    expect(screen.getByText("Endpoint Connectivity")).toBeInTheDocument();
    expect(screen.getByText("Timeline")).toBeInTheDocument();
    expect(screen.getByText("Flows")).toBeInTheDocument();
  });

  it("DSREG-005 shows the Event Logs surface with channel and severity filters", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    fireEvent.click(screen.getByRole("button", { name: /Event Logs/ }));

    expect(screen.getByText("Channel:")).toBeInTheDocument();
    expect(screen.getByText("Severity:")).toBeInTheDocument();
    expect(screen.getByText("1 of 1 entries")).toBeInTheDocument();
    expect(screen.getAllByText("AAD Operational").length).toBeGreaterThan(0);
    expect(screen.getByText("PRT refresh failed")).toBeInTheDocument();
  });

  it("DSREG-006 shows export controls for JSON, status, summary, and raw input", () => {
    seedReady();
    render(<DsregcmdWorkspace />);

    expect(screen.getByText("Export")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy JSON" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy status text" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy summary" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save JSON..." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save summary..." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show raw input" })).toBeInTheDocument();
  });
});
