/**
 * Focused builder functions for each FactGroup produced by getFactGroups.
 * Extracted from dsregcmd-formatters.ts to keep that module under 1,000 lines.
 */

import type {
  DsregcmdAnalysisResult,
  DsregcmdSourceContext,
} from "./types";
import {
  type DisplayConfidenceAssessment,
  type DisplayPhaseAssessment,
  type FactGroup,
  type FactRow,
  formatBool,
  formatCertificateValidityRange,
  formatConfidenceLabel,
  formatDateTimeValue,
  formatHourDuration,
  formatPolicyEvidenceValue,
  formatRegistryArtifacts,
  formatValue,
  getMdmVisibilityLabel,
  getPolicyDisplayValue,
  getPolicyEvidenceSummary,
  getPolicyValueTone,
  toneForBool,
  toneForCaptureConfidence,
  toneForDomainJoined,
  toneForEnterpriseJoined,
  toneForEnterprisePrt,
  toneForMdmVisibility,
  toneForNgcReadiness,
  toneForWorkplaceJoined,
  withNotReportedMetadata,
} from "./dsregcmd-formatters";

// ---------------------------------------------------------------------------
// NGC rows (returned as FactRow[] because the caller wraps them in a group)
// ---------------------------------------------------------------------------

export function buildNgcRows(
  result: DsregcmdAnalysisResult,
): FactRow[] {
  const { facts } = result;
  const policyEnabledDisplay = getPolicyDisplayValue(
    facts.userState.policyEnabled,
    result.policyEvidence.policyEnabled,
  );
  const postLogonEnabledDisplay = getPolicyDisplayValue(
    facts.userState.postLogonEnabled,
    result.policyEvidence.postLogonEnabled,
  );

  const ngcRows = withNotReportedMetadata([
    {
      label: "NGC Set",
      value: formatBool(facts.userState.ngcSet),
      tone: facts.userState.ngcSet ? "good" : "neutral",
    },
    {
      label: "Device Joined for NGC",
      value: formatBool(facts.userState.isDeviceJoined),
      tone: facts.userState.isDeviceJoined ? "good" : "neutral",
    },
    {
      label: "User Azure AD",
      value: formatBool(facts.userState.isUserAzureAd),
      tone: facts.userState.isUserAzureAd ? "good" : "neutral",
    },
    {
      label: "Policy Enabled",
      value: policyEnabledDisplay,
      tone: getPolicyValueTone(
        facts.userState.policyEnabled,
        result.policyEvidence.policyEnabled,
      ),
    },
    {
      label: "Post-Logon Enabled",
      value: postLogonEnabledDisplay,
      tone: getPolicyValueTone(
        facts.userState.postLogonEnabled,
        result.policyEvidence.postLogonEnabled,
      ),
    },
    {
      label: "Device Eligible",
      value: formatBool(facts.userState.deviceEligible),
      tone: facts.userState.deviceEligible ? "good" : "neutral",
    },
    {
      label: "Session Is Not Remote",
      value: formatBool(facts.userState.sessionIsNotRemote),
      tone: facts.userState.sessionIsNotRemote ? "good" : "neutral",
    },
    {
      label: "PreReq Result",
      value: formatValue(facts.registration.preReqResult),
      tone: toneForNgcReadiness(result),
    },
  ]);

  if (
    facts.registration.certEnrollment &&
    facts.registration.certEnrollment.toLowerCase() !== "none"
  ) {
    ngcRows.push({
      label: "Cert Enrollment",
      value: formatValue(facts.registration.certEnrollment),
      tone: "neutral",
    });
  }

  if (facts.ssoState.adfsRefreshToken != null) {
    ngcRows.push({
      label: "ADFS Refresh Token",
      value: formatBool(facts.ssoState.adfsRefreshToken),
      tone: facts.ssoState.adfsRefreshToken ? "good" : "neutral",
    });
  }

  if (facts.ssoState.adfsRaIsReady != null) {
    ngcRows.push({
      label: "ADFS RA Ready",
      value: formatBool(facts.ssoState.adfsRaIsReady),
      tone: facts.ssoState.adfsRaIsReady ? "good" : "neutral",
    });
  }

  if (facts.registration.logonCertTemplateReady) {
    ngcRows.push({
      label: "Logon Cert Template",
      value: formatValue(facts.registration.logonCertTemplateReady),
      tone: facts.registration.logonCertTemplateReady.includes("StateReady")
        ? "good"
        : "neutral",
    });
  }

  if (facts.postJoinDiagnostics.keySignTest != null) {
    ngcRows.push({
      label: "Key Sign Test",
      value: formatValue(facts.postJoinDiagnostics.keySignTest),
      tone: facts.postJoinDiagnostics.keySignTest.toLowerCase().includes("pass")
        ? "good"
        : "warn",
    });
  }

  if (facts.postJoinDiagnostics.aadRecoveryEnabled != null) {
    ngcRows.push({
      label: "AAD Recovery Enabled",
      value: formatBool(facts.postJoinDiagnostics.aadRecoveryEnabled),
      tone: facts.postJoinDiagnostics.aadRecoveryEnabled ? "warn" : "good",
    });
  }

  return ngcRows;
}

// ---------------------------------------------------------------------------
// Phase & Confidence evidence
// ---------------------------------------------------------------------------

export function buildPhaseEvidenceGroup(
  result: DsregcmdAnalysisResult,
  displayPhase: DisplayPhaseAssessment,
  displayConfidence: DisplayConfidenceAssessment,
): FactGroup {
  const { facts } = result;
  return {
    id: "phase-evidence",
    title: "Phase and Confidence",
    caption:
      "Derived stage and evidence used to explain where the current problem appears to sit.",
    rows: withNotReportedMetadata([
      {
        label: "Dominant Phase",
        value: displayPhase.label,
        tone: displayPhase.tone,
      },
      {
        label: "Phase Summary",
        value: displayPhase.summary,
        tone: "neutral",
      },
      {
        label: "Capture Confidence",
        value: formatConfidenceLabel(displayConfidence.confidence),
        tone: toneForCaptureConfidence(displayConfidence.confidence),
      },
      {
        label: "Confidence Reason",
        value: displayConfidence.reason,
        tone: "neutral",
      },
      {
        label: "Error Phase",
        value: formatValue(facts.registration.errorPhase),
      },
      {
        label: "Client Error",
        value: formatValue(facts.registration.clientErrorCode),
      },
      {
        label: "DRS Discovery",
        value: formatValue(facts.preJoinTests.drsDiscoveryTest),
      },
      {
        label: "Token Acquisition",
        value: formatValue(facts.preJoinTests.tokenAcquisitionTest),
      },
      {
        label: "Attempt Status",
        value: formatValue(facts.diagnostics.attemptStatus),
      },
      {
        label: "HTTP Status",
        value: formatValue(facts.diagnostics.httpStatus),
      },
      {
        label: "Endpoint URI",
        value: formatValue(facts.diagnostics.endpointUri),
      },
      {
        label: "User Context",
        value: formatValue(facts.diagnostics.userContext),
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Join State
// ---------------------------------------------------------------------------

export function buildJoinStateGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  const { facts, derived } = result;
  return {
    id: "join-state",
    title: "Join State",
    caption: "Identity, join posture, and major derived signals.",
    rows: withNotReportedMetadata([
      {
        label: "Join Type",
        value: formatValue(derived.joinTypeLabel),
        tone: "good",
      },
      {
        label: "Azure AD Joined",
        value: formatBool(facts.joinState.azureAdJoined),
        tone: toneForBool(facts.joinState.azureAdJoined),
      },
      {
        label: "Domain Joined",
        value: formatBool(facts.joinState.domainJoined),
        tone: toneForDomainJoined(facts.joinState.domainJoined),
      },
      {
        label: "Workplace Joined",
        value: formatBool(facts.joinState.workplaceJoined),
        tone: toneForWorkplaceJoined(facts.joinState.workplaceJoined),
      },
      {
        label: "Enterprise Joined",
        value: formatBool(facts.joinState.enterpriseJoined),
        tone: toneForEnterpriseJoined(facts.joinState.enterpriseJoined),
      },
      {
        label: "Device Auth Status",
        value: formatValue(facts.deviceDetails.deviceAuthStatus),
        tone:
          facts.deviceDetails.deviceAuthStatus?.toUpperCase() === "SUCCESS"
            ? "good"
            : facts.deviceDetails.deviceAuthStatus
              ? "bad"
              : "neutral",
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Tenant and Device
// ---------------------------------------------------------------------------

export function buildTenantDeviceGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  const { facts, derived } = result;
  return {
    id: "tenant-device",
    title: "Tenant and Device",
    caption: "Core identifiers and certificate-related device details.",
    rows: withNotReportedMetadata([
      {
        label: "Tenant Id",
        value: formatValue(facts.tenantDetails.tenantId),
      },
      {
        label: "Tenant Name",
        value: formatValue(facts.tenantDetails.tenantName),
      },
      {
        label: "Domain Name",
        value: formatValue(facts.tenantDetails.domainName),
      },
      {
        label: "Device Id",
        value: formatValue(facts.deviceDetails.deviceId),
      },
      {
        label: "Thumbprint",
        value: formatValue(facts.deviceDetails.thumbprint),
      },
      {
        label: "TPM Protected",
        value: formatBool(facts.deviceDetails.tpmProtected),
        tone: toneForBool(facts.deviceDetails.tpmProtected),
      },
      {
        label: "Certificate Validity",
        value: formatCertificateValidityRange(
          facts.deviceDetails.deviceCertificateValidity,
          derived.certificateValidFrom,
          derived.certificateValidTo,
        ),
        tone: derived.certificateExpiringSoon ? "warn" : "neutral",
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Management and MDM
// ---------------------------------------------------------------------------

export function buildManagementGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  const { facts, derived } = result;
  return {
    id: "management",
    title: "Management and MDM",
    caption:
      "Management visibility and tenant-advertised endpoints. Missing values can be out of scope, unconfigured, or simply absent from this capture.",
    rows: withNotReportedMetadata([
      {
        label: "MDM Visibility",
        value: getMdmVisibilityLabel(derived),
        tone: toneForMdmVisibility(derived),
      },
      {
        label: "MDM URL",
        value: formatValue(facts.managementDetails.mdmUrl),
        tone: derived.missingMdm ? "neutral" : "neutral",
      },
      {
        label: "Compliance URL",
        value: formatValue(facts.managementDetails.mdmComplianceUrl),
        tone: derived.missingComplianceUrl ? "neutral" : "neutral",
      },
      {
        label: "Settings URL",
        value: formatValue(facts.managementDetails.settingsUrl),
      },
      {
        label: "DM Service URL",
        value: formatValue(facts.managementDetails.deviceManagementSrvUrl),
      },
      {
        label: "DM Service ID",
        value: formatValue(facts.managementDetails.deviceManagementSrvId),
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// SSO and PRT
// ---------------------------------------------------------------------------

export function buildSsoGroup(
  result: DsregcmdAnalysisResult,
  displayedPrtAgeHours: number | null,
): FactGroup {
  const { facts, derived } = result;
  return {
    id: "sso-prt",
    title: "SSO and PRT",
    caption: "Token presence, freshness, and user session indicators.",
    rows: withNotReportedMetadata([
      {
        label: "Azure AD PRT",
        value: formatBool(facts.ssoState.azureAdPrt),
        tone: toneForBool(facts.ssoState.azureAdPrt),
      },
      {
        label: "PRT Update Time",
        value: formatDateTimeValue(facts.ssoState.azureAdPrtUpdateTime),
        tone: derived.stalePrt ? "warn" : "neutral",
      },
      {
        label: "PRT Age Hours",
        value: formatHourDuration(displayedPrtAgeHours),
        tone: derived.stalePrt ? "warn" : "neutral",
      },
      {
        label: "Enterprise PRT",
        value: formatBool(facts.ssoState.enterprisePrt),
        tone: toneForEnterprisePrt(facts.ssoState.enterprisePrt),
      },
      {
        label: "WAM Default Set",
        value: formatBool(facts.userState.wamDefaultSet),
        tone: toneForBool(facts.userState.wamDefaultSet),
      },
      {
        label: "User Context",
        value: formatValue(facts.diagnostics.userContext),
        tone: derived.remoteSessionSystem ? "warn" : "neutral",
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Diagnostics and Errors
// ---------------------------------------------------------------------------

export function buildDiagnosticsGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  const { facts } = result;
  return {
    id: "diagnostics",
    title: "Diagnostics and Errors",
    caption: "Correlation, transport, and registration error fields.",
    rows: withNotReportedMetadata([
      {
        label: "Attempt Status",
        value: formatValue(facts.diagnostics.attemptStatus),
      },
      {
        label: "HTTP Error",
        value: formatValue(facts.diagnostics.httpError),
      },
      {
        label: "HTTP Status",
        value: formatValue(facts.diagnostics.httpStatus),
      },
      {
        label: "Endpoint URI",
        value: formatValue(facts.diagnostics.endpointUri),
      },
      {
        label: "Correlation ID",
        value: formatValue(facts.diagnostics.correlationId),
      },
      {
        label: "Request ID",
        value: formatValue(facts.diagnostics.requestId),
      },
      {
        label: "Client Error",
        value: formatValue(facts.registration.clientErrorCode),
      },
      {
        label: "Server Error",
        value: formatValue(facts.registration.serverErrorCode),
      },
      {
        label: "Server Message",
        value: formatValue(facts.registration.serverMessage),
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Pre-Join and Registration
// ---------------------------------------------------------------------------

export function buildPreJoinGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  const { facts } = result;
  return {
    id: "prejoin-registration",
    title: "Pre-Join and Registration",
    caption: "Hybrid join readiness and registration workflow checks.",
    rows: withNotReportedMetadata([
      {
        label: "AD Connectivity",
        value: formatValue(facts.preJoinTests.adConnectivityTest),
      },
      {
        label: "AD Configuration",
        value: formatValue(facts.preJoinTests.adConfigurationTest),
      },
      {
        label: "DRS Discovery",
        value: formatValue(facts.preJoinTests.drsDiscoveryTest),
      },
      {
        label: "DRS Connectivity",
        value: formatValue(facts.preJoinTests.drsConnectivityTest),
      },
      {
        label: "Token Acquisition",
        value: formatValue(facts.preJoinTests.tokenAcquisitionTest),
      },
      {
        label: "Fallback to Sync-Join",
        value: formatValue(facts.preJoinTests.fallbackToSyncJoin),
      },
      {
        label: "Error Phase",
        value: formatValue(facts.registration.errorPhase),
      },
      {
        label: "Logon Cert Template",
        value: formatValue(facts.registration.logonCertTemplateReady),
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Policy Evidence
// ---------------------------------------------------------------------------

export function buildPolicyEvidenceGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  return {
    id: "policy-evidence",
    title: "Policy Evidence",
    caption:
      "Registry-backed WHfB policy state used only when dsregcmd leaves policy fields unreported.",
    rows: withNotReportedMetadata([
      {
        label: "Policy Enabled Evidence",
        value: formatPolicyEvidenceValue(result.policyEvidence.policyEnabled),
        tone: toneForBool(result.policyEvidence.policyEnabled.displayValue),
      },
      {
        label: "Post-Logon Evidence",
        value: formatPolicyEvidenceValue(
          result.policyEvidence.postLogonEnabled,
        ),
        tone: toneForBool(
          result.policyEvidence.postLogonEnabled.displayValue,
        ),
      },
      {
        label: "PIN Recovery Policy",
        value: formatPolicyEvidenceValue(
          result.policyEvidence.pinRecoveryEnabled,
        ),
        tone: toneForBool(
          result.policyEvidence.pinRecoveryEnabled.displayValue,
        ),
      },
      {
        label: "Require Security Device",
        value: formatPolicyEvidenceValue(
          result.policyEvidence.requireSecurityDevice,
        ),
        tone: toneForBool(
          result.policyEvidence.requireSecurityDevice.displayValue,
        ),
      },
      {
        label: "Use Certificate Trust",
        value: formatPolicyEvidenceValue(
          result.policyEvidence.useCertificateForOnPremAuth,
        ),
        tone: toneForBool(
          result.policyEvidence.useCertificateForOnPremAuth.displayValue,
        ),
      },
      {
        label: "Use Cloud Trust",
        value: formatPolicyEvidenceValue(
          result.policyEvidence.useCloudTrustForOnPremAuth,
        ),
        tone: toneForBool(
          result.policyEvidence.useCloudTrustForOnPremAuth.displayValue,
        ),
      },
      {
        label: "Evidence Status",
        value: getPolicyEvidenceSummary(result),
      },
      {
        label: "Registry Artifacts",
        value: formatRegistryArtifacts(result.policyEvidence.artifactPaths),
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// Service Endpoints
// ---------------------------------------------------------------------------

export function buildServiceEndpointsGroup(
  result: DsregcmdAnalysisResult,
): FactGroup {
  const { facts } = result;
  return {
    id: "service-endpoints",
    title: "Service Endpoints",
    caption: "Relevant identity and registration service URLs.",
    rows: withNotReportedMetadata([
      {
        label: "Join Server URL",
        value: formatValue(facts.serviceEndpoints.joinSrvUrl),
      },
      {
        label: "Join Server ID",
        value: formatValue(facts.serviceEndpoints.joinSrvId),
      },
      {
        label: "Key Server URL",
        value: formatValue(facts.serviceEndpoints.keySrvUrl),
      },
      {
        label: "Auth Code URL",
        value: formatValue(facts.serviceEndpoints.authCodeUrl),
      },
      {
        label: "Access Token URL",
        value: formatValue(facts.serviceEndpoints.accessTokenUrl),
      },
      {
        label: "WebAuthn Service URL",
        value: formatValue(facts.serviceEndpoints.webAuthnSrvUrl),
      },
    ]),
  };
}

// ---------------------------------------------------------------------------
// OS Version (conditional)
// ---------------------------------------------------------------------------

export function buildOsVersionGroup(
  result: DsregcmdAnalysisResult,
): FactGroup[] {
  if (!result.osVersion) {
    return [];
  }
  return [
    {
      id: "os-version",
      title: "Operating System",
      caption: "OS version details from the registry evidence.",
      rows: withNotReportedMetadata([
        {
          label: "Product Name",
          value: formatValue(result.osVersion.productName),
        },
        {
          label: "Display Version",
          value: formatValue(result.osVersion.displayVersion),
        },
        {
          label: "Current Build",
          value: formatValue(result.osVersion.currentBuild),
        },
        {
          label: "UBR",
          value:
            result.osVersion.ubr != null
              ? String(result.osVersion.ubr)
              : "Not reported",
        },
        {
          label: "Edition",
          value: formatValue(result.osVersion.editionId),
        },
      ]),
    },
  ];
}

// ---------------------------------------------------------------------------
// Proxy Configuration (conditional)
// ---------------------------------------------------------------------------

export function buildProxyConfigGroup(
  result: DsregcmdAnalysisResult,
): FactGroup[] {
  if (!result.proxyEvidence) {
    return [];
  }
  return [
    {
      id: "proxy-config",
      title: "Proxy Configuration",
      caption: "Proxy settings that may affect connectivity to Entra ID endpoints.",
      rows: withNotReportedMetadata([
        {
          label: "Proxy Enabled",
          value: formatBool(result.proxyEvidence.proxyEnabled ?? null),
          tone: result.proxyEvidence.proxyEnabled === true
            ? ("warn" as const)
            : ("neutral" as const),
        },
        {
          label: "Proxy Server",
          value: formatValue(result.proxyEvidence.proxyServer),
        },
        {
          label: "Proxy Override",
          value: formatValue(result.proxyEvidence.proxyOverride),
        },
        {
          label: "Auto Config URL",
          value: formatValue(result.proxyEvidence.autoConfigUrl),
        },
        {
          label: "WPAD Detected",
          value: result.proxyEvidence.wpadDetected ? "Yes" : "No",
          tone: result.proxyEvidence.wpadDetected
            ? ("warn" as const)
            : ("neutral" as const),
        },
        {
          label: "WinHTTP Proxy",
          value: formatValue(result.proxyEvidence.winhttpProxy),
        },
      ]),
    },
  ];
}

// ---------------------------------------------------------------------------
// Enrollment Status (conditional)
// ---------------------------------------------------------------------------

export function buildEnrollmentStatusGroup(
  result: DsregcmdAnalysisResult,
): FactGroup[] {
  if (!result.enrollmentEvidence) {
    return [];
  }
  const { facts } = result;
  return [
    {
      id: "enrollment-status",
      title: "Enrollment Status",
      caption: "MDM enrollment entries found in the registry.",
      rows: withNotReportedMetadata([
        {
          label: "Enrollment Count",
          value: String(result.enrollmentEvidence.enrollmentCount),
          tone:
            result.enrollmentEvidence.enrollmentCount === 0 &&
            facts.joinState.azureAdJoined === true
              ? ("warn" as const)
              : result.enrollmentEvidence.enrollmentCount > 1
                ? ("warn" as const)
                : ("good" as const),
        },
        ...(() => {
          const taskGuidSet = new Set(
            (result.scheduledTaskEvidence?.enterpriseMgmtGuids ?? []).map(
              (g) => g.toLowerCase(),
            ),
          );
          return result.enrollmentEvidence!.enrollments.map((e, i) => {
            const guidLower = e.guid?.toLowerCase();
            const hasTaskMatch =
              guidLower != null && taskGuidSet.has(guidLower);
            return {
              label: `Enrollment ${i + 1}`,
              value: [
                e.guid ?? "(no GUID)",
                e.upn ?? "(no UPN)",
                e.providerId ?? "(no provider)",
                e.enrollmentState != null
                  ? `state=${e.enrollmentState}`
                  : "",
                hasTaskMatch ? "task-matched" : "",
              ]
                .filter(Boolean)
                .join(" — "),
              tone:
                e.enrollmentState === 1 && hasTaskMatch
                  ? ("good" as const)
                  : undefined,
            };
          });
        })(),
      ]),
    },
  ];
}

// ---------------------------------------------------------------------------
// Enterprise Management Tasks (conditional)
// ---------------------------------------------------------------------------

export function buildEnterpriseMgmtTasksGroup(
  result: DsregcmdAnalysisResult,
): FactGroup[] {
  if (!result.scheduledTaskEvidence?.enterpriseMgmtGuids?.length) {
    return [];
  }
  const enrollments = result.enrollmentEvidence?.enrollments ?? [];
  const enrollmentByGuid = new Map<
    string,
    (typeof enrollments)[number]
  >();
  for (const enrollment of enrollments) {
    const key = enrollment.guid?.toLowerCase();
    if (key && !enrollmentByGuid.has(key)) {
      enrollmentByGuid.set(key, enrollment);
    }
  }
  return [
    {
      id: "enterprise-mgmt-tasks",
      title: "Enterprise Management Tasks",
      caption:
        "Scheduled task GUIDs under \\Microsoft\\Windows\\EnterpriseMgmt, cross-referenced with enrollment registry entries.",
      rows: withNotReportedMetadata([
        {
          label: "Task GUID Count",
          value: String(
            result.scheduledTaskEvidence.enterpriseMgmtGuids.length,
          ),
        },
        ...result.scheduledTaskEvidence.enterpriseMgmtGuids.map(
          (guid) => {
            const matchingEnrollment = enrollmentByGuid.get(
              guid.toLowerCase(),
            );
            const enrolled =
              matchingEnrollment?.enrollmentState === 1;
            return {
              label: guid,
              value: matchingEnrollment
                ? `Registry match — ${matchingEnrollment.upn ?? "(no UPN)"} — state=${matchingEnrollment.enrollmentState}`
                : "No matching enrollment registry entry",
              tone: enrolled
                ? ("good" as const)
                : ("neutral" as const),
            };
          },
        ),
      ]),
    },
  ];
}

// ---------------------------------------------------------------------------
// Endpoint Connectivity (conditional)
// ---------------------------------------------------------------------------

export function buildEndpointConnectivityGroup(
  result: DsregcmdAnalysisResult,
): FactGroup[] {
  if (!result.activeEvidence?.connectivityTests?.length) {
    return [];
  }
  return [
    {
      id: "endpoint-connectivity",
      title: "Endpoint Connectivity",
      caption: "Live reachability tests to required Microsoft Entra endpoints.",
      rows: result.activeEvidence.connectivityTests.map((test) => ({
        label: new URL(test.endpoint).hostname,
        value: test.reachable
          ? `Reachable${test.statusCode ? ` (${test.statusCode})` : ""}${test.latencyMs != null ? ` — ${test.latencyMs}ms` : ""}`
          : `Unreachable${test.errorMessage ? ` — ${test.errorMessage}` : ""}`,
        tone: test.reachable
          ? test.latencyMs != null && test.latencyMs > 2000
            ? ("warn" as const)
            : ("good" as const)
          : ("bad" as const),
      })),
    },
  ];
}

// ---------------------------------------------------------------------------
// SCP Configuration (conditional)
// ---------------------------------------------------------------------------

export function buildScpConfigGroup(
  result: DsregcmdAnalysisResult,
): FactGroup[] {
  if (!result.activeEvidence?.scpQuery) {
    return [];
  }
  const { facts } = result;
  return [
    {
      id: "scp-config",
      title: "SCP Configuration",
      caption: "Service Connection Point query results from Active Directory.",
      rows: withNotReportedMetadata([
        {
          label: "SCP Found",
          value: result.activeEvidence.scpQuery.scpFound ? "Yes" : "No",
          tone: result.activeEvidence.scpQuery.scpFound
            ? ("good" as const)
            : facts.joinState.domainJoined === true
              ? ("bad" as const)
              : ("neutral" as const),
        },
        {
          label: "Tenant Domain",
          value: formatValue(result.activeEvidence.scpQuery.tenantDomain),
        },
        {
          label: "Azure AD ID",
          value: formatValue(result.activeEvidence.scpQuery.azureadId),
        },
        {
          label: "Domain Controller",
          value: formatValue(result.activeEvidence.scpQuery.domainController),
        },
        ...(result.activeEvidence.scpQuery.error
          ? [
              {
                label: "Error",
                value: result.activeEvidence.scpQuery.error,
                tone: "warn" as const,
              },
            ]
          : []),
      ]),
    },
  ];
}

// ---------------------------------------------------------------------------
// Source Details
// ---------------------------------------------------------------------------

export function buildSourceDetailsGroup(
  sourceContext: DsregcmdSourceContext,
): FactGroup {
  return {
    id: "source-details",
    title: "Source Details",
    caption:
      "Where this dsregcmd analysis came from and how much text was processed.",
    rows: withNotReportedMetadata([
      { label: "Source", value: sourceContext.displayLabel },
      {
        label: "Resolved Path",
        value: formatValue(sourceContext.resolvedPath),
      },
      {
        label: "Evidence File",
        value: formatValue(sourceContext.evidenceFilePath),
      },
      { label: "Lines", value: String(sourceContext.rawLineCount) },
      { label: "Characters", value: String(sourceContext.rawCharCount) },
    ]),
  };
}
