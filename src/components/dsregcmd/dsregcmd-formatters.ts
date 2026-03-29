import {
  formatDisplayDateTime,
  parseDisplayDateTime,
} from "../../lib/date-time-format";
import type {
  DsregcmdAnalysisResult,
  DsregcmdEvidenceSource,
  DsregcmdFacts,
  DsregcmdPolicyEvidenceValue,
  DsregcmdSeverity,
  DsregcmdSourceContext,
} from "../../types/dsregcmd";
import { tokens } from "@fluentui/react-components";

export interface FactRow {
  label: string;
  value: string;
  tone?: "neutral" | "good" | "warn" | "bad";
  isNotReported?: boolean;
}

export interface FactGroup {
  id: string;
  title: string;
  caption: string;
  rows: FactRow[];
}

export interface DisplayPhaseAssessment {
  phase: DsregcmdAnalysisResult["derived"]["dominantPhase"];
  label: string;
  tone: FactRow["tone"];
  summary: string;
}

export interface DisplayConfidenceAssessment {
  confidence: DsregcmdAnalysisResult["derived"]["captureConfidence"];
  reason: string;
}

export const NOT_REPORTED_LABEL = "Not Reported";

export function formatBool(value: boolean | null): string {
  if (value === true) {
    return "Yes";
  }

  if (value === false) {
    return "No";
  }

  return "Unknown";
}

export function formatValue(
  value: string | number | boolean | null | undefined,
): string {
  if (value === null || value === undefined || value === "") {
    return NOT_REPORTED_LABEL;
  }

  if (typeof value === "boolean") {
    return formatBool(value);
  }

  return String(value);
}

export function formatEvidenceSource(
  source: DsregcmdEvidenceSource | null | undefined,
): string {
  switch (source) {
    case "dsregcmd":
      return "dsregcmd";
    case "policy_manager_current":
      return "PolicyManager current";
    case "policy_manager_provider":
      return "PolicyManager provider";
    case "policy_manager_comparison":
      return "PolicyManager current + provider";
    case "windows_policy_machine":
      return "Windows policy (machine)";
    case "windows_policy_user":
      return "Windows policy (user)";
    default:
      return "";
  }
}

function getPathBaseName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

export function getPolicyDisplayValue(
  dsregValue: boolean | null | undefined,
  policyValue: DsregcmdPolicyEvidenceValue,
): string {
  if (dsregValue != null) {
    return `${formatBool(dsregValue)} (dsregcmd)`;
  }

  if (policyValue.displayValue != null) {
    const sourceLabel = formatEvidenceSource(policyValue.source);
    return sourceLabel
      ? `${formatBool(policyValue.displayValue)} (${sourceLabel})`
      : formatBool(policyValue.displayValue);
  }

  return NOT_REPORTED_LABEL;
}

export function getPolicyValueTone(
  dsregValue: boolean | null | undefined,
  policyValue: DsregcmdPolicyEvidenceValue,
): FactRow["tone"] {
  if (dsregValue != null) {
    return toneForBool(dsregValue);
  }

  return toneForBool(policyValue.displayValue);
}

export function formatPolicyEvidenceValue(
  value: DsregcmdPolicyEvidenceValue,
): string {
  if (value.displayValue == null) {
    return NOT_REPORTED_LABEL;
  }

  const currentLabel =
    value.currentValue == null
      ? null
      : `effective ${formatBool(value.currentValue)}`;
  const providerLabel =
    value.providerValue == null
      ? null
      : `provider ${formatBool(value.providerValue)}`;
  const sourceLabel = formatEvidenceSource(value.source);
  const parts = [currentLabel, providerLabel].filter((part): part is string =>
    Boolean(part),
  );

  if (parts.length > 0 && sourceLabel) {
    return `${parts.join(" / ")} (${sourceLabel})`;
  }

  if (parts.length > 0) {
    return parts.join(" / ");
  }

  return sourceLabel
    ? `${formatBool(value.displayValue)} (${sourceLabel})`
    : formatBool(value.displayValue);
}

export function getPolicyEvidenceSummary(
  result: DsregcmdAnalysisResult,
): string {
  const notes = [
    result.policyEvidence.policyEnabled.note,
    result.policyEvidence.postLogonEnabled.note,
  ].filter((note): note is string => Boolean(note));

  const uniqueNotes = Array.from(new Set(notes));
  if (uniqueNotes.length === 0) {
    return NOT_REPORTED_LABEL;
  }

  const firstNote = uniqueNotes[0];
  if (
    firstNote.includes(
      "no mapped PassportForWork PolicyManager values were present",
    )
  ) {
    return "Registry captured, but no mapped WHfB policy values were found.";
  }

  return firstNote;
}

export function formatRegistryArtifacts(paths: string[]): string {
  if (paths.length === 0) {
    return NOT_REPORTED_LABEL;
  }

  const names = Array.from(new Set(paths.map(getPathBaseName)));
  if (names.length <= 2) {
    return names.join(" | ");
  }

  return `${names.slice(0, 2).join(" | ")} +${names.length - 2} more`;
}

export function getEffectivePolicyEnabled(
  result: DsregcmdAnalysisResult,
): boolean | null {
  return (
    result.facts.userState.policyEnabled ??
    result.policyEvidence.policyEnabled.displayValue
  );
}

export function getEffectivePostLogonEnabled(
  result: DsregcmdAnalysisResult,
): boolean | null {
  return (
    result.facts.userState.postLogonEnabled ??
    result.policyEvidence.postLogonEnabled.displayValue
  );
}

export function formatLocalDateTime(
  value: string | null | undefined,
): string | null {
  return formatDisplayDateTime(value);
}

function parseCertificateValidityRange(
  value: string | null | undefined,
): { from: string; to: string } | null {
  if (!value) {
    return null;
  }

  const match = value.trim().match(/^\[\s*(.*?)\s*--\s*(.*?)\s*\]$/);
  if (!match) {
    return null;
  }

  return { from: match[1], to: match[2] };
}

export function formatCertificateValidityRange(
  rawValue: string | null | undefined,
  validFrom: string | null | undefined,
  validTo: string | null | undefined,
): string {
  const parsedRange = parseCertificateValidityRange(rawValue);
  const from =
    formatLocalDateTime(validFrom) ?? formatLocalDateTime(parsedRange?.from);
  const to =
    formatLocalDateTime(validTo) ?? formatLocalDateTime(parsedRange?.to);

  if (from && to) {
    return `${from} to ${to}`;
  }

  return formatValue(rawValue);
}

export function formatHourDuration(
  value: number | null | undefined,
): string {
  if (value == null || !Number.isFinite(value)) {
    return "(unknown)";
  }

  const totalMinutes = Math.max(0, Math.round(value * 60));
  if (totalMinutes < 60) {
    return `${totalMinutes} min`;
  }

  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (minutes === 0) {
    return `${hours} hr`;
  }

  return `${hours} hr ${minutes} min`;
}

export function formatDateTimeValue(
  value: string | null | undefined,
): string {
  return formatLocalDateTime(value) ?? formatValue(value);
}

export function toneForBool(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  if (value === false) {
    return "bad";
  }

  return "neutral";
}

export function toneForWorkplaceJoined(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "warn";
  }

  return "neutral";
}

export function toneForEnterpriseJoined(
  _value: boolean | null | undefined,
): FactRow["tone"] {
  return "neutral";
}

export function toneForDomainJoined(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  return "neutral";
}

export function toneForEnterprisePrt(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  return "neutral";
}

export function toneForJoinType(
  joinType: DsregcmdAnalysisResult["derived"]["joinType"],
): FactRow["tone"] {
  return joinType === "NotJoined" ? "bad" : "good";
}

export function toneForPrtState(
  prtPresent: boolean | null,
  stalePrt: boolean | null | undefined,
): FactRow["tone"] {
  if (prtPresent === null) {
    return "neutral";
  }

  if (!prtPresent) {
    return "bad";
  }

  return stalePrt ? "warn" : "good";
}

export function formatPhaseLabel(
  phase: DsregcmdAnalysisResult["derived"]["dominantPhase"],
): string {
  switch (phase) {
    case "precheck":
      return "Precheck";
    case "discover":
      return "Discover";
    case "auth":
      return "Authentication";
    case "join":
      return "Join";
    case "post_join":
      return "Post-Join";
    case "unknown":
      return "Unknown";
  }
}

export function toneForPhase(
  phase: DsregcmdAnalysisResult["derived"]["dominantPhase"],
): FactRow["tone"] {
  if (phase === "unknown") {
    return "neutral";
  }

  return phase === "post_join" ? "warn" : "bad";
}

export function formatConfidenceLabel(
  confidence: DsregcmdAnalysisResult["derived"]["captureConfidence"],
): string {
  switch (confidence) {
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
  }
}

export function toneForCaptureConfidence(
  confidence: DsregcmdAnalysisResult["derived"]["captureConfidence"],
): FactRow["tone"] {
  switch (confidence) {
    case "high":
      return "good";
    case "medium":
      return "warn";
    case "low":
      return "bad";
  }
}

export function qualifyByCaptureConfidence(
  confidence: DsregcmdAnalysisResult["derived"]["captureConfidence"],
  text: string,
): string {
  return confidence === "high"
    ? text
    : `Based on this capture, ${text.charAt(0).toLowerCase()}${text.slice(1)}`;
}

export function getDisplayPhaseAssessment(
  result: DsregcmdAnalysisResult,
  errorCount: number,
  warningCount: number,
): DisplayPhaseAssessment {
  if (errorCount === 0 && warningCount === 0) {
    return {
      phase: "unknown",
      label: "No Active Issue",
      tone: "good",
      summary:
        "Current evidence does not show an active failure phase in this capture.",
    };
  }

  return {
    phase: result.derived.dominantPhase,
    label: formatPhaseLabel(result.derived.dominantPhase),
    tone: toneForPhase(result.derived.dominantPhase),
    summary: result.derived.phaseSummary,
  };
}

export function getDisplayConfidenceAssessment(
  result: DsregcmdAnalysisResult,
  sourceContext: DsregcmdSourceContext,
): DisplayConfidenceAssessment {
  if (
    sourceContext.source?.kind === "capture" &&
    result.derived.remoteSessionSystem !== true
  ) {
    return {
      confidence: "high",
      reason:
        "Live capture was taken from this session, so freshness is based on the capture action rather than dsregcmd diagnostic timestamps.",
    };
  }

  return {
    confidence: result.derived.captureConfidence,
    reason: result.derived.captureConfidenceReason,
  };
}

export function toneForMdmVisibility(
  derived: DsregcmdAnalysisResult["derived"],
): FactRow["tone"] {
  if (derived.mdmEnrolled === true) {
    return derived.missingMdm || derived.missingComplianceUrl
      ? "neutral"
      : "good";
  }

  return "neutral";
}

export function getMdmVisibilityLabel(
  derived: DsregcmdAnalysisResult["derived"],
): string {
  if (derived.mdmEnrolled === true) {
    return derived.missingMdm || derived.missingComplianceUrl
      ? "Partial"
      : "Present";
  }

  return "Unknown";
}

export function getNgcReadinessValue(
  result: DsregcmdAnalysisResult,
): string {
  const { facts } = result;
  const policyEnabled = getEffectivePolicyEnabled(result);

  if (facts.postJoinDiagnostics.aadRecoveryEnabled === true) {
    return "Recovery Required";
  }

  if (
    (facts.postJoinDiagnostics.keySignTest ?? "").toLowerCase().includes("fail")
  ) {
    return "Key Health Issue";
  }

  if (facts.userState.ngcSet === true) {
    return "Configured";
  }

  if (
    (facts.registration.preReqResult ?? "").toLowerCase() === "willprovision"
  ) {
    return "Will Provision";
  }

  if (policyEnabled === false) {
    return "Policy Off";
  }

  if (facts.userState.deviceEligible === false) {
    return "Not Eligible";
  }

  return "Context Only";
}

export function toneForNgcReadiness(
  result: DsregcmdAnalysisResult,
): FactRow["tone"] {
  const { facts } = result;

  if (facts.postJoinDiagnostics.aadRecoveryEnabled === true) {
    return "warn";
  }

  if (
    (facts.postJoinDiagnostics.keySignTest ?? "").toLowerCase().includes("fail")
  ) {
    return "warn";
  }

  if (facts.userState.ngcSet === true) {
    return "good";
  }

  if (
    (facts.registration.preReqResult ?? "").toLowerCase() === "willprovision"
  ) {
    return "good";
  }

  return "neutral";
}

export function getNgcCaption(result: DsregcmdAnalysisResult): string {
  const { facts } = result;
  const policyEnabled = getEffectivePolicyEnabled(result);
  const postLogonEnabled = getEffectivePostLogonEnabled(result);

  if (facts.postJoinDiagnostics.aadRecoveryEnabled === true) {
    return "Post-join diagnostics indicate the current Windows Hello key state is marked for recovery.";
  }

  if (
    (facts.postJoinDiagnostics.keySignTest ?? "").toLowerCase().includes("fail")
  ) {
    return "Post-join diagnostics indicate the Windows Hello key health check did not pass.";
  }

  if (policyEnabled === false) {
    return "Windows Hello for Business is disabled by policy evidence for this bundle.";
  }

  if (postLogonEnabled === false && facts.userState.ngcSet !== true) {
    return "Post-logon Windows Hello provisioning is disabled by policy evidence for this bundle.";
  }

  if (facts.userState.ngcSet === true) {
    return "Windows Hello for Business is already configured for the current user.";
  }

  if (
    (facts.registration.preReqResult ?? "").toLowerCase() === "willprovision"
  ) {
    return "Prerequisites look satisfied enough for Windows Hello provisioning to happen later.";
  }

  return "Windows Hello fields are shown as readiness context and should not be treated as a failure by default.";
}

export function getSeverityColor(severity: DsregcmdSeverity) {
  switch (severity) {
    case "Error":
      return { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground1 };
    case "Warning":
      return { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 };
    case "Info":
      return { border: tokens.colorPaletteBlueBorderActive, background: tokens.colorPaletteBlueBackground2, text: tokens.colorPaletteBlueForeground2 };
  }
}

export function withNotReportedMetadata(rows: FactRow[]): FactRow[] {
  return rows.map((row) => ({
    ...row,
    isNotReported: row.isNotReported ?? row.value === NOT_REPORTED_LABEL,
  }));
}

export function getFactGroups(
  result: DsregcmdAnalysisResult,
  displayedPrtAgeHours: number | null,
  displayPhase: DisplayPhaseAssessment,
  displayConfidence: DisplayConfidenceAssessment,
  sourceContext: DsregcmdSourceContext,
): FactGroup[] {
  const { facts, derived } = result;
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

  return [
    {
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
    },
    {
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
    },
    {
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
    },
    {
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
    },
    {
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
    },
    {
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
    },
    {
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
    },
    {
      id: "ngc-readiness",
      title: "Windows Hello and NGC",
      caption:
        "Lightweight Windows Hello for Business readiness context. These fields are posture signals, not default failure indicators.",
      rows: ngcRows,
    },
    {
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
    },
    {
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
    },
    ...(result.osVersion
      ? [
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
        ]
      : []),
    ...(result.proxyEvidence
      ? [
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
        ]
      : []),
    ...(result.enrollmentEvidence
      ? [
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
        ]
      : []),
    ...(result.scheduledTaskEvidence?.enterpriseMgmtGuids?.length
      ? [
          {
            id: "enterprise-mgmt-tasks",
            title: "Enterprise Management Tasks",
            caption:
              "Scheduled task GUIDs under \\Microsoft\\Windows\\EnterpriseMgmt, cross-referenced with enrollment registry entries.",
            rows: (() => {
              const enrollments =
                result.enrollmentEvidence?.enrollments ?? [];
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
              return withNotReportedMetadata([
                {
                  label: "Task GUID Count",
                  value: String(
                    result.scheduledTaskEvidence.enterpriseMgmtGuids
                      .length,
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
              ]);
            })(),
          },
        ]
      : []),
    ...(result.activeEvidence?.connectivityTests?.length
      ? [
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
        ]
      : []),
    ...(result.activeEvidence?.scpQuery
      ? [
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
        ]
      : []),
    {
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
    },
  ];
}

export function getSummaryText(
  result: DsregcmdAnalysisResult,
  sourceLabel: string,
  displayPhase: DisplayPhaseAssessment,
  displayConfidence: DisplayConfidenceAssessment,
): string {
  const errorCount = result.diagnostics.filter(
    (item) => item.severity === "Error",
  ).length;
  const warningCount = result.diagnostics.filter(
    (item) => item.severity === "Warning",
  ).length;
  const infoCount = result.diagnostics.filter(
    (item) => item.severity === "Info",
  ).length;
  const criticalIssue = result.diagnostics.find(
    (item) => item.severity === "Error",
  );

  return [
    `Source: ${sourceLabel}`,
    `Join type: ${result.derived.joinTypeLabel}`,
    `Current stage: ${displayPhase.label}`,
    `Stage summary: ${displayPhase.summary}`,
    `Capture confidence: ${formatConfidenceLabel(displayConfidence.confidence)}`,
    `Confidence note: ${displayConfidence.reason}`,
    `Diagnostics: ${errorCount} errors, ${warningCount} warnings, ${infoCount} info`,
    criticalIssue
      ? `Top issue: ${criticalIssue.title}`
      : "Top issue: No critical issues detected",
    qualifyByCaptureConfidence(
      displayConfidence.confidence,
      `PRT present: ${formatBool(result.derived.azureAdPrtPresent)}`,
    ),
    qualifyByCaptureConfidence(
      displayConfidence.confidence,
      `MDM visibility: ${getMdmVisibilityLabel(result.derived)}`,
    ),
    qualifyByCaptureConfidence(
      displayConfidence.confidence,
      `NGC readiness: ${getNgcReadinessValue(result)}`,
    ),
    qualifyByCaptureConfidence(
      displayConfidence.confidence,
      `Device auth status: ${formatValue(result.facts.deviceDetails.deviceAuthStatus)}`,
    ),
  ].join("\n");
}

export function buildTimelineItems(
  facts: DsregcmdFacts,
  result: DsregcmdAnalysisResult,
) {
  return [
    {
      id: "cert-valid-from",
      label: "Certificate valid from",
      value:
        formatLocalDateTime(result.derived.certificateValidFrom) ??
        result.derived.certificateValidFrom ??
        facts.deviceDetails.deviceCertificateValidity,
      tone: "neutral" as const,
    },
    {
      id: "cert-valid-to",
      label: "Certificate valid to",
      value:
        formatLocalDateTime(result.derived.certificateValidTo) ??
        result.derived.certificateValidTo ??
        facts.deviceDetails.deviceCertificateValidity,
      tone: result.derived.certificateExpiringSoon
        ? ("warn" as const)
        : ("neutral" as const),
    },
    {
      id: "previous-prt",
      label: "Previous PRT attempt",
      value: formatDateTimeValue(facts.diagnostics.previousPrtAttempt),
      tone: "neutral" as const,
    },
    {
      id: "prt-update",
      label: "Azure AD PRT update",
      value: formatDateTimeValue(facts.ssoState.azureAdPrtUpdateTime),
      tone: result.derived.stalePrt ? ("warn" as const) : ("good" as const),
    },
    {
      id: "client-time",
      label: "Client reference time",
      value: formatDateTimeValue(facts.diagnostics.clientTime),
      tone: "neutral" as const,
    },
  ].filter((item) => item.value);
}

export function computeDisplayedPrtAgeHours(
  result: DsregcmdAnalysisResult | null,
  sourceContext: DsregcmdSourceContext,
): number | null {
  if (!result) {
    return null;
  }

  if (sourceContext.source?.kind === "capture") {
    const lastUpdate = parseDisplayDateTime(result.derived.prtLastUpdate);
    if (!lastUpdate) {
      return result.derived.prtAgeHours;
    }

    return Math.max(0, (Date.now() - lastUpdate.getTime()) / 3_600_000);
  }

  return result.derived.prtAgeHours;
}
