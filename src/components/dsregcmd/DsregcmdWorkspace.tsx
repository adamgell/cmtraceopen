import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Badge, Button, Textarea, tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { save } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  formatDisplayDateTime,
  parseDisplayDateTime,
} from "../../lib/date-time-format";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import { DsregcmdEventLogSurface } from "./DsregcmdEventLogSurface";
import { useAppActions } from "../layout/Toolbar";
import { writeTextOutputFile } from "../../lib/commands";
import type {
  DsregcmdAnalysisResult,
  DsregcmdDiagnosticInsight,
  DsregcmdEvidenceSource,
  DsregcmdFacts,
  DsregcmdPolicyEvidenceValue,
  DsregcmdSeverity,
  DsregcmdSourceContext,
} from "../../types/dsregcmd";

interface FactRow {
  label: string;
  value: string;
  tone?: "neutral" | "good" | "warn" | "bad";
  isNotReported?: boolean;
}

interface FactGroup {
  id: string;
  title: string;
  caption: string;
  rows: FactRow[];
}

interface DisplayPhaseAssessment {
  phase: DsregcmdAnalysisResult["derived"]["dominantPhase"];
  label: string;
  tone: FactRow["tone"];
  summary: string;
}

interface DisplayConfidenceAssessment {
  confidence: DsregcmdAnalysisResult["derived"]["captureConfidence"];
  reason: string;
}

const NOT_REPORTED_LABEL = "Not Reported";

function formatBool(value: boolean | null): string {
  if (value === true) {
    return "Yes";
  }

  if (value === false) {
    return "No";
  }

  return "Unknown";
}

function formatValue(
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

function formatEvidenceSource(
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

function getPolicyDisplayValue(
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

function getPolicyValueTone(
  dsregValue: boolean | null | undefined,
  policyValue: DsregcmdPolicyEvidenceValue,
): FactRow["tone"] {
  if (dsregValue != null) {
    return toneForBool(dsregValue);
  }

  return toneForBool(policyValue.displayValue);
}

function formatPolicyEvidenceValue(value: DsregcmdPolicyEvidenceValue): string {
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

function getPolicyEvidenceSummary(result: DsregcmdAnalysisResult): string {
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

function formatRegistryArtifacts(paths: string[]): string {
  if (paths.length === 0) {
    return NOT_REPORTED_LABEL;
  }

  const names = Array.from(new Set(paths.map(getPathBaseName)));
  if (names.length <= 2) {
    return names.join(" | ");
  }

  return `${names.slice(0, 2).join(" | ")} +${names.length - 2} more`;
}

function getEffectivePolicyEnabled(
  result: DsregcmdAnalysisResult,
): boolean | null {
  return (
    result.facts.userState.policyEnabled ??
    result.policyEvidence.policyEnabled.displayValue
  );
}

function getEffectivePostLogonEnabled(
  result: DsregcmdAnalysisResult,
): boolean | null {
  return (
    result.facts.userState.postLogonEnabled ??
    result.policyEvidence.postLogonEnabled.displayValue
  );
}

function formatLocalDateTime(value: string | null | undefined): string | null {
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

function formatCertificateValidityRange(
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

function formatHourDuration(value: number | null | undefined): string {
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

function formatDateTimeValue(value: string | null | undefined): string {
  return formatLocalDateTime(value) ?? formatValue(value);
}

function toneForBool(value: boolean | null | undefined): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  if (value === false) {
    return "bad";
  }

  return "neutral";
}

function toneForWorkplaceJoined(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "warn";
  }

  return "neutral";
}

function toneForEnterpriseJoined(
  _value: boolean | null | undefined,
): FactRow["tone"] {
  return "neutral";
}

function toneForDomainJoined(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  return "neutral";
}

function toneForEnterprisePrt(
  value: boolean | null | undefined,
): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  return "neutral";
}

function toneForJoinType(
  joinType: DsregcmdAnalysisResult["derived"]["joinType"],
): FactRow["tone"] {
  return joinType === "NotJoined" ? "bad" : "good";
}

function toneForPrtState(
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

function formatPhaseLabel(
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

function toneForPhase(
  phase: DsregcmdAnalysisResult["derived"]["dominantPhase"],
): FactRow["tone"] {
  if (phase === "unknown") {
    return "neutral";
  }

  return phase === "post_join" ? "warn" : "bad";
}

function formatConfidenceLabel(
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

function toneForCaptureConfidence(
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

function qualifyByCaptureConfidence(
  confidence: DsregcmdAnalysisResult["derived"]["captureConfidence"],
  text: string,
): string {
  return confidence === "high"
    ? text
    : `Based on this capture, ${text.charAt(0).toLowerCase()}${text.slice(1)}`;
}

function getDisplayPhaseAssessment(
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

function getDisplayConfidenceAssessment(
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

function toneForMdmVisibility(
  derived: DsregcmdAnalysisResult["derived"],
): FactRow["tone"] {
  if (derived.mdmEnrolled === true) {
    return derived.missingMdm || derived.missingComplianceUrl
      ? "neutral"
      : "good";
  }

  return "neutral";
}

function getMdmVisibilityLabel(
  derived: DsregcmdAnalysisResult["derived"],
): string {
  if (derived.mdmEnrolled === true) {
    return derived.missingMdm || derived.missingComplianceUrl
      ? "Partial"
      : "Present";
  }

  return "Unknown";
}

function getNgcReadinessValue(result: DsregcmdAnalysisResult): string {
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

function toneForNgcReadiness(result: DsregcmdAnalysisResult): FactRow["tone"] {
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

function getNgcCaption(result: DsregcmdAnalysisResult): string {
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

function getSeverityColor(severity: DsregcmdSeverity) {
  switch (severity) {
    case "Error":
      return { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground1 };
    case "Warning":
      return { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 };
    case "Info":
      return { border: tokens.colorPaletteBlueBorderActive, background: tokens.colorPaletteBlueBackground2, text: tokens.colorPaletteBlueForeground2 };
  }
}

function withNotReportedMetadata(rows: FactRow[]): FactRow[] {
  return rows.map((row) => ({
    ...row,
    isNotReported: row.isNotReported ?? row.value === NOT_REPORTED_LABEL,
  }));
}

function getFactGroups(
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

function getSummaryText(
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

function StatCard({
  title,
  value,
  caption,
  tone = "neutral",
}: {
  title: string;
  value: string;
  caption: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const tones = {
    neutral: { border: tokens.colorNeutralStroke2, background: tokens.colorNeutralCardBackground, value: tokens.colorNeutralForeground1 },
    good: { border: tokens.colorPaletteGreenBorder2, background: tokens.colorPaletteGreenBackground1, value: tokens.colorPaletteGreenForeground1 },
    warn: { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, value: tokens.colorPaletteMarigoldForeground2 },
    bad: { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, value: tokens.colorPaletteRedForeground1 },
  } as const;

  const colors = tones[tone];

  return (
    <div
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
        minWidth: 0,
        borderRadius: "10px",
      }}
    >
      <div
        style={{
          fontSize: "11px",
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {title}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "20px",
          fontWeight: 700,
          color: colors.value,
          lineHeight: 1.2,
        }}
      >
        {value}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "12px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.45,
        }}
      >
        {caption}
      </div>
    </div>
  );
}

function SectionFrame({
  title,
  caption,
  children,
}: {
  title: string;
  caption: string;
  children: ReactNode;
}) {
  return (
    <section
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralCardBackground,
        borderRadius: "10px",
        overflow: "hidden",
        flexShrink: 0,
      }}
    >
      <div style={{ padding: "12px 14px", backgroundColor: tokens.colorNeutralBackground3 }}>
        <div style={{ fontSize: "14px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
          {title}
        </div>
        <div style={{ marginTop: "4px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
          {caption}
        </div>
      </div>
      <div style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}` }} />
      <div style={{ padding: "14px" }}>{children}</div>
    </section>
  );
}

function IssueCard({ issue }: { issue: DsregcmdDiagnosticInsight }) {
  const colors = getSeverityColor(issue.severity);

  return (
    <article
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
        borderRadius: "10px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          flexWrap: "wrap",
        }}
      >
        <Badge
          appearance="outline"
          style={{
            fontSize: "10px",
            fontWeight: 700,
            border: `1px solid ${colors.border}`,
            color: colors.text,
            backgroundColor: tokens.colorNeutralCardBackground,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          {issue.severity}
        </Badge>
        <span
          style={{
            fontSize: "11px",
            color: tokens.colorNeutralForeground3,
            textTransform: "uppercase",
          }}
        >
          {issue.category}
        </span>
      </div>
      <div
        style={{
          marginTop: "8px",
          fontSize: "15px",
          fontWeight: 700,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {issue.title}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "13px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.5,
        }}
      >
        {issue.summary}
      </div>

      {issue.suggestedFixes.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            Suggested fixes
          </div>
          <ul
            style={{
              marginTop: "6px",
              paddingLeft: "18px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {issue.suggestedFixes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {issue.nextChecks.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            Next checks
          </div>
          <ul
            style={{
              marginTop: "6px",
              paddingLeft: "18px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {issue.nextChecks.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {issue.evidence.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            Evidence
          </div>
          <ul
            style={{
              marginTop: "6px",
              paddingLeft: "18px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {issue.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

function FactsTable({
  group,
  showNotReported,
}: {
  group: FactGroup;
  showNotReported: boolean;
}) {
  const visibleRows = showNotReported
    ? group.rows
    : group.rows.filter((row) => row.isNotReported !== true);
  const hiddenCount = group.rows.length - visibleRows.length;

  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralCardBackground,
        borderRadius: "10px",
        overflow: "hidden",
      }}
    >
      <div style={{ padding: "10px 12px", backgroundColor: tokens.colorNeutralBackground3 }}>
        <div style={{ fontSize: "13px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
          {group.title}
        </div>
        <div style={{ marginTop: "4px", fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
          {group.caption}
        </div>
      </div>
      <div style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}` }} />
      <div>
        {visibleRows.length === 0 ? (
          <div
            style={{ padding: "10px 12px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}
          >
            All fields in this group were not reported by dsregcmd for this
            capture.
          </div>
        ) : (
          visibleRows.map((row) => {
            const tones = {
              neutral: { value: tokens.colorNeutralForeground1, background: tokens.colorNeutralCardBackground },
              good: { value: tokens.colorPaletteGreenForeground1, background: tokens.colorPaletteGreenBackground1 },
              warn: { value: tokens.colorPaletteMarigoldForeground2, background: tokens.colorPaletteYellowBackground1 },
              bad: { value: tokens.colorPaletteRedForeground1, background: tokens.colorPaletteRedBackground1 },
            } as const;
            const palette = tones[row.tone ?? "neutral"];

            return (
              <div
                key={`${group.id}-${row.label}`}
                style={{
                  display: "grid",
                  gridTemplateColumns: "170px minmax(0, 1fr)",
                  gap: "8px",
                  padding: "9px 12px",
                  borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                  alignItems: "start",
                }}
              >
                <div
                  style={{
                    fontSize: "12px",
                    fontWeight: 600,
                    color: tokens.colorNeutralForeground3,
                  }}
                >
                  {row.label}
                </div>
                <div
                  style={{
                    fontSize: "12px",
                    color: palette.value,
                    backgroundColor: palette.background,
                    padding: "2px 6px",
                    borderRadius: "2px",
                    wordBreak: "break-word",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {row.value}
                </div>
              </div>
            );
          })
        )}
        {!showNotReported && hiddenCount > 0 && (
          <div
            style={{
              padding: "10px 12px",
              borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
              fontSize: "11px",
              color: tokens.colorNeutralForeground3,
            }}
          >
            {hiddenCount} not reported {hiddenCount === 1 ? "field" : "fields"}{" "}
            hidden.
          </div>
        )}
      </div>
    </div>
  );
}

function EmptyWorkspace({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        margin: "18px",
        border: `1px dashed ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground3,
        padding: "24px",
        color: tokens.colorNeutralForeground2,
        borderRadius: "12px",
      }}
    >
      <div style={{ fontSize: "18px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
        {title}
      </div>
      <div style={{ marginTop: "8px", fontSize: "13px", lineHeight: 1.6 }}>
        {body}
      </div>
    </div>
  );
}

function buildTimelineItems(
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

function FlowBox({
  title,
  detail,
  tone = "neutral",
}: {
  title: string;
  detail: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const colors = {
    neutral: { border: tokens.colorNeutralStroke2, background: tokens.colorNeutralCardBackground, text: tokens.colorNeutralForeground1 },
    good: { border: tokens.colorPaletteGreenBorder2, background: tokens.colorPaletteGreenBackground1, text: tokens.colorPaletteGreenForeground1 },
    warn: { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 },
    bad: { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground1 },
  } as const;
  const palette = colors[tone];

  return (
    <div
      style={{
        flex: 1,
        minWidth: "180px",
        border: `1px solid ${palette.border}`,
        backgroundColor: palette.background,
        padding: "12px",
        borderRadius: "10px",
      }}
    >
      <div style={{ fontSize: "12px", fontWeight: 700, color: palette.text }}>
        {title}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "12px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.5,
        }}
      >
        {detail}
      </div>
    </div>
  );
}

export function DsregcmdWorkspace() {
  const result = useDsregcmdStore((s) => s.result);
  const rawInput = useDsregcmdStore((s) => s.rawInput);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const {
    openSourceFileDialog,
    openSourceFolderDialog,
    pasteDsregcmdSource,
    captureDsregcmdSource,
  } = useAppActions();
  const [exportStatus, setExportStatus] = useState<{
    tone: "success" | "error";
    message: string;
  } | null>(null);
  const [showRawInput, setShowRawInput] = useState(false);
  const [showNotReported, setShowNotReported] = useState(false);
  const activeTab = useDsregcmdStore((s) => s.activeTab);
  const setActiveTab = useDsregcmdStore((s) => s.setActiveTab);

  const eventLogEntryCount = result?.eventLogAnalysis?.totalEntryCount ?? 0;

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter(
    (item) => item.severity === "Error",
  ).length;
  const warningCount = diagnostics.filter(
    (item) => item.severity === "Warning",
  ).length;

  const displayedPrtAgeHours = useMemo(() => {
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
  }, [result, sourceContext.source]);

  const displayPhase = useMemo(
    () =>
      result
        ? getDisplayPhaseAssessment(result, errorCount, warningCount)
        : null,
    [errorCount, result, warningCount],
  );
  const displayConfidence = useMemo(
    () =>
      result ? getDisplayConfidenceAssessment(result, sourceContext) : null,
    [result, sourceContext],
  );

  const factGroups = useMemo(
    () =>
      result && displayPhase && displayConfidence
        ? getFactGroups(
            result,
            displayedPrtAgeHours,
            displayPhase,
            displayConfidence,
            sourceContext,
          )
        : [],
    [
      displayConfidence,
      displayPhase,
      displayedPrtAgeHours,
      result,
      sourceContext,
    ],
  );
  const summaryText = useMemo(
    () =>
      result && displayPhase && displayConfidence
        ? getSummaryText(
            result,
            sourceContext.displayLabel,
            displayPhase,
            displayConfidence,
          )
        : "",
    [displayConfidence, displayPhase, result, sourceContext.displayLabel],
  );
  const timelineItems = useMemo(
    () => (result ? buildTimelineItems(result.facts, result) : []),
    [result],
  );

  useEffect(() => {
    if (!exportStatus) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setExportStatus(null);
    }, 5000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [exportStatus]);

  const setExportSuccess = useCallback((message: string) => {
    setExportStatus({ tone: "success", message });
  }, []);

  const setExportError = useCallback((message: string) => {
    setExportStatus({ tone: "error", message });
  }, []);

  const handleCopyJson = async () => {
    if (!result) {
      return;
    }

    try {
      await writeText(JSON.stringify(result, null, 2));
      setExportSuccess("Copied dsregcmd analysis JSON to the clipboard.");
    } catch (error) {
      console.error("[dsregcmd] failed to copy JSON export", { error });
      setExportError(
        error instanceof Error
          ? error.message
          : "Could not copy dsregcmd JSON to the clipboard.",
      );
    }
  };

  const handleCopySummary = async () => {
    if (!result) {
      return;
    }

    try {
      await writeText(summaryText);
      setExportSuccess("Copied dsregcmd summary to the clipboard.");
    } catch (error) {
      console.error("[dsregcmd] failed to copy summary export", { error });
      setExportError(
        error instanceof Error
          ? error.message
          : "Could not copy the dsregcmd summary to the clipboard.",
      );
    }
  };

  const handleCopyStatus = async () => {
    if (!rawInput.trim()) {
      setExportError("No dsregcmd status text is available to copy.");
      return;
    }

    try {
      await writeText(rawInput);
      setExportSuccess("Copied dsregcmd status text to the clipboard.");
    } catch (error) {
      console.error("[dsregcmd] failed to copy raw status", { error });
      setExportError(
        error instanceof Error
          ? error.message
          : "Could not copy dsregcmd status text to the clipboard.",
      );
    }
  };

  const handleSaveExport = async (kind: "json" | "summary") => {
    if (!result) {
      return;
    }

    const defaultPath =
      kind === "json" ? "dsregcmd-analysis.json" : "dsregcmd-summary.txt";

    try {
      const destination = await save({
        defaultPath,
        filters:
          kind === "json"
            ? [{ name: "JSON", extensions: ["json"] }]
            : [{ name: "Text", extensions: ["txt"] }],
      });

      if (!destination) {
        return;
      }

      const contents =
        kind === "json" ? JSON.stringify(result, null, 2) : summaryText;
      await writeTextOutputFile(destination, contents);
      setExportSuccess(
        `Saved ${kind === "json" ? "JSON export" : "summary export"} to ${destination}.`,
      );
    } catch (error) {
      console.error("[dsregcmd] failed to save export", { error, kind });
      setExportError(
        error instanceof Error
          ? error.message
          : `Could not save the ${kind === "json" ? "JSON" : "summary"} export.`,
      );
    }
  };

  if (!result && isAnalyzing) {
    return (
      <EmptyWorkspace
        title="Analyzing dsregcmd source"
        body={
          analysisState.detail ??
          "Reading source text, extracting facts, and building the first-pass health view..."
        }
      />
    );
  }

  if (!result && analysisState.phase === "error") {
    return (
      <EmptyWorkspace
        title="dsregcmd analysis failed"
        body={
          analysisState.detail ??
          "The selected dsregcmd source could not be analyzed."
        }
      />
    );
  }

  if (!result) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "10px",
            padding: "8px 12px",
            backgroundColor: tokens.colorNeutralBackground3,
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          }}
        >
          <div>
            <div
              style={{ fontSize: "14px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
            >
              dsregcmd Workspace
            </div>
            <div
              style={{ marginTop: "4px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}
            >
              Capture a live snapshot, paste clipboard text, open a text file,
              or select an evidence bundle folder.
            </div>
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <Button
              appearance="primary"
              onClick={() => void captureDsregcmdSource()}
            >
              Capture
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void pasteDsregcmdSource()}
            >
              Paste
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void openSourceFileDialog()}
            >
              Open Text File
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void openSourceFolderDialog()}
            >
              Open Evidence Folder
            </Button>
          </div>
        </div>

        <EmptyWorkspace
          title="No dsregcmd source loaded"
          body="Use the workspace actions above to analyze dsregcmd /status output. Open a bundle root, its evidence folder, or its command-output folder, or run a live capture that stages dsregcmd and registry evidence together."
        />
      </div>
    );
  }

  const issueSpotlight =
    diagnostics.find((item) => item.severity === "Error") ??
    diagnostics[0] ??
    null;
  const stage = displayPhase ?? {
    phase: result.derived.dominantPhase,
    label: formatPhaseLabel(result.derived.dominantPhase),
    tone: toneForPhase(result.derived.dominantPhase),
    summary: result.derived.phaseSummary,
  };
  const confidence = displayConfidence ?? {
    confidence: result.derived.captureConfidence,
    reason: result.derived.captureConfidenceReason,
  };
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "10px",
          padding: "8px 12px",
          backgroundColor: tokens.colorNeutralBackground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          flexWrap: "wrap",
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: "14px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            dsregcmd Workspace
          </div>
          <div
            style={{
              marginTop: "4px",
              fontSize: "12px",
              color: tokens.colorNeutralForeground3,
              lineHeight: 1.4,
            }}
          >
            {sourceContext.displayLabel}
            {sourceContext.resolvedPath && ` • ${sourceContext.resolvedPath}`}
            {sourceContext.evidenceFilePath &&
            sourceContext.evidenceFilePath !== sourceContext.resolvedPath
              ? ` • evidence ${sourceContext.evidenceFilePath}`
              : ""}
          </div>
        </div>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <Button
            appearance="primary"
            onClick={() => void captureDsregcmdSource()}
            disabled={isAnalyzing}
          >
            Capture
          </Button>
          <Button
            appearance="secondary"
            onClick={() => void pasteDsregcmdSource()}
            disabled={isAnalyzing}
          >
            Paste
          </Button>
          <Button
            appearance="secondary"
            onClick={() => void openSourceFileDialog()}
            disabled={isAnalyzing}
          >
            Open Text File
          </Button>
          <Button
            appearance="secondary"
            onClick={() => void openSourceFolderDialog()}
            disabled={isAnalyzing}
          >
            Open Evidence Folder
          </Button>
        </div>
      </div>

      {/* Tab strip */}
      <div
        style={{
          display: "flex",
          gap: 2,
          padding: "0 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          background: tokens.colorNeutralBackground3,
          flexShrink: 0,
        }}
      >
        <TabButton
          label="Analysis"
          isActive={activeTab === "analysis"}
          onClick={() => setActiveTab("analysis")}
        />
        <TabButton
          label="Event Logs"
          count={eventLogEntryCount}
          isActive={activeTab === "event-logs"}
          onClick={() => setActiveTab("event-logs")}
        />
      </div>

      {activeTab === "event-logs" && result.eventLogAnalysis ? (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <DsregcmdEventLogSurface eventLogAnalysis={result.eventLogAnalysis} />
        </div>
      ) : (
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "12px",
            flexShrink: 0,
          }}
        >
          <StatCard
            title="Join Type"
            value={result.derived.joinTypeLabel}
            caption="Derived from AzureAdJoined and DomainJoined fields."
            tone={toneForJoinType(result.derived.joinType)}
          />
          <StatCard
            title="Current Stage"
            value={stage.label}
            caption={stage.summary}
            tone={stage.tone}
          />
          <StatCard
            title="Capture Confidence"
            value={formatConfidenceLabel(confidence.confidence)}
            caption={confidence.reason}
            tone={toneForCaptureConfidence(confidence.confidence)}
          />
          <StatCard
            title="PRT State"
            value={formatBool(result.derived.azureAdPrtPresent)}
            caption={
              result.derived.stalePrt
                ? qualifyByCaptureConfidence(
                    confidence.confidence,
                    `PRT looks stale by ${formatHourDuration(result.derived.prtAgeHours)}.`,
                  )
                : qualifyByCaptureConfidence(
                    confidence.confidence,
                    "Primary Refresh Token presence was derived from SSO state.",
                  )
            }
            tone={toneForPrtState(
              result.derived.azureAdPrtPresent,
              result.derived.stalePrt,
            )}
          />
          <StatCard
            title="MDM Signals"
            value={getMdmVisibilityLabel(result.derived)}
            caption={qualifyByCaptureConfidence(
              confidence.confidence,
              "visible tenant management metadata can be out of scope, not configured, or simply absent from this capture.",
            )}
            tone={toneForMdmVisibility(result.derived)}
          />
          <StatCard
            title="NGC"
            value={getNgcReadinessValue(result)}
            caption={qualifyByCaptureConfidence(
              confidence.confidence,
              getNgcCaption(result),
            )}
            tone={toneForNgcReadiness(result)}
          />
          <StatCard
            title="Certificate"
            value={
              result.derived.certificateDaysRemaining == null
                ? "Unknown"
                : `${result.derived.certificateDaysRemaining} days`
            }
            caption="Remaining device certificate lifetime, when the validity range was parsed."
            tone={result.derived.certificateExpiringSoon ? "warn" : "neutral"}
          />
        </div>

        <SectionFrame
          title="Health Summary"
          caption="Fast first-pass readout of the current dsregcmd capture."
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(260px, 1.2fr) minmax(220px, 0.8fr)",
              gap: "16px",
            }}
          >
            <div>
              <div
                style={{
                  fontSize: "13px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                  whiteSpace: "pre-wrap",
                }}
              >
                {summaryText}
              </div>
              {issueSpotlight && (
                <div
                  style={{
                    marginTop: "12px",
                    padding: "10px",
                    border: `1px solid ${tokens.colorNeutralStroke2}`,
                    backgroundColor: tokens.colorNeutralBackground2,
                  }}
                >
                  <div
                    style={{
                      fontSize: "12px",
                      fontWeight: 700,
                      color: tokens.colorNeutralForeground1,
                    }}
                  >
                    Issue spotlight
                  </div>
                  <div
                    style={{
                      marginTop: "6px",
                      fontSize: "13px",
                      fontWeight: 600,
                      color: tokens.colorNeutralForeground1,
                    }}
                  >
                    {issueSpotlight.title}
                  </div>
                  <div
                    style={{
                      marginTop: "4px",
                      fontSize: "12px",
                      color: tokens.colorNeutralForeground3,
                      lineHeight: 1.5,
                    }}
                  >
                    {issueSpotlight.summary}{" "}
                    {confidence.confidence === "high"
                      ? ""
                      : `Interpret this in the context of ${formatConfidenceLabel(confidence.confidence).toLowerCase()} capture confidence.`}
                  </div>
                </div>
              )}
            </div>
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralCardBackground,
                padding: "12px",
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                Quick interpretation
              </div>
              <ul
                style={{
                  marginTop: "8px",
                  paddingLeft: "18px",
                  color: tokens.colorNeutralForeground2,
                  lineHeight: 1.6,
                }}
              >
                <li>{stage.summary}</li>
                <li>{`Capture confidence is ${formatConfidenceLabel(confidence.confidence).toLowerCase()}: ${confidence.reason}`}</li>
                <li>
                  {result.policyEvidence.artifactPaths.length > 0
                    ? "Registry-backed WHfB policy evidence is available for this bundle."
                    : "No sibling registry policy evidence was available for this capture."}
                </li>
                <li>
                  {result.derived.hasNetworkError
                    ? `Network marker detected: ${result.derived.networkErrorCode}.`
                    : "No explicit network marker was detected in the capture."}
                </li>
                <li>
                  {result.derived.remoteSessionSystem
                    ? "Capture looks like SYSTEM in a remote session, so user token fields may be misleading."
                    : "Capture does not look like a SYSTEM remote-session snapshot."}
                </li>
                <li>
                  {result.derived.certificateExpiringSoon
                    ? "Device certificate is nearing expiry and deserves follow-up."
                    : "Certificate expiry was not flagged as near-term."}
                </li>
              </ul>
            </div>
          </div>
        </SectionFrame>

        <SectionFrame
          title="Issues Overview"
          caption="Ordered diagnostic findings with evidence, recommended checks, and suggested fixes."
        >
          {diagnostics.length === 0 ? (
            <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground2 }}>
              No diagnostics were produced for this dsregcmd capture.
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
                gap: "12px",
              }}
            >
              {diagnostics.map((issue) => (
                <IssueCard key={issue.id} issue={issue} />
              ))}
            </div>
          )}
        </SectionFrame>

        <SectionFrame
          title="Facts by Group"
          caption="Backend-extracted facts organized for quick review rather than raw line order."
        >
          <div
            style={{
              display: "flex",
              justifyContent: "flex-end",
              marginBottom: "12px",
            }}
          >
            <Button
              appearance={showNotReported ? "primary" : "secondary"}
              onClick={() => setShowNotReported((value) => !value)}
            >
              {showNotReported
                ? "Hide Not Reported Fields"
                : "Show Not Reported Fields"}
            </Button>
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
              gap: "12px",
            }}
          >
            {factGroups.map((group) => (
              <FactsTable
                key={group.id}
                group={group}
                showNotReported={showNotReported}
              />
            ))}
          </div>
        </SectionFrame>

        <SectionFrame
          title="Timeline"
          caption="Important timestamps surfaced from PRT, certificate, and diagnostics fields."
        >
          {timelineItems.length === 0 ? (
            <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground2 }}>
              No timeline-friendly timestamps were found in this capture.
            </div>
          ) : (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "10px" }}
            >
              {timelineItems.map((item, index) => {
                const palette =
                  item.tone === "warn"
                    ? { line: tokens.colorPaletteMarigoldForeground1, dot: tokens.colorPaletteMarigoldForeground1, card: tokens.colorPaletteYellowBackground1 }
                    : item.tone === "good"
                      ? { line: tokens.colorPaletteGreenForeground1, dot: tokens.colorPaletteGreenForeground1, card: tokens.colorPaletteGreenBackground1 }
                      : { line: tokens.colorNeutralStroke1, dot: tokens.colorNeutralForeground3, card: tokens.colorNeutralBackground3 };

                return (
                  <div
                    key={item.id}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "20px 1fr",
                      gap: "10px",
                      alignItems: "stretch",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                      }}
                    >
                      <div
                        style={{
                          width: "10px",
                          height: "10px",
                          borderRadius: "999px",
                          backgroundColor: palette.dot,
                          marginTop: "8px",
                        }}
                      />
                      {index < timelineItems.length - 1 && (
                        <div
                          style={{
                            flex: 1,
                            width: "2px",
                            backgroundColor: palette.line,
                            marginTop: "4px",
                          }}
                        />
                      )}
                    </div>
                    <div
                      style={{
                        border: `1px solid ${tokens.colorNeutralStroke2}`,
                        backgroundColor: palette.card,
                        padding: "10px 12px",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "12px",
                          fontWeight: 700,
                          color: tokens.colorNeutralForeground1,
                        }}
                      >
                        {item.label}
                      </div>
                      <div
                        style={{
                          marginTop: "4px",
                          fontSize: "12px",
                          color: tokens.colorNeutralForeground2,
                          wordBreak: "break-word",
                        }}
                      >
                        {item.value}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </SectionFrame>

        <SectionFrame
          title="Flows"
          caption="Pragmatic first-pass flow boxes for registration, management, and token health."
        >
          <div
            style={{
              display: "flex",
              gap: "10px",
              flexWrap: "wrap",
              alignItems: "stretch",
            }}
          >
            <FlowBox
              title="Current phase"
              detail={`${stage.label}. ${stage.summary}`}
              tone={stage.tone}
            />
            <FlowBox
              title="Join posture"
              detail={`${result.derived.joinTypeLabel}. Azure AD joined: ${formatBool(result.facts.joinState.azureAdJoined)}. Domain joined: ${formatBool(result.facts.joinState.domainJoined)}.`}
              tone={toneForJoinType(result.derived.joinType)}
            />
            <FlowBox
              title="Device authentication"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `device auth status is ${formatValue(result.facts.deviceDetails.deviceAuthStatus)} and TPM protected is ${formatBool(result.facts.deviceDetails.tpmProtected)}.`,
              )}
              tone={
                result.facts.deviceDetails.deviceAuthStatus?.toUpperCase() ===
                "SUCCESS"
                  ? "good"
                  : "bad"
              }
            />
            <FlowBox
              title="Management"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `MDM visibility is ${getMdmVisibilityLabel(result.derived)} and compliance URL present is ${formatBool(result.derived.complianceUrlPresent)}. Missing fields are not proof that management is broken.`,
              )}
              tone={toneForMdmVisibility(result.derived)}
            />
            <FlowBox
              title="PRT and session"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `PRT present is ${formatBool(result.derived.azureAdPrtPresent)}, stale is ${formatBool(result.derived.stalePrt)}, and remote SYSTEM is ${formatBool(result.derived.remoteSessionSystem)}.`,
              )}
              tone={toneForPrtState(
                result.derived.azureAdPrtPresent,
                result.derived.stalePrt,
              )}
            />
            <FlowBox
              title="NGC readiness"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `NGC is ${formatBool(result.facts.userState.ngcSet)}, policy enabled is ${getPolicyDisplayValue(result.facts.userState.policyEnabled, result.policyEvidence.policyEnabled)}, PreReq Result is ${formatValue(result.facts.registration.preReqResult)}, and device eligible is ${formatBool(result.facts.userState.deviceEligible)}.`,
              )}
              tone={toneForNgcReadiness(result)}
            />
            <FlowBox
              title="Capture trust"
              detail={`${formatConfidenceLabel(confidence.confidence)} confidence. ${confidence.reason}`}
              tone={toneForCaptureConfidence(confidence.confidence)}
            />
          </div>
        </SectionFrame>

        <SectionFrame
          title="Explainer"
          caption="Short practical notes for what this workspace is showing and how to use it."
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: "12px",
            }}
          >
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                padding: "12px",
                backgroundColor: tokens.colorNeutralCardBackground,
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                What the health cards mean
              </div>
              <div
                style={{
                  marginTop: "8px",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                Cards summarize join posture, token state, MDM visibility,
                certificate lifetime, and issue counts. They are not a
                replacement for the raw dsregcmd output, but they do make triage
                faster.
              </div>
            </div>
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                padding: "12px",
                backgroundColor: tokens.colorNeutralCardBackground,
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                When the capture may mislead
              </div>
              <div
                style={{
                  marginTop: "8px",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                SYSTEM and remote-session captures can distort user-scoped token
                state. Evidence bundle captures can also be older than the
                current device state, so compare timestamps before acting.
              </div>
            </div>
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                padding: "12px",
                backgroundColor: tokens.colorNeutralCardBackground,
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                Suggested next step
              </div>
              <div
                style={{
                  marginTop: "8px",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                Start with the highest-severity issue card, validate the
                evidence line items against the grouped facts below, and then
                re-run capture after remediation to confirm the signal changes.
              </div>
            </div>
          </div>
        </SectionFrame>

        <SectionFrame
          title="Export"
          caption="No-dependency export controls for handing off or attaching analysis output."
        >
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <Button
              appearance="secondary"
              onClick={() => void handleCopyJson()}
            >
              Copy JSON
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleCopyStatus()}
            >
              Copy Status Text
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleCopySummary()}
            >
              Copy Summary
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleSaveExport("json")}
            >
              Save JSON
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleSaveExport("summary")}
            >
              Save Summary
            </Button>
            <Button
              appearance={showRawInput ? "primary" : "secondary"}
              onClick={() => setShowRawInput((value) => !value)}
            >
              {showRawInput ? "Hide Raw Input" : "Show Raw Input"}
            </Button>
          </div>
          {exportStatus && (
            <div
              style={{
                marginTop: "10px",
                fontSize: "12px",
                color: exportStatus.tone === "error" ? tokens.colorPaletteRedForeground1 : tokens.colorPaletteGreenForeground1,
              }}
            >
              {exportStatus.message}
            </div>
          )}
          {showRawInput && (
            <Textarea
              readOnly
              value={rawInput}
              style={{
                marginTop: "12px",
                width: "100%",
                minHeight: "220px",
                resize: "vertical",
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: "12px",
                padding: "10px",
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralBackground2,
              }}
            />
          )}
        </SectionFrame>
      </div>
      )}
    </div>
  );
}

function TabButton({
  label,
  count,
  isActive,
  onClick,
}: {
  label: string;
  count?: number;
  isActive: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        padding: "8px 14px",
        fontSize: 13,
        fontWeight: isActive ? 600 : 400,
        color: isActive ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
        background: "transparent",
        border: "none",
        borderBottom: isActive ? `2px solid ${tokens.colorBrandForeground1}` : "2px solid transparent",
        cursor: "pointer",
        transition: "border-color 0.15s, color 0.15s",
        display: "flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      {label}
      {count != null && count > 0 && (
        <span
          style={{
            fontSize: 11,
            padding: "1px 6px",
            borderRadius: 10,
            background: isActive ? tokens.colorPaletteBlueBackground2 : tokens.colorNeutralBackground3,
            color: isActive ? tokens.colorPaletteBlueForeground2 : tokens.colorNeutralForeground3,
          }}
        >
          {count}
        </span>
      )}
    </button>
  );
}
