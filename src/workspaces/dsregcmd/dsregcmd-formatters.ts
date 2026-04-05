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
} from "./types";
import { tokens } from "@fluentui/react-components";
import {
  buildDiagnosticsGroup,
  buildEndpointConnectivityGroup,
  buildEnrollmentStatusGroup,
  buildEnterpriseMgmtTasksGroup,
  buildJoinStateGroup,
  buildManagementGroup,
  buildNgcRows,
  buildOsVersionGroup,
  buildPhaseEvidenceGroup,
  buildPolicyEvidenceGroup,
  buildPreJoinGroup,
  buildProxyConfigGroup,
  buildScpConfigGroup,
  buildServiceEndpointsGroup,
  buildSourceDetailsGroup,
  buildSsoGroup,
  buildTenantDeviceGroup,
} from "./fact-group-builders";

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
  return [
    buildPhaseEvidenceGroup(result, displayPhase, displayConfidence),
    buildJoinStateGroup(result),
    buildTenantDeviceGroup(result),
    buildManagementGroup(result),
    buildSsoGroup(result, displayedPrtAgeHours),
    buildDiagnosticsGroup(result),
    buildPreJoinGroup(result),
    {
      id: "ngc-readiness",
      title: "Windows Hello and NGC",
      caption:
        "Lightweight Windows Hello for Business readiness context. These fields are posture signals, not default failure indicators.",
      rows: buildNgcRows(result),
    },
    buildPolicyEvidenceGroup(result),
    buildServiceEndpointsGroup(result),
    ...buildOsVersionGroup(result),
    ...buildProxyConfigGroup(result),
    ...buildEnrollmentStatusGroup(result),
    ...buildEnterpriseMgmtTasksGroup(result),
    ...buildEndpointConnectivityGroup(result),
    ...buildScpConfigGroup(result),
    buildSourceDetailsGroup(sourceContext),
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
