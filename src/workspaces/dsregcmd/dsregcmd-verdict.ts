import { selectTopFindings } from "./dsregcmd-formatters";
import type {
  DsregcmdAnalysisResult,
  DsregcmdDiagnosticInsight,
  DsregcmdJoinType,
} from "./types";

export type VerdictTone = "error" | "warning" | "healthy" | "neutral";

export type MdmStateKind =
  | "enrolled-registry"
  | "no-enrollment-registry"
  | "urls-present"
  | "urls-partial"
  | "no-urls";

export interface MdmState {
  kind: MdmStateKind;
  label: string;
  tone: "pass" | "warn" | "neutral";
}

const HEADLINE_SEPARATOR = " · ";

const JOIN_CLAUSES: Record<DsregcmdJoinType, string> = {
  EntraIdJoined: "Entra joined",
  HybridEntraIdJoined: "Hybrid Entra joined",
  NotJoined: "Not joined to Entra ID",
  Unknown: "Join state not reported",
};

const MANAGEMENT_CLAUSES: Record<MdmStateKind, string> = {
  "enrolled-registry": "MDM enrollment confirmed in registry",
  "no-enrollment-registry": "No MDM enrollment in registry",
  "urls-present": "MDM URLs present",
  "urls-partial": "MDM URLs partially reported",
  "no-urls": "No MDM URLs reported",
};

/**
 * Error if any diagnostic is an Error, else Warning if any is a Warning, else
 * healthy only for a joined device. A NotJoined or Unknown join type is never
 * healthy: a missing value is a coverage state, not a clean bill of health.
 */
export function getVerdictTone(result: DsregcmdAnalysisResult): VerdictTone {
  const { diagnostics, derived } = result;
  if (diagnostics.some((item) => item.severity === "Error")) {
    return "error";
  }
  if (diagnostics.some((item) => item.severity === "Warning")) {
    return "warning";
  }
  return derived.joinType === "EntraIdJoined" ||
    derived.joinType === "HybridEntraIdJoined"
    ? "healthy"
    : "neutral";
}

/**
 * Mirrors `apply_enrollment_cross_reference`
 * (crates/cmtraceopen-parser/src/dsregcmd/extended.rs): an enrollment entry in
 * state 1 whose GUID equals, after `toLowerCase` folding, an EnterpriseMgmt
 * scheduled task GUID.
 *
 * Deliberately omits the Rust `mdm_enrolled` gate of that function
 * (extended.rs:11-13): registry evidence must still confirm enrollment when
 * MDM URLs are present, which is the most common enrolled device.
 */
function hasRegistryEnrollmentMatch(result: DsregcmdAnalysisResult): boolean {
  const { enrollmentEvidence, scheduledTaskEvidence } = result;
  if (!enrollmentEvidence || !scheduledTaskEvidence) {
    return false;
  }
  const taskGuids = scheduledTaskEvidence.enterpriseMgmtGuids.map((guid) =>
    guid.toLowerCase(),
  );
  return enrollmentEvidence.enrollments.some(
    (entry) =>
      entry.enrollmentState === 1 &&
      entry.guid !== null &&
      taskGuids.includes(entry.guid.toLowerCase()),
  );
}

/** MDM chip state. The first matching rule wins (spec 8.4). */
export function getMdmState(result: DsregcmdAnalysisResult): MdmState {
  const hasDiagnostic = (id: string) =>
    result.diagnostics.some((item) => item.id === id);

  if (
    hasDiagnostic("mdm-confirmed-via-registry") ||
    hasRegistryEnrollmentMatch(result)
  ) {
    return {
      kind: "enrolled-registry",
      label: "Enrolled (registry)",
      tone: "pass",
    };
  }
  if (hasDiagnostic("enrollment-missing-on-joined")) {
    return {
      kind: "no-enrollment-registry",
      label: "No enrollment (registry)",
      tone: "warn",
    };
  }

  const { mdmUrl, mdmComplianceUrl } = result.facts.managementDetails;
  if (mdmUrl !== null && mdmComplianceUrl !== null) {
    return { kind: "urls-present", label: "URLs present", tone: "neutral" };
  }
  if (mdmUrl !== null || mdmComplianceUrl !== null) {
    return { kind: "urls-partial", label: "URLs partial", tone: "neutral" };
  }
  return { kind: "no-urls", label: "No URLs", tone: "neutral" };
}

/**
 * "{join clause} · {management clause}". NotJoined and Unknown carry no
 * management clause.
 */
export function getVerdictHeadline(result: DsregcmdAnalysisResult): string {
  const { joinType } = result.derived;
  const joinClause = JOIN_CLAUSES[joinType];
  if (joinType === "NotJoined" || joinType === "Unknown") {
    return joinClause;
  }
  return [joinClause, MANAGEMENT_CLAUSES[getMdmState(result).kind]].join(
    HEADLINE_SEPARATOR,
  );
}

/** "Top issue: {title}" for the first Error, as `getSummaryText` picks it. */
export function getTopIssueLine(result: DsregcmdAnalysisResult): string | null {
  const critical = result.diagnostics.find((item) => item.severity === "Error");
  return critical ? `Top issue: ${critical.title}` : null;
}

/** Error, then Warning, then Info; engine order is kept inside a severity. */
export function sortDiagnostics(
  diagnostics: readonly DsregcmdDiagnosticInsight[],
): DsregcmdDiagnosticInsight[] {
  return selectTopFindings(diagnostics, diagnostics.length);
}
