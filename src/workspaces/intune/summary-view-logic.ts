import type {
  IntuneDiagnosticCategory,
  IntuneDiagnosticInsight,
  IntuneDiagnosticsCoverage,
  IntuneDiagnosticsConfidence,
  IntuneEvent,
  IntuneEventType,
  IntuneRepeatedFailureGroup,
  IntuneRemediationPriority,
  IntuneStatus,
  IntuneSummary,
} from "./types";
import {
  formatEventShare,
  getFileName,
  remediationPriorityRank,
  toSentence,
  truncateText,
} from "./intune-dashboard-utils";
import { formatEventTypeLabel } from "./useTimeWindowFilter";

export type SummaryConclusionSection = "coverage" | "confidence" | "repeatedFailures" | "guidance";

type SummaryConclusionAction =
  | {
    kind: "section";
    section: SummaryConclusionSection;
  }
  | {
    kind: "timeline";
    eventType?: IntuneEventType | "All";
    status?: IntuneStatus | "All";
    filePath?: string | null;
    selectFirstMatch?: boolean;
  };

export interface SummaryConclusion {
  id: string;
  text: string;
  tone: "neutral" | "info" | "warning" | "critical";
  hint: string;
  action: SummaryConclusionAction;
}

export interface RemediationPlanStep {
  diagnosticId: string;
  title: string;
  action: string;
  reason: string;
  priority: IntuneRemediationPriority;
  category: IntuneDiagnosticCategory;
}

export function buildSummaryConclusions({
  summary,
  diagnostics,
  diagnosticsCoverage,
  diagnosticsConfidence,
  repeatedFailures,
}: {
  summary: IntuneSummary;
  diagnostics: IntuneDiagnosticInsight[];
  diagnosticsCoverage: IntuneDiagnosticsCoverage;
  diagnosticsConfidence: IntuneDiagnosticsConfidence;
  repeatedFailures: IntuneRepeatedFailureGroup[];
}): SummaryConclusion[] {
  const conclusions: SummaryConclusion[] = [];
  const topRepeatedFailure = repeatedFailures[0];
  const topDiagnostic =
    diagnostics.find((diagnostic) => diagnostic.severity === "Error") ??
    diagnostics.find((diagnostic) => diagnostic.severity === "Warning") ??
    diagnostics[0];

  if (topRepeatedFailure) {
    conclusions.push({
      id: "repeated-failure",
      text: `Start with ${truncateText(topRepeatedFailure.name, 88)}: ${topRepeatedFailure.occurrences} ${formatEventTypeLabel(topRepeatedFailure.eventType).toLowerCase()} failures repeat with the same outcome.`,
      tone: "critical",
      hint: "Filter timeline",
      action: {
        kind: "timeline",
        eventType: topRepeatedFailure.eventType,
        status: "Failed",
        filePath: null,
        selectFirstMatch: true,
      },
    });
  } else if (summary.failed > 0 || summary.timedOut > 0) {
    conclusions.push({
      id: "failed-events",
      text: `Review the failure queue: ${summary.failed + summary.timedOut} event(s) finished failed in this analysis window.`,
      tone: "warning",
      hint: "Filter timeline",
      action: {
        kind: "timeline",
        eventType: "All",
        status: "Failed",
        filePath: null,
        selectFirstMatch: true,
      },
    });
  }

  if (topDiagnostic) {
    conclusions.push({
      id: `diagnostic-${topDiagnostic.id}`,
      text: `Next check: ${topDiagnostic.title}. ${toSentence(topDiagnostic.summary)}`,
      tone:
        topDiagnostic.severity === "Error"
          ? "critical"
          : topDiagnostic.severity === "Warning"
            ? "warning"
            : "info",
      hint: "Jump to guidance",
      action: {
        kind: "section",
        section: "guidance",
      },
    });
  }

  if (diagnosticsCoverage.dominantSource) {
    const dominantSource = diagnosticsCoverage.dominantSource;
    conclusions.push({
      id: "dominant-source",
      text: `Use ${getFileName(dominantSource.filePath)} as the lead evidence file: it contributes ${formatEventShare(dominantSource.eventShare ?? 0)} of extracted events.`,
      tone: diagnosticsConfidence.level === "Low" ? "warning" : "neutral",
      hint: "Scope timeline",
      action: {
        kind: "timeline",
        eventType: "All",
        status: "All",
        filePath: dominantSource.filePath,
      },
    });
  } else if (diagnosticsConfidence.reasons[0]) {
    conclusions.push({
      id: "confidence",
      text: `Treat this summary as ${diagnosticsConfidence.level.toLowerCase()} confidence because ${toSentence(diagnosticsConfidence.reasons[0]).replace(/[.]$/, "")}.`,
      tone: diagnosticsConfidence.level === "Low" ? "warning" : "info",
      hint: "Jump to confidence",
      action: {
        kind: "section",
        section: "confidence",
      },
    });
  }

  return conclusions.slice(0, 3);
}

export function matchesTimelineAction(
  event: IntuneEvent,
  action: Extract<SummaryConclusionAction, { kind: "timeline" }>
): boolean {
  if (action.filePath != null && event.sourceFile !== action.filePath) {
    return false;
  }

  if (action.eventType != null && action.eventType !== "All" && event.eventType !== action.eventType) {
    return false;
  }

  if (action.status != null && action.status !== "All" && event.status !== action.status) {
    return false;
  }

  return true;
}

export function buildRemediationPlan(
  diagnostics: IntuneDiagnosticInsight[]
): RemediationPlanStep[] {
  return [...diagnostics]
    .sort((left, right) => {
      return remediationPriorityRank(right.remediationPriority) - remediationPriorityRank(left.remediationPriority);
    })
    .slice(0, 3)
    .map((diagnostic) => ({
      diagnosticId: diagnostic.id,
      title: diagnostic.title,
      action:
        diagnostic.suggestedFixes[0] ??
        diagnostic.nextChecks[0] ??
        diagnostic.summary,
      reason:
        diagnostic.likelyCause ??
        diagnostic.evidence[0] ??
        diagnostic.summary,
      priority: diagnostic.remediationPriority,
      category: diagnostic.category,
    }));
}
