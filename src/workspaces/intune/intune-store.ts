import { create } from "zustand";
import { parseDisplayDateTimeValue } from "../../lib/date-time-format";
import type { EvidenceBundleMetadata } from "../../types/evidence";
import type {
  EventLogAnalysis,
  EventLogChannel,
  EventLogCorrelationLink,
  EventLogSeverity,
} from "../../types/event-log";
import type {
  AppPolicyMetadata,
  DownloadStat,
  IntuneAnalysisProgressEvent,
  IntuneAnalysisSourceKind,
  IntuneAnalysisState,
  IntuneDiagnosticInsight,
  IntuneDiagnosticsConfidence,
  IntuneDiagnosticsCoverage,
  IntuneDiagnosticsFileCoverage,
  IntuneEvent,
  IntuneEventType,
  IntuneRepeatedFailureGroup,
  IntuneResultMetadata,
  IntuneSourceContext,
  IntuneSourceSelection,
  IntuneStatus,
  IntuneSummary,
  IntuneTimeWindowPreset,
  IntuneTimelineScope,
  IntuneTimestampBounds,
} from "./types";

export type IntuneWorkspaceTab = "timeline" | "downloads" | "summary";
export type IntuneTimelineViewMode = "list" | "activity";
export type IntuneSortField = "time" | "name" | "type" | "status" | "duration";
export type DownloadSortField = "name" | "size" | "speed" | "doPercentage" | "duration" | "timestamp";
export type SortDirection = "asc" | "desc";

function buildSourceContext(
  sourceFile: string | null,
  sourceFiles: string[]
): IntuneSourceContext {
  return {
    analyzedPath: sourceFile,
    includedFiles:
      sourceFiles.length > 0 ? sourceFiles : sourceFile != null ? [sourceFile] : [],
  };
}

function buildSourceSelection(
  filePath: string | null,
  lineNumber: number | null = null
): IntuneSourceSelection {
  return {
    filePath,
    lineNumber,
  };
}

function buildTimelineScope(filePath: string | null): IntuneTimelineScope {
  return { filePath };
}

function buildEmptyDiagnosticsCoverage(): IntuneDiagnosticsCoverage {
  return {
    files: [],
    timestampBounds: null,
    hasRotatedLogs: false,
    dominantSource: null,
  };
}

function buildEmptyDiagnosticsConfidence(): IntuneDiagnosticsConfidence {
  return {
    level: "Unknown",
    score: null,
    reasons: [],
  };
}

function isEmptyAnalysisDetail(detail: string): boolean {
  const normalized = detail.toLowerCase();
  return (
    normalized.includes("does not contain any .log files") ||
    normalized.includes("no .log files found in directory")
  );
}

function getAnalysisFailureState(
  error: unknown,
  requestedKind: IntuneAnalysisSourceKind | null
): Pick<IntuneAnalysisState, "phase" | "message" | "detail" | "lastError"> {
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "The selected Intune source could not be analyzed.";

  if (isEmptyAnalysisDetail(detail)) {
    return {
      phase: "empty",
      message: "No IME log files were found in this folder.",
      detail:
        "Choose a folder that contains IME log files such as IntuneManagementExtension.log or AppWorkload.log.",
      lastError: detail,
    };
  }

  const sourceLabel =
    requestedKind === "folder"
      ? "folder"
      : requestedKind === "file"
        ? "file"
        : "source";

  return {
    phase: "error",
    message: `Intune diagnostics could not read the selected ${sourceLabel}.`,
    detail,
    lastError: detail,
  };
}

function buildResultMetadata(
  events: IntuneEvent[],
  downloads: DownloadStat[],
  summary: IntuneSummary,
  sourceFiles: string[],
  metadata?: Partial<IntuneResultMetadata>
): IntuneResultMetadata {
  const diagnosticsCoverage =
    metadata?.diagnosticsCoverage ?? buildDerivedCoverage(sourceFiles, events, downloads);
  const repeatedFailures =
    metadata?.repeatedFailures ?? buildDerivedRepeatedFailures(events);
  const diagnosticsConfidence =
    metadata?.diagnosticsConfidence ??
    buildDerivedConfidence(summary, diagnosticsCoverage, repeatedFailures, events);

  return {
    diagnosticsCoverage,
    diagnosticsConfidence,
    repeatedFailures,
  };
}

const emptySourceContext = buildSourceContext(null, []);
const emptyTimelineScope = buildTimelineScope(null);
const emptyDiagnosticsCoverage = buildEmptyDiagnosticsCoverage();
const emptyDiagnosticsConfidence = buildEmptyDiagnosticsConfidence();

const defaultAnalysisState: IntuneAnalysisState = {
  phase: "idle",
  requestedPath: null,
  requestedKind: null,
  requestId: null,
  message: "Choose an Intune log file or folder to analyze.",
  detail: null,
  lastError: null,
  progress: null,
};

interface IntuneState {
  events: IntuneEvent[];
  downloads: DownloadStat[];
  summary: IntuneSummary | null;
  diagnostics: IntuneDiagnosticInsight[];
  diagnosticsCoverage: IntuneDiagnosticsCoverage;
  diagnosticsConfidence: IntuneDiagnosticsConfidence;
  repeatedFailures: IntuneRepeatedFailureGroup[];
  evidenceBundle: EvidenceBundleMetadata | null;
  eventLogAnalysis: EventLogAnalysis | null;
  policyMetadata: Record<string, AppPolicyMetadata>;
  guidRegistry: Record<string, import("./types").GuidRegistryEntry>;
  sourceFile: string | null;
  sourceFiles: string[];
  sourceContext: IntuneSourceContext;
  isAnalyzing: boolean;
  analysisState: IntuneAnalysisState;
  selectedEventId: number | null;
  selectedEventLogEntryId: number | null;
  sourceSelection: IntuneSourceSelection;
  timelineScope: IntuneTimelineScope;
  timeWindow: IntuneTimeWindowPreset;
  filterEventType: IntuneEventType | "All";
  filterStatus: IntuneStatus | "All";
  eventLogFilterChannel: EventLogChannel | "All";
  eventLogFilterSeverity: EventLogSeverity | "All";
  activeTab: IntuneWorkspaceTab;
  timelineViewMode: IntuneTimelineViewMode;
  sortField: IntuneSortField;
  sortDirection: SortDirection;
  downloadSortField: DownloadSortField;
  downloadSortDirection: SortDirection;
  resultRevision: number;

  beginAnalysis: (
    requestedPath: string | null,
    requestedKind?: IntuneAnalysisSourceKind,
    requestId?: string | null
  ) => void;
  updateAnalysisProgress: (progress: IntuneAnalysisProgressEvent) => void;
  setResults: (
    events: IntuneEvent[],
    downloads: DownloadStat[],
    summary: IntuneSummary,
    diagnostics: IntuneDiagnosticInsight[],
    sourceFile: string,
    sourceFiles: string[],
    metadata?: Partial<IntuneResultMetadata>
  ) => void;
  failAnalysis: (error: unknown) => void;
  selectEvent: (id: number | null) => void;
  setTimelineFileScope: (path: string | null) => void;
  clearTimelineFileScope: () => void;
  setTimeWindow: (preset: IntuneTimeWindowPreset) => void;
  setFilterEventType: (type_: IntuneEventType | "All") => void;
  setFilterStatus: (status: IntuneStatus | "All") => void;
  setEventLogFilterChannel: (channel: EventLogChannel | "All") => void;
  setEventLogFilterSeverity: (severity: EventLogSeverity | "All") => void;
  mergeGuidRegistry: (entries: Record<string, import("./types").GuidRegistryEntry>) => void;
  selectEventLogEntry: (id: number | null) => void;
  setActiveTab: (tab: IntuneWorkspaceTab) => void;
  setTimelineViewMode: (mode: IntuneTimelineViewMode) => void;
  setSortField: (field: IntuneSortField) => void;
  toggleSortDirection: () => void;
  setDownloadSortField: (field: DownloadSortField) => void;
  toggleDownloadSortDirection: () => void;
  clear: () => void;
}

const defaultInteractionState = {
  selectedEventId: null,
  selectedEventLogEntryId: null as number | null,
  timeWindow: "all" as const,
  filterEventType: "All" as const,
  filterStatus: "All" as const,
  eventLogFilterChannel: "All" as EventLogChannel | "All",
  eventLogFilterSeverity: "All" as EventLogSeverity | "All",
  activeTab: "timeline" as const,
  timelineViewMode: "list" as const,
  sortField: "time" as IntuneSortField,
  sortDirection: "asc" as SortDirection,
  downloadSortField: "timestamp" as DownloadSortField,
  downloadSortDirection: "asc" as SortDirection,
};

export const useIntuneStore = create<IntuneState>((set) => ({
  events: [],
  downloads: [],
  summary: null,
  diagnostics: [],
  diagnosticsCoverage: emptyDiagnosticsCoverage,
  diagnosticsConfidence: emptyDiagnosticsConfidence,
  repeatedFailures: [],
  evidenceBundle: null,
  eventLogAnalysis: null,
  policyMetadata: {},
  guidRegistry: {},
  sourceFile: null,
  sourceFiles: [],
  sourceContext: emptySourceContext,
  isAnalyzing: false,
  analysisState: defaultAnalysisState,
  resultRevision: 0,
  sourceSelection: buildSourceSelection(null),
  timelineScope: emptyTimelineScope,
  ...defaultInteractionState,

  beginAnalysis: (requestedPath, requestedKind = "unknown", requestId = null) =>
    set({
      events: [],
      downloads: [],
      summary: null,
      diagnostics: [],
      diagnosticsCoverage: emptyDiagnosticsCoverage,
      diagnosticsConfidence: emptyDiagnosticsConfidence,
      repeatedFailures: [],
      evidenceBundle: null,
      eventLogAnalysis: null,
      policyMetadata: {},
      guidRegistry: {},
      sourceFile: null,
      sourceFiles: [],
      sourceContext: emptySourceContext,
      isAnalyzing: true,
      analysisState: {
        phase: "analyzing",
        requestedPath,
        requestedKind,
        requestId,
        message:
          requestedKind === "folder"
            ? "Analyzing Intune folder..."
            : "Analyzing Intune log source...",
        detail: requestedPath,
        lastError: null,
        progress: null,
      },
      sourceSelection: buildSourceSelection(null),
      timelineScope: emptyTimelineScope,
      ...defaultInteractionState,
    }),

  updateAnalysisProgress: (progress) =>
    set((state) => {
      if (state.analysisState.phase !== "analyzing") {
        return state;
      }

      if (
        state.analysisState.requestId != null &&
        state.analysisState.requestId !== progress.requestId
      ) {
        return state;
      }

      return {
        analysisState: {
          ...state.analysisState,
          requestId: progress.requestId,
          message: progress.message,
          detail: progress.detail,
          progress: {
            stage: progress.stage,
            currentFile: progress.currentFile,
            completedFiles: progress.completedFiles,
            totalFiles: progress.totalFiles,
          },
        },
      };
    }),

  setResults: (events, downloads, summary, diagnostics, sourceFile, sourceFiles, metadata) =>
    set((state) => {
      const sourceContext = buildSourceContext(sourceFile, sourceFiles);
      const resultMetadata = buildResultMetadata(
        events,
        downloads,
        summary,
        sourceContext.includedFiles,
        metadata
      );
      const requestedKind =
        state.analysisState.requestedKind ?? (sourceFiles.length > 1 ? "folder" : "file");

      return {
        events,
        downloads,
        summary,
        diagnostics,
        diagnosticsCoverage: resultMetadata.diagnosticsCoverage,
        diagnosticsConfidence: resultMetadata.diagnosticsConfidence,
        repeatedFailures: resultMetadata.repeatedFailures,
        evidenceBundle: metadata?.evidenceBundle ?? null,
        eventLogAnalysis: metadata?.eventLogAnalysis ?? null,
        policyMetadata: metadata?.policyMetadata ?? {},
        guidRegistry: metadata?.guidRegistry ?? {},
        sourceFile,
        sourceFiles,
        sourceContext,
        isAnalyzing: false,
        analysisState: {
          phase: "ready",
          requestedPath: state.analysisState.requestedPath ?? sourceFile,
          requestedKind,
          requestId: null,
          message:
            sourceFiles.length > 1
              ? `Analysis complete (${sourceFiles.length} files)`
              : "Analysis complete",
          detail: sourceFile,
          lastError: null,
          progress: null,
        },
        resultRevision: state.resultRevision + 1,
        sourceSelection: buildSourceSelection(null),
        timelineScope: emptyTimelineScope,
        ...defaultInteractionState,
      };
    }),

  failAnalysis: (error) =>
    set((state) => {
      const failureState = getAnalysisFailureState(
        error,
        state.analysisState.requestedKind
      );

      return {
        isAnalyzing: false,
        analysisState: {
          requestedPath: state.analysisState.requestedPath,
          requestedKind: state.analysisState.requestedKind,
          requestId: null,
          ...failureState,
          progress: null,
        },
      };
    }),

  selectEvent: (id) =>
    set((state) => {
      if (id == null) {
        return {
          selectedEventId: null,
          sourceSelection: buildSourceSelection(state.timelineScope.filePath),
        };
      }

      const selectedEvent = state.events.find((event) => event.id === id);

      return {
        selectedEventId: id,
        sourceSelection: buildSourceSelection(
          selectedEvent?.sourceFile ?? state.timelineScope.filePath,
          selectedEvent?.lineNumber ?? null
        ),
      };
    }),

  setTimelineFileScope: (path) =>
    set((state) => {
      const nextPath =
        path != null && state.sourceContext.includedFiles.includes(path) ? path : null;
      const selectedEvent = state.events.find((event) => event.id === state.selectedEventId);
      const keepSelectedEvent =
        selectedEvent != null &&
        (nextPath == null || selectedEvent.sourceFile === nextPath);

      return {
        timelineScope: buildTimelineScope(nextPath),
        selectedEventId: keepSelectedEvent ? state.selectedEventId : null,
        sourceSelection: keepSelectedEvent
          ? buildSourceSelection(
            selectedEvent?.sourceFile ?? nextPath,
            selectedEvent?.lineNumber ?? null
          )
          : buildSourceSelection(nextPath),
      };
    }),

  clearTimelineFileScope: () =>
    set((state) => {
      const selectedEvent = state.events.find((event) => event.id === state.selectedEventId);
      return {
        timelineScope: emptyTimelineScope,
        sourceSelection: buildSourceSelection(
          selectedEvent?.sourceFile ?? null,
          selectedEvent?.lineNumber ?? null
        ),
      };
    }),

  setTimeWindow: (preset) => set({ timeWindow: preset }),
  setFilterEventType: (type_) => set({ filterEventType: type_ }),
  setFilterStatus: (status) => set({ filterStatus: status }),
  setEventLogFilterChannel: (channel) => set({ eventLogFilterChannel: channel }),
  setEventLogFilterSeverity: (severity) => set({ eventLogFilterSeverity: severity }),
  mergeGuidRegistry: (entries) => set((state) => ({
    guidRegistry: { ...state.guidRegistry, ...entries },
  })),
  selectEventLogEntry: (id) => set({ selectedEventLogEntryId: id }),
  setActiveTab: (tab) => set({ activeTab: tab }),
  setTimelineViewMode: (mode) => set({ timelineViewMode: mode }),
  setSortField: (field) => set({ sortField: field }),
  toggleSortDirection: () =>
    set((state) => ({ sortDirection: state.sortDirection === "asc" ? "desc" : "asc" })),
  setDownloadSortField: (field) => set({ downloadSortField: field }),
  toggleDownloadSortDirection: () =>
    set((state) => ({ downloadSortDirection: state.downloadSortDirection === "asc" ? "desc" : "asc" })),

  clear: () =>
    set({
      events: [],
      downloads: [],
      summary: null,
      diagnostics: [],
      diagnosticsCoverage: emptyDiagnosticsCoverage,
      diagnosticsConfidence: emptyDiagnosticsConfidence,
      repeatedFailures: [],
      evidenceBundle: null,
      eventLogAnalysis: null,
      policyMetadata: {},
      guidRegistry: {},
      sourceFile: null,
      sourceFiles: [],
      sourceContext: emptySourceContext,
      isAnalyzing: false,
      analysisState: defaultAnalysisState,
      resultRevision: 0,
      sourceSelection: buildSourceSelection(null),
      timelineScope: emptyTimelineScope,
      ...defaultInteractionState,
    }),
}));

function buildDerivedCoverage(
  sourceFiles: string[],
  events: IntuneEvent[],
  downloads: DownloadStat[]
): IntuneDiagnosticsCoverage {
  const filePaths = new Set<string>(sourceFiles);
  for (const event of events) {
    filePaths.add(event.sourceFile);
  }

  const eventCounts = new Map<string, number>();
  const fileEvents = new Map<string, IntuneEvent[]>();
  for (const event of events) {
    eventCounts.set(event.sourceFile, (eventCounts.get(event.sourceFile) ?? 0) + 1);
    const existing = fileEvents.get(event.sourceFile);
    if (existing) {
      existing.push(event);
    } else {
      fileEvents.set(event.sourceFile, [event]);
    }
  }

  const fallbackDownloadFilePath =
    downloads.length > 0 && sourceFiles.length === 1 ? sourceFiles[0] : null;
  const rotationEntries = Array.from(filePaths).map((filePath) => ({
    filePath,
    rotation: detectRotationMetadata(filePath),
  }));
  const rotationCounts = new Map<string, number>();
  for (const entry of rotationEntries) {
    if (entry.rotation.rotationGroup) {
      rotationCounts.set(
        entry.rotation.rotationGroup,
        (rotationCounts.get(entry.rotation.rotationGroup) ?? 0) + 1
      );
    }
  }

  const files = rotationEntries
    .map(({ filePath, rotation }) => {
      const groupedEvents = fileEvents.get(filePath) ?? [];
      const timestampBounds = buildTimestampBounds(groupedEvents, []);
      const rotationGroup =
        rotation.rotationGroup && (rotationCounts.get(rotation.rotationGroup) ?? 0) > 1
          ? rotation.rotationGroup
          : null;

      return {
        filePath,
        eventCount: eventCounts.get(filePath) ?? 0,
        downloadCount: filePath === fallbackDownloadFilePath ? downloads.length : 0,
        timestampBounds,
        isRotatedSegment: rotationGroup != null ? rotation.isRotatedSegment : false,
        rotationGroup,
      } satisfies IntuneDiagnosticsFileCoverage;
    })
    .sort((left, right) => {
      const leftActivity = left.eventCount + left.downloadCount;
      const rightActivity = right.eventCount + right.downloadCount;
      return rightActivity - leftActivity || left.filePath.localeCompare(right.filePath);
    });

  const overallTimestampBounds = buildTimestampBounds(events, downloads);
  const mergedTimestampBounds = mergeTimestampBounds([
    ...files
      .map((file) => file.timestampBounds)
      .filter((value): value is IntuneTimestampBounds => value != null),
    ...(overallTimestampBounds ? [overallTimestampBounds] : []),
  ]);

  return {
    files,
    timestampBounds: mergedTimestampBounds,
    hasRotatedLogs: files.some((file) => file.rotationGroup != null),
    dominantSource: buildDominantSource(files, events),
  };
}

function buildDerivedConfidence(
  summary: IntuneSummary,
  coverage: IntuneDiagnosticsCoverage,
  repeatedFailures: IntuneRepeatedFailureGroup[],
  events: IntuneEvent[]
): IntuneDiagnosticsConfidence {
  if (summary.totalEvents === 0 && summary.totalDownloads === 0) {
    return {
      level: "Unknown",
      score: null,
      reasons: ["No Intune events or download evidence were available."],
    };
  }

  let score = 0.15;
  const reasons: string[] = [];
  const failedEvents = events.filter(
    (event) => event.status === "Failed" || event.status === "Timeout"
  ).length;
  const distinctKinds = distinctSourceKinds(coverage.files);
  const contributingFiles = coverage.files.filter(
    (file) => file.eventCount > 0 || file.downloadCount > 0
  ).length;

  if (summary.totalEvents >= 20) {
    score += 0.25;
    reasons.push(`${summary.totalEvents} events were extracted across the selected logs.`);
  } else if (summary.totalEvents >= 8) {
    score += 0.15;
    reasons.push(`${summary.totalEvents} events were extracted across the selected logs.`);
  } else if (summary.totalEvents > 0) {
    score += 0.05;
    reasons.push(`Only ${summary.totalEvents} event(s) were extracted, so the evidence set is narrow.`);
  }

  if (failedEvents >= 4) {
    score += 0.2;
    reasons.push(`${failedEvents} failed or timed-out event(s) were available for review.`);
  } else if (failedEvents > 0) {
    score += 0.1;
    reasons.push(`${failedEvents} failed or timed-out event(s) were available for review.`);
  }

  if (distinctKinds >= 3) {
    score += 0.2;
    reasons.push(`Evidence spans ${distinctKinds} distinct Intune log families.`);
  } else if (distinctKinds === 2) {
    score += 0.1;
    reasons.push("Evidence spans two distinct Intune log families.");
  }

  if (coverage.timestampBounds) {
    score += 0.1;
    reasons.push("Parsed timestamps were available for the overall diagnostics window.");
  }

  if (repeatedFailures.length > 0) {
    score += 0.15;
    reasons.push(`${repeatedFailures.length} repeated failure group(s) were identified deterministically.`);
  }

  if (coverage.hasRotatedLogs) {
    score += 0.05;
    reasons.push("Rotated log segments were available, which improves continuity across retries.");
  }

  if (contributingFiles <= 1) {
    score -= 0.15;
    reasons.push("Evidence comes from a single contributing source file.");
  }

  if (
    coverage.files.some(
      (file) =>
        (file.eventCount > 0 || file.downloadCount > 0) && file.timestampBounds == null
    )
  ) {
    score -= 0.1;
    reasons.push(
      "Some contributing files had no parseable timestamps, which weakens ordering confidence."
    );
  }

  if (summary.totalEvents === 0 && summary.totalDownloads > 0) {
    score -= 0.2;
    reasons.push("Only download statistics were available; no correlated Intune events were extracted.");
  }

  if (
    summary.inProgress + summary.pending > summary.failed + summary.succeeded &&
    summary.totalEvents > 0
  ) {
    score -= 0.1;
    reasons.push(
      "Most observed work is still pending or in progress, so the failure picture may be incomplete."
    );
  }

  if (hasAppOrDownloadFailures(events) && !hasSourceKind(coverage.files, "appworkload")) {
    score -= 0.15;
    reasons.push("AppWorkload evidence was not available for app or download failures.");
  }

  if (hasPolicyFailures(events) && !hasSourceKind(coverage.files, "appactionprocessor")) {
    score -= 0.15;
    reasons.push("AppActionProcessor evidence was not available for applicability or policy failures.");
  }

  if (
    hasScriptFailures(events) &&
    !hasSourceKind(coverage.files, "agentexecutor") &&
    !hasSourceKind(coverage.files, "healthscripts")
  ) {
    score -= 0.15;
    reasons.push("AgentExecutor or HealthScripts evidence was not available for script-related failures.");
  }

  score = Math.max(0, Math.min(1, score));

  return {
    level: score >= 0.75 ? "High" : score >= 0.45 ? "Medium" : "Low",
    score: Math.round(score * 1000) / 1000,
    reasons,
  };
}

function buildDerivedRepeatedFailures(events: IntuneEvent[]): IntuneRepeatedFailureGroup[] {
  const groups = new Map<
    string,
    {
      name: string;
      eventType: IntuneEventType;
      errorCode: string | null;
      occurrences: number;
      sourceFiles: Set<string>;
      sampleEventIds: number[];
      earliest: string | null;
      latest: string | null;
      reasonDisplay: string;
    }
  >();

  for (const event of events) {
    if (event.status !== "Failed" && event.status !== "Timeout") {
      continue;
    }

    const reason = normalizeFailureReason(event);
    const subjectKey = event.guid ?? normalizeIdentifier(event.name);
    const key = `${event.eventType}|${subjectKey}|${reason.key}`;
    const existing = groups.get(key);

    if (existing) {
      existing.occurrences += 1;
      existing.sourceFiles.add(event.sourceFile);
      if (existing.sampleEventIds.length < 5) {
        existing.sampleEventIds.push(event.id);
      }
      if (event.name.length < existing.name.length) {
        existing.name = event.name;
      }
      if (!existing.errorCode && event.errorCode) {
        existing.errorCode = event.errorCode;
      }
      const timestamp = event.startTime ?? event.endTime;
      if (timestamp) {
        existing.earliest = pickEarlierTimestamp(existing.earliest, timestamp);
        existing.latest = pickLaterTimestamp(existing.latest, timestamp);
      }
      continue;
    }

    const timestamp = event.startTime ?? event.endTime;
    groups.set(key, {
      name: event.name,
      eventType: event.eventType,
      errorCode: event.errorCode,
      occurrences: 1,
      sourceFiles: new Set([event.sourceFile]),
      sampleEventIds: [event.id],
      earliest: timestamp,
      latest: timestamp,
      reasonDisplay: reason.display,
    });
  }

  return Array.from(groups.entries())
    .filter(([, group]) => group.occurrences >= 2)
    .map(([key, group]) => ({
      id: `repeated-${normalizeIdentifier(key)}`,
      name: `${group.name}: ${group.reasonDisplay}`,
      eventType: group.eventType,
      errorCode: group.errorCode,
      occurrences: group.occurrences,
      timestampBounds:
        group.earliest && group.latest
          ? {
            firstTimestamp: group.earliest,
            lastTimestamp: group.latest,
          }
          : null,
      sourceFiles: Array.from(group.sourceFiles).sort((left, right) => left.localeCompare(right)),
      sampleEventIds: group.sampleEventIds,
    }))
    .sort(
      (left, right) => right.occurrences - left.occurrences || left.name.localeCompare(right.name)
    );
}

function normalizeFailureReason(event: IntuneEvent): { key: string; display: string } {
  if (event.errorCode) {
    return {
      key: `code-${normalizeIdentifier(event.errorCode)}`,
      display: event.errorCode,
    };
  }

  const detail = event.detail.toLowerCase();
  const patterns: Array<[string, string]> = [
    ["access is denied", "access is denied"],
    ["permission denied", "permission denied"],
    ["unauthorized", "unauthorized"],
    ["not applicable", "not applicable"],
    ["will not be enforced", "will not be enforced"],
    ["requirement rule", "requirement rule blocked enforcement"],
    ["detection rule", "detection rule blocked enforcement"],
    ["hash validation failed", "hash validation failed"],
    ["hash mismatch", "hash mismatch"],
    ["timed out", "operation timed out"],
    ["timeout", "operation timed out"],
  ];

  for (const [pattern, label] of patterns) {
    if (detail.includes(pattern)) {
      return {
        key: normalizeIdentifier(label),
        display: label,
      };
    }
  }

  const compactDetail = event.detail.trim().replace(/\s+/g, " ");
  const fallback = compactDetail.length > 72 ? `${compactDetail.slice(0, 69)}...` : compactDetail;
  return {
    key: normalizeIdentifier(fallback || event.status),
    display: fallback || event.status,
  };
}

function buildTimestampBounds(
  events: IntuneEvent[],
  downloads: DownloadStat[]
): IntuneTimestampBounds | null {
  const timestamps = [
    ...events.flatMap((event) => [event.startTime, event.endTime]),
    ...downloads.map((download) => download.timestamp),
  ].filter((value): value is string => Boolean(value));

  let earliest: string | null = null;
  let latest: string | null = null;
  for (const timestamp of timestamps) {
    earliest = pickEarlierTimestamp(earliest, timestamp);
    latest = pickLaterTimestamp(latest, timestamp);
  }

  if (!earliest || !latest) {
    return null;
  }

  return {
    firstTimestamp: earliest,
    lastTimestamp: latest,
  };
}

function mergeTimestampBounds(boundsList: IntuneTimestampBounds[]): IntuneTimestampBounds | null {
  let earliest: string | null = null;
  let latest: string | null = null;

  for (const bounds of boundsList) {
    if (bounds.firstTimestamp) {
      earliest = pickEarlierTimestamp(earliest, bounds.firstTimestamp);
    }
    if (bounds.lastTimestamp) {
      latest = pickLaterTimestamp(latest, bounds.lastTimestamp);
    }
  }

  if (!earliest || !latest) {
    return null;
  }

  return {
    firstTimestamp: earliest,
    lastTimestamp: latest,
  };
}

function buildDominantSource(
  files: IntuneDiagnosticsFileCoverage[],
  events: IntuneEvent[]
): IntuneDiagnosticsCoverage["dominantSource"] {
  const totalEvents = events.length;
  const scores = new Map<string, number>();

  for (const event of events) {
    scores.set(event.sourceFile, (scores.get(event.sourceFile) ?? 0) + eventSignalScore(event));
  }

  const rankedFiles = files
    .map((file) => ({ file, score: scores.get(file.filePath) ?? 0 }))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => {
      return (
        right.score - left.score ||
        right.file.eventCount - left.file.eventCount ||
        right.file.downloadCount - left.file.downloadCount ||
        left.file.filePath.localeCompare(right.file.filePath)
      );
    });

  const best = rankedFiles[0];
  if (!best) {
    return null;
  }

  return {
    filePath: best.file.filePath,
    eventCount: best.file.eventCount,
    eventShare: totalEvents > 0 ? best.file.eventCount / totalEvents : null,
  };
}

function eventSignalScore(event: IntuneEvent): number {
  const statusWeight =
    event.status === "Failed" || event.status === "Timeout"
      ? 5
      : event.status === "Success"
        ? 2
        : 1;
  const typeWeight =
    event.eventType === "ContentDownload"
      ? 4
      : event.eventType === "Win32App" || event.eventType === "WinGetApp"
        ? 4
        : event.eventType === "PowerShellScript" || event.eventType === "Remediation"
          ? 4
          : event.eventType === "PolicyEvaluation"
            ? 3
            : 1;
  const errorWeight = event.errorCode ? 1 : 0;
  return statusWeight + typeWeight + errorWeight;
}

function distinctSourceKinds(files: IntuneDiagnosticsFileCoverage[]): number {
  return new Set(
    files
      .filter((file) => file.eventCount > 0 || file.downloadCount > 0)
      .map((file) => sourceKindKey(file.filePath))
  ).size;
}

function hasSourceKind(files: IntuneDiagnosticsFileCoverage[], kind: string): boolean {
  return files.some(
    (file) => (file.eventCount > 0 || file.downloadCount > 0) && sourceKindKey(file.filePath) === kind
  );
}

function sourceKindKey(filePath: string): string {
  const name = getFileName(filePath).toLowerCase();
  if (name.includes("appworkload")) {
    return "appworkload";
  }
  if (name.includes("appactionprocessor")) {
    return "appactionprocessor";
  }
  if (name.includes("agentexecutor")) {
    return "agentexecutor";
  }
  if (name.includes("healthscripts")) {
    return "healthscripts";
  }
  if (name.includes("intunemanagementextension")) {
    return "intunemanagementextension";
  }
  return "other";
}

function hasAppOrDownloadFailures(events: IntuneEvent[]): boolean {
  return events.some(
    (event) =>
      (event.status === "Failed" || event.status === "Timeout") &&
      (event.eventType === "Win32App" ||
        event.eventType === "WinGetApp" ||
        event.eventType === "ContentDownload")
  );
}

function hasPolicyFailures(events: IntuneEvent[]): boolean {
  return events.some(
    (event) =>
      (event.status === "Failed" || event.status === "Timeout") &&
      event.eventType === "PolicyEvaluation"
  );
}

function hasScriptFailures(events: IntuneEvent[]): boolean {
  return events.some(
    (event) =>
      (event.status === "Failed" || event.status === "Timeout") &&
      (event.eventType === "PowerShellScript" || event.eventType === "Remediation")
  );
}

function detectRotationMetadata(filePath: string): {
  isRotatedSegment: boolean;
  rotationGroup: string | null;
} {
  const fileName = getFileName(filePath);
  const stem = fileName.replace(/\.[^.]+$/, "");

  for (const separator of [".", "-", "_"]) {
    const index = stem.lastIndexOf(separator);
    if (index > 0) {
      const base = stem.slice(0, index);
      const suffix = stem.slice(index + 1);
      if (isRotationSuffix(suffix)) {
        return {
          isRotatedSegment: true,
          rotationGroup: base.toLowerCase(),
        };
      }
    }
  }

  return {
    isRotatedSegment: false,
    rotationGroup: stem ? stem.toLowerCase() : null,
  };
}

function isRotationSuffix(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  if (/^\d+$/.test(normalized)) {
    return true;
  }
  if (normalized.startsWith("lo_") || normalized === "bak" || normalized === "old") {
    return true;
  }
  return /^\d{8}$/.test(normalized);
}

function pickEarlierTimestamp(current: string | null, candidate: string): string {
  if (!current) {
    return candidate;
  }
  const currentValue = parseDisplayDateTimeValue(current);
  const candidateValue = parseDisplayDateTimeValue(candidate);
  if (currentValue == null || candidateValue == null) {
    return candidate.localeCompare(current) < 0 ? candidate : current;
  }
  return candidateValue < currentValue ? candidate : current;
}

function pickLaterTimestamp(current: string | null, candidate: string): string {
  if (!current) {
    return candidate;
  }
  const currentValue = parseDisplayDateTimeValue(current);
  const candidateValue = parseDisplayDateTimeValue(candidate);
  if (currentValue == null || candidateValue == null) {
    return candidate.localeCompare(current) > 0 ? candidate : current;
  }
  return candidateValue > currentValue ? candidate : current;
}

function normalizeIdentifier(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "unknown";
}

function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || path;
}

// ---------------------------------------------------------------------------
// Event log correlation helpers (exported for use by UI components)
// ---------------------------------------------------------------------------

/** Get all event log entry IDs correlated with a specific IME event. */
export function getEventLogEntryIdsForIntuneEvent(
  intuneEventId: number,
  links: EventLogCorrelationLink[]
): number[] {
  return links
    .filter((l) => l.linkedIntuneEventId === intuneEventId)
    .map((l) => l.eventLogEntryId);
}

/** Get all event log entry IDs correlated with a specific diagnostic. */
export function getEventLogEntryIdsForDiagnostic(
  diagnosticId: string,
  links: EventLogCorrelationLink[]
): number[] {
  return links
    .filter((l) => l.linkedDiagnosticId === diagnosticId)
    .map((l) => l.eventLogEntryId);
}

/** Get all correlation links that reference a specific event log entry. */
export function getCorrelationLinksForEntry(
  entryId: number,
  links: EventLogCorrelationLink[]
): EventLogCorrelationLink[] {
  return links.filter((l) => l.eventLogEntryId === entryId);
}
