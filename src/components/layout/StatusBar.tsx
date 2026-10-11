import {
  Fragment,
  Suspense,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Badge, tokens } from "@fluentui/react-components";
import {
  ArrowSync12Regular,
  ErrorCircle12Regular,
  Warning12Regular,
} from "@fluentui/react-icons";
import { create } from "zustand";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { getBaseName } from "../../lib/file-paths";
import {
  getActiveSourceLabel,
  getAggregateParserDisplay,
  getParserSelectionDisplay,
  getSourceFailureReason,
  getStreamStateSnapshot,
  useLogStore,
} from "../../stores/log-store";
import {
  getFilterStatusSnapshot,
  useFilterStore,
} from "../../stores/filter-store";
import {
  getUiChromeStatus,
  isIntuneWorkspace,
  useUiStore,
  type GraphApiPhase,
} from "../../stores/ui-store";
import { useIntuneStore } from "../../workspaces/intune/intune-store";
import { useDsregcmdStore } from "../../workspaces/dsregcmd/dsregcmd-store";
import { useDeploymentStore } from "../../workspaces/deployment/deployment-store";
import { useSysmonStore } from "../../workspaces/sysmon/sysmon-store";
import type { CorrelationChainModel } from "../../workspaces/event-log/evtx-correlation-chains";
import {
  EVTX_VIEW_LABELS,
  useEvtxLayoutStore,
} from "../../workspaces/event-log/evtx-layout-store";
import {
  useEvtxStore,
  type EvtxSourceMode,
} from "../../workspaces/event-log/evtx-store";
import {
  formatEventTime,
  timeZoneLabel,
  type EvtxTimeZoneMode,
} from "../../workspaces/event-log/evtx-time";
import type { EvtxRecord } from "../../workspaces/event-log/types";
import { scopeLogEntries } from "../../workspaces/event-log/unified-timeline";
import { useSecureBootStore } from "../../workspaces/secureboot/secureboot-store";
import { getWorkspace } from "../../workspaces/registry";
import type { WorkspaceDefinition } from "../../workspaces/types";
import { useStatusBarForeground } from "./status-bar-foreground";

interface SeverityCounts {
  errors: number;
  warnings: number;
  info: number;
  success: number;
}

type GraphApiIndicatorPhase = Exclude<GraphApiPhase, "disconnected">;

const GRAPH_API_INDICATORS: Record<
  GraphApiIndicatorPhase,
  { color: string; title: string; label: string }
> = {
  signingIn: {
    color: tokens.colorNeutralForeground3,
    title: "Connecting to Graph API...",
    label: "Graph API: Connecting...",
  },
  cancelling: {
    color: tokens.colorNeutralForeground3,
    title: "Cancelling Microsoft Graph sign-in...",
    label: "Graph API: Cancelling...",
  },
  connected: {
    color: tokens.colorPaletteGreenForeground1,
    title: "Graph API connected — GUID resolution active",
    label: "Graph API: Connected",
  },
  unsupported: {
    color: tokens.colorPaletteYellowForeground2,
    title: "Microsoft Graph is unavailable on this host",
    label: "Graph API: Unavailable",
  },
  error: {
    color: tokens.colorPaletteRedForeground1,
    title: "Graph API connection failed",
    label: "Graph API: Error",
  },
};

/**
 * Colored text fails contrast on the brand background, so the right-hand
 * status carries its tone as an icon next to the label instead.
 */
type StatusTone = "progress" | "warning" | "error";

const STATUS_TONE_ICONS: Record<
  StatusTone,
  { Icon: typeof ErrorCircle12Regular; label: string }
> = {
  progress: { Icon: ArrowSync12Regular, label: "In progress" },
  warning: { Icon: Warning12Regular, label: "Warning" },
  error: { Icon: ErrorCircle12Regular, label: "Error" },
};

function formatSeverityCounts(counts: SeverityCounts): string {
  const parts: string[] = [];
  if (counts.errors > 0)
    parts.push(`${counts.errors} error${counts.errors === 1 ? "" : "s"}`);
  if (counts.warnings > 0)
    parts.push(`${counts.warnings} warning${counts.warnings === 1 ? "" : "s"}`);
  if (counts.info > 0) parts.push(`${counts.info} info`);
  if (counts.success > 0) parts.push(`${counts.success} success`);
  return parts.join(", ");
}

/**
 * Event Logs status text (spec 8.14). Counts render in the numeric font, so the text is built
 * from runs rather than one string. A segment is one run group; segments join with " · ".
 */
export interface EvtxStatusRun {
  text: string;
  /** Counts and times: `tokens.fontFamilyNumeric` with tabular figures (spec D4). */
  numeric?: boolean;
}
export type EvtxStatusSegment = readonly EvtxStatusRun[];

const EVTX_STATUS_SEPARATOR = " · ";

export function evtxStatusText(segments: readonly EvtxStatusSegment[]): string {
  return segments
    .map((segment) => segment.map((run) => run.text).join(""))
    .join(EVTX_STATUS_SEPARATOR);
}

function countRuns(count: number, singular: string, plural = `${singular}s`) {
  return [
    { text: count.toLocaleString(), numeric: true },
    { text: ` ${count === 1 ? singular : plural}` },
  ] satisfies EvtxStatusSegment;
}

export interface EvtxProblemCounts {
  errors: number;
  warnings: number;
}

/**
 * Errors and warnings among the loaded records. Critical counts as an error: the grid draws both
 * on the same error row tint (spec D3), so a Critical row that is missing from "errors" would be
 * a red row the count does not account for. Verbose and Information are not problems.
 */
export function countProblemLevels(
  records: readonly Pick<EvtxRecord, "level">[],
): EvtxProblemCounts {
  let errors = 0;
  let warnings = 0;
  for (const record of records) {
    if (record.level === "Error" || record.level === "Critical") errors += 1;
    else if (record.level === "Warning") warnings += 1;
  }
  return { errors, warnings };
}

/** Distinct source files among the text-log entries the workspace correlates. */
export function countTextLogFiles(
  entries: readonly { filePath: string }[],
): number {
  return new Set(entries.map((entry) => entry.filePath)).size;
}

export interface EvtxStatusCounts {
  sourceMode: Exclude<EvtxSourceMode, null>;
  channels: number;
  textLogs: number;
  events: number;
  errors: number;
  warnings: number;
}

/** "{Live|Files} · {c} channels · {l} text logs · {n} events · {e} errors · {w} warnings". */
export function buildEvtxCountsSegments(
  counts: EvtxStatusCounts,
): EvtxStatusSegment[] {
  return [
    [{ text: counts.sourceMode === "live" ? "Live" : "Files" }],
    countRuns(counts.channels, "channel"),
    countRuns(counts.textLogs, "text log"),
    countRuns(counts.events, "event"),
    countRuns(counts.errors, "error"),
    countRuns(counts.warnings, "warning"),
  ];
}

/**
 * What the Correlation view variant of the left segment needs (spec 8.14). `exact` and
 * `candidate` are the chain counts; ambiguous and coverage-blocked rows are not chains (Q-4) and
 * `timestampOnly` / `notCausal` relations are never counted at all (D7).
 */
export interface EvtxCorrelationStatus {
  exact: number;
  candidate: number;
  ambiguous: number;
  /** Items the analysis session could not place: the session total, not the capped preview. */
  unplaced: number;
}

/**
 * Reduces the chain model to the status counts, or null when they would not be totals.
 *
 * `model.counts` is taken before the 100-row render cap. It is only the session's total when
 * every edge was loaded (`edgeInputComplete`): a bounded edge preview can miss chains, and a
 * missed ambiguous or coverage-blocked edge would also have vetoed a link that is counted. No
 * bound on either direction holds, so an incomplete model yields no counts rather than a
 * number that reads as a total.
 *
 * `totalUnplaced` is `EventLogAnalysisSessionStatus.totalUnplaced`, not the length of
 * `unplacedPreview`, which is capped.
 */
export function summarizeEvtxCorrelationStatus(
  model: Pick<CorrelationChainModel, "counts" | "edgeInputComplete">,
  totalUnplaced: number,
): EvtxCorrelationStatus | null {
  if (!model.edgeInputComplete) return null;
  if (!Number.isSafeInteger(totalUnplaced) || totalUnplaced < 0) return null;
  return {
    exact: model.counts.exact,
    candidate: model.counts.candidate,
    ambiguous: model.counts.ambiguous,
    unplaced: totalUnplaced,
  };
}

/** "Correlation · {n} chains · {e} exact, {c} candidate, {a} ambiguous · {u} not placed". */
export function buildEvtxCorrelationSegments(
  status: EvtxCorrelationStatus,
): EvtxStatusSegment[] {
  const { exact, candidate, ambiguous, unplaced } = status;
  return [
    [{ text: "Correlation" }],
    countRuns(exact + candidate, "chain"),
    [
      { text: exact.toLocaleString(), numeric: true },
      { text: " exact, " },
      { text: candidate.toLocaleString(), numeric: true },
      { text: " candidate, " },
      { text: ambiguous.toLocaleString(), numeric: true },
      { text: " ambiguous" },
    ],
    [
      { text: unplaced.toLocaleString(), numeric: true },
      { text: " not placed" },
    ],
  ];
}

/**
 * The Correlation variant's counts, published by whatever builds the chain model from the
 * analysis session (Phase 10). Until it publishes, or while the model is incomplete or being
 * rebuilt, the status bar keeps the standard segment instead of showing counts it cannot back.
 * The publisher clears it when the analysis session is rebuilt.
 */
interface EvtxCorrelationStatusState {
  status: EvtxCorrelationStatus | null;
  publish: (status: EvtxCorrelationStatus | null) => void;
}

export const useEvtxCorrelationStatusStore = create<EvtxCorrelationStatusState>()(
  (set) => ({
    status: null,
    publish: (status) => set({ status }),
  }),
);

/** `HH:MM:SS` plus the zone label, in the clock the grid shows event times in. */
export function formatEvtxUpdatedTime(
  epochMs: number,
  mode: EvtxTimeZoneMode,
): EvtxStatusSegment {
  // formatEventTime prints `YYYY-MM-DD HH:MM:SS.mmm`; the time of day is columns 11 to 19.
  return [
    { text: formatEventTime(epochMs, mode).slice(11, 19), numeric: true },
    { text: ` ${timeZoneLabel(mode, epochMs)}` },
  ];
}

const numericRunStyle = {
  fontFamily: tokens.fontFamilyNumeric,
  fontVariantNumeric: "tabular-nums",
} as const;

function EvtxStatusRuns({
  segments,
}: {
  segments: readonly EvtxStatusSegment[];
}) {
  return (
    <>
      {segments.map((segment, segmentIndex) => (
        <Fragment key={segmentIndex}>
          {segmentIndex > 0 ? EVTX_STATUS_SEPARATOR : null}
          {segment.map((run, runIndex) =>
            run.numeric ? (
              <span key={runIndex} style={numericRunStyle}>
                {run.text}
              </span>
            ) : (
              <Fragment key={runIndex}>{run.text}</Fragment>
            ),
          )}
        </Fragment>
      ))}
    </>
  );
}

export function WorkspaceStatusBarContent({
  workspace,
  children,
}: {
  workspace: WorkspaceDefinition;
  children: ReactNode;
}) {
  const StatusContent = workspace.statusBarContent;
  if (!StatusContent) {
    return <>{children}</>;
  }

  return (
    <Suspense fallback={<>{children}</>}>
      <StatusContent />
    </Suspense>
  );
}

export function StatusBar() {
  const foreground = useStatusBarForeground();
  const entries = useLogStore((s) => s.entries);
  const totalLines = useLogStore((s) => s.totalLines);
  const formatDetected = useLogStore((s) => s.formatDetected);
  const parserSelection = useLogStore((s) => s.parserSelection);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const selectedSourceFilePath = useLogStore((s) => s.selectedSourceFilePath);
  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const aggregateFiles = useLogStore((s) => s.aggregateFiles);
  const activeSource = useLogStore((s) => s.activeSource);
  const knownSources = useLogStore((s) => s.knownSources);
  const selectedId = useLogStore((s) => s.selectedId);
  const isLoading = useLogStore((s) => s.isLoading);
  const isPaused = useLogStore((s) => s.isPaused);
  const sourceStatus = useLogStore((s) => s.sourceStatus);
  const folderLoadProgress = useLogStore((s) => s.folderLoadProgress);
  const folderLoadCurrentFile = useLogStore((s) => s.folderLoadCurrentFile);
  const folderLoadCompletedFiles = useLogStore(
    (s) => s.folderLoadCompletedFiles,
  );
  const folderLoadTotalFiles = useLogStore((s) => s.folderLoadTotalFiles);

  const activeView = useUiStore((s) => s.activeView);
  const showDetails = useUiStore((s) => s.showDetails);
  const showInfoPane = useUiStore((s) => s.showInfoPane);
  const openTabs = useUiStore((s) => s.openTabs);
  const activeTabIndex = useUiStore((s) => s.activeTabIndex);

  const graphApiStatus = useUiStore((s) => s.graphApiStatus);
  const graphApiIndicator =
    graphApiStatus === "disconnected"
      ? null
      : GRAPH_API_INDICATORS[graphApiStatus];

  const intuneAnalysisState = useIntuneStore((s) => s.analysisState);
  const intuneSummary = useIntuneStore((s) => s.summary);
  const intuneSourceContext = useIntuneStore((s) => s.sourceContext);
  const intuneTimelineScope = useIntuneStore((s) => s.timelineScope);

  const dsregcmdAnalysisState = useDsregcmdStore((s) => s.analysisState);
  const dsregcmdSourceContext = useDsregcmdStore((s) => s.sourceContext);
  const dsregcmdResult = useDsregcmdStore((s) => s.result);
  const dsregcmdIsAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);

  const deploymentPhase = useDeploymentStore((s) => s.phase);
  const deploymentResult = useDeploymentStore((s) => s.result);

  const sysmonIsAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const sysmonSummary = useSysmonStore((s) => s.summary);
  const sysmonError = useSysmonStore((s) => s.analysisError);
  const sysmonSourcePath = useSysmonStore((s) => s.sourcePath);

  // The raw store references are only dereferenced inside the event-log branch below, so a test
  // that stubs `useEvtxStore` with a partial state keeps working for the other workspaces.
  const evtxRecords = useEvtxStore((s) => s.records);
  const evtxChannels = useEvtxStore((s) => s.channels);
  const evtxSourceMode = useEvtxStore((s) => s.sourceMode);
  const evtxIsLoading = useEvtxStore((s) => s.isLoading);
  const evtxLoadedChannelCount = useEvtxStore((s) => s.loadedChannels.size);
  const evtxTimeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const evtxLayoutView = useEvtxLayoutStore((s) => s.activeView);
  const evtxCorrelationStatus = useEvtxCorrelationStatusStore((s) => s.status);
  const currentPlatform = useUiStore((s) => s.currentPlatform);

  const securebootAnalysisState = useSecureBootStore((s) => s.analysisState);
  const securebootResult = useSecureBootStore((s) => s.result);
  const securebootIsAnalyzing = useSecureBootStore((s) => s.isAnalyzing);

  const filterClauseCount = useFilterStore((s) => s.clauses.length);
  const filteredIds = useFilterStore((s) => s.filteredIds);
  const isFiltering = useFilterStore((s) => s.isFiltering);
  const filterError = useFilterStore((s) => s.filterError);

  const { filteredCount, severityCounts } = useMemo(() => {
    let errors = 0;
    let warnings = 0;
    let info = 0;
    let success = 0;
    let counter = 0;

    for (const entry of entries) {
      if (filteredIds && !filteredIds.has(entry.id)) continue;
      counter++;
      switch (entry.severity) {
        case "Error":
          errors++;
          break;
        case "Warning":
          warnings++;
          break;
        case "Info":
          info++;
          break;
        case "Success":
          success++;
          break;
      }
    }

    return {
      filteredCount: counter,
      severityCounts: { errors, warnings, info, success },
    };
  }, [entries, filteredIds]);

  const selectedPosition = useMemo(() => {
    if (selectedId === null) {
      return null;
    }

    let counter = 0;

    for (const entry of entries) {
      if (filteredIds && !filteredIds.has(entry.id)) continue;
      counter++;
      if (entry.id === selectedId) {
        return counter;
      }
    }

    return null;
  }, [entries, filteredIds, selectedId]);

  // Counts cover the loaded records, the same total the grid and the chip row's "of {loaded}"
  // start from. They are derived only while Event Logs is the active workspace and nothing is
  // loading, and memoized on the records array so a tail append is one pass.
  const evtxProblemCounts = useMemo(
    () =>
      activeView === "event-log" && !evtxIsLoading
        ? countProblemLevels(evtxRecords)
        : null,
    [activeView, evtxIsLoading, evtxRecords],
  );
  // The text logs Event Logs correlates are the log store's entries after the same scoping the
  // workspace applies before it builds the analysis session.
  const evtxTextLogCount = useMemo(
    () =>
      activeView === "event-log"
        ? countTextLogFiles(
            scopeLogEntries(
              entries,
              activeSource,
              sourceOpenMode,
              currentPlatform,
            ),
          )
        : 0,
    [activeView, entries, activeSource, sourceOpenMode, currentPlatform],
  );

  // "Updated" is the last load or tail append the status bar observed. The store keeps no
  // wall-clock stamp, and the bar stays mounted across workspaces, so every settled change to
  // the loaded records is seen here. Records that were already loaded when the bar mounted get no
  // stamp: that time was not observed, so it is left out rather than guessed.
  const [evtxUpdatedAt, setEvtxUpdatedAt] = useState<number | null>(null);
  const observedRecordsRef = useRef(evtxRecords);
  const wasLoadingRef = useRef(evtxIsLoading);
  useEffect(() => {
    const recordsChanged = observedRecordsRef.current !== evtxRecords;
    const loadFinished = wasLoadingRef.current && !evtxIsLoading;
    observedRecordsRef.current = evtxRecords;
    wasLoadingRef.current = evtxIsLoading;
    if (evtxIsLoading || (!recordsChanged && !loadFinished)) return;
    if (evtxSourceMode !== "live" && evtxSourceMode !== "files") return;
    setEvtxUpdatedAt(Date.now());
  }, [evtxRecords, evtxIsLoading, evtxSourceMode]);

  let elapsedText = "";
  if (activeView === "log" && selectedId !== null && entries.length > 0) {
    const firstEntry = entries[0];
    const selectedEntry = entries.find((e) => e.id === selectedId);
    if (firstEntry?.timestamp && selectedEntry?.timestamp) {
      const diffMs = Math.abs(selectedEntry.timestamp - firstEntry.timestamp);
      const totalSeconds = Math.floor(diffMs / 1000);
      const ms = diffMs % 1000;
      const hours = Math.floor(totalSeconds / 3600);
      const minutes = Math.floor((totalSeconds % 3600) / 60);
      const seconds = totalSeconds % 60;
      elapsedText = `Elapsed ${hours}h ${minutes}m ${seconds}s ${ms}ms`;
    }
  }

  const activeFilePath = selectedSourceFilePath ?? openFilePath;
  const activeFileName = getBaseName(activeFilePath);
  const activeSourceLabel = getActiveSourceLabel(activeSource, knownSources);
  const failureReason = getSourceFailureReason(sourceStatus);
  const streamStatus = getStreamStateSnapshot(
    isLoading,
    isPaused,
    activeSource,
    openFilePath,
  );
  const parserDisplay = getParserSelectionDisplay(parserSelection);
  // The merged stream has no single parser selection, so it reports the
  // composition of the parsers that read its files instead of "Unknown".
  const aggregateParserDisplay = useMemo(
    () =>
      sourceOpenMode === "aggregate-folder"
        ? getAggregateParserDisplay(aggregateFiles)
        : null,
    [aggregateFiles, sourceOpenMode]
  );
  const uiChromeStatus = getUiChromeStatus(
    activeView,
    showDetails,
    showInfoPane,
  );
  const filterStatus = getFilterStatusSnapshot(
    filterClauseCount,
    filteredIds?.size ?? null,
    isFiltering,
    filterError,
  );

  let leftParts: string[] = [];
  let rightStatusText = "";
  let rightTone: StatusTone | undefined;
  // Set by the Event Logs branch, whose counts render in the numeric font. When present they
  // replace `leftParts` and `rightStatusText`.
  let leftSegments: readonly EvtxStatusSegment[] | null = null;
  let rightSegments: readonly EvtxStatusSegment[] | null = null;

  if (activeView === "log") {
    leftParts = [
      streamStatus.label,
      uiChromeStatus.viewLabel,
      uiChromeStatus.detailsLabel,
      uiChromeStatus.infoLabel,
      sourceOpenMode === "aggregate-folder"
        ? `Source ${aggregateFiles.length} file${aggregateFiles.length === 1 ? "" : "s"}`
        : activeFileName
          ? `Source ${activeFileName}`
          : `Source ${activeSourceLabel}`,
    ];

    if (openTabs.length > 0) {
      leftParts.push(`Tab ${activeTabIndex + 1} of ${openTabs.length}`);
    }

    if (aggregateParserDisplay) {
      leftParts.push(
        aggregateParserDisplay.parserLabel
          ? `Parser ${aggregateParserDisplay.parserLabel}`
          : `${aggregateParserDisplay.parserCount} parsers`
      );
    } else if (parserDisplay) {
      leftParts.push(`Parser ${parserDisplay.parserLabel}`);
    }

    if (elapsedText) {
      leftParts.push(elapsedText);
    }

    const totalCount = entries.length;
    const isFilterActive = filteredIds !== null && filteredCount !== totalCount;

    const positionText =
      selectedPosition !== null
        ? isFilterActive
          ? `Entry ${selectedPosition.toLocaleString()} of ${filteredCount.toLocaleString()} (${totalCount.toLocaleString()} total)`
          : `Entry ${selectedPosition.toLocaleString()} of ${filteredCount.toLocaleString()}`
        : null;

    const entriesCountText = isFilterActive
      ? `${filteredCount.toLocaleString()} of ${totalCount.toLocaleString()} entries`
      : `${filteredCount.toLocaleString()} entries`;

    const severityText =
      filteredCount > 0 ? formatSeverityCounts(severityCounts) : null;

    // When a folder load is in progress, show real-time per-file progress
    // from Rust parse events instead of the generic status text.
    const folderLoadStatusText =
      folderLoadProgress !== null && folderLoadTotalFiles
        ? `Parsing ${folderLoadCompletedFiles ?? 0} of ${folderLoadTotalFiles} files${folderLoadCurrentFile ? ` — ${folderLoadCurrentFile}` : ""}`
        : null;

    const logStatusText =
      folderLoadStatusText ??
      (entries.length > 0
        ? [
            positionText ?? entriesCountText,
            `${totalLines} lines`,
            sourceOpenMode === "aggregate-folder"
              ? `${aggregateFiles.length} files`
              : null,
            severityText,
            `${aggregateParserDisplay?.formatLabel ?? formatDetected ?? "Unknown"} format`,
            aggregateParserDisplay?.provenanceLabel ??
              parserDisplay?.provenanceLabel,
            aggregateParserDisplay?.qualityLabel ?? parserDisplay?.qualityLabel,
          ]
            .filter((part): part is string => Boolean(part))
            .join(" | ")
        : failureReason
          ? `Reason: ${failureReason}`
          : sourceStatus.kind !== "idle"
            ? [
                sourceStatus.detail ?? sourceStatus.message,
                // A stream whose files parsed to no entries still knows which
                // parsers read them, so the merged view reports its composition
                // here too rather than only when it has rows to show.
                aggregateParserDisplay
                  ? `${aggregateParserDisplay.formatLabel} format`
                  : null,
                aggregateParserDisplay?.provenanceLabel,
                aggregateParserDisplay?.qualityLabel,
              ]
                .filter((part): part is string => Boolean(part))
                .join(" | ")
            : "");

    const filterStatusText = filterError
      ? `Filter error: ${filterError}`
      : filterStatus.label;

    rightStatusText = [logStatusText, filterStatusText]
      .filter((part) => part.length > 0)
      .join(" | ");
    rightTone = filterStatus.tone === "error" ? "error" : undefined;
  } else if (isIntuneWorkspace(activeView)) {
    const intuneSourceLabel = getBaseName(
      intuneAnalysisState.requestedPath ?? intuneSourceContext.analyzedPath,
    );

    leftParts = [
      getWorkspace(activeView).label,
      intuneAnalysisState.phase === "analyzing"
        ? "Analyzing"
        : intuneAnalysisState.phase === "error"
          ? "Analysis failed"
          : intuneAnalysisState.phase === "empty"
            ? "No IME logs found"
            : intuneSummary
              ? `Events ${intuneSummary.totalEvents}`
              : "No analysis",
    ];

    if (intuneSourceLabel) {
      leftParts.push(`Source ${intuneSourceLabel}`);
    }

    if (intuneTimelineScope.filePath) {
      leftParts.push(`Timeline ${getBaseName(intuneTimelineScope.filePath)}`);
    }

    if (intuneAnalysisState.phase === "analyzing") {
      rightStatusText =
        intuneAnalysisState.detail ?? intuneAnalysisState.message;
      rightTone = "progress";
    } else if (
      intuneAnalysisState.phase === "error" ||
      intuneAnalysisState.phase === "empty"
    ) {
      rightStatusText = [
        intuneAnalysisState.message,
        intuneAnalysisState.detail,
      ]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
      rightTone = intuneAnalysisState.phase === "error" ? "error" : "warning";
    } else if (intuneSummary) {
      rightStatusText = [
        `${intuneSummary.totalEvents} events`,
        `${intuneSummary.totalDownloads} downloads`,
        intuneSummary.logTimeSpan,
      ]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
    } else {
      rightStatusText = intuneAnalysisState.message;
    }
  } else if (activeView === "sysmon") {
    leftParts = [
      "Sysmon",
      sysmonIsAnalyzing
        ? "Analyzing"
        : sysmonError
          ? "Analysis failed"
          : sysmonSummary
            ? `${sysmonSummary.totalEvents.toLocaleString()} events`
            : "Ready",
    ];
    if (sysmonSourcePath) {
      leftParts.push(`Source ${getBaseName(sysmonSourcePath)}`);
    }
    if (sysmonIsAnalyzing) {
      rightStatusText = "Analyzing Sysmon EVTX files...";
      rightTone = "progress";
    } else if (sysmonError) {
      rightStatusText = sysmonError;
      rightTone = "error";
    } else if (sysmonSummary) {
      rightStatusText = [
        `${sysmonSummary.totalEvents.toLocaleString()} events`,
        `${sysmonSummary.uniqueProcesses.toLocaleString()} processes`,
        `${sysmonSummary.sourceFiles.length} files`,
      ].join(" | ");
    }
  } else if (activeView === "deployment") {
    leftParts = [
      "Software Deployment",
      deploymentPhase === "analyzing"
        ? "Analyzing"
        : deploymentPhase === "ready" && deploymentResult
          ? `${deploymentResult.totalFiles} files${
              deploymentResult.limitations.length > 0
                ? " (scan incomplete)"
                : ""
            }`
          : deploymentPhase === "error"
            ? "Analysis failed"
            : deploymentPhase === "empty"
              ? deploymentResult && deploymentResult.limitations.length > 0
                ? "Scan incomplete"
                : "No deployment logs found"
              : "Ready",
    ];
    if (deploymentResult) {
      rightStatusText = [
        `${deploymentResult.succeeded} succeeded`,
        `${deploymentResult.failed} failed`,
        deploymentResult.deferred > 0
          ? `${deploymentResult.deferred} deferred`
          : null,
      ]
        .filter(Boolean)
        .join(" | ");
    }
  } else if (activeView === "event-log") {
    if (evtxIsLoading) {
      leftSegments = [[{ text: "Loading..." }]];
      rightStatusText =
        evtxRecords.length > 0
          ? `${evtxRecords.length.toLocaleString()} events loaded...`
          : "Querying event logs...";
      rightTone = "progress";
    } else if (evtxSourceMode === null || evtxProblemCounts === null) {
      // Nothing is loaded, so there is nothing to count. Zeros here would read as a result.
      leftSegments = [[{ text: "Ready" }]];
    } else {
      leftSegments =
        evtxLayoutView === "correlation" && evtxCorrelationStatus !== null
          ? buildEvtxCorrelationSegments(evtxCorrelationStatus)
          : buildEvtxCountsSegments({
              sourceMode: evtxSourceMode,
              // Live reads report the channels actually loaded. A file parse never fills
              // `loadedChannels`, so a file source counts the channels it contains.
              channels:
                evtxSourceMode === "live"
                  ? evtxLoadedChannelCount
                  : evtxChannels.length,
              textLogs: evtxTextLogCount,
              events: evtxRecords.length,
              errors: evtxProblemCounts.errors,
              warnings: evtxProblemCounts.warnings,
            });
      rightSegments = [
        [{ text: `${EVTX_VIEW_LABELS[evtxLayoutView]} view` }],
        ...(evtxUpdatedAt === null
          ? []
          : [
              [
                { text: "Updated " },
                ...formatEvtxUpdatedTime(evtxUpdatedAt, evtxTimeZoneMode),
              ] satisfies EvtxStatusSegment,
            ]),
      ];
    }
  } else if (activeView === "secureboot") {
    const sbDiagnostics = securebootResult?.diagnostics ?? [];
    const sbErrors = sbDiagnostics.filter((d) => d.severity === "error").length;
    const sbWarnings = sbDiagnostics.filter(
      (d) => d.severity === "warning",
    ).length;

    leftParts = [
      "Secure Boot",
      securebootIsAnalyzing
        ? "Analyzing"
        : securebootResult
          ? `Stage ${securebootResult.stage}`
          : "No analysis",
    ];

    if (securebootResult?.scanState.deviceName) {
      leftParts.push(securebootResult.scanState.deviceName);
    }

    if (securebootAnalysisState.phase === "analyzing") {
      rightStatusText =
        securebootAnalysisState.detail ?? securebootAnalysisState.message;
      rightTone = "progress";
    } else if (securebootAnalysisState.phase === "error") {
      rightStatusText = [
        securebootAnalysisState.message,
        securebootAnalysisState.detail,
      ]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
      rightTone = "error";
    } else if (securebootResult) {
      rightStatusText = [
        `${sbDiagnostics.length} diagnostics`,
        `${sbErrors} errors`,
        `${sbWarnings} warnings`,
      ].join(" | ");
    } else {
      rightStatusText = securebootAnalysisState.message;
    }
  } else if (activeView === "dsregcmd") {
    const diagnostics = dsregcmdResult?.diagnostics ?? [];
    const errorCount = diagnostics.filter(
      (item) => item.severity === "Error",
    ).length;
    const warningCount = diagnostics.filter(
      (item) => item.severity === "Warning",
    ).length;

    leftParts = [
      "dsregcmd",
      dsregcmdIsAnalyzing
        ? "Analyzing"
        : dsregcmdResult
          ? dsregcmdResult.derived.joinTypeLabel
          : "No analysis",
    ];

    if (dsregcmdSourceContext.source !== null) {
      leftParts.push(`Source ${dsregcmdSourceContext.displayLabel}`);
    }

    if (dsregcmdAnalysisState.phase === "analyzing") {
      rightStatusText =
        dsregcmdAnalysisState.detail ?? dsregcmdAnalysisState.message;
      rightTone = "progress";
    } else if (dsregcmdAnalysisState.phase === "error") {
      rightStatusText = [
        dsregcmdAnalysisState.message,
        dsregcmdAnalysisState.detail,
      ]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
      rightTone = "error";
    } else if (dsregcmdResult) {
      rightStatusText = [
        `${diagnostics.length} diagnostics`,
        `${errorCount} errors`,
        `${warningCount} warnings`,
        `PRT ${dsregcmdResult.derived.azureAdPrtPresent === null ? "unknown" : dsregcmdResult.derived.azureAdPrtPresent ? "present" : "missing"}`,
      ].join(" | ");
    } else {
      rightStatusText = dsregcmdAnalysisState.message;
    }
  } else {
    // Workspaces without a branch above report only their view label rather
    // than borrowing another workspace's analysis state.
    leftParts = [uiChromeStatus.viewLabel];
  }

  const leftStatusText = leftSegments
    ? evtxStatusText(leftSegments)
    : leftParts.join(" • ");
  const rightDisplayText = rightSegments
    ? evtxStatusText(rightSegments)
    : rightStatusText;
  const toneIcon = rightTone ? STATUS_TONE_ICONS[rightTone] : null;

  const activeViewLabel =
    activeView === "log"
      ? "Log"
      : activeView === "intune"
        ? "Intune"
        : activeView === "new-intune"
          ? getWorkspace(activeView).label
          : activeView === "sysmon"
            ? "Sysmon Analysis"
            : activeView === "event-log"
              ? uiChromeStatus.viewLabel
              : activeView === "deployment"
                ? "Software Deployment"
                : activeView === "macos-diag"
                  ? "macOS Diagnostics"
                  : activeView === "macos-jamf"
                    ? "macOS JAMF"
                    : activeView === "secureboot"
                      ? "Secure Boot"
                      : activeView === "dsregcmd"
                        ? "dsregcmd"
                        : getWorkspace(activeView).label;

  return (
    <div
      data-testid="global-status-bar"
      data-workspace={activeView}
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "0 10px",
        height: "24px",
        boxSizing: "border-box",
        backgroundColor: tokens.colorBrandBackground,
        color: foreground,
        fontSize: "12px",
        fontFamily: LOG_UI_FONT_FAMILY,
        flexShrink: 0,
        gap: "10px",
      }}
    >
      <WorkspaceStatusBarContent workspace={getWorkspace(activeView)}>
        <>
          <div
            style={{
              minWidth: 0,
              display: "flex",
              alignItems: "center",
              gap: "8px",
              overflow: "hidden",
            }}
          >
            <Badge
              appearance="outline"
              color="brand"
              style={{ color: foreground, borderColor: foreground }}
            >
              {activeViewLabel}
            </Badge>
            <span
              data-testid="status-bar-left"
              title={leftStatusText}
              style={{
                minWidth: 0,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {leftSegments ? (
                <EvtxStatusRuns segments={leftSegments} />
              ) : (
                leftStatusText
              )}
            </span>
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              flexShrink: 0,
            }}
          >
            {graphApiIndicator && (
              <span
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                }}
                title={graphApiIndicator.title}
              >
                <span
                  style={{
                    width: "6px",
                    height: "6px",
                    borderRadius: "50%",
                    backgroundColor: graphApiIndicator.color,
                    boxShadow: `0 0 0 1px ${foreground}`,
                    display: "inline-block",
                  }}
                />
                {graphApiIndicator.label}
              </span>
            )}
            {toneIcon && (
              <toneIcon.Icon
                role="img"
                aria-label={toneIcon.label}
                style={{ flexShrink: 0 }}
              />
            )}
            <span
              data-testid="status-bar-right"
              title={rightDisplayText}
              style={{
                minWidth: 0,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                fontWeight: 500,
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {rightSegments ? (
                <EvtxStatusRuns segments={rightSegments} />
              ) : (
                rightStatusText
              )}
            </span>
          </div>
        </>
      </WorkspaceStatusBarContent>
    </div>
  );
}
