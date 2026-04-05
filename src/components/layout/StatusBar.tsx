import { useMemo } from "react";
import { Badge, Spinner, tokens } from "@fluentui/react-components";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { getBaseName } from "../../lib/file-paths";
import {
  getActiveSourceLabel,
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
} from "../../stores/ui-store";
import { useIntuneStore } from "../../workspaces/intune/intune-store";
import { useDsregcmdStore } from "../../workspaces/dsregcmd/dsregcmd-store";
import { useDeploymentStore } from "../../workspaces/deployment/deployment-store";
import { useSysmonStore } from "../../workspaces/sysmon/sysmon-store";
import { useEvtxStore } from "../../workspaces/event-log/evtx-store";

interface SeverityCounts {
  errors: number;
  warnings: number;
  info: number;
}

function formatSeverityCounts(counts: SeverityCounts): string {
  const parts: string[] = [];
  if (counts.errors > 0) parts.push(`${counts.errors} error${counts.errors === 1 ? "" : "s"}`);
  if (counts.warnings > 0) parts.push(`${counts.warnings} warning${counts.warnings === 1 ? "" : "s"}`);
  if (counts.info > 0) parts.push(`${counts.info} info`);
  return parts.join(", ");
}

export function StatusBar() {
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
  const folderLoadCompletedFiles = useLogStore((s) => s.folderLoadCompletedFiles);
  const folderLoadTotalFiles = useLogStore((s) => s.folderLoadTotalFiles);

  const activeView = useUiStore((s) => s.activeView);
  const showDetails = useUiStore((s) => s.showDetails);
  const showInfoPane = useUiStore((s) => s.showInfoPane);
  const openTabs = useUiStore((s) => s.openTabs);
  const activeTabIndex = useUiStore((s) => s.activeTabIndex);

  const graphApiStatus = useUiStore((s) => s.graphApiStatus);

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

  const evtxRecordCount = useEvtxStore((s) => s.records.length);
  const evtxSourceMode = useEvtxStore((s) => s.sourceMode);
  const evtxIsLoading = useEvtxStore((s) => s.isLoading);
  const evtxLoadedChannelCount = useEvtxStore((s) => s.loadedChannels.size);
  const evtxLoadElapsedMs = useEvtxStore((s) => s.loadElapsedMs);

  const filterClauseCount = useFilterStore((s) => s.clauses.length);
  const filteredIds = useFilterStore((s) => s.filteredIds);
  const isFiltering = useFilterStore((s) => s.isFiltering);
  const filterError = useFilterStore((s) => s.filterError);

  const { filteredCount, severityCounts } = useMemo(() => {
    let errors = 0;
    let warnings = 0;
    let info = 0;
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
      }
    }

    return {
      filteredCount: counter,
      severityCounts: { errors, warnings, info },
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
    openFilePath
  );
  const parserDisplay = getParserSelectionDisplay(parserSelection);
  const uiChromeStatus = getUiChromeStatus(activeView, showDetails, showInfoPane);
  const filterStatus = getFilterStatusSnapshot(
    filterClauseCount,
    filteredIds?.size ?? null,
    isFiltering,
    filterError
  );

  let leftParts: string[] = [];
  let rightStatusText = "";
  let rightTone: string | undefined;

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

    if (parserDisplay) {
      leftParts.push(`Parser ${parserDisplay.parserLabel}`);
    }

    if (elapsedText) {
      leftParts.push(elapsedText);
    }

    const positionText =
      selectedPosition !== null
        ? `Entry ${selectedPosition} of ${filteredCount}`
        : null;

    const severityText =
      filteredCount > 0 ? formatSeverityCounts(severityCounts) : null;

    // When a folder load is in progress, show real-time per-file progress
    // from Rust parse events instead of the generic status text.
    const folderLoadStatusText =
      folderLoadProgress !== null && folderLoadTotalFiles
        ? `Parsing ${folderLoadCompletedFiles ?? 0} of ${folderLoadTotalFiles} files${folderLoadCurrentFile ? ` — ${folderLoadCurrentFile}` : ""}`
        : null;

    const logStatusText =
      folderLoadStatusText
        ?? (entries.length > 0
        ? [
            positionText ?? `${filteredCount} entries`,
            `${totalLines} lines`,
            sourceOpenMode === "aggregate-folder"
              ? `${aggregateFiles.length} files`
              : null,
            severityText,
            `${formatDetected ?? "Unknown"} format`,
            parserDisplay?.provenanceLabel,
            parserDisplay?.qualityLabel,
          ]
            .filter((part): part is string => Boolean(part))
            .join(" | ")
        : failureReason
          ? `Reason: ${failureReason}`
          : sourceStatus.kind !== "idle"
            ? sourceStatus.detail ?? sourceStatus.message
            : "");

    const filterStatusText = filterError ? `Filter error: ${filterError}` : filterStatus.label;

    rightStatusText = [logStatusText, filterStatusText]
      .filter((part) => part.length > 0)
      .join(" | ");
    rightTone = filterStatus.tone === "error" ? tokens.colorPaletteRedForeground2 : undefined;
  } else if (isIntuneWorkspace(activeView)) {
    const intuneSourceLabel = getBaseName(
      intuneAnalysisState.requestedPath ?? intuneSourceContext.analyzedPath
    );

    leftParts = [
      activeView === "new-intune" ? "New Intune Workspace" : "Intune Diagnostics",
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
      rightStatusText = intuneAnalysisState.detail ?? intuneAnalysisState.message;
      rightTone = tokens.colorPaletteBlueForeground2;
    } else if (intuneAnalysisState.phase === "error" || intuneAnalysisState.phase === "empty") {
      rightStatusText = [intuneAnalysisState.message, intuneAnalysisState.detail]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
      rightTone = intuneAnalysisState.phase === "error" ? tokens.colorPaletteRedForeground2 : tokens.colorPaletteMarigoldForeground2;
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
      rightTone = tokens.colorPaletteBlueForeground2;
    } else if (sysmonError) {
      rightStatusText = sysmonError;
      rightTone = tokens.colorPaletteRedForeground2;
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
          ? `${deploymentResult.totalFiles} files`
          : deploymentPhase === "error"
            ? "Analysis failed"
            : deploymentPhase === "empty"
              ? "No deployment logs found"
              : "Ready",
    ];
    if (deploymentResult) {
      rightStatusText = [
        `${deploymentResult.succeeded} succeeded`,
        `${deploymentResult.failed} failed`,
        deploymentResult.deferred > 0 ? `${deploymentResult.deferred} deferred` : null,
      ].filter(Boolean).join(" | ");
    }
  } else if (activeView === "event-log") {
    leftParts = [
      "Event Log",
      evtxIsLoading
        ? "Loading..."
        : evtxSourceMode === "live"
          ? `${evtxLoadedChannelCount} channel${evtxLoadedChannelCount !== 1 ? "s" : ""} loaded`
          : evtxSourceMode === "files"
            ? "File mode"
            : "Ready",
    ];

    if (evtxIsLoading) {
      rightStatusText = evtxRecordCount > 0
        ? `${evtxRecordCount.toLocaleString()} events loaded...`
        : "Querying event logs...";
      rightTone = tokens.colorPaletteBlueForeground2;
    } else if (evtxRecordCount > 0) {
      const timeStr = evtxLoadElapsedMs != null
        ? ` in ${(evtxLoadElapsedMs / 1000).toFixed(1)}s`
        : "";
      rightStatusText = `${evtxRecordCount.toLocaleString()} events${timeStr}`;
    }
  } else {
    const diagnostics = dsregcmdResult?.diagnostics ?? [];
    const errorCount = diagnostics.filter((item) => item.severity === "Error").length;
    const warningCount = diagnostics.filter((item) => item.severity === "Warning").length;

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
      rightStatusText = dsregcmdAnalysisState.detail ?? dsregcmdAnalysisState.message;
      rightTone = tokens.colorPaletteBlueForeground2;
    } else if (dsregcmdAnalysisState.phase === "error") {
      rightStatusText = [dsregcmdAnalysisState.message, dsregcmdAnalysisState.detail]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
      rightTone = tokens.colorPaletteRedForeground2;
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
  }

  const leftStatusText = leftParts.join(" • ");

  const activeViewLabel =
    activeView === "log"
      ? "Log"
      : activeView === "intune"
        ? "Intune"
        : activeView === "new-intune"
          ? "New Intune"
          : activeView === "sysmon"
            ? "Sysmon Analysis"
            : activeView === "event-log"
              ? "Event Log"
              : activeView === "deployment"
                ? "Software Deployment"
                : activeView === "macos-diag"
                  ? "macOS Diagnostics"
                  : activeView === "dsregcmd"
                    ? "dsregcmd"
                    : activeView;

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "6px 10px",
        backgroundColor: tokens.colorNeutralBackground2,
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        fontSize: "12px",
        fontFamily: LOG_UI_FONT_FAMILY,
        flexShrink: 0,
        minHeight: "34px",
        gap: "10px",
      }}
    >
      <div
        style={{
          minWidth: 0,
          display: "flex",
          alignItems: "center",
          gap: "8px",
          overflow: "hidden",
        }}
      >
        <Badge appearance="outline" color="brand">
          {activeViewLabel}
        </Badge>
        <span
          title={leftStatusText}
          style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        >
          {leftStatusText}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
        {graphApiStatus !== "idle" && (
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "11px",
              color: graphApiStatus === "connected"
                ? tokens.colorPaletteGreenForeground1
                : graphApiStatus === "connecting"
                  ? tokens.colorNeutralForeground3
                  : tokens.colorPaletteRedForeground1,
            }}
            title={
              graphApiStatus === "connected"
                ? "Graph API connected — GUID resolution active"
                : graphApiStatus === "connecting"
                  ? "Connecting to Graph API..."
                  : "Graph API connection failed"
            }
          >
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                backgroundColor: "currentColor",
                display: "inline-block",
              }}
            />
            {graphApiStatus === "connecting"
              ? "Graph API: Connecting..."
              : graphApiStatus === "connected"
                ? "Graph API: Connected"
                : "Graph API: Error"}
          </span>
        )}
        {activeView === "event-log" && evtxIsLoading && (
          <Spinner size="tiny" />
        )}
        <span
          title={rightStatusText}
          style={{
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            color: rightTone,
            fontWeight: 500,
          }}
        >
          {rightStatusText}
        </span>
      </div>
    </div>
  );
}
