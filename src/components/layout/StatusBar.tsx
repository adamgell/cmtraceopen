import {
  getActiveSourceLabel,
  getBaseName,
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
  useUiStore,
} from "../../stores/ui-store";
import { useIntuneStore } from "../../stores/intune-store";

export function StatusBar() {
  const entries = useLogStore((s) => s.entries);
  const totalLines = useLogStore((s) => s.totalLines);
  const formatDetected = useLogStore((s) => s.formatDetected);
  const parserSelection = useLogStore((s) => s.parserSelection);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const selectedSourceFilePath = useLogStore((s) => s.selectedSourceFilePath);
  const activeSource = useLogStore((s) => s.activeSource);
  const knownSources = useLogStore((s) => s.knownSources);
  const selectedId = useLogStore((s) => s.selectedId);
  const isLoading = useLogStore((s) => s.isLoading);
  const isPaused = useLogStore((s) => s.isPaused);
  const sourceStatus = useLogStore((s) => s.sourceStatus);

  const activeView = useUiStore((s) => s.activeView);
  const showDetails = useUiStore((s) => s.showDetails);
  const showInfoPane = useUiStore((s) => s.showInfoPane);
  const intuneAnalysisState = useIntuneStore((s) => s.analysisState);
  const intuneSummary = useIntuneStore((s) => s.summary);
  const intuneSourceContext = useIntuneStore((s) => s.sourceContext);
  const intuneTimelineScope = useIntuneStore((s) => s.timelineScope);

  const filterClauseCount = useFilterStore((s) => s.clauses.length);
  const filteredIds = useFilterStore((s) => s.filteredIds);
  const isFiltering = useFilterStore((s) => s.isFiltering);
  const filterError = useFilterStore((s) => s.filterError);

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

  if (activeView === "log") {
    leftParts = [
      streamStatus.label,
      uiChromeStatus.viewLabel,
      uiChromeStatus.detailsLabel,
      uiChromeStatus.infoLabel,
      activeFileName ? `Source ${activeFileName}` : `Source ${activeSourceLabel}`,
    ];

    if (parserDisplay) {
      leftParts.push(`Parser ${parserDisplay.parserLabel}`);
    }

    if (elapsedText) {
      leftParts.push(elapsedText);
    }

    const logStatusText =
      entries.length > 0
        ? [
          `${entries.length} entries`,
          `${totalLines} lines`,
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
            : "";

    const filterStatusText =
      filterError
        ? `Filter error: ${filterError}`
        : filterStatus.label;

    rightStatusText = [logStatusText, filterStatusText]
      .filter((part) => part.length > 0)
      .join(" | ");
  } else {
    const intuneSourceLabel = getBaseName(
      intuneAnalysisState.requestedPath ?? intuneSourceContext.analyzedPath
    );

    leftParts = [
      "Intune Diagnostics",
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
    } else if (intuneAnalysisState.phase === "error" || intuneAnalysisState.phase === "empty") {
      rightStatusText = [intuneAnalysisState.message, intuneAnalysisState.detail]
        .filter((part): part is string => Boolean(part))
        .join(" | ");
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
  }

  const leftStatusText = leftParts.join(" • ");

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "2px 8px",
        backgroundColor: "#f0f0f0",
        borderTop: "1px solid #c0c0c0",
        fontSize: "12px",
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
        flexShrink: 0,
        height: "22px",
        gap: "10px",
      }}
    >
      <span
        title={leftStatusText}
        style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
      >
        {leftStatusText}
      </span>
      <span
        title={rightStatusText}
        style={{
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          color:
            activeView === "intune"
              ? intuneAnalysisState.phase === "error"
                ? "#991b1b"
                : intuneAnalysisState.phase === "empty"
                  ? "#92400e"
                  : intuneAnalysisState.phase === "analyzing"
                    ? "#1d4ed8"
                    : undefined
              : filterStatus.tone === "error"
                ? "#991b1b"
                : undefined,
        }}
      >
        {rightStatusText}
      </span>
    </div>
  );
}
