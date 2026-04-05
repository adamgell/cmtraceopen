import { Badge, tokens } from "@fluentui/react-components";
import { getBaseName } from "../../lib/file-paths";
import { useUiStore } from "../../stores/ui-store";
import { useIntuneStore } from "./intune-store";
import {
  EmptyState,
  SectionHeader,
  SourceStatusNotice,
  SourceSummaryCard,
} from "../../components/common/sidebar-primitives";

// ---------------------------------------------------------------------------
// IntuneSidebar
// ---------------------------------------------------------------------------

export function IntuneSidebar() {
  const activeView = useUiStore((s) => s.activeView);
  const intuneAnalysisState = useIntuneStore((s) => s.analysisState);
  const intuneIsAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const intuneSummary = useIntuneStore((s) => s.summary);
  const eventLogAnalysis = useIntuneStore((s) => s.eventLogAnalysis);
  const intuneEvidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const intuneSourceContext = useIntuneStore((s) => s.sourceContext);
  const intuneTimelineScope = useIntuneStore((s) => s.timelineScope);
  const setIntuneTimelineFileScope = useIntuneStore((s) => s.setTimelineFileScope);

  const intuneIncludedFiles = intuneSourceContext.includedFiles;
  const intuneSelectedFilePath = intuneTimelineScope.filePath;
  const intuneRequestedPath = intuneAnalysisState.requestedPath;
  const hasIntuneResults = intuneSummary != null || intuneIncludedFiles.length > 0;
  const workspaceTitle = activeView === "new-intune" ? "New Intune Workspace" : "Intune diagnostics workspace";
  const workspaceBadge = activeView === "new-intune" ? "New Intune" : intuneEvidenceBundle ? "Intune Bundle" : "Intune";

  return (
    <>
      <SourceSummaryCard
        badge={workspaceBadge}
        title={getBaseName(intuneRequestedPath) || workspaceTitle}
        subtitle={intuneRequestedPath ?? "Select an IME log source to begin analysis."}
        body={
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.45 }}>
            <div>{intuneAnalysisState.message}</div>
            <div style={{ marginTop: "4px" }}>Included files: {intuneIncludedFiles.length}</div>
            {intuneEvidenceBundle && (
              <div style={{ marginTop: "4px" }}>
                Bundle: {intuneEvidenceBundle.bundleLabel ?? intuneEvidenceBundle.bundleId ?? "Detected"}
              </div>
            )}
            {intuneSummary && <div style={{ marginTop: "4px" }}>Events: {intuneSummary.totalEvents}</div>}
            {eventLogAnalysis && (
              <div style={{ marginTop: "4px" }}>
                Event logs: {eventLogAnalysis.totalEntryCount} entries
                {eventLogAnalysis.sourceKind === "Live" && eventLogAnalysis.liveQuery
                  ? ` across ${eventLogAnalysis.liveQuery.channelsWithResultsCount}/${eventLogAnalysis.liveQuery.attemptedChannelCount} queried channels`
                  : ` across ${eventLogAnalysis.parsedFileCount} channel(s)`}
              </div>
            )}
          </div>
        }
      />

      {(intuneAnalysisState.phase === "analyzing" ||
        intuneAnalysisState.phase === "error" ||
        intuneAnalysisState.phase === "empty") && (
        <SourceStatusNotice
          kind={
            intuneAnalysisState.phase === "error"
              ? "error"
              : intuneAnalysisState.phase === "empty"
                ? "empty"
                : "info"
          }
          message={intuneAnalysisState.message}
          detail={intuneAnalysisState.detail ?? undefined}
        />
      )}

      <div style={{ flex: 1, overflow: "auto", backgroundColor: tokens.colorNeutralBackground2 }}>
        {!hasIntuneResults && !intuneIsAnalyzing && intuneAnalysisState.phase !== "error" && (
          <EmptyState
            title="No Intune diagnostics data"
            body="Select an Intune Management Extension (IME) log source to begin analysis."
          />
        )}

        {intuneIsAnalyzing && (
          <EmptyState
            title="Analyzing Intune logs"
            body="Scanning source files for events, downloads, and metrics..."
          />
        )}

        {!hasIntuneResults && intuneAnalysisState.phase === "error" && (
          <EmptyState
            title="Intune diagnostics failed"
            body={intuneAnalysisState.detail ?? "The selected Intune source could not be analyzed."}
          />
        )}

        {intuneSummary && (
          <>
            <SectionHeader title="Diagnostics Summary" caption="Overview of the current Intune diagnostics data" />
            <div style={{
              padding: "10px",
              borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              display: "grid",
              gridTemplateColumns: "auto 1fr",
              gap: "4px 10px",
              alignItems: "baseline",
            }}>
              <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Events</span>
              <span>{intuneSummary.totalEvents.toLocaleString()}</span>
              <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Downloads</span>
              <span>{intuneSummary.totalDownloads}</span>
              {eventLogAnalysis && (
                <>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Event logs</span>
                  <span>{eventLogAnalysis.totalEntryCount.toLocaleString()} entries</span>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Severity</span>
                  <span>{eventLogAnalysis.errorEntryCount} errors, {eventLogAnalysis.warningEntryCount} warnings</span>
                </>
              )}
              {eventLogAnalysis?.sourceKind === "Live" && eventLogAnalysis.liveQuery && (
                <>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Live query</span>
                  <span>{eventLogAnalysis.liveQuery.successfulChannelCount} ok, {eventLogAnalysis.liveQuery.failedChannelCount} failed</span>
                </>
              )}
              {intuneSummary.logTimeSpan && (
                <>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Time span</span>
                  <span>{intuneSummary.logTimeSpan}</span>
                </>
              )}
            </div>
          </>
        )}

        {intuneIncludedFiles.length > 0 && (
          <>
            <SectionHeader
              title={`Included Files (${intuneIncludedFiles.length})`}
              caption={intuneSelectedFilePath
                ? "Timeline is scoped — click the active file to clear scope"
                : "Click a file to scope the timeline to that log only"}
            />
            {intuneIncludedFiles.map((path) => {
              const isSelected = intuneSelectedFilePath === path;
              return (
                <button
                  key={path}
                  type="button"
                  onClick={() => setIntuneTimelineFileScope(isSelected ? null : path)}
                  aria-pressed={isSelected}
                  title={path}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    padding: isSelected ? "10px 10px 10px 9px" : "7px 10px 7px 9px",
                    border: "none",
                    borderLeft: isSelected ? `4px solid ${tokens.colorCompoundBrandStroke}` : "4px solid transparent",
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    fontSize: "inherit",
                    color: isSelected ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground2,
                    backgroundColor: isSelected ? tokens.colorNeutralBackground1Selected : tokens.colorNeutralBackground1,
                    cursor: "pointer",
                    transition: "background-color 100ms ease",
                  }}
                >
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}>
                    <div style={{
                      flex: 1,
                      minWidth: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontWeight: isSelected ? 700 : 400,
                    }}>
                      {getBaseName(path)}
                    </div>
                    {isSelected && (
                      <Badge appearance="filled" color="brand" size="small" style={{ flexShrink: 0 }}>
                        Scoped
                      </Badge>
                    )}
                  </div>
                  {isSelected && (
                    <div style={{
                      marginTop: "4px",
                      fontSize: "0.85em",
                      color: tokens.colorBrandForeground1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {path}
                    </div>
                  )}
                </button>
              );
            })}
          </>
        )}
      </div>
    </>
  );
}
