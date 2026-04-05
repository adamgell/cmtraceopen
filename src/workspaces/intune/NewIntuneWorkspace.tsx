import { useMemo, useState } from "react";
import {
  Badge,
  Body1,
  Body1Strong,
  Button,
  Caption1,
  Card,
  Divider,
  Title3,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useIntuneStore } from "./intune-store";
import { useUiStore } from "../../stores/ui-store";
import { useAppActions } from "../../components/layout/Toolbar";
import { EventLogSurface } from "./EventLogSurface";
import { InvestigationPanel } from "./InvestigationPanel";
import { OverviewSurface } from "./OverviewSurface";
import type {
  IntuneDiagnosticInsight,
  IntuneDiagnosticSeverity,
  IntuneEvent,
  IntuneEventType,
  IntuneRepeatedFailureGroup,
  IntuneRemediationPriority,
  IntuneStatus,
} from "./types";

type NewIntuneSurface = "overview" | "timeline" | "downloads" | "event-logs";

const useStyles = makeStyles({
  root: {
    display: "flex",
    flexDirection: "column",
    height: "100%",
    minHeight: 0,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  hero: {
    ...shorthands.padding("18px", "20px", "16px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground1,
    backdropFilter: "blur(10px)",
  },
  heroTop: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "16px",
    flexWrap: "wrap",
  },
  heroTitleBlock: {
    display: "grid",
    gap: "6px",
    minWidth: 0,
  },
  heroActions: {
    display: "flex",
    gap: "8px",
    alignItems: "center",
    flexWrap: "wrap",
  },
  sourcePillRow: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap",
    marginTop: "12px",
  },
  sourcePill: {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    ...shorthands.padding("6px", "10px"),
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    backgroundColor: tokens.colorNeutralBackground1,
    minWidth: 0,
  },
  bandCaption: {
    color: tokens.colorNeutralForeground3,
  },
  surfaceNav: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "12px",
    flexWrap: "wrap",
    ...shorthands.padding("10px", "20px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  navButtons: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap",
  },
  filterSummary: {
    display: "flex",
    gap: "6px",
    flexWrap: "wrap",
    alignItems: "center",
  },
  body: {
    flex: 1,
    minHeight: 0,
    overflow: "auto",
    ...shorthands.padding("18px", "20px", "20px"),
  },
  investigationBody: {
    flex: 1,
    minHeight: 0,
  },
  emptyWrap: {
    display: "grid",
    placeItems: "center",
    height: "100%",
  },
  emptyCard: {
    width: "min(720px, 100%)",
    backgroundColor: tokens.colorNeutralCardBackground,
  },
});

/** Inline style that forces Fluent typography components to inherit font size. */
const inheritFontSize: React.CSSProperties = { fontSize: "inherit" };

export function NewIntuneWorkspace() {
  const styles = useStyles();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );
  const LIVE_COLLECTION_SOURCE_ID = "windows-intune-ime-logs";
  const events = useIntuneStore((s) => s.events);
  const downloads = useIntuneStore((s) => s.downloads);
  const summary = useIntuneStore((s) => s.summary);
  const diagnostics = useIntuneStore((s) => s.diagnostics);
  const diagnosticsCoverage = useIntuneStore((s) => s.diagnosticsCoverage);
  const diagnosticsConfidence = useIntuneStore((s) => s.diagnosticsConfidence);
  const repeatedFailures = useIntuneStore((s) => s.repeatedFailures);
  const evidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const eventLogAnalysis = useIntuneStore((s) => s.eventLogAnalysis);
  const sourceContext = useIntuneStore((s) => s.sourceContext);
  const analysisState = useIntuneStore((s) => s.analysisState);
  const isAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const timelineScope = useIntuneStore((s) => s.timelineScope);
  const filterEventType = useIntuneStore((s) => s.filterEventType);
  const filterStatus = useIntuneStore((s) => s.filterStatus);
  const setFilterEventType = useIntuneStore((s) => s.setFilterEventType);
  const setFilterStatus = useIntuneStore((s) => s.setFilterStatus);
  const setTimelineFileScope = useIntuneStore((s) => s.setTimelineFileScope);
  const clearTimelineFileScope = useIntuneStore(
    (s) => s.clearTimelineFileScope,
  );
  const selectEvent = useIntuneStore((s) => s.selectEvent);
  const selectEventLogEntry = useIntuneStore((s) => s.selectEventLogEntry);
  const {
    commandState,
    openKnownSourceById,
    openSourceFileDialog,
    openSourceFolderDialog,
    refreshActiveSource,
  } = useAppActions();

  const [surface, setSurface] = useState<NewIntuneSurface>("overview");
  const sourceLabel = analysisState.requestedPath ?? sourceContext.analyzedPath;
  const sortedDiagnostics = useMemo(() => {
    return [...diagnostics].sort((left, right) => {
      const severityOrder =
        severityRank(right.severity) - severityRank(left.severity);
      if (severityOrder !== 0) {
        return severityOrder;
      }

      return (
        priorityRank(right.remediationPriority) -
        priorityRank(left.remediationPriority)
      );
    });
  }, [diagnostics]);
  const featuredDiagnostics = sortedDiagnostics.slice(0, 4);
  const immediateCount = diagnostics.filter(
    (item) => item.remediationPriority === "Immediate",
  ).length;
  const warningCount = diagnostics.filter(
    (item) => item.severity === "Warning",
  ).length;
  const hasAnyResult =
    summary != null || events.length > 0 || downloads.length > 0;
  const dominantSourceLabel = diagnosticsCoverage.dominantSource
    ? getFileName(diagnosticsCoverage.dominantSource.filePath)
    : "No dominant source";
  const hasEventLogAnalysis = eventLogAnalysis != null;
  const eventLogHint = useMemo(() => {
    if (!eventLogAnalysis) {
      return null;
    }

    if (eventLogAnalysis.sourceKind === "Live" && eventLogAnalysis.liveQuery) {
      return `${eventLogAnalysis.totalEntryCount} entries from ${eventLogAnalysis.liveQuery.channelsWithResultsCount} of ${eventLogAnalysis.liveQuery.attemptedChannelCount} channels`;
    }

    return `${eventLogAnalysis.totalEntryCount} entries across ${eventLogAnalysis.parsedFileCount} channel(s)`;
  }, [eventLogAnalysis]);

  function resetInvestigation() {
    setFilterEventType("All");
    setFilterStatus("All");
    clearTimelineFileScope();
    selectEvent(null);
  }

  function openTimelineForDiagnostic(diagnostic: IntuneDiagnosticInsight) {
    const eventType = inferEventTypeForDiagnostic(diagnostic);
    const status = inferStatusForDiagnostic(diagnostic);
    setSurface("timeline");
    setFilterEventType(eventType);
    setFilterStatus(status);

    const scopedFile = diagnostic.affectedSourceFiles[0] ?? null;
    if (scopedFile) {
      setTimelineFileScope(scopedFile);
    } else {
      clearTimelineFileScope();
    }

    const matchingEvent = events.find((event) =>
      eventMatchesDiagnostic(event, diagnostic, eventType, status),
    );
    selectEvent(matchingEvent?.id ?? null);
  }

  function openTimelineForFailure(group: IntuneRepeatedFailureGroup) {
    setSurface("timeline");
    setFilterEventType(group.eventType);
    setFilterStatus("All");

    if (group.sourceFiles.length === 1) {
      setTimelineFileScope(group.sourceFiles[0]);
    } else {
      clearTimelineFileScope();
    }

    selectEvent(group.sampleEventIds[0] ?? null);
  }

  function scopeToFile(filePath: string | null) {
    setSurface("timeline");
    setFilterEventType("All");
    setFilterStatus("All");
    if (filePath) {
      setTimelineFileScope(filePath);
    } else {
      clearTimelineFileScope();
    }
    selectEvent(null);
  }

  function startLiveAnalysis() {
    void openKnownSourceById(
      LIVE_COLLECTION_SOURCE_ID,
      "new-intune.start-live-analysis",
    );
  }

  if (
    !hasAnyResult &&
    !isAnalyzing &&
    analysisState.phase !== "error" &&
    analysisState.phase !== "empty"
  ) {
    return (
      <div className={styles.root}>
        <div className={styles.emptyWrap}>
          <Card className={styles.emptyCard}>
            <div className={styles.heroTitleBlock}>
              <Badge appearance="filled" color="brand">
                New Intune Workspace
              </Badge>
              <Title3 style={inheritFontSize}>Start from the signals, not the scrollback</Title3>
              <Body1 style={inheritFontSize}>
                This workspace is tuned for triage-first Intune diagnostics.
                Analyze the live IME logs and live Windows event channels
                directly from the machine, or open a captured file or evidence
                folder when you need to work from a saved snapshot.
              </Body1>
            </div>
            <Divider />
            <div className={styles.heroActions}>
              <Button
                appearance="primary"
                onClick={startLiveAnalysis}
                disabled={!commandState.canOpenKnownSources}
              >
                Analyze Live Logs + Event Logs
              </Button>
              <Button
                appearance="secondary"
                onClick={() => void openSourceFileDialog()}
                disabled={!commandState.canOpenSources}
              >
                Open IME Log File
              </Button>
              <Button
                appearance="secondary"
                onClick={() => void openSourceFolderDialog()}
                disabled={!commandState.canOpenSources}
              >
                Open IME Or Evidence Folder
              </Button>
            </div>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.root} style={{ fontSize: `${metrics.fontSize}px`, lineHeight: `${metrics.rowLineHeight}px` }}>
      <div className={styles.hero}>
        <div className={styles.heroTop}>
          <div className={styles.heroTitleBlock}>
            <Badge appearance="filled" color="brand">
              New Intune Workspace
            </Badge>
            <Title3 style={inheritFontSize}>
              Operational Triage for Intune Evidence
            </Title3>
            <Caption1 className={styles.bandCaption}>
              Move from failure signal to supporting log activity without
              dropping into a long text-first summary.
            </Caption1>
          </div>

          <div className={styles.heroActions}>
            <Button
              appearance="primary"
              onClick={startLiveAnalysis}
              disabled={!commandState.canOpenKnownSources}
            >
              Analyze Live Logs + Event Logs
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void openSourceFileDialog()}
              disabled={!commandState.canOpenSources}
            >
              Open IME Log File
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void openSourceFolderDialog()}
              disabled={!commandState.canOpenSources}
            >
              Open IME Or Evidence Folder
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void refreshActiveSource()}
              disabled={!commandState.canRefresh}
            >
              Refresh Analysis
            </Button>
          </div>
        </div>

        <div className={styles.sourcePillRow}>
          <div className={styles.sourcePill}>
            <Caption1 style={inheritFontSize}>Source</Caption1>
            <Body1Strong style={inheritFontSize} title={sourceLabel ?? undefined}>
              {sourceLabel ?? "No source selected"}
            </Body1Strong>
          </div>
          <div className={styles.sourcePill}>
            <Caption1 style={inheritFontSize}>State</Caption1>
            <Body1Strong style={inheritFontSize}>{analysisState.message}</Body1Strong>
          </div>
          <div className={styles.sourcePill}>
            <Caption1 style={inheritFontSize}>Bundle</Caption1>
            <Body1Strong style={inheritFontSize}>
              {evidenceBundle?.bundleLabel ??
                evidenceBundle?.bundleId ??
                "Standalone logs"}
            </Body1Strong>
          </div>
        </div>
      </div>

      <nav className={styles.surfaceNav} aria-label="Intune analysis views">
        <div className={styles.navButtons} role="tablist">
          <Button
            appearance={surface === "overview" ? "primary" : "secondary"}
            onClick={() => setSurface("overview")}
            role="tab"
            aria-selected={surface === "overview"}
          >
            Overview
          </Button>
          <Button
            appearance={surface === "timeline" ? "primary" : "secondary"}
            onClick={() => setSurface("timeline")}
            disabled={events.length === 0}
            role="tab"
            aria-selected={surface === "timeline"}
          >
            Event Evidence
          </Button>
          <Button
            appearance={surface === "downloads" ? "primary" : "secondary"}
            onClick={() => setSurface("downloads")}
            disabled={downloads.length === 0}
            role="tab"
            aria-selected={surface === "downloads"}
          >
            Download Evidence
          </Button>
          <Button
            appearance={surface === "event-logs" ? "primary" : "secondary"}
            onClick={() => setSurface("event-logs")}
            disabled={!hasEventLogAnalysis}
            role="tab"
            aria-selected={surface === "event-logs"}
          >
            Event Log Evidence
            {eventLogAnalysis && eventLogAnalysis.errorEntryCount > 0 && (
              <Badge
                appearance="filled"
                color="important"
                style={{ marginLeft: 6 }}
              >
                {eventLogAnalysis.errorEntryCount}
              </Badge>
            )}
          </Button>
          <Button appearance="secondary" onClick={resetInvestigation}>
            Reset Investigation
          </Button>
        </div>

        <div className={styles.filterSummary}>
          {timelineScope.filePath && (
            <Badge appearance="filled" color="informative">
              Scoped to {getFileName(timelineScope.filePath)}
            </Badge>
          )}
          {filterEventType !== "All" && (
            <Badge appearance="outline" color="brand">
              Type {formatEventTypeLabel(filterEventType)}
            </Badge>
          )}
          {filterStatus !== "All" && (
            <Badge appearance="outline" color="warning">
              Status {filterStatus}
            </Badge>
          )}
          {diagnosticsCoverage.hasRotatedLogs && (
            <Badge appearance="outline" color="warning">
              Rotated logs detected
            </Badge>
          )}
        </div>
      </nav>

      <div
        className={
          surface === "event-logs" ? styles.investigationBody : styles.body
        }
        role="tabpanel"
      >
        {surface === "overview" ? (
          <OverviewSurface
            sortedDiagnostics={sortedDiagnostics}
            featuredDiagnostics={featuredDiagnostics}
            immediateCount={immediateCount}
            warningCount={warningCount}
            repeatedFailures={repeatedFailures}
            dominantSourceLabel={dominantSourceLabel}
            diagnosticsCoverageFiles={diagnosticsCoverage.files}
            dominantSourceEventShare={
              diagnosticsCoverage.dominantSource?.eventShare ?? null
            }
            diagnosticsConfidence={diagnosticsConfidence}
            eventLogAnalysis={eventLogAnalysis}
            eventLogHint={eventLogHint}
            totalDownloads={summary?.totalDownloads ?? 0}
            successfulDownloads={summary?.successfulDownloads ?? 0}
            failedDownloads={summary?.failedDownloads ?? 0}
            diagnosticsCoverageHasRotatedLogs={diagnosticsCoverage.hasRotatedLogs}
            onOpenTimelineForDiagnostic={openTimelineForDiagnostic}
            onOpenTimelineForFailure={openTimelineForFailure}
            onScopeToFile={scopeToFile}
            onShowDownloads={() => setSurface("downloads")}
            onShowEventLogs={() => setSurface("event-logs")}
            onSelectEventLogEntry={(id) => {
              selectEventLogEntry(id);
              setSurface("event-logs");
            }}
          />
        ) : surface === "event-logs" ? (
          <EventLogSurface
            onNavigateToTimeline={(intuneEventId) => {
              setSurface("timeline");
              selectEvent(intuneEventId);
            }}
            onNavigateToOverview={() => setSurface("overview")}
          />
        ) : (
          <InvestigationPanel
            surface={surface === "timeline" ? "timeline" : "downloads"}
            events={events}
            downloads={downloads}
            timelineScopeFilePath={timelineScope.filePath}
            filterEventType={filterEventType}
            filterStatus={filterStatus}
          />
        )}
      </div>
    </div>
  );
}

/* ─── Pure utility functions ─── */

function severityRank(severity: IntuneDiagnosticSeverity): number {
  switch (severity) {
    case "Error":
      return 3;
    case "Warning":
      return 2;
    case "Info":
    default:
      return 1;
  }
}

function priorityRank(priority: IntuneRemediationPriority): number {
  switch (priority) {
    case "Immediate":
      return 4;
    case "High":
      return 3;
    case "Medium":
      return 2;
    case "Monitor":
    default:
      return 1;
  }
}

function inferEventTypeForDiagnostic(
  diagnostic: IntuneDiagnosticInsight,
): IntuneEventType | "All" {
  switch (diagnostic.category) {
    case "Download":
      return "ContentDownload";
    case "Install":
      return "Win32App";
    case "Script":
      return "PowerShellScript";
    case "Policy":
      return "PolicyEvaluation";
    case "Timeout":
    case "State":
    case "General":
    default:
      return "All";
  }
}

function inferStatusForDiagnostic(
  diagnostic: IntuneDiagnosticInsight,
): IntuneStatus | "All" {
  if (diagnostic.category === "Timeout") {
    return "Timeout";
  }

  if (diagnostic.severity === "Info") {
    return "All";
  }

  return "Failed";
}

function eventMatchesDiagnostic(
  event: IntuneEvent,
  diagnostic: IntuneDiagnosticInsight,
  eventType: IntuneEventType | "All",
  status: IntuneStatus | "All",
): boolean {
  if (eventType !== "All" && event.eventType !== eventType) {
    return false;
  }

  if (status !== "All" && event.status !== status) {
    return false;
  }

  if (
    diagnostic.relatedErrorCodes.length > 0 &&
    event.errorCode &&
    diagnostic.relatedErrorCodes.includes(event.errorCode)
  ) {
    return true;
  }

  if (
    diagnostic.affectedSourceFiles.length > 0 &&
    diagnostic.affectedSourceFiles.includes(event.sourceFile)
  ) {
    return true;
  }

  return eventType !== "All" || status !== "All";
}

function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  return normalized.split("/").pop() ?? path;
}

function formatEventTypeLabel(eventType: IntuneEventType): string {
  switch (eventType) {
    case "Win32App":
      return "Win32 app";
    case "WinGetApp":
      return "WinGet app";
    case "PowerShellScript":
      return "PowerShell script";
    case "Remediation":
      return "Remediation";
    case "Esp":
      return "ESP";
    case "SyncSession":
      return "Sync session";
    case "PolicyEvaluation":
      return "Policy evaluation";
    case "ContentDownload":
      return "Content download";
    case "Other":
    default:
      return "Other";
  }
}
