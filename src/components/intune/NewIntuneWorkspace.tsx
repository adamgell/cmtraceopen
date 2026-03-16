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
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getLogListMetrics } from "../../lib/log-accessibility";
import {
  useIntuneStore,
  getEventLogEntryIdsForDiagnostic,
} from "../../stores/intune-store";
import { useUiStore } from "../../stores/ui-store";
import { useAppActions } from "../layout/Toolbar";
import { DownloadSurface } from "./DownloadSurface";
import { EventLogSurface } from "./EventLogSurface";
import { EventTimeline } from "./EventTimeline";
import type { EventLogEntry } from "../../types/event-log";
import type {
  IntuneDiagnosticInsight,
  IntuneDiagnosticSeverity,
  IntuneEvent,
  IntuneEventType,
  IntuneRepeatedFailureGroup,
  IntuneRemediationPriority,
  IntuneStatus,
} from "../../types/intune";

type NewIntuneSurface = "overview" | "timeline" | "downloads" | "event-logs";

const useStyles = makeStyles({
  root: {
    display: "flex",
    flexDirection: "column",
    height: "100%",
    minHeight: 0,
    backgroundColor: tokens.colorNeutralBackground1,
    backgroundImage:
      "radial-gradient(circle at top right, rgba(15,108,189,0.12), transparent 28%), linear-gradient(180deg, rgba(255,255,255,0.96) 0%, rgba(244,247,251,1) 100%)",
  },
  hero: {
    ...shorthands.padding("18px", "20px", "16px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: "rgba(255,255,255,0.86)",
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
    backgroundColor: "rgba(255,255,255,0.72)",
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
  emptyWrap: {
    display: "grid",
    placeItems: "center",
    height: "100%",
  },
  emptyCard: {
    width: "min(720px, 100%)",
    backgroundColor: "rgba(255,255,255,0.96)",
  },
  metricsGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
    gap: "12px",
    marginBottom: "16px",
  },
  metricCard: {
    display: "grid",
    gap: "8px",
    minHeight: "116px",
    backgroundColor: "rgba(255,255,255,0.96)",
  },
  metricValue: {
    fontWeight: 700,
    color: tokens.colorNeutralForeground1,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  textStack: {
    display: "grid",
    gap: "4px",
  },
  overviewGrid: {
    display: "grid",
    gridTemplateColumns: "minmax(0, 1.6fr) minmax(320px, 1fr)",
    gap: "14px",
    alignItems: "start",
  },
  column: {
    display: "grid",
    gap: "14px",
    minWidth: 0,
  },
  sectionCard: {
    display: "grid",
    gap: "12px",
    backgroundColor: "rgba(255,255,255,0.96)",
  },
  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    alignItems: "flex-start",
    flexWrap: "wrap",
  },
  issueList: {
    display: "grid",
    gap: "12px",
  },
  issueCard: {
    display: "grid",
    gap: "10px",
    ...shorthands.padding("14px"),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    backgroundColor: tokens.colorNeutralBackground1,
    borderLeftWidth: "4px",
    borderLeftStyle: "solid",
  },
  issueMeta: {
    display: "flex",
    gap: "6px",
    flexWrap: "wrap",
    alignItems: "center",
  },
  issueActions: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap",
  },
  bulletList: {
    display: "grid",
    gap: "6px",
  },
  bulletItem: {
    display: "grid",
    gridTemplateColumns: "10px minmax(0, 1fr)",
    gap: "8px",
    alignItems: "start",
    color: tokens.colorNeutralForeground2,
  },
  bulletDot: {
    width: "6px",
    height: "6px",
    marginTop: "6px",
    ...shorthands.borderRadius("999px"),
    backgroundColor: tokens.colorBrandBackground,
  },
  failureRow: {
    display: "grid",
    gap: "10px",
    ...shorthands.padding("12px"),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    backgroundColor: tokens.colorNeutralBackground1,
  },
  compactFact: {
    display: "grid",
    gap: "2px",
    ...shorthands.padding("10px", "12px"),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: tokens.colorNeutralBackground2,
  },
  investigationShell: {
    display: "grid",
    gap: "12px",
    height: "100%",
    minHeight: 0,
  },
  investigationFrame: {
    minHeight: "520px",
    display: "flex",
    flexDirection: "column",
    overflow: "hidden",
    backgroundColor: "rgba(255,255,255,0.96)",
  },
  investigationHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    alignItems: "center",
    flexWrap: "wrap",
    ...shorthands.padding("12px", "14px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  investigationBody: {
    flex: 1,
    minHeight: 0,
  },
  scopeRow: {
    display: "flex",
    gap: "6px",
    flexWrap: "wrap",
    alignItems: "center",
  },
  sourceList: {
    display: "grid",
    gap: "8px",
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
  const sourceFamilies = useMemo(
    () =>
      buildSourceFamilies(
        diagnosticsCoverage.files.map((file) => file.filePath),
      ),
    [diagnosticsCoverage.files],
  );
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

  const topCorrelatedEventLogEntries = useMemo(() => {
    if (!eventLogAnalysis || eventLogAnalysis.correlationLinks.length === 0)
      return [];

    const entryMap = new Map(eventLogAnalysis.entries.map((e) => [e.id, e]));
    const seenIds = new Set<number>();
    const results: Array<{ entry: EventLogEntry; timeDelta: number | null }> =
      [];

    for (const link of eventLogAnalysis.correlationLinks) {
      if (seenIds.has(link.eventLogEntryId)) continue;
      const entry = entryMap.get(link.eventLogEntryId);
      if (!entry) continue;
      seenIds.add(link.eventLogEntryId);
      results.push({ entry, timeDelta: link.timeDeltaSecs });
    }

    // Sort by severity rank (Critical > Error > Warning > rest), then by time delta (closest first)
    const sevRank: Record<string, number> = {
      Critical: 5,
      Error: 4,
      Warning: 3,
      Information: 2,
      Verbose: 1,
      Unknown: 0,
    };
    results.sort((a, b) => {
      const sevDiff =
        (sevRank[b.entry.severity] ?? 0) - (sevRank[a.entry.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return (a.timeDelta ?? Infinity) - (b.timeDelta ?? Infinity);
    });

    return results.slice(0, 5);
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
          <div>
            <div className={styles.metricsGrid} role="region" aria-label="Analysis metrics">
              <MetricCard
                title="Active issues"
                value={String(sortedDiagnostics.length)}
                hint={`${immediateCount} immediate, ${warningCount} warnings`}
                accent={getSeverityBorderColor("Error")}
              />
              <MetricCard
                title="Repeated failures"
                value={String(repeatedFailures.length)}
                hint={
                  repeatedFailures[0]
                    ? `${repeatedFailures[0].occurrences} hits in ${repeatedFailures[0].name}`
                    : "No repeated failure clusters"
                }
                accent={tokens.colorPaletteMarigoldBorder2}
              />
              <MetricCard
                title="Evidence confidence"
                value={diagnosticsConfidence.level}
                hint={formatConfidenceHint(
                  diagnosticsConfidence.score,
                  diagnosticsConfidence.reasons.length,
                )}
                accent={tokens.colorBrandBackground2}
              />
              <MetricCard
                title="Dominant source"
                value={dominantSourceLabel}
                hint={
                  diagnosticsCoverage.dominantSource?.eventShare != null
                    ? `${Math.round(diagnosticsCoverage.dominantSource.eventShare * 100)}% of scored events`
                    : `${diagnosticsCoverage.files.length} analyzed files`
                }
                accent="#0f766e"
              />
              {eventLogAnalysis && (
                <MetricCard
                  title="Event log signals"
                  value={String(
                    eventLogAnalysis.errorEntryCount +
                      eventLogAnalysis.warningEntryCount,
                  )}
                  hint={eventLogHint ?? "No Windows Event Log evidence"}
                  accent="#7c3aed"
                />
              )}
              {(summary?.totalDownloads ?? 0) > 0 && (
                <MetricCard
                  title="Content downloads"
                  value={String(summary?.totalDownloads ?? 0)}
                  hint={`${summary?.successfulDownloads ?? 0} succeeded, ${summary?.failedDownloads ?? 0} failed`}
                  accent="#ea580c"
                />
              )}
            </div>

            <div className={styles.overviewGrid}>
              <div className={styles.column}>
                <Card className={styles.sectionCard}>
                  <div className={styles.sectionHeader}>
                    <div className={styles.textStack}>
                      <Title3 style={inheritFontSize}>Priority issues</Title3>
                      <Caption1 style={inheritFontSize}>
                        These are the best entry points into the current
                        investigation set.
                      </Caption1>
                    </div>
                    <Badge appearance="outline" color="brand">
                      {featuredDiagnostics.length} shown
                    </Badge>
                  </div>

                  <div className={styles.issueList}>
                    {featuredDiagnostics.length > 0 ? (
                      featuredDiagnostics.map((diagnostic) => {
                        const elSignalCount = getEventLogEntryIdsForDiagnostic(
                          diagnostic.id,
                          eventLogAnalysis?.correlationLinks ?? [],
                        ).length;
                        return (
                          <DiagnosticTriageCard
                            key={diagnostic.id}
                            diagnostic={diagnostic}
                            onShowTimeline={() =>
                              openTimelineForDiagnostic(diagnostic)
                            }
                            onShowDownloads={() => setSurface("downloads")}
                            onScopeSource={() =>
                              scopeToFile(
                                diagnostic.affectedSourceFiles[0] ?? null,
                              )
                            }
                            eventLogSignalCount={elSignalCount}
                            onShowEventLogs={() => setSurface("event-logs")}
                          />
                        );
                      })
                    ) : (
                      <Body1 style={inheritFontSize}>
                        No diagnostics were generated for this analysis set.
                      </Body1>
                    )}
                  </div>
                </Card>

                <Card className={styles.sectionCard}>
                  <div className={styles.sectionHeader}>
                    <div className={styles.textStack}>
                      <Title3 style={inheritFontSize}>Evidence quality</Title3>
                      <Caption1 style={inheritFontSize}>
                        Why the current confidence level is what it is.
                      </Caption1>
                    </div>
                    <Badge
                      appearance="filled"
                      color={confidenceBadgeColor(diagnosticsConfidence.level)}
                    >
                      {diagnosticsConfidence.level}
                    </Badge>
                  </div>

                  <div className={styles.bulletList}>
                    {diagnosticsConfidence.reasons.length > 0 ? (
                      diagnosticsConfidence.reasons
                        .slice(0, 5)
                        .map((reason) => (
                          <BulletItem key={reason} text={reason} />
                        ))
                    ) : (
                      <Body1 style={inheritFontSize}>
                        No confidence rationale was produced for this result.
                      </Body1>
                    )}
                  </div>
                </Card>
              </div>

              <div className={styles.column}>
                <Card className={styles.sectionCard}>
                  <div className={styles.sectionHeader}>
                    <div className={styles.textStack}>
                      <Title3 style={inheritFontSize}>Failure patterns</Title3>
                      <Caption1 style={inheritFontSize}>
                        Repeated groups are usually the fastest way to isolate
                        broken cycles.
                      </Caption1>
                    </div>
                    <Badge appearance="outline" color="warning">
                      {repeatedFailures.length} groups
                    </Badge>
                  </div>

                  <div className={styles.issueList}>
                    {repeatedFailures.length > 0 ? (
                      repeatedFailures.slice(0, 5).map((group) => (
                        <div key={group.id} className={styles.failureRow}>
                          <div className={styles.issueMeta}>
                            <Badge appearance="filled" color="warning">
                              {group.occurrences} hits
                            </Badge>
                            <Badge appearance="outline" color="brand">
                              {formatEventTypeLabel(group.eventType)}
                            </Badge>
                            {group.errorCode && (
                              <Badge appearance="outline" color="important">
                                {group.errorCode}
                              </Badge>
                            )}
                          </div>
                          <div className={styles.textStack}>
                            <Body1Strong style={inheritFontSize}>{group.name}</Body1Strong>
                            <Caption1 style={inheritFontSize}>
                              {group.timestampBounds?.lastTimestamp
                                ? `Last seen ${formatDisplayDateTime(group.timestampBounds.lastTimestamp) ?? group.timestampBounds.lastTimestamp}`
                                : "Timestamp unavailable"}
                            </Caption1>
                          </div>
                          <div className={styles.issueActions}>
                            <Button
                              size="small"
                              appearance="primary"
                              onClick={() => openTimelineForFailure(group)}
                            >
                              Show related events
                            </Button>
                            <Button
                              size="small"
                              appearance="secondary"
                              onClick={() =>
                                scopeToFile(group.sourceFiles[0] ?? null)
                              }
                              disabled={group.sourceFiles.length === 0}
                            >
                              Scope source
                            </Button>
                          </div>
                        </div>
                      ))
                    ) : (
                      <Body1 style={inheritFontSize}>No repeated failure clusters were detected.</Body1>
                    )}
                  </div>
                </Card>

                <Card className={styles.sectionCard}>
                  <div className={styles.sectionHeader}>
                    <div className={styles.textStack}>
                      <Title3 style={inheritFontSize}>Source coverage</Title3>
                      <Caption1 style={inheritFontSize}>
                        Use this when you need to move from guidance to proof in
                        a specific log family.
                      </Caption1>
                    </div>
                    <Badge appearance="outline" color="informative">
                      {diagnosticsCoverage.files.length} files
                    </Badge>
                  </div>

                  <div className={styles.sourceList}>
                    {sourceFamilies.length > 0 ? (
                      sourceFamilies.map((family) => (
                        <div key={family.label} className={styles.compactFact}>
                          <Body1Strong style={inheritFontSize}>{family.label}</Body1Strong>
                          <Caption1 style={inheritFontSize}>
                            {family.count} file{family.count === 1 ? "" : "s"}
                          </Caption1>
                        </div>
                      ))
                    ) : (
                      <Body1 style={inheritFontSize}>No source family summary is available yet.</Body1>
                    )}
                  </div>
                </Card>

                {topCorrelatedEventLogEntries.length > 0 && (
                  <Card className={styles.sectionCard}>
                    <div className={styles.sectionHeader}>
                      <div className={styles.textStack}>
                        <Title3 style={inheritFontSize}>Correlated event log evidence</Title3>
                        <Caption1 style={inheritFontSize}>
                          Windows Event Log entries linked to IME diagnostics by
                          time, channel, or error code.
                        </Caption1>
                      </div>
                      <Badge appearance="filled" color="brand">
                        {eventLogAnalysis?.correlationLinks.length ?? 0} links
                      </Badge>
                    </div>

                    <div className={styles.issueList}>
                      {topCorrelatedEventLogEntries.map(
                        ({ entry, timeDelta }) => (
                          <div
                            key={entry.id}
                            className={styles.failureRow}
                            style={{ cursor: "pointer" }}
                            onClick={() => {
                              selectEventLogEntry(entry.id);
                              setSurface("event-logs");
                            }}
                          >
                            <div className={styles.issueMeta}>
                              <Badge
                                appearance="filled"
                                color={
                                  entry.severity === "Critical" ||
                                  entry.severity === "Error"
                                    ? "important"
                                    : entry.severity === "Warning"
                                      ? "warning"
                                      : "informative"
                                }
                              >
                                {entry.severity}
                              </Badge>
                              <Badge appearance="outline" color="brand">
                                {entry.channelDisplay}
                              </Badge>
                              <Badge appearance="outline" color="informative">
                                ID {entry.eventId}
                              </Badge>
                              {timeDelta != null && (
                                <Caption1 style={inheritFontSize}>
                                  {timeDelta < 60
                                    ? `${Math.round(timeDelta)}s delta`
                                    : timeDelta < 3600
                                      ? `${Math.round(timeDelta / 60)}m delta`
                                      : `${Math.round(timeDelta / 3600)}h delta`}
                                </Caption1>
                              )}
                            </div>
                            <div>
                              <Body1
                                style={{
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                  display: "block",
                                }}
                              >
                                {entry.message || "(no message)"}
                              </Body1>
                              <Caption1 style={inheritFontSize}>
                                {formatDisplayDateTime(entry.timestamp) ??
                                  entry.timestamp}
                              </Caption1>
                            </div>
                          </div>
                        ),
                      )}
                    </div>

                    <Button
                      size="small"
                      appearance="secondary"
                      onClick={() => setSurface("event-logs")}
                    >
                      View all event log evidence
                    </Button>
                  </Card>
                )}
              </div>
            </div>
          </div>
        ) : surface === "event-logs" ? (
          <EventLogSurface
            onNavigateToTimeline={(intuneEventId) => {
              setSurface("timeline");
              selectEvent(intuneEventId);
            }}
            onNavigateToOverview={() => setSurface("overview")}
          />
        ) : (
          <div className={styles.investigationShell}>
            <Card className={styles.investigationFrame}>
              <div className={styles.investigationHeader}>
                <div className={styles.textStack}>
                  <Title3 style={inheritFontSize}>
                    {surface === "timeline"
                      ? "Event evidence"
                      : "Download evidence"}
                  </Title3>
                  <Caption1 style={inheritFontSize}>
                    {surface === "timeline"
                      ? "Timeline filters and file scope are driven by the triage actions you choose above."
                      : "Download rows remain available as the supporting evidence surface for content retrieval failures."}
                  </Caption1>
                </div>
                <div className={styles.scopeRow}>
                  {surface === "timeline" && timelineScope.filePath && (
                    <Badge appearance="filled" color="informative">
                      {getFileName(timelineScope.filePath)}
                    </Badge>
                  )}
                  {surface === "timeline" && filterEventType !== "All" && (
                    <Badge appearance="outline" color="brand">
                      {formatEventTypeLabel(filterEventType)}
                    </Badge>
                  )}
                  {surface === "timeline" && filterStatus !== "All" && (
                    <Badge appearance="outline" color="warning">
                      {filterStatus}
                    </Badge>
                  )}
                </div>
              </div>

              <div className={styles.investigationBody}>
                {surface === "timeline" ? (
                  <EventTimeline events={events} />
                ) : (
                  <DownloadSurface downloads={downloads} />
                )}
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  hint,
  accent,
}: {
  title: string;
  value: string;
  hint: string;
  accent: string;
}) {
  const styles = useStyles();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metricFontSize = Math.round(
    getLogListMetrics(logListFontSize).fontSize * 2.2,
  );

  return (
    <Card
      className={styles.metricCard}
      style={{ borderTop: `4px solid ${accent}` }}
      role="group"
      aria-label={`${title}: ${value}`}
    >
      <Caption1 style={inheritFontSize}>{title}</Caption1>
      <div
        className={styles.metricValue}
        style={{
          fontSize: `${metricFontSize}px`,
          lineHeight: `${metricFontSize + 4}px`,
        }}
      >
        {value}
      </div>
      <Body1 style={inheritFontSize}>{hint}</Body1>
    </Card>
  );
}

function DiagnosticTriageCard({
  diagnostic,
  onShowTimeline,
  onShowDownloads,
  onScopeSource,
  eventLogSignalCount,
  onShowEventLogs,
}: {
  diagnostic: IntuneDiagnosticInsight;
  onShowTimeline: () => void;
  onShowDownloads: () => void;
  onScopeSource: () => void;
  eventLogSignalCount?: number;
  onShowEventLogs?: () => void;
}) {
  const styles = useStyles();

  return (
    <div
      className={styles.issueCard}
      style={{ borderLeftColor: getSeverityBorderColor(diagnostic.severity) }}
    >
      <div className={styles.issueMeta}>
        <Badge
          appearance="filled"
          color={severityBadgeColor(diagnostic.severity)}
        >
          {diagnostic.severity}
        </Badge>
        <Badge appearance="outline" color="brand">
          {diagnostic.category}
        </Badge>
        <Badge
          appearance="outline"
          color={priorityBadgeColor(diagnostic.remediationPriority)}
        >
          {diagnostic.remediationPriority}
        </Badge>
      </div>

      <div className={styles.textStack}>
        <Body1Strong style={inheritFontSize}>{diagnostic.title}</Body1Strong>
        <Body1 style={inheritFontSize}>{diagnostic.summary}</Body1>
      </div>

      {diagnostic.likelyCause && (
        <div className={styles.textStack}>
          <Caption1 style={inheritFontSize}>Likely cause</Caption1>
          <Body1 style={inheritFontSize}>{diagnostic.likelyCause}</Body1>
        </div>
      )}

      <div className={styles.bulletList}>
        {diagnostic.evidence.slice(0, 2).map((item) => (
          <BulletItem key={item} text={item} />
        ))}
      </div>

      <div className={styles.issueActions}>
        <Button size="small" appearance="primary" onClick={onShowTimeline}>
          Show related events
        </Button>
        <Button
          size="small"
          appearance="secondary"
          onClick={onScopeSource}
          disabled={diagnostic.affectedSourceFiles.length === 0}
        >
          Scope source
        </Button>
        <Button size="small" appearance="secondary" onClick={onShowDownloads}>
          Open downloads
        </Button>
        {eventLogSignalCount != null &&
          eventLogSignalCount > 0 &&
          onShowEventLogs && (
            <Button size="small" appearance="subtle" onClick={onShowEventLogs}>
              {eventLogSignalCount} event log signal
              {eventLogSignalCount !== 1 ? "s" : ""}
            </Button>
          )}
      </div>
    </div>
  );
}

function BulletItem({ text }: { text: string }) {
  const styles = useStyles();

  return (
    <div className={styles.bulletItem}>
      <span className={styles.bulletDot} />
      <span>{text}</span>
    </div>
  );
}

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

function getSeverityBorderColor(severity: IntuneDiagnosticSeverity): string {
  switch (severity) {
    case "Error":
      return tokens.colorPaletteRedBorder2;
    case "Warning":
      return tokens.colorPaletteMarigoldBorder2;
    case "Info":
    default:
      return tokens.colorBrandBackground2;
  }
}

function severityBadgeColor(
  severity: IntuneDiagnosticSeverity,
): "important" | "warning" | "informative" {
  switch (severity) {
    case "Error":
      return "important";
    case "Warning":
      return "warning";
    case "Info":
    default:
      return "informative";
  }
}

function priorityBadgeColor(
  priority: IntuneRemediationPriority,
): "important" | "warning" | "brand" | "informative" {
  switch (priority) {
    case "Immediate":
      return "important";
    case "High":
      return "warning";
    case "Medium":
      return "brand";
    case "Monitor":
    default:
      return "informative";
  }
}

function confidenceBadgeColor(
  level: string,
): "brand" | "informative" | "warning" | "success" {
  switch (level) {
    case "High":
      return "success";
    case "Medium":
      return "brand";
    case "Low":
      return "warning";
    case "Unknown":
    default:
      return "informative";
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

function buildSourceFamilies(
  filePaths: string[],
): Array<{ label: string; count: number }> {
  const counts = new Map<string, number>();

  for (const filePath of filePaths) {
    const label = inferSourceFamilyLabel(filePath);
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }

  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort(
      (left, right) =>
        right.count - left.count || left.label.localeCompare(right.label),
    );
}

function inferSourceFamilyLabel(filePath: string): string {
  const fileName = getFileName(filePath).toLowerCase();

  if (fileName.includes("appworkload")) {
    return "AppWorkload";
  }
  if (fileName.includes("appactionprocessor")) {
    return "AppActionProcessor";
  }
  if (fileName.includes("agentexecutor")) {
    return "AgentExecutor";
  }
  if (fileName.includes("healthscripts")) {
    return "HealthScripts";
  }
  if (fileName.includes("clienthealth")) {
    return "ClientHealth";
  }
  if (fileName.includes("intunemanagementextension")) {
    return "IntuneManagementExtension";
  }

  return "Other";
}

function formatConfidenceHint(
  score: number | null,
  reasonCount: number,
): string {
  const scoreText =
    score == null ? "No score" : `${Math.round(score * 100)}% confidence score`;
  return `${scoreText} • ${reasonCount} rationale item${reasonCount === 1 ? "" : "s"}`;
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
