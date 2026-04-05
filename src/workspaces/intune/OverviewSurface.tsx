import { useMemo } from "react";
import {
  Badge,
  Body1,
  Body1Strong,
  Button,
  Caption1,
  Card,
  Title3,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getEventLogEntryIdsForDiagnostic } from "./intune-store";
import { useUiStore } from "../../stores/ui-store";
import type {
  EventLogAnalysis,
  EventLogEntry,
} from "../../types/event-log";
import type {
  IntuneDiagnosticInsight,
  IntuneDiagnosticSeverity,
  IntuneEventType,
  IntuneRepeatedFailureGroup,
  IntuneRemediationPriority,
} from "./types";

/** Inline style that forces Fluent typography components to inherit font size. */
const inheritFontSize: React.CSSProperties = { fontSize: "inherit" };

const useOverviewStyles = makeStyles({
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
    backgroundColor: tokens.colorNeutralCardBackground,
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
  sectionCard: {
    display: "grid",
    gap: "12px",
    backgroundColor: tokens.colorNeutralCardBackground,
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
  sourceList: {
    display: "grid",
    gap: "8px",
  },
});

export interface OverviewSurfaceProps {
  sortedDiagnostics: IntuneDiagnosticInsight[];
  featuredDiagnostics: IntuneDiagnosticInsight[];
  immediateCount: number;
  warningCount: number;
  repeatedFailures: IntuneRepeatedFailureGroup[];
  dominantSourceLabel: string;
  diagnosticsCoverageFiles: Array<{ filePath: string }>;
  dominantSourceEventShare: number | null;
  diagnosticsConfidence: {
    level: string;
    score: number | null;
    reasons: string[];
  };
  eventLogAnalysis: EventLogAnalysis | null;
  eventLogHint: string | null;
  totalDownloads: number;
  successfulDownloads: number;
  failedDownloads: number;
  diagnosticsCoverageHasRotatedLogs: boolean;
  onOpenTimelineForDiagnostic: (diagnostic: IntuneDiagnosticInsight) => void;
  onOpenTimelineForFailure: (group: IntuneRepeatedFailureGroup) => void;
  onScopeToFile: (filePath: string | null) => void;
  onShowDownloads: () => void;
  onShowEventLogs: () => void;
  onSelectEventLogEntry: (id: number) => void;
}

export function OverviewSurface(props: OverviewSurfaceProps) {
  const styles = useOverviewStyles();

  const {
    sortedDiagnostics,
    featuredDiagnostics,
    immediateCount,
    warningCount,
    repeatedFailures,
    dominantSourceLabel,
    diagnosticsCoverageFiles,
    dominantSourceEventShare,
    diagnosticsConfidence,
    eventLogAnalysis,
    eventLogHint,
    totalDownloads,
    successfulDownloads,
    failedDownloads,
    onOpenTimelineForDiagnostic,
    onOpenTimelineForFailure,
    onScopeToFile,
    onShowDownloads,
    onShowEventLogs,
    onSelectEventLogEntry,
  } = props;

  const sourceFamilies = useMemo(
    () =>
      buildSourceFamilies(
        diagnosticsCoverageFiles.map((file) => file.filePath),
      ),
    [diagnosticsCoverageFiles],
  );

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

  return (
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
            dominantSourceEventShare != null
              ? `${Math.round(dominantSourceEventShare * 100)}% of scored events`
              : `${diagnosticsCoverageFiles.length} analyzed files`
          }
          accent={tokens.colorPaletteTealForeground2}
        />
        {eventLogAnalysis && (
          <MetricCard
            title="Event log signals"
            value={String(
              eventLogAnalysis.errorEntryCount +
                eventLogAnalysis.warningEntryCount,
            )}
            hint={eventLogHint ?? "No Windows Event Log evidence"}
            accent={tokens.colorPalettePurpleForeground2}
          />
        )}
        {totalDownloads > 0 && (
          <MetricCard
            title="Content downloads"
            value={String(totalDownloads)}
            hint={`${successfulDownloads} succeeded, ${failedDownloads} failed`}
            accent={tokens.colorPalettePeachForeground2}
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
                        onOpenTimelineForDiagnostic(diagnostic)
                      }
                      onShowDownloads={onShowDownloads}
                      onScopeSource={() =>
                        onScopeToFile(
                          diagnostic.affectedSourceFiles[0] ?? null,
                        )
                      }
                      eventLogSignalCount={elSignalCount}
                      onShowEventLogs={onShowEventLogs}
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
                        onClick={() => onOpenTimelineForFailure(group)}
                      >
                        Show related events
                      </Button>
                      <Button
                        size="small"
                        appearance="secondary"
                        onClick={() =>
                          onScopeToFile(group.sourceFiles[0] ?? null)
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
                {diagnosticsCoverageFiles.length} files
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
                        onSelectEventLogEntry(entry.id);
                        onShowEventLogs();
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
                onClick={onShowEventLogs}
              >
                View all event log evidence
              </Button>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Private sub-components ─── */

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
  const styles = useOverviewStyles();
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
  const styles = useOverviewStyles();

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
  const styles = useOverviewStyles();

  return (
    <div className={styles.bulletItem}>
      <span className={styles.bulletDot} />
      <span>{text}</span>
    </div>
  );
}

/* ─── Pure utility functions ─── */

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
