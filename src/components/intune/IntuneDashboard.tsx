import { useEffect, useMemo, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_UI_FONT_FAMILY, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { formatDisplayDateTime, parseDisplayDateTimeValue } from "../../lib/date-time-format";
import { useIntuneStore } from "../../stores/intune-store";
import { useAppActions } from "../layout/Toolbar";
import { EventTimeline } from "./EventTimeline";
import { DownloadStats } from "./DownloadStats";
import type {
  DownloadStat,
  IntuneDiagnosticCategory,
  IntuneDiagnosticInsight,
  IntuneRemediationPriority,
  IntuneDiagnosticSeverity,
  IntuneDiagnosticsConfidence,
  IntuneDiagnosticsCoverage,
  IntuneDiagnosticsFileCoverage,
  IntuneEvent,
  IntuneEventType,
  IntuneLogSourceKind,
  IntuneRepeatedFailureGroup,
  IntuneStatus,
  IntuneSourceFamilySummary,
  IntuneSummary,
  IntuneTimeWindowPreset,
  IntuneTimestampBounds,
} from "../../types/intune";

type TabId = "timeline" | "downloads" | "summary";

const TAB_LABELS: Record<TabId, string> = {
  timeline: "Timeline",
  downloads: "Downloads",
  summary: "Summary",
};

export function IntuneDashboard() {
  const events = useIntuneStore((s) => s.events);
  const downloads = useIntuneStore((s) => s.downloads);
  const summary = useIntuneStore((s) => s.summary);
  const diagnostics = useIntuneStore((s) => s.diagnostics);
  const evidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const diagnosticsCoverage = useIntuneStore((s) => s.diagnosticsCoverage);
  const sourceContext = useIntuneStore((s) => s.sourceContext);
  const analysisState = useIntuneStore((s) => s.analysisState);
  const isAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const timelineScope = useIntuneStore((s) => s.timelineScope);
  const timeWindow = useIntuneStore((s) => s.timeWindow);
  const activeTab = useIntuneStore((s) => s.activeTab);
  const setActiveTab = useIntuneStore((s) => s.setActiveTab);
  const clearTimelineFileScope = useIntuneStore((s) => s.clearTimelineFileScope);
  const setTimeWindow = useIntuneStore((s) => s.setTimeWindow);
  const filterEventType = useIntuneStore((s) => s.filterEventType);
  const filterStatus = useIntuneStore((s) => s.filterStatus);
  const setFilterEventType = useIntuneStore((s) => s.setFilterEventType);
  const setFilterStatus = useIntuneStore((s) => s.setFilterStatus);
  const { commandState, openSourceFileDialog, openSourceFolderDialog } = useAppActions();

  const timeWindowAnchor = useMemo(
    () => getLatestActivityTimestamp(events, downloads),
    [downloads, events]
  );
  const filteredEventsByTime = useMemo(
    () => filterEventsByTimeWindow(events, timeWindow, timeWindowAnchor),
    [events, timeWindow, timeWindowAnchor]
  );
  const filteredDownloadsByTime = useMemo(
    () => filterDownloadsByTimeWindow(downloads, timeWindow, timeWindowAnchor),
    [downloads, timeWindow, timeWindowAnchor]
  );
  const filteredSummary = useMemo(
    () => buildWindowedSummary(filteredEventsByTime, filteredDownloadsByTime),
    [filteredDownloadsByTime, filteredEventsByTime]
  );
  const timeWindowLabel = getTimeWindowLabel(timeWindow);
  const isWindowFiltered = timeWindow !== "all";

  const availableTabs = useMemo(
    () => ({
      timeline: filteredEventsByTime.length > 0,
      downloads: filteredDownloadsByTime.length > 0,
      summary: summary != null,
    }),
    [filteredDownloadsByTime.length, filteredEventsByTime.length, summary]
  );

  const filteredEventCount = useMemo(() => {
    return filteredEventsByTime.filter((event) => {
      if (filterEventType !== "All" && event.eventType !== filterEventType) {
        return false;
      }
      if (filterStatus !== "All" && event.status !== filterStatus) {
        return false;
      }
      return true;
    }).length;
  }, [filteredEventsByTime, filterEventType, filterStatus]);

  const hasActiveFilters = filterEventType !== "All" || filterStatus !== "All";

  useEffect(() => {
    if (!availableTabs[activeTab]) {
      if (availableTabs.timeline) {
        setActiveTab("timeline");
        return;
      }
      if (availableTabs.downloads) {
        setActiveTab("downloads");
        return;
      }
      if (availableTabs.summary) {
        setActiveTab("summary");
        return;
      }
      setActiveTab("timeline");
    }
  }, [activeTab, availableTabs, setActiveTab]);

  const hasAnyResult = summary != null || events.length > 0 || downloads.length > 0;
  const sourceFiles = sourceContext.includedFiles;
  const sourceLabel = analysisState.requestedPath ?? sourceContext.analyzedPath;
  const sourceFamilies = useMemo(
    () => buildSourceFamilySummary(diagnosticsCoverage.files),
    [diagnosticsCoverage.files]
  );
  const emptySourceFamilies = useMemo(
    () => sourceFamilies.filter((family) => family.contributingFileCount === 0),
    [sourceFamilies]
  );
  const sourceStatusTone =
    analysisState.phase === "error"
      ? tokens.colorPaletteRedForeground1
      : analysisState.phase === "empty"
        ? tokens.colorPaletteMarigoldForeground1
        : analysisState.phase === "analyzing"
          ? tokens.colorBrandForeground1
          : tokens.colorNeutralForeground3;
  const timelineScopeFileName = timelineScope.filePath ? getFileName(timelineScope.filePath) : null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "6px 12px",
          backgroundColor: tokens.colorNeutralBackground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span
            style={{
              fontSize: "13px",
              fontWeight: 600,
              color: tokens.colorNeutralForeground1,
              fontFamily: LOG_UI_FONT_FAMILY,
            }}
          >
            Intune Diagnostics Workspace
          </span>
          <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2 }} />
          <ActionButton
            onClick={() => {
              void openSourceFileDialog();
            }}
            disabled={!commandState.canOpenSources}
            label={isAnalyzing ? "Analyzing..." : "Open IME Log File..."}
          />
          <ActionButton
            onClick={() => {
              void openSourceFolderDialog();
            }}
            disabled={!commandState.canOpenSources}
            label={isAnalyzing ? "Analyzing..." : "Open IME Or Evidence Folder..."}
          />

          {(analysisState.phase === "analyzing" || analysisState.phase === "error" || analysisState.phase === "empty") && (
            <span style={{ fontSize: "12px", color: sourceStatusTone, fontWeight: 500, marginLeft: "4px" }}>
              {analysisState.message}
            </span>
          )}
        </div>

        {sourceLabel && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-end",
              minWidth: 0,
              maxWidth: "400px",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                color: tokens.colorNeutralForeground3,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                maxWidth: "100%",
                fontWeight: 500,
              }}
              title={sourceLabel}
            >
              {sourceLabel}
            </span>
            {(analysisState.detail || sourceFiles.length > 0) && (
              <span style={{ fontSize: "10px", color: sourceStatusTone }}>
                {analysisState.phase === "error"
                  ? analysisState.detail
                  : analysisState.phase === "empty"
                    ? analysisState.detail
                    : sourceFiles.length > 0
                      ? `${sourceFiles.length} included files`
                      : analysisState.detail}
              </span>
            )}
            {evidenceBundle && (
              <span
                style={{
                  marginTop: "4px",
                  fontSize: "10px",
                  color: emptySourceFamilies.length > 0 ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteBlueForeground2,
                  fontWeight: 600,
                }}
              >
                Bundle {evidenceBundle.bundleLabel ?? evidenceBundle.bundleId ?? "attached"}
                {sourceFamilies.length > 0 ? ` • ${sourceFamilies.length} file family${sourceFamilies.length === 1 ? "" : "ies"}` : ""}
                {emptySourceFamilies.length > 0 ? ` • ${emptySourceFamilies.length} quiet family${emptySourceFamilies.length === 1 ? "" : "ies"}` : ""}
              </span>
            )}
          </div>
        )}
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 12px",
          backgroundColor: tokens.colorNeutralBackground2,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          minHeight: "40px",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", gap: "2px", alignItems: "center", height: "100%" }}>
          {(Object.keys(TAB_LABELS) as TabId[]).map((tabId) => (
            <CanvasTabButton
              key={tabId}
              label={TAB_LABELS[tabId]}
              active={activeTab === tabId}
              disabled={isAnalyzing || !availableTabs[tabId]}
              count={tabId === "timeline" ? filteredEventsByTime.length : tabId === "downloads" ? filteredDownloadsByTime.length : summary ? 1 : 0}
              onClick={() => setActiveTab(tabId)}
            />
          ))}
        </div>

        {summary && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              marginLeft: "12px",
              flex: 1,
              overflow: "hidden",
            }}
          >
            <div style={{ width: "1px", height: "20px", backgroundColor: tokens.colorNeutralStroke2, marginRight: "12px" }} />
            <div
              style={{
                display: "flex",
                gap: "10px",
                flexWrap: "nowrap",
                overflowX: "auto",
                scrollbarWidth: "none",
                alignItems: "center",
              }}
            >
              <StrongBadge label="Total" value={filteredSummary.totalEvents} />
              <StrongBadge label="Success" value={filteredSummary.succeeded} color={tokens.colorPaletteGreenForeground1} />
              <StrongBadge label="Fail" value={filteredSummary.failed} color={tokens.colorPaletteRedForeground1} />
              <StrongBadge label="Prog" value={filteredSummary.inProgress} color={tokens.colorBrandForeground1} />
              <StrongBadge label="Win32" value={filteredSummary.win32Apps} />
              <StrongBadge label="WinGet" value={filteredSummary.wingetApps} />
              {filteredSummary.logTimeSpan && (
                <>
                  <div style={{ width: "1px", height: "12px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 4px" }} />
                  <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, fontWeight: 500 }}>
                    {filteredSummary.logTimeSpan}
                  </span>
                </>
              )}
              {isWindowFiltered && (
                <>
                  <div style={{ width: "1px", height: "12px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 4px" }} />
                  <span style={{ fontSize: "11px", color: tokens.colorPaletteBlueForeground2, fontWeight: 700 }}>
                    {timeWindowLabel}
                  </span>
                </>
              )}
            </div>
          </div>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginLeft: "auto", paddingLeft: "12px" }}>
          <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, fontWeight: 600, textTransform: "uppercase" }}>Window:</span>
          <select
            value={timeWindow}
            onChange={(e) => setTimeWindow(e.target.value as IntuneTimeWindowPreset)}
            style={selectStyle}
            disabled={isAnalyzing}
          >
            <option value="all">All Activity</option>
            <option value="last-hour">Last Hour</option>
            <option value="last-6-hours">Last 6 Hours</option>
            <option value="last-day">Last Day</option>
            <option value="last-7-days">Last 7 Days</option>
          </select>
        </div>

        {activeTab === "timeline" && filteredEventsByTime.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginLeft: "auto", paddingLeft: "12px" }}>
            <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, fontWeight: 600, textTransform: "uppercase" }}>Filters:</span>
            <select
              value={filterEventType}
              onChange={(e) => setFilterEventType(e.target.value as IntuneEventType | "All")}
              style={selectStyle}
              disabled={isAnalyzing}
            >
              <option value="All">All Types</option>
              <option value="Win32App">Win32</option>
              <option value="WinGetApp">WinGet</option>
              <option value="PowerShellScript">Script</option>
              <option value="Remediation">Remediation</option>
              <option value="Esp">ESP</option>
              <option value="SyncSession">Sync</option>
              <option value="PolicyEvaluation">Policy</option>
              <option value="ContentDownload">Download</option>
              <option value="Other">Other</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value as IntuneStatus | "All")}
              style={selectStyle}
              disabled={isAnalyzing}
            >
              <option value="All">All Statuses</option>
              <option value="Success">Success</option>
              <option value="Failed">Failed</option>
              <option value="InProgress">In Progress</option>
              <option value="Pending">Pending</option>
              <option value="Timeout">Timeout</option>
              <option value="Unknown">Unknown</option>
            </select>
            <button
              onClick={() => {
                setFilterEventType("All");
                setFilterStatus("All");
              }}
              disabled={!hasActiveFilters || isAnalyzing}
              style={{
                marginLeft: "2px",
                fontSize: "10px",
                padding: "2px 6px",
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                borderRadius: "3px",
                backgroundColor: hasActiveFilters ? tokens.colorNeutralCardBackground : tokens.colorNeutralBackground3,
                color: hasActiveFilters ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground4,
                cursor: hasActiveFilters && !isAnalyzing ? "pointer" : "not-allowed",
              }}
            >
              Reset
            </button>
            <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, fontWeight: 500, marginLeft: "4px" }}>
              {filteredEventCount}/{filteredEventsByTime.length}
            </span>
            {timelineScope.filePath && (
              <>
                <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px" }} />
                <span
                  title={timelineScope.filePath}
                  style={{
                    maxWidth: "220px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontSize: "11px",
                    color: tokens.colorPaletteMarigoldForeground2,
                    backgroundColor: tokens.colorPaletteYellowBackground1,
                    border: `1px solid ${tokens.colorPaletteYellowBorder2}`,
                    borderRadius: "999px",
                    padding: "3px 8px",
                    fontWeight: 600,
                  }}
                >
                  Timeline scoped to {timelineScopeFileName}
                </span>
                <button
                  onClick={() => clearTimelineFileScope()}
                  disabled={isAnalyzing}
                  style={{
                    fontSize: "10px",
                    padding: "2px 6px",
                    border: `1px solid ${tokens.colorNeutralStroke2}`,
                    borderRadius: "3px",
                    backgroundColor: tokens.colorNeutralCardBackground,
                    color: tokens.colorNeutralForeground1,
                    cursor: isAnalyzing ? "not-allowed" : "pointer",
                  }}
                >
                  Clear Scope
                </button>
              </>
            )}
          </div>
        )}
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", display: "flex", flexDirection: "column" }}>
        {(analysisState.phase === "error" || analysisState.phase === "empty") && (
          <div
            role="alert"
            style={{
              margin: "12px 12px 0",
              padding: "10px 12px",
              border: analysisState.phase === "empty" ? `1px solid ${tokens.colorPaletteYellowBorder2}` : `1px solid ${tokens.colorPaletteRedBorder2}`,
              backgroundColor: analysisState.phase === "empty" ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteRedBackground1,
              color: analysisState.phase === "empty" ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteRedForeground1,
              fontSize: "12px",
            }}
          >
            <div style={{ fontWeight: 600 }}>{analysisState.message}</div>
            {analysisState.detail && <div style={{ marginTop: "4px" }}>{analysisState.detail}</div>}
          </div>
        )}

        {!hasAnyResult && analysisState.phase !== "analyzing" && analysisState.phase !== "error" ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              color: tokens.colorNeutralForeground4,
              fontSize: "14px",
            }}
          >
            Open an Intune IME log file or folder to analyze
          </div>
        ) : isAnalyzing && !hasAnyResult ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              color: tokens.colorNeutralForeground3,
              fontSize: "14px",
            }}
          >
            {analysisState.message}
          </div>
        ) : analysisState.phase === "empty" && !hasAnyResult ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              color: tokens.colorPaletteMarigoldForeground2,
              fontSize: "14px",
              padding: "0 24px",
              textAlign: "center",
            }}
          >
            {analysisState.detail ?? "No IME log files were found in this folder."}
          </div>
        ) : analysisState.phase === "error" && !hasAnyResult ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              color: tokens.colorPaletteRedForeground1,
              fontSize: "14px",
              padding: "0 24px",
              textAlign: "center",
            }}
          >
            {analysisState.detail ?? "The selected Intune source could not be analyzed."}
          </div>
        ) : (
          <>
            {activeTab === "timeline" && <EventTimeline events={filteredEventsByTime} />}
            {activeTab === "downloads" && <DownloadStats downloads={filteredDownloadsByTime} />}
            {activeTab === "summary" && summary && (
              <SummaryView
                summary={filteredSummary}
                diagnostics={diagnostics}
                events={filteredEventsByTime}
                sourceFile={sourceContext.analyzedPath}
                sourceFiles={sourceContext.includedFiles}
                timeWindow={timeWindow}
                timeWindowLabel={timeWindowLabel}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}

function ActionButton({
  onClick,
  disabled,
  label,
}: {
  onClick: () => void;
  disabled: boolean;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        fontSize: "12px",
        padding: "4px 10px",
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        borderRadius: "4px",
        backgroundColor: disabled ? tokens.colorNeutralBackground3 : tokens.colorNeutralCardBackground,
        color: disabled ? tokens.colorNeutralForeground3 : tokens.colorNeutralForeground1,
        cursor: disabled ? "not-allowed" : "pointer",
      }}
    >
      {label}
    </button>
  );
}

const selectStyle: React.CSSProperties = {
  fontSize: "11px",
  padding: "2px 6px",
  borderRadius: "3px",
  border: `1px solid ${tokens.colorNeutralStroke2}`,
  backgroundColor: tokens.colorNeutralCardBackground,
  outline: "none",
};

function CanvasTabButton({
  label,
  active,
  disabled,
  count,
  onClick,
}: {
  label: string;
  active: boolean;
  disabled: boolean;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        fontSize: "11px",
        padding: "6px 12px",
        border: "none",
        borderBottom: active ? `2px solid ${tokens.colorBrandForeground1}` : "2px solid transparent",
        backgroundColor: "transparent",
        color: disabled ? tokens.colorNeutralForeground4 : active ? tokens.colorPaletteBlueForeground2 : tokens.colorNeutralForeground3,
        fontWeight: active ? 600 : 500,
        cursor: disabled ? "not-allowed" : "pointer",
        height: "100%",
        display: "flex",
        alignItems: "center",
        gap: "6px",
        transition: "all 0.1s ease",
      }}
    >
      <span>{label}</span>
      <span style={{
        fontSize: "9px",
        backgroundColor: active ? tokens.colorPaletteBlueBackground2 : tokens.colorNeutralBackground3,
        color: active ? tokens.colorPaletteBlueForeground2 : tokens.colorNeutralForeground3,
        padding: "2px 6px",
        borderRadius: "99px",
        fontWeight: 700,
      }}>
        {count}
      </span>
    </button>
  );
}

function StrongBadge({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: "4px" }}>
      <span style={{ color: tokens.colorNeutralForeground3, fontSize: "10px", fontWeight: 600, textTransform: "uppercase" }}>{label}</span>
      <span style={{ color: color || tokens.colorNeutralForeground1, fontSize: "12px", fontWeight: 700 }}>{value}</span>
    </div>
  );
}

function SummaryView({
  summary,
  diagnostics,
  events,
  sourceFile,
  sourceFiles,
  timeWindow,
  timeWindowLabel,
}: {
  summary: IntuneSummary;
  diagnostics: IntuneDiagnosticInsight[];
  events: IntuneEvent[];
  sourceFile: string | null;
  sourceFiles: string[];
  timeWindow: IntuneTimeWindowPreset;
  timeWindowLabel: string;
}) {
  const evidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const setActiveTab = useIntuneStore((s) => s.setActiveTab);
  const diagnosticsCoverage = useIntuneStore((s) => s.diagnosticsCoverage);
  const diagnosticsConfidence = useIntuneStore((s) => s.diagnosticsConfidence);
  const repeatedFailures = useIntuneStore((s) => s.repeatedFailures);
  const setFilterEventType = useIntuneStore((s) => s.setFilterEventType);
  const setFilterStatus = useIntuneStore((s) => s.setFilterStatus);
  const selectEvent = useIntuneStore((s) => s.selectEvent);
  const setTimelineFileScope = useIntuneStore((s) => s.setTimelineFileScope);
  const clearTimelineFileScope = useIntuneStore((s) => s.clearTimelineFileScope);

  const [showAllConfidenceReasons, setShowAllConfidenceReasons] = useState(false);
  const [showAllRepeatedFailures, setShowAllRepeatedFailures] = useState(false);
  const [showCoverageDetails, setShowCoverageDetails] = useState(false);
  const isWindowFiltered = timeWindow !== "all";

  const coverageSectionRef = useRef<HTMLDivElement | null>(null);
  const confidenceSectionRef = useRef<HTMLDivElement | null>(null);
  const repeatedFailuresSectionRef = useRef<HTMLDivElement | null>(null);
  const diagnosticsGuidanceSectionRef = useRef<HTMLDivElement | null>(null);

  const contributingFileCount = diagnosticsCoverage.files.filter(
    (file) => file.eventCount > 0 || file.downloadCount > 0
  ).length;
  const sourceFamilies = useMemo(
    () => buildSourceFamilySummary(diagnosticsCoverage.files),
    [diagnosticsCoverage.files]
  );
  const visibleSourceFamilies = sourceFamilies.slice(0, 4);
  const inactiveSourceFamilies = sourceFamilies.filter(
    (family) => family.contributingFileCount === 0
  );
  const hiddenSourceFamilyCount = Math.max(
    sourceFamilies.length - visibleSourceFamilies.length,
    0
  );
  const visibleConfidenceReasons = showAllConfidenceReasons
    ? diagnosticsConfidence.reasons
    : diagnosticsConfidence.reasons.slice(0, 2);
  const hiddenConfidenceReasonCount = Math.max(
    diagnosticsConfidence.reasons.length - visibleConfidenceReasons.length,
    0
  );
  const visibleRepeatedFailures = showAllRepeatedFailures
    ? repeatedFailures
    : repeatedFailures.slice(0, 2);
  const hiddenRepeatedFailureCount = Math.max(
    repeatedFailures.length - visibleRepeatedFailures.length,
    0
  );
  const conclusions = useMemo(
    () =>
      buildSummaryConclusions({
        summary,
        diagnostics,
        diagnosticsCoverage,
        diagnosticsConfidence,
        repeatedFailures,
      }),
    [diagnostics, diagnosticsConfidence, diagnosticsCoverage, repeatedFailures, summary]
  );
  const remediationPlan = useMemo(
    () => buildRemediationPlan(diagnostics),
    [diagnostics]
  );

  function scrollToSection(section: SummaryConclusionSection) {
    const sectionRef =
      section === "coverage"
        ? coverageSectionRef
        : section === "confidence"
          ? confidenceSectionRef
          : section === "repeatedFailures"
            ? repeatedFailuresSectionRef
            : diagnosticsGuidanceSectionRef;

    sectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function handleConclusionClick(conclusion: SummaryConclusion) {
    if (conclusion.action.kind === "section") {
      scrollToSection(conclusion.action.section);
      return;
    }

    const action = conclusion.action;
    const nextEventType = action.eventType ?? "All";
    const nextStatus = action.status ?? "All";
    const nextFilePath = action.filePath;
    const firstMatchingEventId = action.selectFirstMatch
      ? events.find((event) => matchesTimelineAction(event, action))?.id ?? null
      : null;

    setActiveTab("timeline");
    setFilterEventType(nextEventType);
    setFilterStatus(nextStatus);

    if (nextFilePath === null) {
      clearTimelineFileScope();
    } else if (nextFilePath) {
      setTimelineFileScope(nextFilePath);
    }

    if (firstMatchingEventId != null) {
      selectEvent(firstMatchingEventId);
    }
  }

  return (
    <div style={{ padding: "16px", fontSize: "13px" }}>
      <h3
        style={{
          margin: "0 0 12px 0",
          fontSize: "15px",
          fontFamily: LOG_UI_FONT_FAMILY,
        }}
      >
        Intune Diagnostics Summary
      </h3>

      {sourceFile && (
        <div style={{ marginBottom: "12px", color: tokens.colorNeutralForeground3 }}>
          <strong>Analyzed Path:</strong> {sourceFile}
        </div>
      )}

      {evidenceBundle && (
        <div
          style={{
            marginBottom: "12px",
            padding: "10px 12px",
            borderRadius: "8px",
            border: inactiveSourceFamilies.length > 0 ? `1px solid ${tokens.colorPaletteYellowBorder2}` : `1px solid ${tokens.colorPaletteBlueBorderActive}`,
            backgroundColor: inactiveSourceFamilies.length > 0 ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteBlueBackground2,
            color: inactiveSourceFamilies.length > 0 ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteBlueForeground2,
          }}
        >
          <div style={{ fontSize: "12px", fontWeight: 700 }}>
            Evidence bundle: {evidenceBundle.bundleLabel ?? evidenceBundle.bundleId ?? "Detected bundle"}
          </div>
          <div style={{ marginTop: "4px", fontSize: "12px", lineHeight: 1.5 }}>
            {evidenceBundle.caseReference
              ? `Case ${evidenceBundle.caseReference}. `
              : ""}
            {sourceFamilies.length > 0
              ? `${sourceFamilies.length} source family${sourceFamilies.length === 1 ? "" : "ies"} contributed to this analysis.`
              : "Bundle metadata is attached to this analysis result."}
          </div>
          {inactiveSourceFamilies.length > 0 && (
            <div style={{ marginTop: "6px", fontSize: "11px", lineHeight: 1.45 }}>
              Bundle files were present for {inactiveSourceFamilies.map((family) => family.label).join(", ")}, but no parsed events or downloads came from them in this view.
            </div>
          )}
        </div>
      )}

      {sourceFiles.length > 0 && (
        <div style={{ marginBottom: "12px", color: tokens.colorNeutralForeground3 }}>
          <div style={{ marginBottom: "4px" }}>
            <strong>Included IME Log Files:</strong> {sourceFiles.length}
          </div>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "6px",
            }}
          >
            {sourceFiles.map((file) => (
              <span
                key={file}
                title={file}
                style={{
                  padding: "2px 8px",
                  borderRadius: "999px",
                  backgroundColor: tokens.colorPaletteBlueBackground2,
                  border: `1px solid ${tokens.colorPaletteBlueBorderActive}`,
                  color: tokens.colorPaletteBlueForeground2,
                  fontSize: "11px",
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                }}
              >
                {getFileName(file)}
              </span>
            ))}
          </div>
        </div>
      )}

      {summary.logTimeSpan && (
        <div style={{ marginBottom: "12px", color: tokens.colorNeutralForeground3 }}>
          <strong>Log Time Span:</strong> {summary.logTimeSpan}
        </div>
      )}

      {isWindowFiltered && (
        <div
          style={{
            marginBottom: "12px",
            padding: "10px 12px",
            borderRadius: "8px",
            border: `1px solid ${tokens.colorPaletteBlueBorderActive}`,
            backgroundColor: tokens.colorPaletteBlueBackground2,
            color: tokens.colorPaletteBlueForeground2,
            fontSize: "12px",
            lineHeight: 1.5,
          }}
        >
          <div style={{ fontWeight: 700, marginBottom: "4px" }}>Activity window: {timeWindowLabel}</div>
          <div>
            Timeline events, download rows, and activity metrics are filtered to this recent slice relative to the latest parsed log activity. Diagnostics guidance, confidence, and repeated-failure analysis still reflect the full analyzed source set.
          </div>
        </div>
      )}

      {conclusions.length > 0 && (
        <div
          style={{
            position: "sticky",
            top: 0,
            zIndex: 1,
            marginBottom: "12px",
            paddingBottom: "8px",
            background:
              "linear-gradient(180deg, rgba(255,255,255,0.98) 0%, rgba(255,255,255,0.98) 78%, rgba(255,255,255,0) 100%)",
          }}
        >
          <div
            style={{
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: "8px",
              backgroundColor: tokens.colorNeutralBackground2,
              padding: "10px 12px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "baseline",
                justifyContent: "space-between",
                gap: "10px",
                marginBottom: "8px",
                flexWrap: "wrap",
              }}
            >
              <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>Conclusions</div>
              <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3 }}>Click to jump to proof or focus the timeline.</div>
            </div>
            <div style={{ display: "grid", gap: "6px" }}>
              {conclusions.map((conclusion) => (
                <ConclusionButton
                  key={conclusion.id}
                  conclusion={conclusion}
                  onClick={() => handleConclusionClick(conclusion)}
                />
              ))}
            </div>
          </div>
        </div>
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.4fr) minmax(280px, 1fr)",
          gap: "12px",
          marginBottom: "16px",
        }}
      >
        <div ref={coverageSectionRef}>
          <SectionCard
            title="Diagnostics Coverage"
            subtitle="Source continuity, timestamp bounds, and dominant evidence."
          >
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "8px",
                marginBottom: diagnosticsCoverage.files.length > 0 ? "10px" : 0,
              }}
            >
              <CompactFact label="Files" value={String(diagnosticsCoverage.files.length)} />
              <CompactFact label="Contributing" value={String(contributingFileCount)} color={tokens.colorBrandForeground1} />
              <CompactFact label="Families" value={String(sourceFamilies.length)} color={tokens.colorPaletteTealForeground2} />
              <CompactFact
                label="Rotated"
                value={diagnosticsCoverage.hasRotatedLogs ? "Yes" : "No"}
                color={diagnosticsCoverage.hasRotatedLogs ? tokens.colorPaletteMarigoldForeground2 : tokens.colorNeutralForeground3}
              />
              {diagnosticsCoverage.dominantSource && (
                <CompactFact
                  label="Dominant"
                  value={buildDominantSourceLabel(diagnosticsCoverage.dominantSource)}
                  color={tokens.colorPaletteTealForeground2}
                />
              )}
            </div>

            {diagnosticsCoverage.timestampBounds && (
              <div
                style={{
                  marginBottom: diagnosticsCoverage.files.length > 0 ? "10px" : 0,
                  padding: "8px 10px",
                  borderRadius: "6px",
                  backgroundColor: tokens.colorNeutralBackground2,
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  color: tokens.colorNeutralForeground2,
                  fontSize: "12px",
                }}
              >
                <strong style={{ color: tokens.colorNeutralForeground1 }}>Timestamp Bounds:</strong>{" "}
                {formatTimestampBounds(diagnosticsCoverage.timestampBounds)}
              </div>
            )}

            {sourceFamilies.length > 0 && (
              <div
                style={{
                  marginBottom: diagnosticsCoverage.files.length > 0 ? "10px" : 0,
                }}
              >
                <div
                  style={{
                    fontSize: "11px",
                    fontWeight: 700,
                    color: tokens.colorNeutralForeground3,
                    marginBottom: "6px",
                  }}
                >
                  Source families
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {visibleSourceFamilies.map((family) => (
                    <SourceFamilyBadge key={family.kind} family={family} />
                  ))}
                  {hiddenSourceFamilyCount > 0 && (
                    <span
                      style={{
                        fontSize: "10px",
                        padding: "4px 8px",
                        borderRadius: "999px",
                        border: `1px solid ${tokens.colorNeutralStroke2}`,
                        backgroundColor: tokens.colorNeutralBackground2,
                        color: tokens.colorNeutralForeground3,
                        fontWeight: 700,
                      }}
                    >
                      +{hiddenSourceFamilyCount} more
                    </span>
                  )}
                </div>
              </div>
            )}

            {diagnosticsCoverage.files.length > 0 ? (
              <div>
                <button
                  onClick={() => setShowCoverageDetails((current) => !current)}
                  style={secondaryToggleButtonStyle}
                >
                  {showCoverageDetails
                    ? "Hide file coverage"
                    : `Show file coverage (${diagnosticsCoverage.files.length})`}
                </button>
                {showCoverageDetails && (
                  <div style={{ display: "grid", gap: "6px", marginTop: "10px" }}>
                    {diagnosticsCoverage.files.map((file) => (
                      <CoverageRow key={file.filePath} file={file} />
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <EmptyStateText label="No file-level coverage evidence was available." />
            )}
          </SectionCard>
        </div>

        <div ref={confidenceSectionRef}>
          <SectionCard
            title="Confidence"
            subtitle="Why this summary is strong, partial, or still tentative."
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "12px",
                marginBottom: "10px",
                flexWrap: "wrap",
              }}
            >
              <ConfidenceBadge confidence={diagnosticsConfidence} />
              <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
                {diagnosticsConfidence.score != null
                  ? `Score ${(diagnosticsConfidence.score * 100).toFixed(0)}%`
                  : "Score unavailable"}
              </div>
            </div>

            {diagnosticsConfidence.reasons.length > 0 ? (
              <>
                <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
                  {visibleConfidenceReasons.map((reason) => (
                    <li key={reason} style={{ marginBottom: "4px", lineHeight: 1.35 }}>
                      {reason}
                    </li>
                  ))}
                </ul>
                {(hiddenConfidenceReasonCount > 0 || diagnosticsConfidence.reasons.length > 2) && (
                  <button
                    onClick={() => setShowAllConfidenceReasons((current) => !current)}
                    style={{
                      ...secondaryToggleButtonStyle,
                      marginTop: "8px",
                    }}
                  >
                    {showAllConfidenceReasons
                      ? "Show less"
                      : `Show all (${diagnosticsConfidence.reasons.length})`}
                  </button>
                )}
              </>
            ) : (
              <EmptyStateText label="No confidence rationale was available." />
            )}
          </SectionCard>
        </div>
      </div>

      <div ref={repeatedFailuresSectionRef}>
        <SectionCard
          title="Repeated Failures"
          subtitle="Recurrence is grouped by subject and failure reason to keep the summary compact."
        >
          {visibleRepeatedFailures.length > 0 ? (
            <div style={{ display: "grid", gap: "8px" }}>
              {visibleRepeatedFailures.map((group) => (
                <RepeatedFailureRow key={group.id} group={group} />
              ))}
              {hiddenRepeatedFailureCount > 0 && (
                <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
                  {hiddenRepeatedFailureCount} more repeated failure group(s) were detected.
                </div>
              )}
              {(hiddenRepeatedFailureCount > 0 || repeatedFailures.length > 2) && (
                <button
                  onClick={() => setShowAllRepeatedFailures((current) => !current)}
                  style={secondaryToggleButtonStyle}
                >
                  {showAllRepeatedFailures ? "Show less" : `Show all (${repeatedFailures.length})`}
                </button>
              )}
            </div>
          ) : (
            <EmptyStateText label="No repeated failure patterns were detected." />
          )}
        </SectionCard>
      </div>

      {remediationPlan.length > 0 && (
        <div style={{ margin: "16px 0 20px" }}>
          <SectionCard
            title="Remediation Assistant"
            subtitle="Start with the highest-priority actions that best match the current failure pattern."
          >
            <div style={{ display: "grid", gap: "10px" }}>
              {remediationPlan.map((step, index) => (
                <div
                  key={`${step.diagnosticId}-${step.title}`}
                  style={{
                    border: `1px solid ${tokens.colorNeutralStroke2}`,
                    borderRadius: "8px",
                    backgroundColor: tokens.colorNeutralBackground2,
                    padding: "10px 12px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      gap: "12px",
                      alignItems: "center",
                      marginBottom: "6px",
                      flexWrap: "wrap",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                      <span
                        style={{
                          width: "22px",
                          height: "22px",
                          borderRadius: "999px",
                          backgroundColor: tokens.colorPaletteBlueBackground2,
                          color: tokens.colorPaletteBlueForeground2,
                          display: "inline-flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "11px",
                          fontWeight: 800,
                        }}
                      >
                        {index + 1}
                      </span>
                      <div style={{ fontSize: "13px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>{step.title}</div>
                    </div>
                    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                      <DiagnosticMetaBadge label={step.priority} tone={getPriorityTone(step.priority)} />
                      <DiagnosticMetaBadge label={step.category} tone={getCategoryTone(step.category)} />
                    </div>
                  </div>

                  <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2, marginBottom: "8px", lineHeight: 1.45 }}>
                    {step.action}
                  </div>

                  <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, lineHeight: 1.45 }}>
                    {step.reason}
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      )}

      {diagnostics.length > 0 && (
        <div ref={diagnosticsGuidanceSectionRef} style={{ marginBottom: "20px" }}>
          <h4
            style={{
              margin: "0 0 10px 0",
              fontSize: "13px",
              color: tokens.colorNeutralForeground1,
            }}
          >
            Diagnostics Guidance
          </h4>
          <div
            style={{
              display: "grid",
              gap: "12px",
            }}
          >
            {diagnostics.map((diagnostic) => (
              <DiagnosticCard key={diagnostic.id} diagnostic={diagnostic} />
            ))}
          </div>
        </div>
      )}

      <div style={{ marginTop: "16px" }}>
        <div
          style={{
            fontSize: "11px",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            color: tokens.colorNeutralForeground3,
            marginBottom: "8px",
            fontWeight: 700,
          }}
        >
          Activity Metrics
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
            gap: "10px",
          }}
        >
          <SummaryCard title="Total Events" value={summary.totalEvents} />
          <SummaryCard title="Win32 Apps" value={summary.win32Apps} color={tokens.colorPalettePurpleForeground2} />
          <SummaryCard title="WinGet Apps" value={summary.wingetApps} color={tokens.colorPalettePurpleForeground2} />
          <SummaryCard title="Scripts" value={summary.scripts} color={tokens.colorPaletteTealForeground2} />
          <SummaryCard title="Remediations" value={summary.remediations} color={tokens.colorPaletteTealForeground2} />
          <SummaryCard title="Downloads" value={summary.totalDownloads} color={tokens.colorPalettePeachForeground2} />
          <SummaryCard
            title="Download Successes"
            value={summary.successfulDownloads}
            color={tokens.colorPalettePeachForeground2}
          />
          <SummaryCard
            title="Download Failures"
            value={summary.failedDownloads}
            color={tokens.colorPalettePeachForeground2}
          />
          <SummaryCard title="Succeeded" value={summary.succeeded} color={tokens.colorPaletteGreenForeground1} />
          <SummaryCard title="Failed" value={summary.failed} color={tokens.colorPaletteRedForeground1} />
          <SummaryCard title="In Progress" value={summary.inProgress} color={tokens.colorBrandForeground1} />
          <SummaryCard title="Pending" value={summary.pending} color={tokens.colorNeutralForeground3} />
          <SummaryCard title="Timed Out" value={summary.timedOut} color={tokens.colorPaletteMarigoldForeground1} />
          <SummaryCard title="Script Failures" value={summary.failedScripts} color={tokens.colorPaletteRedForeground1} />
        </div>
      </div>
    </div>
  );
}

type SummaryConclusionSection = "coverage" | "confidence" | "repeatedFailures" | "guidance";

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

interface SummaryConclusion {
  id: string;
  text: string;
  tone: "neutral" | "info" | "warning" | "critical";
  hint: string;
  action: SummaryConclusionAction;
}

interface RemediationPlanStep {
  diagnosticId: string;
  title: string;
  action: string;
  reason: string;
  priority: IntuneRemediationPriority;
  category: IntuneDiagnosticCategory;
}

const secondaryToggleButtonStyle: React.CSSProperties = {
  fontSize: "11px",
  padding: "4px 8px",
  borderRadius: "4px",
  border: `1px solid ${tokens.colorNeutralStroke2}`,
  backgroundColor: tokens.colorNeutralCardBackground,
  color: tokens.colorNeutralForeground2,
  cursor: "pointer",
};

function DiagnosticMetaBadge({ label, tone }: { label: string; tone: string }) {
  return (
    <span
      style={{
        fontSize: "10px",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        color: tone,
        border: `1px solid ${tone}33`,
        backgroundColor: `${tone}12`,
        fontWeight: 700,
        borderRadius: "999px",
        padding: "3px 8px",
      }}
    >
      {label}
    </span>
  );
}

function DiagnosticChipRow({
  label,
  items,
  itemTone,
  background,
  border,
}: {
  label: string;
  items: string[];
  itemTone: string;
  background: string;
  border: string;
}) {
  return (
    <div>
      <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em", color: tokens.colorNeutralForeground3, marginBottom: "4px" }}>
        {label}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {items.map((item) => (
          <span
            key={`${label}-${item}`}
            style={{
              fontSize: "10px",
              borderRadius: "999px",
              padding: "3px 8px",
              color: itemTone,
              backgroundColor: background,
              border: `1px solid ${border}`,
              fontWeight: 600,
            }}
            title={item}
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

function ConclusionButton({
  conclusion,
  onClick,
}: {
  conclusion: SummaryConclusion;
  onClick: () => void;
}) {
  const tone = getConclusionTone(conclusion.tone);

  return (
    <button
      onClick={onClick}
      style={{
        width: "100%",
        display: "grid",
        gridTemplateColumns: "auto minmax(0, 1fr) auto",
        gap: "10px",
        alignItems: "center",
        textAlign: "left",
        padding: "8px 10px",
        borderRadius: "6px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
        cursor: "pointer",
      }}
    >
      <span
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "999px",
          backgroundColor: tone.accent,
          flexShrink: 0,
        }}
      />
      <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground1, lineHeight: 1.35 }}>{conclusion.text}</span>
      <span
        style={{
          fontSize: "10px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          color: tone.label,
          whiteSpace: "nowrap",
        }}
      >
        {conclusion.hint}
      </span>
    </button>
  );
}

function SectionCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "8px",
        backgroundColor: tokens.colorNeutralCardBackground,
        padding: "12px 14px",
      }}
    >
      <div style={{ marginBottom: "10px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>{title}</div>
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "2px" }}>{subtitle}</div>
      </div>
      {children}
    </div>
  );
}

function CompactFact({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "baseline",
        gap: "6px",
        padding: "5px 8px",
        borderRadius: "999px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <span style={{ fontSize: "10px", fontWeight: 700, color: tokens.colorNeutralForeground3, textTransform: "uppercase" }}>
        {label}
      </span>
      <span style={{ fontSize: "12px", fontWeight: 700, color: color ?? tokens.colorNeutralForeground1 }}>{value}</span>
    </div>
  );
}

function SourceFamilyBadge({ family }: { family: IntuneSourceFamilySummary }) {
  const tone = getSourceKindTone(family.kind);

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 8px",
        borderRadius: "999px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
        color: tone.label,
        fontSize: "10px",
        fontWeight: 700,
      }}
    >
      <span>{family.label}</span>
      <span style={{ color: tone.value }}>{formatSourceFamilyDetail(family)}</span>
    </span>
  );
}

function SourceKindBadge({ kind }: { kind: IntuneLogSourceKind }) {
  const tone = getSourceKindTone(kind);

  return (
    <span
      style={{
        fontSize: "10px",
        padding: "2px 6px",
        borderRadius: "999px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
        color: tone.label,
        fontWeight: 700,
      }}
    >
      {getIntuneSourceKindLabel(kind)}
    </span>
  );
}

function CoverageRow({ file }: { file: IntuneDiagnosticsFileCoverage }) {
  const hasActivity = file.eventCount > 0 || file.downloadCount > 0;
  const sourceKind = getIntuneSourceKind(file.filePath);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(0, 1fr) auto",
        gap: "8px",
        alignItems: "center",
        padding: "8px 10px",
        borderRadius: "6px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: hasActivity ? tokens.colorNeutralCardBackground : tokens.colorNeutralBackground2,
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div
          title={file.filePath}
          style={{
            fontSize: "12px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {getFileName(file.filePath)}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "4px" }}>
          <SourceKindBadge kind={sourceKind} />
          <RowStat label="Events" value={file.eventCount} color={tokens.colorBrandForeground1} />
          <RowStat label="Downloads" value={file.downloadCount} color={tokens.colorPalettePeachForeground2} />
          {file.rotationGroup && (
            <span
              style={{
                fontSize: "10px",
                padding: "2px 6px",
                borderRadius: "999px",
                backgroundColor: file.isRotatedSegment ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteBlueBackground2,
                color: file.isRotatedSegment ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteTealForeground2,
                fontWeight: 700,
              }}
            >
              {file.isRotatedSegment ? "Rotated segment" : "Rotation base"}
            </span>
          )}
        </div>
      </div>
      <div style={{ textAlign: "right", fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
        {file.timestampBounds ? formatTimestampBounds(file.timestampBounds) : "No timestamps"}
      </div>
    </div>
  );
}

function RowStat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <span
      style={{
        fontSize: "10px",
        padding: "2px 6px",
        borderRadius: "999px",
        backgroundColor: tokens.colorPaletteBlueBackground2,
        color,
        fontWeight: 700,
      }}
    >
      {label} {value}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: IntuneDiagnosticsConfidence }) {
  const tone = getConfidenceTone(confidence.level);
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        padding: "6px 10px",
        borderRadius: "999px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
      }}
    >
      <span style={{ fontSize: "10px", fontWeight: 700, color: tone.labelColor, textTransform: "uppercase" }}>
        Confidence
      </span>
      <span style={{ fontSize: "12px", fontWeight: 700, color: tone.valueColor }}>{confidence.level}</span>
    </div>
  );
}

function RepeatedFailureRow({ group }: { group: IntuneRepeatedFailureGroup }) {
  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "6px",
        padding: "10px 12px",
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: "12px",
          alignItems: "baseline",
          flexWrap: "wrap",
        }}
      >
        <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
          {buildRepeatedFailureConclusion(group)}
        </div>
        <span style={{ fontSize: "11px", color: tokens.colorPaletteRedForeground1, fontWeight: 700 }}>
          {group.occurrences} occurrence{group.occurrences === 1 ? "" : "s"}
        </span>
      </div>

      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2, marginTop: "4px" }}>{group.name}</div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "6px", fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
        <span>{formatEventTypeLabel(group.eventType)}</span>
        <span>{group.sourceFiles.length} file(s)</span>
        {group.errorCode && <span>Error {group.errorCode}</span>}
        {group.timestampBounds && <span>{formatTimestampBounds(group.timestampBounds)}</span>}
      </div>
    </div>
  );
}

function EmptyStateText({ label }: { label: string }) {
  return <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>{label}</div>;
}

function buildSummaryConclusions({
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

function matchesTimelineAction(
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

function buildDominantSourceLabel(
  dominantSource: NonNullable<IntuneDiagnosticsCoverage["dominantSource"]>
): string {
  const share = dominantSource.eventShare != null ? ` (${formatEventShare(dominantSource.eventShare)})` : "";
  return `${getFileName(dominantSource.filePath)}${share}`;
}

function buildRepeatedFailureConclusion(group: IntuneRepeatedFailureGroup): string {
  const subject =
    group.eventType === "Win32App" || group.eventType === "WinGetApp"
      ? "Repeated app failures for the same reason"
      : group.eventType === "PowerShellScript" || group.eventType === "Remediation"
        ? "Repeated script failures for the same reason"
        : "Repeated failures for the same reason";

  return subject;
}

function buildSourceFamilySummary(
  files: IntuneDiagnosticsFileCoverage[]
): IntuneSourceFamilySummary[] {
  const families = new Map<IntuneLogSourceKind, IntuneSourceFamilySummary>();

  for (const file of files) {
    const kind = getIntuneSourceKind(file.filePath);
    const existing = families.get(kind) ?? {
      kind,
      label: getIntuneSourceKindLabel(kind),
      fileCount: 0,
      contributingFileCount: 0,
      eventCount: 0,
      downloadCount: 0,
    };

    existing.fileCount += 1;
    existing.eventCount += file.eventCount;
    existing.downloadCount += file.downloadCount;
    if (file.eventCount > 0 || file.downloadCount > 0) {
      existing.contributingFileCount += 1;
    }

    families.set(kind, existing);
  }

  return Array.from(families.values()).sort((left, right) => {
    const leftSignals = left.eventCount + left.downloadCount;
    const rightSignals = right.eventCount + right.downloadCount;
    return (
      right.contributingFileCount - left.contributingFileCount ||
      rightSignals - leftSignals ||
      right.fileCount - left.fileCount ||
      left.label.localeCompare(right.label)
    );
  });
}

function formatSourceFamilyDetail(family: IntuneSourceFamilySummary): string {
  const parts: string[] = [];
  if (family.eventCount > 0) {
    parts.push(`${family.eventCount} event${family.eventCount === 1 ? "" : "s"}`);
  }
  if (family.downloadCount > 0) {
    parts.push(`${family.downloadCount} download${family.downloadCount === 1 ? "" : "s"}`);
  }
  if (parts.length > 0) {
    return parts.join(" • ");
  }

  return `${family.fileCount} file${family.fileCount === 1 ? "" : "s"}`;
}

function getIntuneSourceKind(filePath: string): IntuneLogSourceKind {
  const fileName = getFileName(filePath).toLowerCase();

  if (fileName.includes("appworkload")) {
    return "appworkload";
  }
  if (fileName.includes("appactionprocessor")) {
    return "appactionprocessor";
  }
  if (fileName.includes("agentexecutor")) {
    return "agentexecutor";
  }
  if (fileName.includes("healthscripts")) {
    return "healthscripts";
  }
  if (fileName.includes("clienthealth")) {
    return "clienthealth";
  }
  if (fileName.includes("clientcertcheck")) {
    return "clientcertcheck";
  }
  if (fileName.includes("devicehealthmonitoring")) {
    return "devicehealthmonitoring";
  }
  if (fileName.includes("sensor")) {
    return "sensor";
  }
  if (fileName.includes("win32appinventory")) {
    return "win32appinventory";
  }
  if (fileName.includes("intunemanagementextension")) {
    return "intunemanagementextension";
  }
  return "other";
}

function getIntuneSourceKindLabel(kind: IntuneLogSourceKind): string {
  switch (kind) {
    case "appworkload":
      return "AppWorkload";
    case "appactionprocessor":
      return "AppActionProcessor";
    case "agentexecutor":
      return "AgentExecutor";
    case "healthscripts":
      return "HealthScripts";
    case "clienthealth":
      return "ClientHealth";
    case "clientcertcheck":
      return "ClientCertCheck";
    case "devicehealthmonitoring":
      return "DeviceHealthMonitoring";
    case "sensor":
      return "Sensor";
    case "win32appinventory":
      return "Win32AppInventory";
    case "intunemanagementextension":
      return "IME core";
    case "other":
    default:
      return "Other IME";
  }
}

function getSourceKindTone(kind: IntuneLogSourceKind) {
  switch (kind) {
    case "appworkload":
      return {
        border: tokens.colorPalettePeachBorderActive,
        background: tokens.colorPalettePeachBackground2,
        label: tokens.colorPalettePeachForeground2,
        value: tokens.colorPalettePeachForeground2,
      };
    case "appactionprocessor":
      return {
        border: tokens.colorPaletteBlueBorderActive,
        background: tokens.colorPaletteBlueBackground2,
        label: tokens.colorPaletteBlueForeground2,
        value: tokens.colorPaletteBlueForeground2,
      };
    case "agentexecutor":
    case "healthscripts":
      return {
        border: tokens.colorPaletteGreenBorder2,
        background: tokens.colorPaletteGreenBackground1,
        label: tokens.colorPaletteGreenForeground1,
        value: tokens.colorPaletteGreenForeground1,
      };
    case "clientcertcheck":
    case "devicehealthmonitoring":
      return {
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
        label: tokens.colorPaletteRedForeground1,
        value: tokens.colorPaletteRedForeground1,
      };
    case "sensor":
    case "win32appinventory":
      return {
        border: tokens.colorPaletteTealBorderActive,
        background: tokens.colorPaletteTealBackground2,
        label: tokens.colorPaletteTealForeground2,
        value: tokens.colorPaletteTealForeground2,
      };
    case "clienthealth":
    case "intunemanagementextension":
    case "other":
    default:
      return {
        border: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralBackground2,
        label: tokens.colorNeutralForeground3,
        value: tokens.colorNeutralForeground2,
      };
  }
}

function formatTimestampBounds(bounds: IntuneTimestampBounds): string {
  const start = bounds.firstTimestamp ? formatTimestamp(bounds.firstTimestamp) : "Unknown start";
  const end = bounds.lastTimestamp ? formatTimestamp(bounds.lastTimestamp) : "Unknown end";
  return `${start} to ${end}`;
}

function formatTimestamp(value: string): string {
  return formatDisplayDateTime(value) ?? value;
}

function formatEventShare(value: number): string {
  return `${(value * 100).toFixed(value >= 0.1 ? 0 : 1)}%`;
}

function getConfidenceTone(level: IntuneDiagnosticsConfidence["level"]) {
  switch (level) {
    case "High":
      return {
        border: tokens.colorPaletteGreenBorder2,
        background: tokens.colorPaletteGreenBackground1,
        labelColor: tokens.colorPaletteGreenForeground1,
        valueColor: tokens.colorPaletteGreenForeground1,
      };
    case "Medium":
      return {
        border: tokens.colorPaletteYellowBorder2,
        background: tokens.colorPaletteYellowBackground1,
        labelColor: tokens.colorPaletteMarigoldForeground2,
        valueColor: tokens.colorPaletteMarigoldForeground2,
      };
    case "Low":
      return {
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
        labelColor: tokens.colorPaletteRedForeground1,
        valueColor: tokens.colorPaletteRedForeground1,
      };
    case "Unknown":
    default:
      return {
        border: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralBackground2,
        labelColor: tokens.colorNeutralForeground3,
        valueColor: tokens.colorNeutralForeground2,
      };
  }
}

function formatEventTypeLabel(eventType: IntuneEventType): string {
  switch (eventType) {
    case "Win32App":
      return "Win32 app";
    case "WinGetApp":
      return "WinGet app";
    case "PowerShellScript":
      return "PowerShell script";
    case "PolicyEvaluation":
      return "Policy evaluation";
    case "ContentDownload":
      return "Content download";
    default:
      return eventType;
  }
}

function DiagnosticCard({
  diagnostic,
}: {
  diagnostic: IntuneDiagnosticInsight;
}) {
  const accent = getDiagnosticAccent(diagnostic.severity);
  const priorityTone = getPriorityTone(diagnostic.remediationPriority);
  const categoryTone = getCategoryTone(diagnostic.category);

  return (
    <div
      style={{
        border: `1px solid ${accent.border}`,
        borderLeft: `4px solid ${accent.accent}`,
        borderRadius: "6px",
        backgroundColor: accent.background,
        padding: "12px 14px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          marginBottom: "6px",
        }}
      >
        <div style={{ fontSize: "13px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          {diagnostic.title}
        </div>
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", justifyContent: "flex-end" }}>
          <DiagnosticMetaBadge label={diagnostic.severity} tone={accent.accent} />
          <DiagnosticMetaBadge label={diagnostic.category} tone={categoryTone} />
          <DiagnosticMetaBadge label={diagnostic.remediationPriority} tone={priorityTone} />
        </div>
      </div>

      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2, marginBottom: "10px" }}>
        {diagnostic.summary}
      </div>

      {diagnostic.likelyCause && (
        <div
          style={{
            marginBottom: "10px",
            padding: "8px 10px",
            borderRadius: "6px",
            backgroundColor: "rgba(255,255,255,0.55)",
            border: `1px solid ${accent.border}`,
          }}
        >
          <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em", color: tokens.colorNeutralForeground3, marginBottom: "4px" }}>
            Likely Cause
          </div>
          <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground1, lineHeight: 1.45 }}>{diagnostic.likelyCause}</div>
        </div>
      )}

      {(diagnostic.focusAreas.length > 0 || diagnostic.affectedSourceFiles.length > 0 || diagnostic.relatedErrorCodes.length > 0) && (
        <div style={{ display: "grid", gap: "8px", marginBottom: "10px" }}>
          {diagnostic.focusAreas.length > 0 && (
            <DiagnosticChipRow
              label="Focus Areas"
              items={diagnostic.focusAreas}
              itemTone={tokens.colorPaletteTealForeground2}
              background={tokens.colorPaletteTealBackground2}
              border={tokens.colorPaletteTealBorderActive}
            />
          )}
          {diagnostic.affectedSourceFiles.length > 0 && (
            <DiagnosticChipRow
              label="Affected Sources"
              items={diagnostic.affectedSourceFiles.map((file) => getFileName(file))}
              itemTone={tokens.colorPaletteBlueForeground2}
              background={tokens.colorPaletteBlueBackground2}
              border={tokens.colorPaletteBlueBorderActive}
            />
          )}
          {diagnostic.relatedErrorCodes.length > 0 && (
            <DiagnosticChipRow
              label="Error Codes"
              items={diagnostic.relatedErrorCodes}
              itemTone={tokens.colorPaletteMarigoldForeground2}
              background={tokens.colorPaletteYellowBackground1}
              border={tokens.colorPaletteYellowBorder2}
            />
          )}
        </div>
      )}

      <div style={{ display: "grid", gap: "8px" }}>
        <div>
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: tokens.colorNeutralForeground3,
              marginBottom: "4px",
            }}
          >
            Evidence
          </div>
          <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
            {diagnostic.evidence.map((item) => (
              <li key={item} style={{ marginBottom: "2px" }}>
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: tokens.colorNeutralForeground3,
              marginBottom: "4px",
            }}
          >
            Next Checks
          </div>
          <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
            {diagnostic.nextChecks.map((item) => (
              <li key={item} style={{ marginBottom: "2px" }}>
                {item}
              </li>
            ))}
          </ul>
        </div>

        {diagnostic.suggestedFixes.length > 0 && (
          <div>
            <div
              style={{
                fontSize: "11px",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                color: tokens.colorNeutralForeground3,
                marginBottom: "4px",
              }}
            >
              Suggested Fixes
            </div>
            <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
              {diagnostic.suggestedFixes.map((item) => (
                <li key={item} style={{ marginBottom: "2px" }}>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

function getDiagnosticAccent(severity: IntuneDiagnosticSeverity) {
  switch (severity) {
    case "Error":
      return {
        accent: tokens.colorPaletteRedForeground1,
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
      };
    case "Warning":
      return {
        accent: tokens.colorPaletteMarigoldForeground2,
        border: tokens.colorPaletteYellowBorder2,
        background: tokens.colorPaletteYellowBackground1,
      };
    case "Info":
    default:
      return {
        accent: tokens.colorPaletteBlueForeground2,
        border: tokens.colorPaletteBlueBorderActive,
        background: tokens.colorPaletteBlueBackground2,
      };
  }
}

function getPriorityTone(priority: IntuneRemediationPriority) {
  switch (priority) {
    case "Immediate":
      return tokens.colorPaletteRedForeground1;
    case "High":
      return tokens.colorPaletteMarigoldForeground2;
    case "Medium":
      return tokens.colorPaletteBlueForeground2;
    case "Monitor":
    default:
      return tokens.colorNeutralForeground3;
  }
}

function getCategoryTone(category: IntuneDiagnosticCategory) {
  switch (category) {
    case "Download":
      return tokens.colorPalettePeachForeground2;
    case "Install":
      return tokens.colorPalettePurpleForeground2;
    case "Timeout":
      return tokens.colorPaletteMarigoldForeground2;
    case "Script":
      return tokens.colorPaletteTealForeground2;
    case "Policy":
      return tokens.colorBrandForeground1;
    case "State":
      return tokens.colorPaletteTealForeground2;
    case "General":
    default:
      return tokens.colorNeutralForeground3;
  }
}

function buildRemediationPlan(
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

function remediationPriorityRank(priority: IntuneRemediationPriority): number {
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

function getConclusionTone(tone: SummaryConclusion["tone"]) {
  switch (tone) {
    case "critical":
      return {
        accent: tokens.colorPaletteRedForeground1,
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
        label: tokens.colorPaletteRedForeground1,
      };
    case "warning":
      return {
        accent: tokens.colorPaletteMarigoldForeground2,
        border: tokens.colorPaletteYellowBorder2,
        background: tokens.colorPaletteYellowBackground1,
        label: tokens.colorPaletteMarigoldForeground2,
      };
    case "info":
      return {
        accent: tokens.colorBrandForeground1,
        border: tokens.colorPaletteBlueBorderActive,
        background: tokens.colorPaletteBlueBackground2,
        label: tokens.colorPaletteBlueForeground2,
      };
    case "neutral":
    default:
      return {
        accent: tokens.colorNeutralForeground3,
        border: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralCardBackground,
        label: tokens.colorNeutralForeground3,
      };
  }
}

function toSentence(value: string): string {
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized) {
    return "No further detail was available.";
  }

  const firstSentence = normalized.match(/^.+?[.!?](?:\s|$)/)?.[0]?.trim() ?? normalized;
  return /[.!?]$/.test(firstSentence) ? firstSentence : `${firstSentence}.`;
}

function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || path;
}

function getLatestActivityTimestamp(
  events: IntuneEvent[],
  downloads: DownloadStat[]
): number | null {
  let latest: number | null = null;

  for (const event of events) {
    const candidate = parseIntuneTimestamp(event.startTime) ?? parseIntuneTimestamp(event.endTime);
    if (candidate != null && (latest == null || candidate > latest)) {
      latest = candidate;
    }
  }

  for (const download of downloads) {
    const candidate = parseIntuneTimestamp(download.timestamp);
    if (candidate != null && (latest == null || candidate > latest)) {
      latest = candidate;
    }
  }

  return latest;
}

function filterEventsByTimeWindow(
  events: IntuneEvent[],
  preset: IntuneTimeWindowPreset,
  anchorTimestamp: number | null
): IntuneEvent[] {
  const windowMs = getTimeWindowDurationMs(preset);
  if (windowMs == null || anchorTimestamp == null) {
    return events;
  }

  const threshold = anchorTimestamp - windowMs;
  return events.filter((event) => {
    const timestamp = parseIntuneTimestamp(event.startTime) ?? parseIntuneTimestamp(event.endTime);
    return timestamp != null && timestamp >= threshold;
  });
}

function filterDownloadsByTimeWindow(
  downloads: DownloadStat[],
  preset: IntuneTimeWindowPreset,
  anchorTimestamp: number | null
): DownloadStat[] {
  const windowMs = getTimeWindowDurationMs(preset);
  if (windowMs == null || anchorTimestamp == null) {
    return downloads;
  }

  const threshold = anchorTimestamp - windowMs;
  return downloads.filter((download) => {
    const timestamp = parseIntuneTimestamp(download.timestamp);
    return timestamp != null && timestamp >= threshold;
  });
}

function buildWindowedSummary(
  events: IntuneEvent[],
  downloads: DownloadStat[]
): IntuneSummary {
  const summaryEvents = events.filter((event) => isSummarySignalEvent(event));
  let win32Apps = 0;
  let wingetApps = 0;
  let scripts = 0;
  let remediations = 0;
  let succeeded = 0;
  let failed = 0;
  let inProgress = 0;
  let pending = 0;
  let timedOut = 0;
  let failedScripts = 0;

  for (const event of summaryEvents) {
    switch (event.eventType) {
      case "Win32App":
        win32Apps += 1;
        break;
      case "WinGetApp":
        wingetApps += 1;
        break;
      case "PowerShellScript":
        scripts += 1;
        break;
      case "Remediation":
        remediations += 1;
        break;
      default:
        break;
    }

    switch (event.status) {
      case "Success":
        succeeded += 1;
        break;
      case "Failed":
        failed += 1;
        if (event.eventType === "PowerShellScript") {
          failedScripts += 1;
        }
        break;
      case "InProgress":
        inProgress += 1;
        break;
      case "Pending":
        pending += 1;
        break;
      case "Timeout":
        timedOut += 1;
        failed += 1;
        if (event.eventType === "PowerShellScript") {
          failedScripts += 1;
        }
        break;
      default:
        break;
    }
  }

  const successfulDownloads = downloads.filter((download) => download.success).length;
  const failedDownloads = downloads.length - successfulDownloads;

  return {
    totalEvents: summaryEvents.length,
    win32Apps,
    wingetApps,
    scripts,
    remediations,
    succeeded,
    failed,
    inProgress,
    pending,
    timedOut,
    totalDownloads: downloads.length,
    successfulDownloads,
    failedDownloads,
    failedScripts,
    logTimeSpan: calculateEventTimeSpan(events),
  };
}

function isSummarySignalEvent(event: IntuneEvent): boolean {
  switch (event.eventType) {
    case "Win32App":
    case "WinGetApp":
    case "PowerShellScript":
    case "Remediation":
    case "PolicyEvaluation":
    case "ContentDownload":
    case "Esp":
    case "SyncSession":
      return true;
    case "Other":
      return event.status === "Failed"
        || event.status === "Timeout"
        || event.status === "Pending"
        || event.status === "InProgress";
    default:
      return false;
  }
}

function calculateEventTimeSpan(events: IntuneEvent[]): string | null {
  let earliest: number | null = null;
  let latest: number | null = null;

  for (const event of events) {
    for (const rawTimestamp of [event.startTime, event.endTime]) {
      const timestamp = parseIntuneTimestamp(rawTimestamp);
      if (timestamp == null) {
        continue;
      }

      if (earliest == null || timestamp < earliest) {
        earliest = timestamp;
      }
      if (latest == null || timestamp > latest) {
        latest = timestamp;
      }
    }
  }

  if (earliest == null || latest == null) {
    return null;
  }

  const totalSeconds = Math.max(0, Math.round((latest - earliest) / 1000));
  if (totalSeconds < 60) {
    return `${totalSeconds}s`;
  }

  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }

  return `${minutes}m ${seconds}s`;
}

function getTimeWindowDurationMs(preset: IntuneTimeWindowPreset): number | null {
  switch (preset) {
    case "last-hour":
      return 60 * 60 * 1000;
    case "last-6-hours":
      return 6 * 60 * 60 * 1000;
    case "last-day":
      return 24 * 60 * 60 * 1000;
    case "last-7-days":
      return 7 * 24 * 60 * 60 * 1000;
    case "all":
    default:
      return null;
  }
}

function getTimeWindowLabel(preset: IntuneTimeWindowPreset): string {
  switch (preset) {
    case "last-hour":
      return "Last Hour";
    case "last-6-hours":
      return "Last 6 Hours";
    case "last-day":
      return "Last Day";
    case "last-7-days":
      return "Last 7 Days";
    case "all":
    default:
      return "All Activity";
  }
}

function parseIntuneTimestamp(value: string | null | undefined): number | null {
  return parseDisplayDateTimeValue(value);
}

function SummaryCard({
  title,
  value,
  color,
}: {
  title: string;
  value: number;
  color?: string;
}) {
  return (
    <div
      style={{
        padding: "10px 11px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "6px",
        borderLeft: `3px solid ${color || tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      <div
        style={{
          fontSize: "11px",
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontSize: "20px",
          fontWeight: "bold",
          color: color || tokens.colorNeutralForeground1,
          marginTop: "4px",
        }}
      >
        {value}
      </div>
    </div>
  );
}
