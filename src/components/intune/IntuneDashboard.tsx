import { useEffect, useMemo, useRef, useState } from "react";
import { useIntuneStore } from "../../stores/intune-store";
import { useAppActions } from "../layout/Toolbar";
import { EventTimeline } from "./EventTimeline";
import { DownloadStats } from "./DownloadStats";
import type {
  IntuneDiagnosticInsight,
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
  const sourceContext = useIntuneStore((s) => s.sourceContext);
  const analysisState = useIntuneStore((s) => s.analysisState);
  const isAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const timelineScope = useIntuneStore((s) => s.timelineScope);
  const activeTab = useIntuneStore((s) => s.activeTab);
  const setActiveTab = useIntuneStore((s) => s.setActiveTab);
  const clearTimelineFileScope = useIntuneStore((s) => s.clearTimelineFileScope);
  const filterEventType = useIntuneStore((s) => s.filterEventType);
  const filterStatus = useIntuneStore((s) => s.filterStatus);
  const setFilterEventType = useIntuneStore((s) => s.setFilterEventType);
  const setFilterStatus = useIntuneStore((s) => s.setFilterStatus);
  const { commandState, openSourceFileDialog, openSourceFolderDialog } = useAppActions();

  const availableTabs = useMemo(
    () => ({
      timeline: events.length > 0,
      downloads: downloads.length > 0,
      summary: summary != null,
    }),
    [downloads.length, events.length, summary]
  );

  const filteredEventCount = useMemo(() => {
    return events.filter((event) => {
      if (filterEventType !== "All" && event.eventType !== filterEventType) {
        return false;
      }
      if (filterStatus !== "All" && event.status !== filterStatus) {
        return false;
      }
      return true;
    }).length;
  }, [events, filterEventType, filterStatus]);

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
  const sourceStatusTone =
    analysisState.phase === "error"
      ? "#b91c1c"
      : analysisState.phase === "empty"
        ? "#b45309"
        : analysisState.phase === "analyzing"
          ? "#2563eb"
          : "#6b7280";
  const timelineScopeFileName = timelineScope.filePath ? getFileName(timelineScope.filePath) : null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        backgroundColor: "#ffffff",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "6px 12px",
          backgroundColor: "#f3f4f6",
          borderBottom: "1px solid #d1d5db",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span
            style={{
              fontSize: "13px",
              fontWeight: 600,
              color: "#1f2937",
              fontFamily: "'Segoe UI', Tahoma, sans-serif",
            }}
          >
            Intune Diagnostics Workspace
          </span>
          <div style={{ width: "1px", height: "16px", backgroundColor: "#cbd5e1" }} />
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
            label={isAnalyzing ? "Analyzing..." : "Open IME Log Folder..."}
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
                color: "#4b5563",
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
          </div>
        )}
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 12px",
          backgroundColor: "#f8fafc",
          borderBottom: "1px solid #e2e8f0",
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
              count={tabId === "timeline" ? events.length : tabId === "downloads" ? downloads.length : summary ? 1 : 0}
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
            <div style={{ width: "1px", height: "20px", backgroundColor: "#cbd5e1", marginRight: "12px" }} />
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
              <StrongBadge label="Total" value={summary.totalEvents} />
              <StrongBadge label="Success" value={summary.succeeded} color="#16a34a" />
              <StrongBadge label="Fail" value={summary.failed} color="#dc2626" />
              <StrongBadge label="Prog" value={summary.inProgress} color="#2563eb" />
              <StrongBadge label="Win32" value={summary.win32Apps} />
              <StrongBadge label="WinGet" value={summary.wingetApps} />
              {summary.logTimeSpan && (
                <>
                  <div style={{ width: "1px", height: "12px", backgroundColor: "#cbd5e1", margin: "0 4px" }} />
                  <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 500 }}>
                    {summary.logTimeSpan}
                  </span>
                </>
              )}
            </div>
          </div>
        )}

        {activeTab === "timeline" && events.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginLeft: "auto", paddingLeft: "12px" }}>
            <span style={{ fontSize: "10px", color: "#6b7280", fontWeight: 600, textTransform: "uppercase" }}>Filters:</span>
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
                border: "1px solid #d1d5db",
                borderRadius: "3px",
                backgroundColor: hasActiveFilters ? "#fff" : "#f1f5f9",
                color: hasActiveFilters ? "#1e293b" : "#94a3b8",
                cursor: hasActiveFilters && !isAnalyzing ? "pointer" : "not-allowed",
              }}
            >
              Reset
            </button>
            <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 500, marginLeft: "4px" }}>
              {filteredEventCount}/{events.length}
            </span>
            {timelineScope.filePath && (
              <>
                <div style={{ width: "1px", height: "16px", backgroundColor: "#cbd5e1", margin: "0 2px" }} />
                <span
                  title={timelineScope.filePath}
                  style={{
                    maxWidth: "220px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontSize: "11px",
                    color: "#92400e",
                    backgroundColor: "#fef3c7",
                    border: "1px solid #fcd34d",
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
                    border: "1px solid #d1d5db",
                    borderRadius: "3px",
                    backgroundColor: "#fff",
                    color: "#1e293b",
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
              border: analysisState.phase === "empty" ? "1px solid #fde68a" : "1px solid #fecaca",
              backgroundColor: analysisState.phase === "empty" ? "#fffbeb" : "#fef2f2",
              color: analysisState.phase === "empty" ? "#92400e" : "#991b1b",
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
              color: "#999",
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
              color: "#6b7280",
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
              color: "#92400e",
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
              color: "#991b1b",
              fontSize: "14px",
              padding: "0 24px",
              textAlign: "center",
            }}
          >
            {analysisState.detail ?? "The selected Intune source could not be analyzed."}
          </div>
        ) : (
          <>
            {activeTab === "timeline" && <EventTimeline events={events} />}
            {activeTab === "downloads" && <DownloadStats downloads={downloads} />}
            {activeTab === "summary" && summary && (
              <SummaryView
                summary={summary}
                diagnostics={diagnostics}
                events={events}
                sourceFile={sourceContext.analyzedPath}
                sourceFiles={sourceContext.includedFiles}
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
        border: "1px solid #94a3b8",
        borderRadius: "4px",
        backgroundColor: disabled ? "#e5e7eb" : "#ffffff",
        color: disabled ? "#6b7280" : "#1f2937",
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
  border: "1px solid #cbd5e1",
  backgroundColor: "#fff",
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
        borderBottom: active ? "2px solid #2563eb" : "2px solid transparent",
        backgroundColor: "transparent",
        color: disabled ? "#94a3b8" : active ? "#1e3a8a" : "#475569",
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
        backgroundColor: active ? "#dbeafe" : "#f1f5f9",
        color: active ? "#1d4ed8" : "#64748b",
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
      <span style={{ color: "#64748b", fontSize: "10px", fontWeight: 600, textTransform: "uppercase" }}>{label}</span>
      <span style={{ color: color || "#0f172a", fontSize: "12px", fontWeight: 700 }}>{value}</span>
    </div>
  );
}

function SummaryView({
  summary,
  diagnostics,
  events,
  sourceFile,
  sourceFiles,
}: {
  summary: IntuneSummary;
  diagnostics: IntuneDiagnosticInsight[];
  events: IntuneEvent[];
  sourceFile: string | null;
  sourceFiles: string[];
}) {
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
          fontFamily: "'Segoe UI', Tahoma, sans-serif",
        }}
      >
        Intune Diagnostics Summary
      </h3>

      {sourceFile && (
        <div style={{ marginBottom: "12px", color: "#666" }}>
          <strong>Analyzed Path:</strong> {sourceFile}
        </div>
      )}

      {sourceFiles.length > 0 && (
        <div style={{ marginBottom: "12px", color: "#666" }}>
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
                  backgroundColor: "#eff6ff",
                  border: "1px solid #bfdbfe",
                  color: "#1e3a8a",
                  fontSize: "11px",
                  fontFamily: "'Courier New', monospace",
                }}
              >
                {getFileName(file)}
              </span>
            ))}
          </div>
        </div>
      )}

      {summary.logTimeSpan && (
        <div style={{ marginBottom: "12px", color: "#666" }}>
          <strong>Log Time Span:</strong> {summary.logTimeSpan}
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
              border: "1px solid #dbe3ee",
              borderRadius: "8px",
              backgroundColor: "#f8fafc",
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
              <div style={{ fontSize: "12px", fontWeight: 700, color: "#0f172a" }}>Conclusions</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Click to jump to proof or focus the timeline.</div>
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
              <CompactFact label="Contributing" value={String(contributingFileCount)} color="#2563eb" />
              <CompactFact label="Families" value={String(sourceFamilies.length)} color="#0f766e" />
              <CompactFact
                label="Rotated"
                value={diagnosticsCoverage.hasRotatedLogs ? "Yes" : "No"}
                color={diagnosticsCoverage.hasRotatedLogs ? "#b45309" : "#475569"}
              />
              {diagnosticsCoverage.dominantSource && (
                <CompactFact
                  label="Dominant"
                  value={buildDominantSourceLabel(diagnosticsCoverage.dominantSource)}
                  color="#0f766e"
                />
              )}
            </div>

            {diagnosticsCoverage.timestampBounds && (
              <div
                style={{
                  marginBottom: diagnosticsCoverage.files.length > 0 ? "10px" : 0,
                  padding: "8px 10px",
                  borderRadius: "6px",
                  backgroundColor: "#f8fafc",
                  border: "1px solid #e2e8f0",
                  color: "#334155",
                  fontSize: "12px",
                }}
              >
                <strong style={{ color: "#0f172a" }}>Timestamp Bounds:</strong>{" "}
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
                    color: "#475569",
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
                        border: "1px solid #cbd5e1",
                        backgroundColor: "#f8fafc",
                        color: "#475569",
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
              <div style={{ fontSize: "12px", color: "#475569" }}>
                {diagnosticsConfidence.score != null
                  ? `Score ${(diagnosticsConfidence.score * 100).toFixed(0)}%`
                  : "Score unavailable"}
              </div>
            </div>

            {diagnosticsConfidence.reasons.length > 0 ? (
              <>
                <ul style={{ margin: 0, paddingLeft: "18px", color: "#1f2937" }}>
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
                <div style={{ fontSize: "12px", color: "#64748b" }}>
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

      {diagnostics.length > 0 && (
        <div ref={diagnosticsGuidanceSectionRef} style={{ marginBottom: "20px" }}>
          <h4
            style={{
              margin: "0 0 10px 0",
              fontSize: "13px",
              color: "#111827",
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
            color: "#64748b",
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
          <SummaryCard title="Win32 Apps" value={summary.win32Apps} color="#6366f1" />
          <SummaryCard title="WinGet Apps" value={summary.wingetApps} color="#8b5cf6" />
          <SummaryCard title="Scripts" value={summary.scripts} color="#0ea5e9" />
          <SummaryCard title="Remediations" value={summary.remediations} color="#14b8a6" />
          <SummaryCard title="Downloads" value={summary.totalDownloads} color="#f97316" />
          <SummaryCard
            title="Download Successes"
            value={summary.successfulDownloads}
            color="#fb923c"
          />
          <SummaryCard
            title="Download Failures"
            value={summary.failedDownloads}
            color="#f97316"
          />
          <SummaryCard title="Succeeded" value={summary.succeeded} color="#22c55e" />
          <SummaryCard title="Failed" value={summary.failed} color="#ef4444" />
          <SummaryCard title="In Progress" value={summary.inProgress} color="#3b82f6" />
          <SummaryCard title="Pending" value={summary.pending} color="#64748b" />
          <SummaryCard title="Timed Out" value={summary.timedOut} color="#f59e0b" />
          <SummaryCard title="Script Failures" value={summary.failedScripts} color="#dc2626" />
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

const secondaryToggleButtonStyle: React.CSSProperties = {
  fontSize: "11px",
  padding: "4px 8px",
  borderRadius: "4px",
  border: "1px solid #cbd5e1",
  backgroundColor: "#ffffff",
  color: "#334155",
  cursor: "pointer",
};

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
      <span style={{ fontSize: "12px", color: "#0f172a", lineHeight: 1.35 }}>{conclusion.text}</span>
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
        border: "1px solid #e5e7eb",
        borderRadius: "8px",
        backgroundColor: "#ffffff",
        padding: "12px 14px",
      }}
    >
      <div style={{ marginBottom: "10px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>{title}</div>
        <div style={{ fontSize: "11px", color: "#6b7280", marginTop: "2px" }}>{subtitle}</div>
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
        border: "1px solid #dbe3ee",
        backgroundColor: "#f8fafc",
      }}
    >
      <span style={{ fontSize: "10px", fontWeight: 700, color: "#64748b", textTransform: "uppercase" }}>
        {label}
      </span>
      <span style={{ fontSize: "12px", fontWeight: 700, color: color ?? "#0f172a" }}>{value}</span>
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
        border: "1px solid #e5e7eb",
        backgroundColor: hasActivity ? "#fcfcfd" : "#f8fafc",
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div
          title={file.filePath}
          style={{
            fontSize: "12px",
            fontWeight: 600,
            color: "#111827",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {getFileName(file.filePath)}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "4px" }}>
          <SourceKindBadge kind={sourceKind} />
          <RowStat label="Events" value={file.eventCount} color="#2563eb" />
          <RowStat label="Downloads" value={file.downloadCount} color="#ea580c" />
          {file.rotationGroup && (
            <span
              style={{
                fontSize: "10px",
                padding: "2px 6px",
                borderRadius: "999px",
                backgroundColor: file.isRotatedSegment ? "#fef3c7" : "#e0f2fe",
                color: file.isRotatedSegment ? "#92400e" : "#0f766e",
                fontWeight: 700,
              }}
            >
              {file.isRotatedSegment ? "Rotated segment" : "Rotation base"}
            </span>
          )}
        </div>
      </div>
      <div style={{ textAlign: "right", fontSize: "11px", color: "#64748b" }}>
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
        backgroundColor: "#eef2ff",
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
        border: "1px solid #e5e7eb",
        borderRadius: "6px",
        padding: "10px 12px",
        backgroundColor: "#fcfcfd",
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
        <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>
          {buildRepeatedFailureConclusion(group)}
        </div>
        <span style={{ fontSize: "11px", color: "#b91c1c", fontWeight: 700 }}>
          {group.occurrences} occurrence{group.occurrences === 1 ? "" : "s"}
        </span>
      </div>

      <div style={{ fontSize: "12px", color: "#374151", marginTop: "4px" }}>{group.name}</div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "6px", fontSize: "11px", color: "#64748b" }}>
        <span>{formatEventTypeLabel(group.eventType)}</span>
        <span>{group.sourceFiles.length} file(s)</span>
        {group.errorCode && <span>Error {group.errorCode}</span>}
        {group.timestampBounds && <span>{formatTimestampBounds(group.timestampBounds)}</span>}
      </div>
    </div>
  );
}

function EmptyStateText({ label }: { label: string }) {
  return <div style={{ fontSize: "12px", color: "#64748b" }}>{label}</div>;
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
        border: "#fdba74",
        background: "#fff7ed",
        label: "#9a3412",
        value: "#c2410c",
      };
    case "appactionprocessor":
      return {
        border: "#93c5fd",
        background: "#eff6ff",
        label: "#1d4ed8",
        value: "#1e40af",
      };
    case "agentexecutor":
    case "healthscripts":
      return {
        border: "#86efac",
        background: "#f0fdf4",
        label: "#166534",
        value: "#15803d",
      };
    case "clientcertcheck":
    case "devicehealthmonitoring":
      return {
        border: "#fca5a5",
        background: "#fef2f2",
        label: "#b91c1c",
        value: "#991b1b",
      };
    case "sensor":
    case "win32appinventory":
      return {
        border: "#67e8f9",
        background: "#ecfeff",
        label: "#0f766e",
        value: "#0f766e",
      };
    case "clienthealth":
    case "intunemanagementextension":
    case "other":
    default:
      return {
        border: "#cbd5e1",
        background: "#f8fafc",
        label: "#475569",
        value: "#334155",
      };
  }
}

function formatTimestampBounds(bounds: IntuneTimestampBounds): string {
  const start = bounds.firstTimestamp ? formatTimestamp(bounds.firstTimestamp) : "Unknown start";
  const end = bounds.lastTimestamp ? formatTimestamp(bounds.lastTimestamp) : "Unknown end";
  return `${start} to ${end}`;
}

function formatTimestamp(value: string): string {
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) {
    return value;
  }
  return timestamp.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatEventShare(value: number): string {
  return `${(value * 100).toFixed(value >= 0.1 ? 0 : 1)}%`;
}

function getConfidenceTone(level: IntuneDiagnosticsConfidence["level"]) {
  switch (level) {
    case "High":
      return {
        border: "#86efac",
        background: "#f0fdf4",
        labelColor: "#166534",
        valueColor: "#166534",
      };
    case "Medium":
      return {
        border: "#fde68a",
        background: "#fffbeb",
        labelColor: "#92400e",
        valueColor: "#92400e",
      };
    case "Low":
      return {
        border: "#fecaca",
        background: "#fef2f2",
        labelColor: "#991b1b",
        valueColor: "#991b1b",
      };
    case "Unknown":
    default:
      return {
        border: "#cbd5e1",
        background: "#f8fafc",
        labelColor: "#475569",
        valueColor: "#334155",
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
        <div style={{ fontSize: "13px", fontWeight: 600, color: "#111827" }}>
          {diagnostic.title}
        </div>
        <span
          style={{
            fontSize: "10px",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: accent.accent,
            fontWeight: 700,
          }}
        >
          {diagnostic.severity}
        </span>
      </div>

      <div style={{ fontSize: "12px", color: "#374151", marginBottom: "10px" }}>
        {diagnostic.summary}
      </div>

      <div style={{ display: "grid", gap: "8px" }}>
        <div>
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: "#6b7280",
              marginBottom: "4px",
            }}
          >
            Evidence
          </div>
          <ul style={{ margin: 0, paddingLeft: "18px", color: "#1f2937" }}>
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
              color: "#6b7280",
              marginBottom: "4px",
            }}
          >
            Next Checks
          </div>
          <ul style={{ margin: 0, paddingLeft: "18px", color: "#1f2937" }}>
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
                color: "#6b7280",
                marginBottom: "4px",
              }}
            >
              Suggested Fixes
            </div>
            <ul style={{ margin: 0, paddingLeft: "18px", color: "#1f2937" }}>
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
        accent: "#b91c1c",
        border: "#fecaca",
        background: "#fef2f2",
      };
    case "Warning":
      return {
        accent: "#b45309",
        border: "#fde68a",
        background: "#fffbeb",
      };
    case "Info":
    default:
      return {
        accent: "#1d4ed8",
        border: "#bfdbfe",
        background: "#eff6ff",
      };
  }
}

function getConclusionTone(tone: SummaryConclusion["tone"]) {
  switch (tone) {
    case "critical":
      return {
        accent: "#b91c1c",
        border: "#fecaca",
        background: "#fff7f7",
        label: "#991b1b",
      };
    case "warning":
      return {
        accent: "#b45309",
        border: "#fde68a",
        background: "#fffbeb",
        label: "#92400e",
      };
    case "info":
      return {
        accent: "#2563eb",
        border: "#bfdbfe",
        background: "#eff6ff",
        label: "#1d4ed8",
      };
    case "neutral":
    default:
      return {
        accent: "#475569",
        border: "#dbe3ee",
        background: "#ffffff",
        label: "#475569",
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
        border: "1px solid #e5e7eb",
        borderRadius: "6px",
        borderLeft: `3px solid ${color || "#9ca3af"}`,
        backgroundColor: "#ffffff",
      }}
    >
      <div
        style={{
          fontSize: "11px",
          color: "#6b7280",
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
          color: color || "#111",
          marginTop: "4px",
        }}
      >
        {value}
      </div>
    </div>
  );
}
