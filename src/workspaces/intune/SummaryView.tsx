import { useMemo, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_UI_FONT_FAMILY, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useIntuneStore } from "./intune-store";
import type {
  IntuneDiagnosticInsight,
  IntuneEvent,
  IntuneTimeWindowPreset,
  IntuneSummary,
} from "./types";
import {
  buildDominantSourceLabel,
  buildSourceFamilySummary,
  formatTimestampBounds,
  getCategoryTone,
  getFileName,
  getPriorityTone,
  secondaryToggleButtonStyle,
} from "./intune-dashboard-utils";
import {
  buildRemediationPlan,
  buildSummaryConclusions,
  matchesTimelineAction,
} from "./summary-view-logic";
import type { SummaryConclusion, SummaryConclusionSection } from "./summary-view-logic";
import {
  CompactFact,
  ConclusionButton,
  ConfidenceBadge,
  CoverageRow,
  DiagnosticCard,
  DiagnosticMetaBadge,
  EmptyStateText,
  RepeatedFailureRow,
  SectionCard,
  SourceFamilyBadge,
  SummaryCard,
} from "./SummaryViewComponents";

export function SummaryView({
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
            background: `linear-gradient(180deg, ${tokens.colorNeutralBackground1} 0%, ${tokens.colorNeutralBackground1} 78%, transparent 100%)`,
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
                  type="button"
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
                    type="button"
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
                  type="button"
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
