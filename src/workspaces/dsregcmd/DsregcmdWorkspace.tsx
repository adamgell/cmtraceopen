import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { Button, Textarea, tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { save } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useDsregcmdStore } from "./dsregcmd-store";
import { DsregcmdEventLogSurface } from "./DsregcmdEventLogSurface";
import { useAppActions } from "../../components/layout/Toolbar";
import { writeTextOutputFile } from "../../lib/commands";
import {
  formatBool,
  formatConfidenceLabel,
  formatHourDuration,
  formatPhaseLabel,
  formatValue,
  getDisplayConfidenceAssessment,
  getDisplayPhaseAssessment,
  getFactGroups,
  getMdmVisibilityLabel,
  getNgcCaption,
  getNgcReadinessValue,
  getSummaryText,
  getPolicyDisplayValue,
  buildTimelineItems,
  computeDisplayedPrtAgeHours,
  qualifyByCaptureConfidence,
  toneForCaptureConfidence,
  toneForJoinType,
  toneForMdmVisibility,
  toneForNgcReadiness,
  toneForPhase,
  toneForPrtState,
} from "./dsregcmd-formatters";
import { IssueCard } from "./DiagnosticInsightsCard";
import { FactsTable } from "./FactGroupRenderer";
import {
  StatCard,
  SectionFrame,
  EmptyWorkspace,
  FlowBox,
  TabButton,
} from "./PolicyEvidencePane";

export function DsregcmdWorkspace() {
  const result = useDsregcmdStore((s) => s.result);
  const rawInput = useDsregcmdStore((s) => s.rawInput);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const {
    openSourceFileDialog,
    openSourceFolderDialog,
    pasteDsregcmdSource,
    captureDsregcmdSource,
  } = useAppActions();
  const [exportStatus, setExportStatus] = useState<{
    tone: "success" | "error";
    message: string;
  } | null>(null);
  const [showRawInput, setShowRawInput] = useState(false);
  const [showNotReported, setShowNotReported] = useState(false);
  const activeTab = useDsregcmdStore((s) => s.activeTab);
  const setActiveTab = useDsregcmdStore((s) => s.setActiveTab);

  const eventLogEntryCount = result?.eventLogAnalysis?.totalEntryCount ?? 0;

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter(
    (item) => item.severity === "Error",
  ).length;
  const warningCount = diagnostics.filter(
    (item) => item.severity === "Warning",
  ).length;

  const displayedPrtAgeHours = useMemo(
    () => computeDisplayedPrtAgeHours(result, sourceContext),
    [result, sourceContext],
  );

  const displayPhase = useMemo(
    () =>
      result
        ? getDisplayPhaseAssessment(result, errorCount, warningCount)
        : null,
    [errorCount, result, warningCount],
  );
  const displayConfidence = useMemo(
    () =>
      result ? getDisplayConfidenceAssessment(result, sourceContext) : null,
    [result, sourceContext],
  );

  const factGroups = useMemo(
    () =>
      result && displayPhase && displayConfidence
        ? getFactGroups(
            result,
            displayedPrtAgeHours,
            displayPhase,
            displayConfidence,
            sourceContext,
          )
        : [],
    [
      displayConfidence,
      displayPhase,
      displayedPrtAgeHours,
      result,
      sourceContext,
    ],
  );
  const summaryText = useMemo(
    () =>
      result && displayPhase && displayConfidence
        ? getSummaryText(
            result,
            sourceContext.displayLabel,
            displayPhase,
            displayConfidence,
          )
        : "",
    [displayConfidence, displayPhase, result, sourceContext.displayLabel],
  );
  const timelineItems = useMemo(
    () => (result ? buildTimelineItems(result.facts, result) : []),
    [result],
  );

  useEffect(() => {
    if (!exportStatus) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setExportStatus(null);
    }, 5000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [exportStatus]);

  const setExportSuccess = useCallback((message: string) => {
    setExportStatus({ tone: "success", message });
  }, []);

  const setExportError = useCallback((message: string) => {
    setExportStatus({ tone: "error", message });
  }, []);

  const handleCopyJson = async () => {
    if (!result) {
      return;
    }

    try {
      await writeText(JSON.stringify(result, null, 2));
      setExportSuccess("Copied dsregcmd analysis JSON to the clipboard.");
    } catch (error) {
      console.error("[dsregcmd] failed to copy JSON export", { error });
      setExportError(
        error instanceof Error
          ? error.message
          : "Could not copy dsregcmd JSON to the clipboard.",
      );
    }
  };

  const handleCopySummary = async () => {
    if (!result) {
      return;
    }

    try {
      await writeText(summaryText);
      setExportSuccess("Copied dsregcmd summary to the clipboard.");
    } catch (error) {
      console.error("[dsregcmd] failed to copy summary export", { error });
      setExportError(
        error instanceof Error
          ? error.message
          : "Could not copy the dsregcmd summary to the clipboard.",
      );
    }
  };

  const handleCopyStatus = async () => {
    if (!rawInput.trim()) {
      setExportError("No dsregcmd status text is available to copy.");
      return;
    }

    try {
      await writeText(rawInput);
      setExportSuccess("Copied dsregcmd status text to the clipboard.");
    } catch (error) {
      console.error("[dsregcmd] failed to copy raw status", { error });
      setExportError(
        error instanceof Error
          ? error.message
          : "Could not copy dsregcmd status text to the clipboard.",
      );
    }
  };

  const handleSaveExport = async (kind: "json" | "summary") => {
    if (!result) {
      return;
    }

    const defaultPath =
      kind === "json" ? "dsregcmd-analysis.json" : "dsregcmd-summary.txt";

    try {
      const destination = await save({
        defaultPath,
        filters:
          kind === "json"
            ? [{ name: "JSON", extensions: ["json"] }]
            : [{ name: "Text", extensions: ["txt"] }],
      });

      if (!destination) {
        return;
      }

      const contents =
        kind === "json" ? JSON.stringify(result, null, 2) : summaryText;
      await writeTextOutputFile(destination, contents);
      setExportSuccess(
        `Saved ${kind === "json" ? "JSON export" : "summary export"} to ${destination}.`,
      );
    } catch (error) {
      console.error("[dsregcmd] failed to save export", { error, kind });
      setExportError(
        error instanceof Error
          ? error.message
          : `Could not save the ${kind === "json" ? "JSON" : "summary"} export.`,
      );
    }
  };

  if (!result && isAnalyzing) {
    return (
      <EmptyWorkspace
        title="Analyzing dsregcmd source"
        body={
          analysisState.detail ??
          "Reading source text, extracting facts, and building the first-pass health view..."
        }
      />
    );
  }

  if (!result && analysisState.phase === "error") {
    return (
      <EmptyWorkspace
        title="dsregcmd analysis failed"
        body={
          analysisState.detail ??
          "The selected dsregcmd source could not be analyzed."
        }
      />
    );
  }

  if (!result) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "10px",
            padding: "8px 12px",
            backgroundColor: tokens.colorNeutralBackground3,
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          }}
        >
          <div>
            <div
              style={{ fontSize: "14px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
            >
              dsregcmd Workspace
            </div>
            <div
              style={{ marginTop: "4px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}
            >
              Capture a live snapshot, paste clipboard text, open a text file,
              or select an evidence bundle folder.
            </div>
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <Button
              appearance="primary"
              onClick={() => void captureDsregcmdSource()}
            >
              Capture
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void pasteDsregcmdSource()}
            >
              Paste
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void openSourceFileDialog()}
            >
              Open Text File
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void openSourceFolderDialog()}
            >
              Open Evidence Folder
            </Button>
          </div>
        </div>

        <EmptyWorkspace
          title="No dsregcmd source loaded"
          body="Use the workspace actions above to analyze dsregcmd /status output. Open a bundle root, its evidence folder, or its command-output folder, or run a live capture that stages dsregcmd and registry evidence together."
        />
      </div>
    );
  }

  const issueSpotlight =
    diagnostics.find((item) => item.severity === "Error") ??
    diagnostics[0] ??
    null;
  const stage = displayPhase ?? {
    phase: result.derived.dominantPhase,
    label: formatPhaseLabel(result.derived.dominantPhase),
    tone: toneForPhase(result.derived.dominantPhase),
    summary: result.derived.phaseSummary,
  };
  const confidence = displayConfidence ?? {
    confidence: result.derived.captureConfidence,
    reason: result.derived.captureConfidenceReason,
  };
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "10px",
          padding: "8px 12px",
          backgroundColor: tokens.colorNeutralBackground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          flexWrap: "wrap",
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: "14px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            dsregcmd Workspace
          </div>
          <div
            style={{
              marginTop: "4px",
              fontSize: "12px",
              color: tokens.colorNeutralForeground3,
              lineHeight: 1.4,
            }}
          >
            {sourceContext.displayLabel}
            {sourceContext.resolvedPath && ` • ${sourceContext.resolvedPath}`}
            {sourceContext.evidenceFilePath &&
            sourceContext.evidenceFilePath !== sourceContext.resolvedPath
              ? ` • evidence ${sourceContext.evidenceFilePath}`
              : ""}
          </div>
        </div>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <Button
            appearance="primary"
            onClick={() => void captureDsregcmdSource()}
            disabled={isAnalyzing}
          >
            Capture
          </Button>
          <Button
            appearance="secondary"
            onClick={() => void pasteDsregcmdSource()}
            disabled={isAnalyzing}
          >
            Paste
          </Button>
          <Button
            appearance="secondary"
            onClick={() => void openSourceFileDialog()}
            disabled={isAnalyzing}
          >
            Open Text File
          </Button>
          <Button
            appearance="secondary"
            onClick={() => void openSourceFolderDialog()}
            disabled={isAnalyzing}
          >
            Open Evidence Folder
          </Button>
        </div>
      </div>

      {/* Tab strip */}
      <div
        style={{
          display: "flex",
          gap: 2,
          padding: "0 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          background: tokens.colorNeutralBackground3,
          flexShrink: 0,
        }}
      >
        <TabButton
          label="Analysis"
          isActive={activeTab === "analysis"}
          onClick={() => setActiveTab("analysis")}
        />
        <TabButton
          label="Event Logs"
          count={eventLogEntryCount}
          isActive={activeTab === "event-logs"}
          onClick={() => setActiveTab("event-logs")}
        />
      </div>

      {activeTab === "event-logs" && result.eventLogAnalysis ? (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <DsregcmdEventLogSurface eventLogAnalysis={result.eventLogAnalysis} />
        </div>
      ) : (
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "12px",
            flexShrink: 0,
          }}
        >
          <StatCard
            title="Join Type"
            value={result.derived.joinTypeLabel}
            caption="Derived from AzureAdJoined and DomainJoined fields."
            tone={toneForJoinType(result.derived.joinType)}
          />
          <StatCard
            title="Current Stage"
            value={stage.label}
            caption={stage.summary}
            tone={stage.tone}
          />
          <StatCard
            title="Capture Confidence"
            value={formatConfidenceLabel(confidence.confidence)}
            caption={confidence.reason}
            tone={toneForCaptureConfidence(confidence.confidence)}
          />
          <StatCard
            title="PRT State"
            value={formatBool(result.derived.azureAdPrtPresent)}
            caption={
              result.derived.stalePrt
                ? qualifyByCaptureConfidence(
                    confidence.confidence,
                    `PRT looks stale by ${formatHourDuration(result.derived.prtAgeHours)}.`,
                  )
                : qualifyByCaptureConfidence(
                    confidence.confidence,
                    "Primary Refresh Token presence was derived from SSO state.",
                  )
            }
            tone={toneForPrtState(
              result.derived.azureAdPrtPresent,
              result.derived.stalePrt,
            )}
          />
          <StatCard
            title="MDM Signals"
            value={getMdmVisibilityLabel(result.derived)}
            caption={qualifyByCaptureConfidence(
              confidence.confidence,
              "visible tenant management metadata can be out of scope, not configured, or simply absent from this capture.",
            )}
            tone={toneForMdmVisibility(result.derived)}
          />
          <StatCard
            title="NGC"
            value={getNgcReadinessValue(result)}
            caption={qualifyByCaptureConfidence(
              confidence.confidence,
              getNgcCaption(result),
            )}
            tone={toneForNgcReadiness(result)}
          />
          <StatCard
            title="Certificate"
            value={
              result.derived.certificateDaysRemaining == null
                ? "Unknown"
                : `${result.derived.certificateDaysRemaining} days`
            }
            caption="Remaining device certificate lifetime, when the validity range was parsed."
            tone={result.derived.certificateExpiringSoon ? "warn" : "neutral"}
          />
        </div>

        <SectionFrame
          title="Health Summary"
          caption="Fast first-pass readout of the current dsregcmd capture."
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(260px, 1.2fr) minmax(220px, 0.8fr)",
              gap: "16px",
            }}
          >
            <div>
              <div
                style={{
                  fontSize: "13px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                  whiteSpace: "pre-wrap",
                }}
              >
                {summaryText}
              </div>
              {issueSpotlight && (
                <div
                  style={{
                    marginTop: "12px",
                    padding: "10px",
                    border: `1px solid ${tokens.colorNeutralStroke2}`,
                    backgroundColor: tokens.colorNeutralBackground2,
                  }}
                >
                  <div
                    style={{
                      fontSize: "12px",
                      fontWeight: 700,
                      color: tokens.colorNeutralForeground1,
                    }}
                  >
                    Issue spotlight
                  </div>
                  <div
                    style={{
                      marginTop: "6px",
                      fontSize: "13px",
                      fontWeight: 600,
                      color: tokens.colorNeutralForeground1,
                    }}
                  >
                    {issueSpotlight.title}
                  </div>
                  <div
                    style={{
                      marginTop: "4px",
                      fontSize: "12px",
                      color: tokens.colorNeutralForeground3,
                      lineHeight: 1.5,
                    }}
                  >
                    {issueSpotlight.summary}{" "}
                    {confidence.confidence === "high"
                      ? ""
                      : `Interpret this in the context of ${formatConfidenceLabel(confidence.confidence).toLowerCase()} capture confidence.`}
                  </div>
                </div>
              )}
            </div>
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralCardBackground,
                padding: "12px",
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                Quick interpretation
              </div>
              <ul
                style={{
                  marginTop: "8px",
                  paddingLeft: "18px",
                  color: tokens.colorNeutralForeground2,
                  lineHeight: 1.6,
                }}
              >
                <li>{stage.summary}</li>
                <li>{`Capture confidence is ${formatConfidenceLabel(confidence.confidence).toLowerCase()}: ${confidence.reason}`}</li>
                <li>
                  {result.policyEvidence.artifactPaths.length > 0
                    ? "Registry-backed WHfB policy evidence is available for this bundle."
                    : "No sibling registry policy evidence was available for this capture."}
                </li>
                <li>
                  {result.derived.hasNetworkError
                    ? `Network marker detected: ${result.derived.networkErrorCode}.`
                    : "No explicit network marker was detected in the capture."}
                </li>
                <li>
                  {result.derived.remoteSessionSystem
                    ? "Capture looks like SYSTEM in a remote session, so user token fields may be misleading."
                    : "Capture does not look like a SYSTEM remote-session snapshot."}
                </li>
                <li>
                  {result.derived.certificateExpiringSoon
                    ? "Device certificate is nearing expiry and deserves follow-up."
                    : "Certificate expiry was not flagged as near-term."}
                </li>
              </ul>
            </div>
          </div>
        </SectionFrame>

        <SectionFrame
          title="Issues Overview"
          caption="Ordered diagnostic findings with evidence, recommended checks, and suggested fixes."
        >
          {diagnostics.length === 0 ? (
            <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground2 }}>
              No diagnostics were produced for this dsregcmd capture.
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
                gap: "12px",
              }}
            >
              {diagnostics.map((issue) => (
                <IssueCard key={issue.id} issue={issue} />
              ))}
            </div>
          )}
        </SectionFrame>

        <SectionFrame
          title="Facts by Group"
          caption="Backend-extracted facts organized for quick review rather than raw line order."
        >
          <div
            style={{
              display: "flex",
              justifyContent: "flex-end",
              marginBottom: "12px",
            }}
          >
            <Button
              appearance={showNotReported ? "primary" : "secondary"}
              onClick={() => setShowNotReported((value) => !value)}
            >
              {showNotReported
                ? "Hide Not Reported Fields"
                : "Show Not Reported Fields"}
            </Button>
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
              gap: "12px",
            }}
          >
            {factGroups.map((group) => (
              <FactsTable
                key={group.id}
                group={group}
                showNotReported={showNotReported}
              />
            ))}
          </div>
        </SectionFrame>

        <SectionFrame
          title="Timeline"
          caption="Important timestamps surfaced from PRT, certificate, and diagnostics fields."
        >
          {timelineItems.length === 0 ? (
            <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground2 }}>
              No timeline-friendly timestamps were found in this capture.
            </div>
          ) : (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "10px" }}
            >
              {timelineItems.map((item, index) => {
                const palette =
                  item.tone === "warn"
                    ? { line: tokens.colorPaletteMarigoldForeground1, dot: tokens.colorPaletteMarigoldForeground1, card: tokens.colorPaletteYellowBackground1 }
                    : item.tone === "good"
                      ? { line: tokens.colorPaletteGreenForeground1, dot: tokens.colorPaletteGreenForeground1, card: tokens.colorPaletteGreenBackground1 }
                      : { line: tokens.colorNeutralStroke1, dot: tokens.colorNeutralForeground3, card: tokens.colorNeutralBackground3 };

                return (
                  <div
                    key={item.id}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "20px 1fr",
                      gap: "10px",
                      alignItems: "stretch",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                      }}
                    >
                      <div
                        style={{
                          width: "10px",
                          height: "10px",
                          borderRadius: "999px",
                          backgroundColor: palette.dot,
                          marginTop: "8px",
                        }}
                      />
                      {index < timelineItems.length - 1 && (
                        <div
                          style={{
                            flex: 1,
                            width: "2px",
                            backgroundColor: palette.line,
                            marginTop: "4px",
                          }}
                        />
                      )}
                    </div>
                    <div
                      style={{
                        border: `1px solid ${tokens.colorNeutralStroke2}`,
                        backgroundColor: palette.card,
                        padding: "10px 12px",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "12px",
                          fontWeight: 700,
                          color: tokens.colorNeutralForeground1,
                        }}
                      >
                        {item.label}
                      </div>
                      <div
                        style={{
                          marginTop: "4px",
                          fontSize: "12px",
                          color: tokens.colorNeutralForeground2,
                          wordBreak: "break-word",
                        }}
                      >
                        {item.value}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </SectionFrame>

        <SectionFrame
          title="Flows"
          caption="Pragmatic first-pass flow boxes for registration, management, and token health."
        >
          <div
            style={{
              display: "flex",
              gap: "10px",
              flexWrap: "wrap",
              alignItems: "stretch",
            }}
          >
            <FlowBox
              title="Current phase"
              detail={`${stage.label}. ${stage.summary}`}
              tone={stage.tone}
            />
            <FlowBox
              title="Join posture"
              detail={`${result.derived.joinTypeLabel}. Azure AD joined: ${formatBool(result.facts.joinState.azureAdJoined)}. Domain joined: ${formatBool(result.facts.joinState.domainJoined)}.`}
              tone={toneForJoinType(result.derived.joinType)}
            />
            <FlowBox
              title="Device authentication"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `device auth status is ${formatValue(result.facts.deviceDetails.deviceAuthStatus)} and TPM protected is ${formatBool(result.facts.deviceDetails.tpmProtected)}.`,
              )}
              tone={
                result.facts.deviceDetails.deviceAuthStatus?.toUpperCase() ===
                "SUCCESS"
                  ? "good"
                  : "bad"
              }
            />
            <FlowBox
              title="Management"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `MDM visibility is ${getMdmVisibilityLabel(result.derived)} and compliance URL present is ${formatBool(result.derived.complianceUrlPresent)}. Missing fields are not proof that management is broken.`,
              )}
              tone={toneForMdmVisibility(result.derived)}
            />
            <FlowBox
              title="PRT and session"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `PRT present is ${formatBool(result.derived.azureAdPrtPresent)}, stale is ${formatBool(result.derived.stalePrt)}, and remote SYSTEM is ${formatBool(result.derived.remoteSessionSystem)}.`,
              )}
              tone={toneForPrtState(
                result.derived.azureAdPrtPresent,
                result.derived.stalePrt,
              )}
            />
            <FlowBox
              title="NGC readiness"
              detail={qualifyByCaptureConfidence(
                confidence.confidence,
                `NGC is ${formatBool(result.facts.userState.ngcSet)}, policy enabled is ${getPolicyDisplayValue(result.facts.userState.policyEnabled, result.policyEvidence.policyEnabled)}, PreReq Result is ${formatValue(result.facts.registration.preReqResult)}, and device eligible is ${formatBool(result.facts.userState.deviceEligible)}.`,
              )}
              tone={toneForNgcReadiness(result)}
            />
            <FlowBox
              title="Capture trust"
              detail={`${formatConfidenceLabel(confidence.confidence)} confidence. ${confidence.reason}`}
              tone={toneForCaptureConfidence(confidence.confidence)}
            />
          </div>
        </SectionFrame>

        <SectionFrame
          title="Explainer"
          caption="Short practical notes for what this workspace is showing and how to use it."
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: "12px",
            }}
          >
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                padding: "12px",
                backgroundColor: tokens.colorNeutralCardBackground,
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                What the health cards mean
              </div>
              <div
                style={{
                  marginTop: "8px",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                Cards summarize join posture, token state, MDM visibility,
                certificate lifetime, and issue counts. They are not a
                replacement for the raw dsregcmd output, but they do make triage
                faster.
              </div>
            </div>
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                padding: "12px",
                backgroundColor: tokens.colorNeutralCardBackground,
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                When the capture may mislead
              </div>
              <div
                style={{
                  marginTop: "8px",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                SYSTEM and remote-session captures can distort user-scoped token
                state. Evidence bundle captures can also be older than the
                current device state, so compare timestamps before acting.
              </div>
            </div>
            <div
              style={{
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                padding: "12px",
                backgroundColor: tokens.colorNeutralCardBackground,
              }}
            >
              <div
                style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}
              >
                Suggested next step
              </div>
              <div
                style={{
                  marginTop: "8px",
                  fontSize: "12px",
                  lineHeight: 1.6,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                Start with the highest-severity issue card, validate the
                evidence line items against the grouped facts below, and then
                re-run capture after remediation to confirm the signal changes.
              </div>
            </div>
          </div>
        </SectionFrame>

        <SectionFrame
          title="Export"
          caption="No-dependency export controls for handing off or attaching analysis output."
        >
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <Button
              appearance="secondary"
              onClick={() => void handleCopyJson()}
            >
              Copy JSON
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleCopyStatus()}
            >
              Copy Status Text
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleCopySummary()}
            >
              Copy Summary
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleSaveExport("json")}
            >
              Save JSON
            </Button>
            <Button
              appearance="secondary"
              onClick={() => void handleSaveExport("summary")}
            >
              Save Summary
            </Button>
            <Button
              appearance={showRawInput ? "primary" : "secondary"}
              onClick={() => setShowRawInput((value) => !value)}
            >
              {showRawInput ? "Hide Raw Input" : "Show Raw Input"}
            </Button>
          </div>
          {exportStatus && (
            <div
              style={{
                marginTop: "10px",
                fontSize: "12px",
                color: exportStatus.tone === "error" ? tokens.colorPaletteRedForeground1 : tokens.colorPaletteGreenForeground1,
              }}
            >
              {exportStatus.message}
            </div>
          )}
          {showRawInput && (
            <Textarea
              readOnly
              value={rawInput}
              style={{
                marginTop: "12px",
                width: "100%",
                minHeight: "220px",
                resize: "vertical",
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: "12px",
                padding: "10px",
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralBackground2,
              }}
            />
          )}
        </SectionFrame>
      </div>
      )}
    </div>
  );
}
