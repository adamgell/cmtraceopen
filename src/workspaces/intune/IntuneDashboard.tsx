import { useEffect, useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { useIntuneStore } from "./intune-store";
import { EventTimeline } from "./EventTimeline";
import { DownloadStats } from "./DownloadStats";
import { SummaryView } from "./SummaryView";
import { IntuneDashboardHeader } from "./IntuneDashboardHeader";
import { IntuneDashboardNavBar } from "./IntuneDashboardNavBar";
import { useTimeWindowFilter } from "./useTimeWindowFilter";

export function IntuneDashboard() {
  const summary = useIntuneStore((s) => s.summary);
  const events = useIntuneStore((s) => s.events);
  const downloads = useIntuneStore((s) => s.downloads);
  const diagnostics = useIntuneStore((s) => s.diagnostics);
  const sourceContext = useIntuneStore((s) => s.sourceContext);
  const analysisState = useIntuneStore((s) => s.analysisState);
  const isAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const timeWindow = useIntuneStore((s) => s.timeWindow);
  const activeTab = useIntuneStore((s) => s.activeTab);
  const setActiveTab = useIntuneStore((s) => s.setActiveTab);

  const {
    filteredEventsByTime,
    filteredDownloadsByTime,
    filteredSummary,
    timeWindowLabel,
    isWindowFiltered,
  } = useTimeWindowFilter();

  const availableTabs = useMemo(
    () => ({
      timeline: filteredEventsByTime.length > 0,
      downloads: filteredDownloadsByTime.length > 0,
      summary: summary != null,
    }),
    [filteredDownloadsByTime.length, filteredEventsByTime.length, summary]
  );

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

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      <IntuneDashboardHeader />

      <IntuneDashboardNavBar
        filteredEventsByTime={filteredEventsByTime}
        filteredDownloadsByTime={filteredDownloadsByTime}
        filteredSummary={filteredSummary}
        timeWindowLabel={timeWindowLabel}
        isWindowFiltered={isWindowFiltered}
      />

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
