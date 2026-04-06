import { useState } from "react";
import { tokens, Button, Spinner, Tab, TabList } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useSysmonStore, type SysmonWorkspaceTab } from "./sysmon-store";
import { useUiStore } from "../../stores/ui-store";
import { analyzeSysmonLogs } from "../../lib/commands";
import { useAppActions } from "../../components/layout/Toolbar";
import { SysmonEventTable } from "./SysmonEventTable";
import { SysmonSummaryView } from "./SysmonSummaryView";
import { SysmonConfigView } from "./SysmonConfigView";
import { SysmonDashboardView } from "./SysmonDashboardView";

const EVTX_FILE_DIALOG_FILTERS = [
  { name: "Event Log Files", extensions: ["evtx"] },
  { name: "All Files", extensions: ["*"] },
];

export function SysmonWorkspace() {
  const isAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const analysisError = useSysmonStore((s) => s.analysisError);
  const progressMessage = useSysmonStore((s) => s.progressMessage);
  const events = useSysmonStore((s) => s.events);
  const activeTab = useSysmonStore((s) => s.activeTab);
  const setActiveTab = useSysmonStore((s) => s.setActiveTab);
  const sourcePath = useSysmonStore((s) => s.sourcePath);
  const beginAnalysis = useSysmonStore((s) => s.beginAnalysis);
  const setResults = useSysmonStore((s) => s.setResults);
  const failAnalysis = useSysmonStore((s) => s.failAnalysis);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
  const { commandState, refreshActiveSource } = useAppActions();
  const [localError, setLocalError] = useState<string | null>(null);

  const isWindows = currentPlatform === "windows";

  const runAnalysis = async (path: string, includeLive: boolean) => {
    setLocalError(null);
    const requestId = `sysmon-${Date.now()}`;
    beginAnalysis(path, requestId);
    try {
      const result = await analyzeSysmonLogs(path, requestId, {
        includeLiveEventLogs: includeLive,
      });
      setResults(result);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      failAnalysis(msg);
    }
  };

  const handleOpenFiles = async () => {
    setLocalError(null);
    try {
      const selected = await open({
        multiple: false,
        filters: EVTX_FILE_DIALOG_FILTERS,
      });
      if (!selected) return;
      const path = Array.isArray(selected) ? selected[0] : selected;
      await runAnalysis(path, false);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      setLocalError(msg);
    }
  };

  const handleThisComputer = async () => {
    setLocalError(null);
    try {
      await runAnalysis("live-event-log", true);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      setLocalError(msg);
    }
  };

  if (isAnalyzing) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
        }}
      >
        <Spinner size="medium" />
        <span style={{ color: tokens.colorNeutralForeground2, fontSize: "13px" }}>
          {progressMessage || "Analyzing Sysmon logs..."}
        </span>
      </div>
    );
  }

  if (analysisError) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          padding: "24px",
        }}
      >
        <span style={{ color: tokens.colorPaletteRedForeground1, fontSize: "13px" }}>
          {analysisError}
        </span>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "24px",
          padding: "40px",
        }}
      >
        <div
          style={{
            fontSize: "18px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
          }}
        >
          Sysmon Log Viewer
        </div>
        <div
          style={{
            fontSize: "13px",
            color: tokens.colorNeutralForeground3,
            textAlign: "center",
            maxWidth: "400px",
          }}
        >
          Open a Sysmon .evtx file to analyze events, or query the live
          Sysmon event log on this computer.
        </div>

        <div style={{ display: "flex", gap: "16px" }}>
          <Button appearance="primary" onClick={() => void handleOpenFiles()}>
            Open .evtx Files
          </Button>
          {isWindows && (
            <Button appearance="secondary" onClick={() => void handleThisComputer()}>
              This Computer
            </Button>
          )}
        </div>

        {(localError || analysisError) && (
          <div
            style={{
              fontSize: "12px",
              color: tokens.colorPaletteRedForeground1,
              maxWidth: "500px",
              textAlign: "center",
            }}
          >
            {localError || analysisError}
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <TabList
          selectedValue={activeTab}
          onTabSelect={(_, data) => setActiveTab(data.value as SysmonWorkspaceTab)}
          size="small"
          style={{ flex: 1 }}
        >
          <Tab value="dashboard">Dashboard</Tab>
          <Tab value="events">Events ({events.length.toLocaleString()})</Tab>
          <Tab value="summary">Summary</Tab>
          <Tab value="config">Configuration</Tab>
        </TabList>
        <Button
          size="small"
          appearance="subtle"
          disabled={!commandState.canRefresh || !sourcePath}
          onClick={() => {
            refreshActiveSource().catch((err) =>
              console.error("[sysmon] refresh failed", err)
            );
          }}
          title="Re-analyze current source"
        >
          Refresh
        </Button>
      </div>

      <div style={{ flex: 1, overflow: "hidden" }}>
        {activeTab === "dashboard" && <SysmonDashboardView />}
        {activeTab === "events" && <SysmonEventTable />}
        {activeTab === "summary" && <SysmonSummaryView />}
        {activeTab === "config" && <SysmonConfigView />}
      </div>
    </div>
  );
}
