import { tokens, Spinner, Tab, TabList } from "@fluentui/react-components";
import { useSysmonStore, type SysmonWorkspaceTab } from "../../stores/sysmon-store";
import { SysmonEventTable } from "./SysmonEventTable";
import { SysmonSummaryView } from "./SysmonSummaryView";
import { SysmonConfigView } from "./SysmonConfigView";

export function SysmonWorkspace() {
  const isAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const analysisError = useSysmonStore((s) => s.analysisError);
  const progressMessage = useSysmonStore((s) => s.progressMessage);
  const events = useSysmonStore((s) => s.events);
  const activeTab = useSysmonStore((s) => s.activeTab);
  const setActiveTab = useSysmonStore((s) => s.setActiveTab);

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
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "8px",
          color: tokens.colorNeutralForeground3,
        }}
      >
        <span style={{ fontSize: "14px", fontWeight: 600 }}>Sysmon Log Viewer</span>
        <span style={{ fontSize: "12px" }}>
          Open a Sysmon .evtx file or folder to analyze events.
        </span>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <div
        style={{
          padding: "0 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <TabList
          selectedValue={activeTab}
          onTabSelect={(_, data) => setActiveTab(data.value as SysmonWorkspaceTab)}
          size="small"
        >
          <Tab value="events">Events ({events.length.toLocaleString()})</Tab>
          <Tab value="summary">Summary</Tab>
          <Tab value="config">Configuration</Tab>
        </TabList>
      </div>

      <div style={{ flex: 1, overflow: "hidden" }}>
        {activeTab === "events" && <SysmonEventTable />}
        {activeTab === "summary" && <SysmonSummaryView />}
        {activeTab === "config" && <SysmonConfigView />}
      </div>
    </div>
  );
}
