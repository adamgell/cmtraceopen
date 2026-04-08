import { Spinner, tokens } from "@fluentui/react-components";
import { useSecureBootStore } from "./secureboot-store";
import { rescanSecureBoot } from "../../lib/commands";
import { StatusBanner } from "./StatusBanner";
import { StageProgressBar } from "./StageProgressBar";
import { FactGroupCards } from "./FactGroupCards";
import { DiagnosticsTab } from "./DiagnosticsTab";
import { TimelineTab } from "./TimelineTab";
import { RawDataTab } from "./RawDataTab";

function handleRescan() {
  const store = useSecureBootStore.getState();
  store.beginAnalysis("Rescanning device...");
  rescanSecureBoot()
    .then((r) => store.setResult(r))
    .catch((e) => store.failAnalysis(e));
}

interface TabButtonProps {
  label: string;
  count?: number;
  isActive: boolean;
  onClick: () => void;
}

function TabButton({ label, count, isActive, onClick }: TabButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        padding: "8px 14px",
        border: "none",
        borderBottom: isActive
          ? `2px solid ${tokens.colorBrandForeground1}`
          : "2px solid transparent",
        backgroundColor: "transparent",
        cursor: "pointer",
        fontSize: "13px",
        fontWeight: isActive ? 600 : 400,
        color: isActive
          ? tokens.colorBrandForeground1
          : tokens.colorNeutralForeground2,
        transition: "color 0.15s, border-color 0.15s",
        whiteSpace: "nowrap",
      }}
    >
      {label}
      {count !== undefined && count > 0 ? ` (${count})` : ""}
    </button>
  );
}

export function SecureBootWorkspace() {
  const result = useSecureBootStore((s) => s.result);
  const analysisState = useSecureBootStore((s) => s.analysisState);
  const isAnalyzing = useSecureBootStore((s) => s.isAnalyzing);
  const activeTab = useSecureBootStore((s) => s.activeTab);
  const setActiveTab = useSecureBootStore((s) => s.setActiveTab);


  // Idle state (no result, not analyzing, no error)
  if (analysisState.phase === "idle") {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
          padding: "40px",
          textAlign: "center",
        }}
      >
        <div
          style={{
            fontSize: "18px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
          }}
        >
          Secure Boot Certificates
        </div>
        <div
          style={{
            fontSize: "13px",
            color: tokens.colorNeutralForeground3,
            maxWidth: "420px",
            lineHeight: 1.6,
          }}
        >
          {analysisState.message}
        </div>
      </div>
    );
  }

  // Analyzing state
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
          {analysisState.message}
        </span>
      </div>
    );
  }

  // Error state
  if (analysisState.phase === "error") {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
          padding: "40px",
          textAlign: "center",
        }}
      >
        <div
          style={{
            fontSize: "14px",
            fontWeight: 600,
            color: tokens.colorPaletteRedForeground2,
          }}
        >
          {analysisState.message}
        </div>
        {analysisState.detail && (
          <div
            style={{
              fontSize: "12px",
              color: tokens.colorNeutralForeground3,
              maxWidth: "500px",
              lineHeight: 1.5,
            }}
          >
            {analysisState.detail}
          </div>
        )}
      </div>
    );
  }

  // Results state
  if (!result) {
    return null;
  }

  const errorCount = result.diagnostics.filter((d) => d.severity === "error").length;
  const warnCount = result.diagnostics.filter((d) => d.severity === "warning").length;
  const infoCount = result.diagnostics.filter((d) => d.severity === "info").length;
  const diagnosticsCount = errorCount + warnCount + infoCount;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        overflow: "hidden",
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      {/* Scrollable top content */}
      <div
        style={{
          flexShrink: 0,
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground1,
        }}
      >
        <StatusBanner
          stage={result.stage}
          onRescan={handleRescan}
          isScanning={isAnalyzing}
        />
        <StageProgressBar currentStage={result.stage} />
        <FactGroupCards scanState={result.scanState} dataSource={result.dataSource} />
      </div>

      {/* Tab strip */}
      <div
        style={{
          flexShrink: 0,
          display: "flex",
          gap: 0,
          paddingLeft: "4px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <TabButton
          label="Diagnostics"
          count={diagnosticsCount}
          isActive={activeTab === "diagnostics"}
          onClick={() => setActiveTab("diagnostics")}
        />
        <TabButton
          label="Timeline"
          count={result.timeline.length}
          isActive={activeTab === "timeline"}
          onClick={() => setActiveTab("timeline")}
        />
        <TabButton
          label="Raw Data"
          isActive={activeTab === "raw"}
          onClick={() => setActiveTab("raw")}
        />
      </div>

      {/* Tab content area — scrollable */}
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "16px",
        }}
      >
        {activeTab === "diagnostics" && (
          <DiagnosticsTab findings={result.diagnostics} />
        )}
        {activeTab === "timeline" && (
          <TimelineTab timeline={result.timeline} />
        )}
        {activeTab === "raw" && (
          <RawDataTab rawDump={result.scanState.rawRegistryDump} />
        )}
      </div>
    </div>
  );
}
