import { tokens } from "@fluentui/react-components";
import { getBaseName } from "../../lib/file-paths";
import { useSysmonStore } from "./sysmon-store";
import { SourceSummaryCard } from "../../components/common/sidebar-primitives";

export function SysmonSidebar() {
  const summary = useSysmonStore((s) => s.summary);
  const sourcePath = useSysmonStore((s) => s.sourcePath);
  const isAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const analysisError = useSysmonStore((s) => s.analysisError);
  const progressMessage = useSysmonStore((s) => s.progressMessage);

  const title = sourcePath ? getBaseName(sourcePath) : "Sysmon";
  const subtitle = sourcePath ?? "Open a folder containing Sysmon EVTX files to begin.";

  return (
    <>
      <SourceSummaryCard
        badge="sysmon"
        title={title}
        subtitle={subtitle}
        body={
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
            {isAnalyzing && <div>{progressMessage ?? "Analyzing..."}</div>}
            {analysisError && <div style={{ color: tokens.colorPaletteRedForeground2 }}>{analysisError}</div>}
            {summary && (
              <>
                <div>Events: {summary.totalEvents.toLocaleString()}</div>
                <div>Processes: {summary.uniqueProcesses.toLocaleString()}</div>
                <div>Files: {summary.sourceFiles.length}</div>
                {summary.parseErrors > 0 && (
                  <div style={{ color: tokens.colorPaletteRedForeground2 }}>
                    Parse errors: {summary.parseErrors}
                  </div>
                )}
              </>
            )}
            {!isAnalyzing && !analysisError && !summary && <div>Ready</div>}
          </div>
        }
      />
    </>
  );
}
