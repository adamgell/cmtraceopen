import type { ReactNode } from "react";
import { Badge, Caption1, Subtitle2, tokens } from "@fluentui/react-components";
import { useSysmonStore } from "./sysmon-store";

// Minimal inline utility — mirrors the one imported from log-store in FileSidebar.tsx
function getBaseName(path: string | null | undefined): string {
  if (!path) return "";
  return path.split(/[\\/]/).pop() ?? "";
}

function SourceSummaryCard({
  badge,
  title,
  subtitle,
  body,
}: {
  badge: string;
  title: string;
  subtitle: string;
  body: ReactNode;
}) {
  return (
    <div
      style={{
        padding: "12px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <Badge
        appearance="outline"
        color="brand"
        style={{
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {badge}
      </Badge>
      <Subtitle2
        title={title}
        style={{
          display: "block",
          marginTop: "8px",
          color: tokens.colorNeutralForeground1,
          fontSize: "inherit",
          fontWeight: 600,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {title}
      </Subtitle2>
      <Caption1
        title={subtitle}
        style={{
          display: "block",
          marginTop: "4px",
          color: tokens.colorNeutralForeground3,
          fontSize: "0.85em",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {subtitle}
      </Caption1>
      <div style={{ marginTop: "10px" }}>{body}</div>
    </div>
  );
}

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
