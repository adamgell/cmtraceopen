import { tokens } from "@fluentui/react-components";
import { useDsregcmdStore } from "./dsregcmd-store";
import { useAppActions } from "../../components/layout/Toolbar";
import {
  EmptyState,
  SectionHeader,
  SidebarActionButton,
  SourceStatusNotice,
  SourceSummaryCard,
} from "../../components/common/sidebar-primitives";

// ---------------------------------------------------------------------------
// DsregcmdSidebar
// ---------------------------------------------------------------------------

export function DsregcmdSidebar() {
  const result = useDsregcmdStore((s) => s.result);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const { openSourceFileDialog, openSourceFolderDialog, pasteDsregcmdSource, captureDsregcmdSource } = useAppActions();

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter((item) => item.severity === "Error").length;
  const warningCount = diagnostics.filter((item) => item.severity === "Warning").length;
  const infoCount = diagnostics.filter((item) => item.severity === "Info").length;

  return (
    <>
      <SourceSummaryCard
        badge="dsregcmd"
        title={sourceContext.displayLabel}
        subtitle={sourceContext.resolvedPath ?? sourceContext.requestedPath ?? "Open a dsregcmd source to begin."}
        body={
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
            <div>{analysisState.message}</div>
            <div style={{ marginTop: "4px" }}>Lines: {sourceContext.rawLineCount}</div>
            <div style={{ marginTop: "4px" }}>Chars: {sourceContext.rawCharCount}</div>
            {result && <div style={{ marginTop: "4px" }}>Join type: {result.derived.joinTypeLabel}</div>}
          </div>
        }
      />

      {(analysisState.phase === "analyzing" || analysisState.phase === "error") && (
        <SourceStatusNotice
          kind={analysisState.phase === "error" ? "error" : "info"}
          message={analysisState.message}
          detail={analysisState.detail ?? undefined}
        />
      )}

      <div style={{ padding: "8px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, backgroundColor: tokens.colorNeutralBackground2, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
        <SidebarActionButton label="Capture" disabled={isAnalyzing} onClick={() => void captureDsregcmdSource().catch((err) => console.error("[dsregcmd-sidebar] capture failed", err))} />
        <SidebarActionButton label="Paste" disabled={isAnalyzing} onClick={() => void pasteDsregcmdSource().catch((err) => console.error("[dsregcmd-sidebar] paste failed", err))} />
        <SidebarActionButton label="Open file" disabled={isAnalyzing} onClick={() => void openSourceFileDialog().catch((err) => console.error("[dsregcmd-sidebar] open file failed", err))} />
        <SidebarActionButton label="Open folder" disabled={isAnalyzing} onClick={() => void openSourceFolderDialog().catch((err) => console.error("[dsregcmd-sidebar] open folder failed", err))} />
      </div>

      <div style={{ flex: 1, overflow: "auto", backgroundColor: tokens.colorNeutralBackground2 }}>
        {!result && !isAnalyzing && analysisState.phase !== "error" && (
          <EmptyState
            title="No dsregcmd analysis yet"
            body="Capture live output with registry evidence, paste clipboard text, open a text file, or select a bundle root, evidence folder, or command-output folder."
          />
        )}

        {result && (
          <>
            <SectionHeader title="Triage Summary" caption="Fast sidebar readout of the current dsregcmd result" />
            <div style={{ padding: "12px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
              <div><strong>Join type:</strong> {result.derived.joinTypeLabel}</div>
              <div style={{ marginTop: "6px" }}><strong>PRT present:</strong> {result.derived.azureAdPrtPresent === null ? 'Unknown' : result.derived.azureAdPrtPresent ? 'Yes' : 'No'}</div>
              <div style={{ marginTop: "6px" }}><strong>MDM enrolled:</strong> {result.derived.mdmEnrolled === null ? 'Unknown' : result.derived.mdmEnrolled ? 'Yes' : 'No'}</div>
              <div style={{ marginTop: "6px" }}><strong>Issues:</strong> {errorCount} errors • {warningCount} warnings • {infoCount} info</div>
              {sourceContext.evidenceFilePath && (
                <div style={{ marginTop: "6px", wordBreak: "break-word" }}><strong>Evidence file:</strong> {sourceContext.evidenceFilePath}</div>
              )}
              {sourceContext.bundlePath && (
                <div style={{ marginTop: "6px", wordBreak: "break-word" }}><strong>Bundle root:</strong> {sourceContext.bundlePath}</div>
              )}
            </div>

            <SectionHeader title="Top Findings" caption="Highest-priority diagnostics first" />
            {diagnostics.length === 0 ? (
              <EmptyState title="No diagnostics" body="The backend parser did not emit diagnostic findings for this capture." />
            ) : (
              diagnostics.slice(0, 8).map((item) => (
                <div key={item.id} style={{ padding: "8px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, backgroundColor: item.severity === 'Error' ? tokens.colorPaletteRedBackground1 : item.severity === 'Warning' ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteBlueBackground2 }}>
                  <div style={{ fontSize: "inherit", textTransform: "uppercase", fontWeight: 700, color: item.severity === 'Error' ? tokens.colorPaletteRedForeground2 : item.severity === 'Warning' ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteBlueForeground2 }}>{item.severity}</div>
                  <div style={{ marginTop: "4px", fontSize: "inherit", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>{item.title}</div>
                  <div style={{ marginTop: "3px", fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.45 }}>{item.summary}</div>
                </div>
              ))
            )}
          </>
        )}
      </div>
    </>
  );
}
