import { tokens } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import { useDsregcmdStore } from "./dsregcmd-store";
import { selectTopFindings } from "./dsregcmd-formatters";
import { useAppActions } from "../../hooks/use-app-actions";
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

/** How many findings the summary sidebar shows. */
const TOP_FINDINGS_LIMIT = 8;

interface CaptureBundleProjection {
  destination: string;
  projectedFiles: number;
  unprojectedFiles: string[];
}

/**
 * Write a shareable copy of the capture bundle beside it.
 *
 * The staged bundle is the analyzer's input and stays as captured, so nothing
 * here changes what the analysis concluded. The copy is what can be archived and
 * sent: every artifact in it has the capture's identities scrubbed out. A file
 * the projection cannot read as text is copied unchanged and named, so whoever
 * hands it over knows what was not projected rather than assuming.
 */
/**
 * The projection in an IPC payload, or nothing when it is not one.
 *
 * `invoke<T>` types the call at compile time only, so the payload is checked
 * before it reaches the render pass: a missing `projectedFiles` would otherwise
 * surface as `undefined` in the message the engineer reads.
 */
function readProjection(payload: unknown): CaptureBundleProjection | null {
  if (typeof payload !== "object" || payload === null) {
    return null;
  }
  const candidate = payload as Partial<CaptureBundleProjection>;
  if (
    typeof candidate.destination !== "string" ||
    typeof candidate.projectedFiles !== "number" ||
    !Array.isArray(candidate.unprojectedFiles) ||
    !candidate.unprojectedFiles.every((file) => typeof file === "string")
  ) {
    return null;
  }
  return candidate as CaptureBundleProjection;
}

function ExportBundleButton({ bundleRoot }: { bundleRoot: string }) {
  const [state, setState] = useState<
    | { kind: "idle" }
    | { kind: "busy" }
    | { kind: "done"; projection: CaptureBundleProjection }
    | { kind: "failed"; message: string }
  >({ kind: "idle" });

  const run = async () => {
    setState({ kind: "busy" });
    try {
      const projection = readProjection(
        await invoke<unknown>("project_dsregcmd_capture_bundle", { bundleRoot }),
      );
      if (!projection) {
        setState({
          kind: "failed",
          message: "The export returned a result this build cannot read.",
        });
        return;
      }
      setState({ kind: "done", projection });
    } catch (error) {
      setState({
        kind: "failed",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  };

  return (
    <div style={{ marginTop: "6px" }}>
      <button
        type="button"
        onClick={run}
        disabled={state.kind === "busy"}
        style={{
          font: "inherit",
          color: tokens.colorNeutralForeground1,
          backgroundColor: tokens.colorNeutralBackground3,
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "4px",
          padding: "4px 8px",
          cursor: state.kind === "busy" ? "default" : "pointer",
        }}
      >
        {state.kind === "busy" ? "Projecting…" : "Export redacted copy"}
      </button>
      {state.kind === "done" && (
        <div style={{ marginTop: "4px", wordBreak: "break-word", color: tokens.colorNeutralForeground2 }}>
          Wrote {state.projection.projectedFiles} projected file
          {state.projection.projectedFiles === 1 ? "" : "s"} to {state.projection.destination}
          {state.projection.unprojectedFiles.length > 0 && (
            <> — not projected, copied as-is: {state.projection.unprojectedFiles.join(", ")}</>
          )}
        </div>
      )}
      {state.kind === "failed" && (
        <div style={{ marginTop: "4px", color: tokens.colorPaletteRedForeground1 }}>
          {state.message}
        </div>
      )}
    </div>
  );
}

export function DsregcmdSidebar() {
  const result = useDsregcmdStore((s) => s.result);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const { openSourceFileDialog, openSourceFolderDialog, pasteDsregcmdSource, captureDsregcmdSource } = useAppActions();

  const diagnostics = result?.diagnostics ?? [];
  // Ordered before it is limited, so the list can keep claiming
  // "highest-priority first" even when the rules emitted the Error below the cut.
  const topFindings = selectTopFindings(diagnostics, TOP_FINDINGS_LIMIT);
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
                <>
                <div style={{ marginTop: "6px", wordBreak: "break-word" }}><strong>Bundle root:</strong> {sourceContext.bundlePath}</div>
                <ExportBundleButton
                  key={sourceContext.bundlePath}
                  bundleRoot={sourceContext.bundlePath}
                />
              </>
              )}
            </div>

            <SectionHeader title="Top Findings" caption="Highest-priority diagnostics first" />
            {diagnostics.length === 0 ? (
              <EmptyState title="No diagnostics" body="The backend parser did not emit diagnostic findings for this capture." />
            ) : (
              topFindings.map((item) => (
                <div key={item.id} style={{ padding: "8px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, backgroundColor: item.severity === 'Error' ? tokens.colorPaletteRedBackground1 : item.severity === 'Warning' ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteBlueBackground2 }}>
                  <div style={{ fontSize: "inherit", textTransform: "uppercase", fontWeight: 700, color: item.severity === 'Error' ? tokens.colorPaletteRedForeground2 : item.severity === 'Warning' ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteBlueForeground2 }}>{item.severity}</div>
                  <div style={{ marginTop: "4px", fontSize: "inherit", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>{item.title}</div>
                  <div style={{ marginTop: "4px", fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.45 }}>{item.summary}</div>
                </div>
              ))
            )}
          </>
        )}
      </div>
    </>
  );
}
