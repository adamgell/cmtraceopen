import type { ReactNode } from "react";
import {
  Badge,
  Button,
  Caption1,
  Subtitle2,
  tokens,
} from "@fluentui/react-components";
import { useDsregcmdStore } from "./dsregcmd-store";
import { useAppActions } from "../../components/layout/Toolbar";

// ---------------------------------------------------------------------------
// Inline helpers — mirrors components in FileSidebar.tsx
// ---------------------------------------------------------------------------

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

function SourceStatusNotice({
  kind,
  message,
  detail,
}: {
  kind: string;
  message: string;
  detail?: string;
}) {
  const colors =
    kind === "missing" || kind === "error"
      ? { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground2 }
      : kind === "empty" || kind === "awaiting-file-selection"
        ? { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 }
        : { border: tokens.colorPaletteBlueBorderActive, background: tokens.colorPaletteBlueBackground2, text: tokens.colorPaletteBlueForeground2 };

  return (
    <div
      role="status"
      style={{
        padding: "9px 12px",
        borderBottom: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        color: colors.text,
        fontSize: "inherit",
        lineHeight: 1.4,
      }}
    >
      <div style={{ fontWeight: 600 }}>{message}</div>
      {detail && <div style={{ marginTop: "2px", opacity: 0.9 }}>{detail}</div>}
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        padding: "18px 14px",
        color: tokens.colorNeutralForeground3,
        fontSize: "inherit",
        lineHeight: 1.5,
      }}
    >
      <Subtitle2 style={{ color: tokens.colorNeutralForeground1, marginBottom: "4px" }}>{title}</Subtitle2>
      <div>{body}</div>
    </div>
  );
}

function SectionHeader({ title, caption }: { title: string; caption?: string }) {
  return (
    <div
      style={{
        padding: "10px 12px 8px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <Caption1
        style={{
          fontWeight: 600,
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {title}
      </Caption1>
      {caption && (
        <Caption1
          style={{
            display: "block",
            marginTop: "2px",
            color: tokens.colorNeutralForeground3,
          }}
        >
          {caption}
        </Caption1>
      )}
    </div>
  );
}

function SidebarActionButton({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      disabled={disabled}
      onClick={onClick}
      size="small"
      appearance="secondary"
      style={{
        justifyContent: "flex-start",
        minWidth: 0,
        flex: 1,
      }}
    >
      {label}
    </Button>
  );
}

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
