import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { useIntuneStore } from "./intune-store";
import { useAppActions } from "../../components/layout/Toolbar";
import { buildSourceFamilySummary } from "./intune-dashboard-utils";

export function IntuneDashboardHeader() {
  const sourceContext = useIntuneStore((s) => s.sourceContext);
  const analysisState = useIntuneStore((s) => s.analysisState);
  const isAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const evidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const diagnosticsCoverage = useIntuneStore((s) => s.diagnosticsCoverage);
  const { commandState, openSourceFileDialog, openSourceFolderDialog } = useAppActions();

  const sourceFiles = sourceContext.includedFiles;
  const sourceLabel = analysisState.requestedPath ?? sourceContext.analyzedPath;
  const sourceFamilies = useMemo(
    () => buildSourceFamilySummary(diagnosticsCoverage.files),
    [diagnosticsCoverage.files]
  );
  const emptySourceFamilies = useMemo(
    () => sourceFamilies.filter((family) => family.contributingFileCount === 0),
    [sourceFamilies]
  );
  const sourceStatusTone =
    analysisState.phase === "error"
      ? tokens.colorPaletteRedForeground1
      : analysisState.phase === "empty"
        ? tokens.colorPaletteMarigoldForeground1
        : analysisState.phase === "analyzing"
          ? tokens.colorBrandForeground1
          : tokens.colorNeutralForeground3;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "6px 12px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        flexShrink: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
            fontFamily: LOG_UI_FONT_FAMILY,
          }}
        >
          Intune Diagnostics Workspace
        </span>
        <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2 }} />
        <ActionButton
          onClick={() => {
            void openSourceFileDialog();
          }}
          disabled={!commandState.canOpenSources}
          label={isAnalyzing ? "Analyzing..." : "Open IME Log File..."}
        />
        <ActionButton
          onClick={() => {
            void openSourceFolderDialog();
          }}
          disabled={!commandState.canOpenSources}
          label={isAnalyzing ? "Analyzing..." : "Open IME Or Evidence Folder..."}
        />

        {(analysisState.phase === "analyzing" || analysisState.phase === "error" || analysisState.phase === "empty") && (
          <span style={{ fontSize: "12px", color: sourceStatusTone, fontWeight: 500, marginLeft: "4px" }}>
            {analysisState.message}
          </span>
        )}
      </div>

      {sourceLabel && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-end",
            minWidth: 0,
            maxWidth: "400px",
          }}
        >
          <span
            style={{
              fontSize: "11px",
              color: tokens.colorNeutralForeground3,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              maxWidth: "100%",
              fontWeight: 500,
            }}
            title={sourceLabel}
          >
            {sourceLabel}
          </span>
          {(analysisState.detail || sourceFiles.length > 0) && (
            <span style={{ fontSize: "10px", color: sourceStatusTone }}>
              {analysisState.phase === "error"
                ? analysisState.detail
                : analysisState.phase === "empty"
                  ? analysisState.detail
                  : sourceFiles.length > 0
                    ? `${sourceFiles.length} included files`
                    : analysisState.detail}
            </span>
          )}
          {evidenceBundle && (
            <span
              style={{
                marginTop: "4px",
                fontSize: "10px",
                color: emptySourceFamilies.length > 0 ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteBlueForeground2,
                fontWeight: 600,
              }}
            >
              Bundle {evidenceBundle.bundleLabel ?? evidenceBundle.bundleId ?? "attached"}
              {sourceFamilies.length > 0 ? ` • ${sourceFamilies.length} file family${sourceFamilies.length === 1 ? "" : "ies"}` : ""}
              {emptySourceFamilies.length > 0 ? ` • ${emptySourceFamilies.length} quiet family${emptySourceFamilies.length === 1 ? "" : "ies"}` : ""}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function ActionButton({
  onClick,
  disabled,
  label,
}: {
  onClick: () => void;
  disabled: boolean;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        fontSize: "12px",
        padding: "4px 10px",
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        borderRadius: "4px",
        backgroundColor: disabled ? tokens.colorNeutralBackground3 : tokens.colorNeutralCardBackground,
        color: disabled ? tokens.colorNeutralForeground3 : tokens.colorNeutralForeground1,
        cursor: disabled ? "not-allowed" : "pointer",
      }}
    >
      {label}
    </button>
  );
}
