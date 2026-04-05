import { tokens, Button } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import {
  useDeploymentStore,
  type DeploymentLogFile,
} from "./deployment-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { loadPathAsLogSource } from "../../lib/log-source";

export function DeploymentErrorCard({
  file,
  index,
}: {
  file: DeploymentLogFile;
  index: number;
}) {
  const expandedErrorIndex = useDeploymentStore((s) => s.expandedErrorIndex);
  const toggleErrorExpanded = useDeploymentStore((s) => s.toggleErrorExpanded);
  const isExpanded = expandedErrorIndex === index;

  const handleOpenInLogViewer = async (lineNumber: number) => {
    // Set the pending scroll target before loading so it's ready when entries arrive
    useLogStore.getState().setPendingScrollTarget({
      filePath: file.path,
      lineNumber,
    });
    // Switch to log view
    useUiStore.getState().setActiveView("log");
    // Load the file
    try {
      await loadPathAsLogSource(file.path);
    } catch (err) {
      console.error("[deployment] failed to open file in log viewer", err);
    }
  };

  // Find the first error line to determine which line to scroll to
  const firstErrorLine = file.errorLines.find((l) => l.severity === "Error")
    ?? file.errorLines[0];

  return (
    <div
      style={{
        border: `1px solid ${tokens.colorPaletteRedBorder2}`,
        borderRadius: "4px",
        padding: "10px 12px",
        marginBottom: "8px",
        backgroundColor: tokens.colorNeutralBackground1,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div>
          <div style={{ fontSize: "13px", fontWeight: 600 }}>
            {file.appName ?? file.fileName}
          </div>
          <div
            style={{
              fontSize: "12px",
              color: tokens.colorNeutralForeground3,
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            {file.deployType && (
              <span
                style={{
                  padding: "1px 6px",
                  borderRadius: "3px",
                  backgroundColor: tokens.colorNeutralBackground3,
                  fontSize: "11px",
                  fontWeight: 600,
                }}
              >
                {file.deployType}
              </span>
            )}
            <span>
              {file.appName ? file.fileName : ""}{file.appVersion ? ` v${file.appVersion}` : ""}{" "}
              {file.format} {file.exitCode != null && `· exit ${file.exitCode}`}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", gap: "4px" }}>
          <Button
            size="small"
            appearance="subtle"
            onClick={() =>
              handleOpenInLogViewer(firstErrorLine?.lineNumber ?? 1)
            }
          >
            Open in Log Viewer
          </Button>
          {file.errorLines.length > 0 && (
            <Button
              size="small"
              appearance="subtle"
              onClick={() => toggleErrorExpanded(index)}
            >
              {isExpanded ? "Collapse" : `${file.errorLines.length} errors`}
            </Button>
          )}
        </div>
      </div>

      {file.errorSummary && (
        <div
          style={{
            fontSize: "12px",
            color: tokens.colorPaletteRedForeground1,
            marginTop: "6px",
          }}
        >
          {file.errorSummary}
        </div>
      )}

      {isExpanded && file.errorLines.length > 0 && (
        <div
          style={{
            marginTop: "8px",
            padding: "8px",
            backgroundColor: tokens.colorNeutralBackground3,
            borderRadius: "3px",
            fontSize: "12px",
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            maxHeight: "200px",
            overflow: "auto",
          }}
        >
          {file.errorLines.map((line, i) => (
            <div
              key={i}
              style={{
                padding: "2px 0",
                display: "flex",
                alignItems: "baseline",
                gap: "4px",
                color:
                  line.severity === "Error"
                    ? tokens.colorPaletteRedForeground1
                    : tokens.colorPaletteYellowForeground1,
              }}
            >
              <button
                onClick={() => handleOpenInLogViewer(line.lineNumber)}
                title={`Open at line ${line.lineNumber}`}
                style={{
                  background: "none",
                  border: "none",
                  padding: 0,
                  cursor: "pointer",
                  color: tokens.colorNeutralForeground3,
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  fontSize: "inherit",
                  textDecoration: "underline",
                }}
              >
                L{line.lineNumber}
              </button>
              <span>{line.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
