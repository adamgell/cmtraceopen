import { tokens } from "@fluentui/react-components";
import {
  getParserSelectionDisplay,
  useLogStore,
} from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";
import {
  getLogDetailsLineHeight,
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";

export function InfoPane() {
  const entries = useLogStore((state) => state.entries);
  const selectedId = useLogStore((state) => state.selectedId);
  const parserSelection = useLogStore((state) => state.parserSelection);
  const logDetailsFontSize = useUiStore((state) => state.logDetailsFontSize);

  const parserDisplay = getParserSelectionDisplay(parserSelection);
  const detailLineHeight = getLogDetailsLineHeight(logDetailsFontSize);

  const selectedEntry =
    selectedId !== null
      ? entries.find((entry) => entry.id === selectedId) ?? null
      : null;
  const selectedTimestamp = selectedEntry
    ? formatLogEntryTimestamp(selectedEntry)
    : null;

  if (!selectedEntry) {
    return (
      <div
        style={{
          padding: "8px",
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: `${logDetailsFontSize}px`,
          lineHeight: `${detailLineHeight}px`,
          color: tokens.colorNeutralForeground3,
          height: "100%",
          overflow: "auto",
          backgroundColor: tokens.colorNeutralBackground2,
          borderTop: `2px solid ${tokens.colorNeutralStroke2}`,
        }}
      >
        {entries.length === 0
          ? "No log entries loaded"
          : "Select a log entry to view details (Arrow keys, Page Up/Down, Home/End supported when list is focused)"}
      </div>
    );
  }

  return (
    <div
      style={{
        padding: "8px",
        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
        fontSize: `${logDetailsFontSize}px`,
        lineHeight: `${detailLineHeight}px`,
        height: "100%",
        overflow: "auto",
        backgroundColor: tokens.colorNeutralBackground2,
        borderTop: `2px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div style={{ marginBottom: "8px", color: tokens.colorNeutralForeground2 }}>
        {`Line ${selectedEntry.lineNumber} | ${selectedEntry.severity}${selectedEntry.component ? ` | ${selectedEntry.component}` : ""
          }${selectedTimestamp ? ` | ${selectedTimestamp}` : ""}`}
      </div>
      <div style={{ marginBottom: "8px", color: tokens.colorNeutralForeground3 }}>
        {`File ${selectedEntry.filePath}`}
      </div>
      {parserDisplay ? (
        <div
          style={{
            marginBottom: "8px",
            color: tokens.colorNeutralForeground3,
            fontSize: `${Math.max(logDetailsFontSize - 1, 11)}px`,
          }}
        >
          {[
            `Parser ${parserDisplay.parserLabel}`,
            parserDisplay.provenanceLabel,
            parserDisplay.qualityLabel,
            parserDisplay.implementationLabel,
            parserDisplay.framingLabel,
            parserDisplay.dateOrderLabel,
          ]
            .filter((part): part is string => Boolean(part))
            .join(" | ")}
        </div>
      ) : null}
      <div
        style={{
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          color: tokens.colorNeutralForeground1,
        }}
      >
        {selectedEntry.message}
      </div>
    </div>
  );
}
