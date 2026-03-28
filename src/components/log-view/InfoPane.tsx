import { Badge, Button, tokens } from "@fluentui/react-components";
import { DismissRegular } from "@fluentui/react-icons";
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
import { getCategoryColor } from "../../lib/error-categories";

export function InfoPane() {
  const entries = useLogStore((state) => state.entries);
  const selectedId = useLogStore((state) => state.selectedId);
  const parserSelection = useLogStore((state) => state.parserSelection);
  const logDetailsFontSize = useUiStore((state) => state.logDetailsFontSize);
  const focusedErrorCode = useUiStore((state) => state.focusedErrorCode);
  const setFocusedErrorCode = useUiStore((state) => state.setFocusedErrorCode);
  const setShowErrorLookupDialog = useUiStore(
    (state) => state.setShowErrorLookupDialog
  );

  const parserDisplay = getParserSelectionDisplay(parserSelection);
  const detailLineHeight = getLogDetailsLineHeight(logDetailsFontSize);

  const selectedEntry =
    selectedId !== null
      ? entries.find((entry) => entry.id === selectedId) ?? null
      : null;
  const selectedTimestamp = selectedEntry
    ? formatLogEntryTimestamp(selectedEntry)
    : null;

  const errorCodeBanner = focusedErrorCode ? (
    <div
      style={{
        padding: "6px 8px",
        marginBottom: "8px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderRadius: "4px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        display: "flex",
        alignItems: "center",
        gap: "8px",
        flexWrap: "wrap",
      }}
    >
      <Badge
        appearance="filled"
        color={getCategoryColor(focusedErrorCode.category)}
        style={{ flexShrink: 0 }}
      >
        {focusedErrorCode.category || "Unknown"}
      </Badge>
      <span
        style={{
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontWeight: 600,
          fontSize: `${logDetailsFontSize}px`,
        }}
      >
        {focusedErrorCode.codeHex}
      </span>
      <span
        style={{
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: `${Math.max(logDetailsFontSize - 1, 11)}px`,
          color: tokens.colorNeutralForeground3,
        }}
      >
        ({focusedErrorCode.codeDecimal})
      </span>
      <span style={{ flex: 1, fontSize: `${logDetailsFontSize}px` }}>
        {focusedErrorCode.description}
      </span>
      <Button
        size="small"
        appearance="subtle"
        onClick={() => {
          setShowErrorLookupDialog(true);
          setFocusedErrorCode(null);
        }}
      >
        Open Lookup
      </Button>
      <Button
        size="small"
        appearance="subtle"
        icon={<DismissRegular />}
        onClick={() => setFocusedErrorCode(null)}
        title="Dismiss"
        aria-label="Dismiss error details"
      />
    </div>
  ) : null;

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
        {errorCodeBanner}
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
      {errorCodeBanner}
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
      {(selectedEntry.resultCode || selectedEntry.gleCode || selectedEntry.setupPhase || selectedEntry.operationName) && (
        <div
          style={{
            marginBottom: "8px",
            color: tokens.colorNeutralForeground3,
            fontSize: `${Math.max(logDetailsFontSize - 1, 11)}px`,
          }}
        >
          {[
            selectedEntry.resultCode ? `Result ${selectedEntry.resultCode}` : null,
            selectedEntry.gleCode ? `GLE ${selectedEntry.gleCode}` : null,
            selectedEntry.setupPhase ? `Phase ${selectedEntry.setupPhase}` : null,
            selectedEntry.operationName ? `Op: ${selectedEntry.operationName}` : null,
          ]
            .filter((part): part is string => Boolean(part))
            .join(" | ")}
        </div>
      )}
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
