import type { LogEntry } from "../../types/log";
import {
  getLogSeverityPalette,
  getLogViewGridTemplateColumns,
  type LogSeverityPaletteMode,
} from "../../lib/constants";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";

interface LogRowProps {
  entry: LogEntry;
  rowDomId: string;
  isSelected: boolean;
  showDetails: boolean;
  listFontSize: number;
  rowLineHeight: number;
  severityPaletteMode: LogSeverityPaletteMode;
  highlightText: string;
  highlightCaseSensitive: boolean;
  onClick: (id: number) => void;
}

function getRowStyle(
  entry: LogEntry,
  isSelected: boolean,
  severityPaletteMode: LogSeverityPaletteMode
) {
  const palette = getLogSeverityPalette(severityPaletteMode);

  if (isSelected) {
    return {
      backgroundColor: "#0078D7",
      color: "#FFFFFF",
    };
  }

  switch (entry.severity) {
    case "Error":
      return {
        backgroundColor: palette.error.background,
        color: palette.error.text,
      };
    case "Warning":
      return {
        backgroundColor: palette.warning.background,
        color: palette.warning.text,
      };
    default:
      return {
        backgroundColor: palette.info.background,
        color: palette.info.text,
      };
  }
}

function highlightMessage(
  text: string,
  highlight: string,
  caseSensitive: boolean,
  severityPaletteMode: LogSeverityPaletteMode
): React.ReactNode {
  if (!highlight) return text;

  const palette = getLogSeverityPalette(severityPaletteMode);
  const flags = caseSensitive ? "g" : "gi";
  const escaped = highlight.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`(${escaped})`, flags);
  const parts = text.split(regex);

  return parts.map((part, i) => {
    const isMatch = caseSensitive
      ? part === highlight
      : part.toLowerCase() === highlight.toLowerCase();

    if (isMatch) {
      return (
        <mark
          key={i}
          style={{
            backgroundColor: palette.highlightDefault,
            color: "#000",
          }}
        >
          {part}
        </mark>
      );
    }

    return part;
  });
}

export function LogRow({
  entry,
  rowDomId,
  isSelected,
  showDetails,
  listFontSize,
  rowLineHeight,
  severityPaletteMode,
  highlightText,
  highlightCaseSensitive,
  onClick,
}: LogRowProps) {
  const style = getRowStyle(entry, isSelected, severityPaletteMode);
  const gridTemplateColumns = getLogViewGridTemplateColumns(showDetails);
  const timestampLabel = formatLogEntryTimestamp(entry);

  return (
    <div
      id={rowDomId}
      role="option"
      aria-selected={isSelected}
      data-selected={isSelected}
      className="log-row"
      style={{
        ...style,
        display: "grid",
        gridTemplateColumns,
        cursor: "pointer",
        borderBottom: "1px solid #e0e0e0",
        fontSize: `${listFontSize}px`,
        fontFamily: LOG_UI_FONT_FAMILY,
        lineHeight: `${rowLineHeight}px`,
        whiteSpace: "nowrap",
        transition: "filter 80ms linear",
        boxShadow: `inset 3px 0 0 ${isSelected ? "#FFFFFF" : "transparent"}`,
      }}
      onClick={() => onClick(entry.id)}
    >
      <div
        className="col-message"
        style={{
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
          padding: "1px 4px",
        }}
      >
        {highlightMessage(
          entry.message,
          highlightText,
          highlightCaseSensitive,
          severityPaletteMode
        )}
      </div>
      {showDetails && (
        <>
          <div
            className="col-component"
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              padding: "1px 4px",
              borderLeft: "1px solid #d0d0d0",
            }}
          >
            {entry.component ?? ""}
          </div>
          <div
            className="col-datetime"
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              padding: "1px 4px",
              borderLeft: "1px solid #d0d0d0",
            }}
          >
            {timestampLabel ?? ""}
          </div>
          <div
            className="col-thread"
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              padding: "1px 4px",
              borderLeft: "1px solid #d0d0d0",
            }}
          >
            {entry.threadDisplay ?? ""}
          </div>
        </>
      )}
    </div>
  );
}
