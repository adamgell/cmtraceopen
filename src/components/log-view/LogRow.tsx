import type { LogEntry } from "../../types/log";
import { COLORS, getLogViewGridTemplateColumns } from "../../lib/constants";

interface LogRowProps {
  entry: LogEntry;
  rowDomId: string;
  isSelected: boolean;
  showDetails: boolean;
  highlightText: string;
  highlightCaseSensitive: boolean;
  onClick: (id: number) => void;
}

function getRowStyle(entry: LogEntry, isSelected: boolean) {
  if (isSelected) {
    return {
      backgroundColor: "#0078D7",
      color: "#FFFFFF",
    };
  }

  switch (entry.severity) {
    case "Error":
      return {
        backgroundColor: COLORS.error.background,
        color: COLORS.error.text,
      };
    case "Warning":
      return {
        backgroundColor: COLORS.warning.background,
        color: COLORS.warning.text,
      };
    default:
      return {
        backgroundColor: COLORS.info.background,
        color: COLORS.info.text,
      };
  }
}

function highlightMessage(
  text: string,
  highlight: string,
  caseSensitive: boolean
): React.ReactNode {
  if (!highlight) return text;

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
            backgroundColor: COLORS.highlightDefault,
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
  highlightText,
  highlightCaseSensitive,
  onClick,
}: LogRowProps) {
  const style = getRowStyle(entry, isSelected);
  const gridTemplateColumns = getLogViewGridTemplateColumns(showDetails);

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
        fontSize: "13px",
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
        lineHeight: "20px",
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
        {highlightMessage(entry.message, highlightText, highlightCaseSensitive)}
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
            {entry.timestampDisplay ?? ""}
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
