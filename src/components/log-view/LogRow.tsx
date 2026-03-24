import { tokens } from "@fluentui/react-components";
import type { LogEntry, ErrorCodeSpan } from "../../types/log";
import type { LogSeverityPalette } from "../../lib/constants";
import type { ColumnDefinition } from "../../lib/column-config";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";

interface LogRowProps {
  entry: LogEntry;
  rowDomId: string;
  isSelected: boolean;
  visibleColumns: ColumnDefinition[];
  gridTemplateColumns: string;
  listFontSize: number;
  rowLineHeight: number;
  severityPalette: LogSeverityPalette;
  highlightText: string;
  highlightCaseSensitive: boolean;
  onClick: (id: number) => void;
  onErrorCodeClick?: (span: ErrorCodeSpan) => void;
}

function getRowStyle(
  entry: LogEntry,
  isSelected: boolean,
  palette: LogSeverityPalette
) {

  if (isSelected) {
    return {
      backgroundColor: tokens.colorBrandBackground,
      color: tokens.colorNeutralForegroundOnBrand,
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
  palette: LogSeverityPalette
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
            backgroundColor: palette.highlightDefault,
            color: tokens.colorNeutralForeground1,
          }}
        >
          {part}
        </mark>
      );
    }

    return part;
  });
}

function renderMessageWithSpans(
  text: string,
  spans: ErrorCodeSpan[] | undefined,
  highlight: string,
  caseSensitive: boolean,
  palette: LogSeverityPalette,
  isSelected: boolean,
  onSpanClick?: (span: ErrorCodeSpan) => void
): React.ReactNode {
  if (!spans || spans.length === 0) {
    return highlightMessage(text, highlight, caseSensitive, palette);
  }

  const segments: React.ReactNode[] = [];
  let lastEnd = 0;

  for (let i = 0; i < spans.length; i++) {
    const span = spans[i];

    // Defensive: skip spans that overlap with previous
    if (span.start < lastEnd) continue;

    // Plain text before this span
    if (span.start > lastEnd) {
      const plainText = text.slice(lastEnd, span.start);
      segments.push(
        <span key={`plain-${i}`}>
          {highlightMessage(plainText, highlight, caseSensitive, palette)}
        </span>
      );
    }

    // The error code span itself
    const codeText = text.slice(span.start, span.end);
    segments.push(
      <span
        key={`code-${span.start}`}
        title={`${span.codeHex} — ${span.description} [${span.category}]`}
        onClick={
          onSpanClick
            ? (e) => {
                e.stopPropagation();
                onSpanClick(span);
              }
            : undefined
        }
        onKeyDown={
          onSpanClick
            ? (e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  e.stopPropagation();
                  onSpanClick(span);
                }
              }
            : undefined
        }
        role={onSpanClick ? "button" : undefined}
        tabIndex={onSpanClick ? 0 : undefined}
        style={{
          textDecoration: "underline dotted",
          textDecorationColor: isSelected
            ? tokens.colorNeutralForegroundOnBrand
            : tokens.colorPaletteRedBorder2,
          textUnderlineOffset: "2px",
          cursor: onSpanClick ? "pointer" : "inherit",
          borderRadius: "2px",
        }}
      >
        {codeText}
      </span>
    );

    lastEnd = span.end;
  }

  // Remaining text after last span
  if (lastEnd < text.length) {
    segments.push(
      <span key="tail">
        {highlightMessage(
          text.slice(lastEnd),
          highlight,
          caseSensitive,
          palette
        )}
      </span>
    );
  }

  return <>{segments}</>;
}

const detailCellStyle: React.CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  padding: "1px 4px",
  borderLeft: `1px solid ${tokens.colorNeutralStroke1}`,
};

export function LogRow({
  entry,
  rowDomId,
  isSelected,
  visibleColumns,
  gridTemplateColumns,
  listFontSize,
  rowLineHeight,
  severityPalette,
  highlightText,
  highlightCaseSensitive,
  onClick,
  onErrorCodeClick,
}: LogRowProps) {
  const style = getRowStyle(entry, isSelected, severityPalette);

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
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        fontSize: `${listFontSize}px`,
        fontFamily: LOG_UI_FONT_FAMILY,
        lineHeight: `${rowLineHeight}px`,
        whiteSpace: "nowrap",
        transition: "filter 80ms linear",
        boxShadow: `inset 3px 0 0 ${isSelected ? tokens.colorNeutralForegroundOnBrand : "transparent"}`,
      }}
      onClick={() => onClick(entry.id)}
    >
      {visibleColumns.map((col) => {
        // Message column: rich rendering with highlights and error code spans
        if (col.id === "message") {
          return (
            <div
              key="message"
              className="col-message"
              style={{
                minWidth: 0,
                overflow: "hidden",
                textOverflow: "ellipsis",
                padding: "1px 4px",
              }}
            >
              {renderMessageWithSpans(
                entry.message,
                entry.errorCodeSpans,
                highlightText,
                highlightCaseSensitive,
                severityPalette,
                isSelected,
                onErrorCodeClick
              )}
            </div>
          );
        }

        // DateTime column: use dedicated formatter
        if (col.id === "dateTime") {
          return (
            <div key="dateTime" style={detailCellStyle}>
              {formatLogEntryTimestamp(entry) ?? ""}
            </div>
          );
        }

        // All other columns: use the accessor
        const value = col.accessor(entry);
        return (
          <div key={col.id} style={detailCellStyle}>
            {value != null ? String(value) : ""}
          </div>
        );
      })}
    </div>
  );
}
