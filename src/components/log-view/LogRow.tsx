import { tokens } from "@fluentui/react-components";
import type { LogEntry, ErrorCodeSpan, Severity } from "../../types/log";
import type { Marker, MarkerCategory } from "../../types/markers";
import type { LogSeverityPalette } from "../../lib/constants";
import type { ColumnDefinition } from "../../lib/column-config";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";

interface LogRowProps {
  entry: LogEntry;
  rowDomId: string;
  isSelected: boolean;
  isMultiSelected?: boolean;
  isFindMatch: boolean;
  visibleColumns: ColumnDefinition[];
  gridTemplateColumns: string;
  listFontSize: number;
  rowLineHeight: number;
  severityPalette: LogSeverityPalette;
  highlightText: string;
  highlightCaseSensitive: boolean;
  onClick: (id: number, event: React.MouseEvent) => void;
  onContextMenu: (entry: LogEntry, event: React.MouseEvent) => void;
  onErrorCodeClick?: (span: ErrorCodeSpan) => void;
  mergeFileColor?: string | null;
  isCorrelated?: boolean;
  correlationColor?: string | null;
  sectionBandColor?: string | null;
  marker?: Marker | null;
  onToggleMarker?: (lineId: number) => void;
  onSetMarkerCategory?: (lineId: number, category: string) => void;
  markerCategories?: MarkerCategory[];
}

/** Subtle tint for find-match rows (not the active selection). */
const FIND_MATCH_OVERLAY = "rgba(255, 210, 50, 0.18)";

function getRowStyle(
  entry: LogEntry,
  isSelected: boolean,
  isFindMatch: boolean,
  palette: LogSeverityPalette
) {

  if (isSelected) {
    return {
      backgroundColor: tokens.colorBrandBackground,
      color: tokens.colorNeutralForegroundOnBrand,
    };
  }

  let bg: string;
  let color: string;

  switch (entry.severity) {
    case "Error":
      bg = palette.error.background;
      color = palette.error.text;
      break;
    case "Warning":
      bg = palette.warning.background;
      color = palette.warning.text;
      break;
    default:
      bg = palette.info.background;
      color = palette.info.text;
      break;
  }

  if (isFindMatch) {
    return {
      backgroundColor: bg,
      backgroundImage: `linear-gradient(${FIND_MATCH_OVERLAY}, ${FIND_MATCH_OVERLAY})`,
      color,
    };
  }

  return { backgroundColor: bg, color };
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

function getSeverityDotColor(
  severity: Severity,
  palette: LogSeverityPalette
): string {
  switch (severity) {
    case "Error":
      return palette.error.text;
    case "Warning":
      return palette.warning.text;
    default:
      return tokens.colorNeutralForeground4;
  }
}

const detailCellStyle: React.CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  padding: "1px 4px",
  borderLeft: `1px solid ${tokens.colorNeutralStroke1}`,
};

import { memo, useState, useCallback } from "react";

export const LogRow = memo(function LogRow({
  entry,
  rowDomId,
  isSelected,
  isMultiSelected,
  isFindMatch,
  visibleColumns,
  gridTemplateColumns,
  listFontSize,
  rowLineHeight,
  severityPalette,
  highlightText,
  highlightCaseSensitive,
  onClick,
  onContextMenu,
  onErrorCodeClick,
  mergeFileColor,
  isCorrelated,
  correlationColor,
  sectionBandColor,
  marker,
  onToggleMarker,
  onSetMarkerCategory,
  markerCategories,
}: LogRowProps) {
  const style = getRowStyle(entry, isSelected, isFindMatch, severityPalette);

  // ── Marker gutter context menu ────────────────────────────────────
  const [gutterMenu, setGutterMenu] = useState<{ x: number; y: number } | null>(null);

  const handleGutterContextMenu = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setGutterMenu({ x: e.clientX, y: e.clientY });
    },
    []
  );

  const closeGutterMenu = useCallback(() => setGutterMenu(null), []);

  // Determine left-edge indicator: marker > mergeFileColor > sectionBandColor > default
  const leftBorderColor = marker
    ? marker.color
    : mergeFileColor
      ? mergeFileColor
      : sectionBandColor
        ? sectionBandColor
        : isSelected
          ? tokens.colorNeutralForegroundOnBrand
          : "transparent";

  // Marker tint: subtle background in marker color (~9% opacity)
  const markerTint = marker && !isSelected
    ? `linear-gradient(${marker.color}17, ${marker.color}17)`
    : undefined;

  // Combine background overlays
  const backgroundOverlays: string[] = [];
  if (markerTint) backgroundOverlays.push(markerTint);
  if (isCorrelated && correlationColor && !isSelected) {
    backgroundOverlays.push(`linear-gradient(${correlationColor}30, ${correlationColor}30)`);
  }

  // Multi-select visual: subtle blue background when no marker tint is present
  const showMultiSelectHighlight = isMultiSelected && !isSelected && !marker;

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
        gridTemplateColumns: `20px ${gridTemplateColumns}`,
        cursor: "pointer",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        fontSize: `${listFontSize}px`,
        fontFamily: LOG_UI_FONT_FAMILY,
        lineHeight: `${rowLineHeight}px`,
        whiteSpace: "nowrap",
        transition: "filter 80ms linear",
        boxShadow: marker
          ? `inset 3px 0 0 ${leftBorderColor}`
          : `inset 4px 0 0 ${leftBorderColor}`,
        ...(backgroundOverlays.length > 0
          ? { backgroundImage: backgroundOverlays.join(", ") }
          : {}),
        ...(entry.whatif ? { opacity: 0.6 } : {}),
        ...(showMultiSelectHighlight
          ? {
              outline: "1px solid rgba(59, 130, 246, 0.5)",
              outlineOffset: -1,
              backgroundImage: [
                ...backgroundOverlays,
                "linear-gradient(rgba(59, 130, 246, 0.08), rgba(59, 130, 246, 0.08))",
              ].join(", "),
            }
          : {}),
        ...(isMultiSelected && !isSelected && marker
          ? {
              outline: "1px solid rgba(59, 130, 246, 0.5)",
              outlineOffset: -1,
            }
          : {}),
      }}
      onClick={(e) => onClick(entry.id, e)}
      onContextMenu={(e) => onContextMenu(entry, e)}
    >
      {/* Marker gutter */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: 20,
          cursor: "pointer",
          flexShrink: 0,
        }}
        onClick={(e) => {
          e.stopPropagation();
          onToggleMarker?.(entry.id);
        }}
        onContextMenu={handleGutterContextMenu}
      >
        <span
          style={{
            display: "inline-block",
            width: 8,
            height: 8,
            borderRadius: "50%",
            backgroundColor: marker ? marker.color : "transparent",
            border: marker ? "none" : `1px solid ${tokens.colorNeutralStroke2}`,
            flexShrink: 0,
          }}
        />
      </div>

      {/* Gutter context menu (positioned overlay) */}
      {gutterMenu && markerCategories && (
        <div
          style={{
            position: "fixed",
            top: gutterMenu.y,
            left: gutterMenu.x,
            zIndex: 9999,
            backgroundColor: tokens.colorNeutralBackground1,
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: 4,
            boxShadow: tokens.shadow8,
            padding: "4px 0",
            minWidth: 140,
          }}
          onMouseLeave={closeGutterMenu}
        >
          {markerCategories.map((cat) => (
            <div
              key={cat.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "4px 12px",
                cursor: "pointer",
                fontSize: `${listFontSize}px`,
                lineHeight: `${rowLineHeight}px`,
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.backgroundColor =
                  tokens.colorNeutralBackground1Hover;
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.backgroundColor = "transparent";
              }}
              onClick={(e) => {
                e.stopPropagation();
                if (!marker) {
                  // First toggle it on, then set category
                  onToggleMarker?.(entry.id);
                }
                onSetMarkerCategory?.(entry.id, cat.id);
                closeGutterMenu();
              }}
            >
              <span
                style={{
                  display: "inline-block",
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  backgroundColor: cat.color,
                  flexShrink: 0,
                }}
              />
              <span>{cat.label}</span>
            </div>
          ))}
          {marker && (
            <>
              <div
                style={{
                  borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                  margin: "4px 0",
                }}
              />
              <div
                style={{
                  padding: "4px 12px",
                  cursor: "pointer",
                  fontSize: `${listFontSize}px`,
                  lineHeight: `${rowLineHeight}px`,
                  color: tokens.colorPaletteRedForeground1,
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.backgroundColor =
                    tokens.colorNeutralBackground1Hover;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.backgroundColor = "transparent";
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleMarker?.(entry.id);
                  closeGutterMenu();
                }}
              >
                Remove Marker
              </div>
            </>
          )}
        </div>
      )}

      {visibleColumns.map((col) => {
        // Severity column: colored dot indicator + WhatIf badge
        if (col.id === "severity") {
          return (
            <div
              key="severity"
              aria-label={entry.severity}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 2,
                overflow: "hidden",
                padding: "1px 2px",
              }}
            >
              <span
                style={{
                  display: "inline-block",
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  backgroundColor: getSeverityDotColor(
                    entry.severity,
                    severityPalette
                  ),
                  flexShrink: 0,
                }}
              />
              {entry.whatif && (
                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 600,
                    lineHeight: "12px",
                    padding: "0 4px",
                    borderRadius: 4,
                    backgroundColor: severityPalette.whatifOverlay,
                    color: severityPalette.whatifText,
                    whiteSpace: "nowrap",
                    flexShrink: 0,
                  }}
                >
                  WhatIf
                </span>
              )}
            </div>
          );
        }

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
                ...(entry.whatif ? { fontStyle: "italic" } : {}),
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
});
