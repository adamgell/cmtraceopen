import { Fragment, memo, forwardRef } from "react";
import { tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { Marker } from "../../types/markers";
import type { EvtxRecord, EvtxLevel } from "./types";
import {
  evtxQuickFilterTerms,
  isEvtxBookmark,
  type EvtxQuickFilterLike,
} from "./evtx-marker-adapter";
import {
  columnValue,
  columnWidth,
  type EvtxColumnConfig,
  type EvtxColumnSpec,
} from "./evtx-columns";
import type { EvtxTimeZoneMode } from "./evtx-time";

const LEVEL_COLORS: Record<EvtxLevel, string> = {
  Critical: tokens.colorPaletteRedForeground1,
  Error: tokens.colorPaletteRedForeground1,
  Warning: tokens.colorPaletteMarigoldForeground1,
  Information: tokens.colorBrandForeground1,
  Verbose: tokens.colorNeutralForeground4,
};

const LEVEL_SHORT: Record<EvtxLevel, string> = {
  Critical: "CRIT",
  Error: "ERR",
  Warning: "WARN",
  Information: "INFO",
  Verbose: "VERB",
};

export type EvtxRowVisualState = "selected" | "marker" | "severity" | "match" | "default";

export function resolveEvtxRowVisualState(input: {
  isSelected: boolean;
  marker: Marker | null;
  level: EvtxLevel;
  quickFilterMatch: boolean;
}): EvtxRowVisualState {
  if (input.isSelected) return "selected";
  if (input.marker) return "marker";
  if (input.level) return "severity";
  if (input.quickFilterMatch) return "match";
  return "default";
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function highlightValue(
  value: string,
  terms: readonly string[],
  caseSensitive: boolean
) {
  if (terms.length === 0) return value;
  const pattern = terms.map(escapeRegExp).join("|");
  if (!pattern) return value;
  const matcher = new RegExp(`(${pattern})`, caseSensitive ? "g" : "gi");
  return value.split(matcher).map((part, index) => {
    const matched = terms.some(
      (term) =>
        term.length > 0 &&
        part.localeCompare(term, undefined, {
          sensitivity: caseSensitive ? "case" : "base",
        }) === 0
    );
    return matched ? (
      <mark key={`${part}-${index}`} aria-label="Quick-filter match">
        {part}
      </mark>
    ) : (
      <Fragment key={`${part}-${index}`}>{part}</Fragment>
    );
  });
}

export interface EvtxTimelineRowProps {
  record: EvtxRecord;
  dataIndex: number;
  isSelected: boolean;
  fontSize: number;
  smallFontSize: number;
  monoFontSize: number;
  lineHeight: string;
  columnConfig: EvtxColumnConfig;
  /** Precomputed by the list, since columnConfig is stable and this renders once per row. */
  columns: EvtxColumnSpec[];
  /** Passed rather than read from the store, so a memoized row re-renders when the clock changes. */
  timeZoneMode: EvtxTimeZoneMode;
  onSelect: (id: number | null) => void;
  marker?: Marker | null;
  quickFilter?: EvtxQuickFilterLike;
  quickFilterMatch?: boolean;
  onTag?: (record: EvtxRecord) => void;
  onBookmark?: (record: EvtxRecord) => void;
  grouped?: boolean;
  depth?: number;
  tabIndex?: number;
  onFocus?: () => void;
}

export const EvtxTimelineRow = memo(
  forwardRef<HTMLDivElement, EvtxTimelineRowProps>(function EvtxTimelineRow(
    {
      record,
      dataIndex,
      isSelected,
      fontSize,
      smallFontSize,
      monoFontSize,
      lineHeight,
      columnConfig,
      columns,
      timeZoneMode,
      onSelect,
      marker = null,
      quickFilter = undefined,
      quickFilterMatch = false,
      onTag,
      onBookmark,
      grouped = false,
      depth = 0,
      tabIndex = 0,
      onFocus,
    },
    ref
  ) {
    const levelColor = LEVEL_COLORS[record.level];
    const bookmark = isEvtxBookmark(marker);
    const highlightEnabled = Boolean(quickFilter?.highlight && quickFilterMatch);
    const highlightTerms = highlightEnabled && quickFilter
      ? evtxQuickFilterTerms(quickFilter)
      : [];
    const visualState = resolveEvtxRowVisualState({
      isSelected,
      marker,
      level: record.level,
      quickFilterMatch: highlightEnabled,
    });
    const ariaDescription = [
      isSelected ? "Selected" : null,
      marker ? `Tagged ${marker.category}` : null,
      bookmark ? "Bookmarked" : null,
      highlightEnabled ? "Quick-filter match" : null,
    ].filter(Boolean).join("; ");
    return (
      <div
        data-index={dataIndex}
        data-evtx-marker-key={`${record.sourceLabel}:${record.channel}:${record.eventRecordId}`}
        data-quick-filter-match={highlightEnabled ? "true" : "false"}
        data-marker-category={marker?.category}
        ref={ref}
        onClick={() => onSelect(isSelected ? null : record.id)}
        onFocus={onFocus}
        role={grouped ? "treeitem" : "option"}
        aria-level={grouped ? depth + 1 : undefined}
        aria-selected={isSelected}
        aria-description={ariaDescription}
        tabIndex={tabIndex}
        onKeyDown={(e) => {
          if (e.target instanceof HTMLButtonElement) return;
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect(isSelected ? null : record.id);
          } else if (e.key.toLowerCase() === "t" && onTag) {
            e.preventDefault();
            onTag(record);
          } else if (e.key.toLowerCase() === "b" && onBookmark) {
            e.preventDefault();
            onBookmark(record);
          }
        }}
        style={{
          display: "flex",
          alignItems: "center",
          padding: "2px 12px",
          cursor: "pointer",
          backgroundColor: isSelected
            ? tokens.colorNeutralBackground1Selected
            : marker
              ? `${marker.color}20`
              : dataIndex % 2 === 0
                ? tokens.colorNeutralBackground1
                : tokens.colorNeutralBackground2,
          borderLeft: `4px solid ${
            visualState === "marker" && marker ? marker.color : levelColor
          }`,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          height: "100%",
          boxSizing: "border-box",
          fontSize: `${fontSize}px`,
          lineHeight,
          gap: "10px",
          minWidth: 0,
        }}
      >
        <div
          role="group"
          aria-label="Event markers"
          style={{ display: "flex", gap: "4px", flexShrink: 0 }}
        >
          <button
            type="button"
            tabIndex={grouped ? -1 : undefined}
            aria-label={marker && !bookmark ? "Remove event tag" : "Tag event"}
            aria-pressed={Boolean(marker && !bookmark)}
            title={marker && !bookmark ? `Remove ${marker.category} tag` : "Tag event"}
            onClick={(event) => {
              event.stopPropagation();
              onTag?.(record);
            }}
            onKeyDown={(event) => event.stopPropagation()}
            style={{
              border: 0,
              borderRadius: "3px",
              padding: "1px 4px",
              cursor: "pointer",
              color: marker && !bookmark ? marker.color : tokens.colorNeutralForeground3,
              background: "transparent",
              fontSize: `${smallFontSize}px`,
            }}
          >
            {marker && !bookmark ? "Tagged" : "Tag"}
          </button>
          <button
            type="button"
            tabIndex={grouped ? -1 : undefined}
            aria-label={bookmark ? "Remove bookmark" : "Bookmark event"}
            aria-pressed={bookmark}
            title={bookmark ? "Remove bookmark" : "Bookmark event"}
            onClick={(event) => {
              event.stopPropagation();
              onBookmark?.(record);
            }}
            onKeyDown={(event) => event.stopPropagation()}
            style={{
              border: 0,
              borderRadius: "3px",
              padding: "1px 4px",
              cursor: "pointer",
              color: bookmark ? "#8b5cf6" : tokens.colorNeutralForeground3,
              background: "transparent",
              fontSize: `${smallFontSize}px`,
            }}
          >
            {bookmark ? "Bookmarked" : "Bookmark"}
          </button>
        </div>
        {columns.map((column) => {
          const width = columnWidth(columnConfig, column);
          const value = columnValue(record, column.id, timeZoneMode);

          if (column.id === "level") {
            return (
              <div
                key={column.id}
                style={{
                  fontSize: `${smallFontSize}px`,
                  fontWeight: 700,
                  padding: "2px 6px",
                  borderRadius: "4px",
                  backgroundColor: levelColor,
                  color: tokens.colorNeutralForegroundOnBrand,
                  width: width != null ? `${width}px` : undefined,
                  textAlign: "center",
                  flexShrink: 0,
                  boxSizing: "border-box",
                }}
              >
                {LEVEL_SHORT[record.level]}
              </div>
            );
          }

          const isDescription = column.id === "message";
          const isMono = column.id === "timestamp" || column.id === "keywords";

          return (
            <div
              key={column.id}
              style={
                isDescription
                  ? {
                      // Absorbs the remaining width only while no width has been set for it.
                      // Ignoring an override meant the Description column could be resized in the
                      // chooser and never actually change.
                      ...(width != null
                        ? { width: `${width}px`, flexShrink: 0 }
                        : { flex: 1 }),
                      fontSize: `${fontSize}px`,
                      fontWeight: isSelected ? 600 : 400,
                      color: isSelected
                        ? tokens.colorBrandForeground1
                        : tokens.colorNeutralForeground1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      minWidth: 0,
                    }
                  : {
                      width: width != null ? `${width}px` : undefined,
                      flexShrink: width != null ? 0 : 1,
                      fontSize: `${isMono ? monoFontSize : smallFontSize}px`,
                      fontFamily: isMono ? LOG_MONOSPACE_FONT_FAMILY : undefined,
                      color: tokens.colorNeutralForeground3,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      boxSizing: "border-box",
                    }
              }
              title={value}
            >
              {highlightEnabled
                ? highlightValue(value, highlightTerms, quickFilter?.caseSensitive ?? false)
                : value}
            </div>
          );
        })}
      </div>
    );
  })
);
