import { Fragment, memo, forwardRef, type KeyboardEvent, type MouseEvent } from "react";
import { tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { Marker } from "../../types/markers";
import type { EvtxRecord, EvtxLevel } from "./types";
import {
  evtxMarkerKey,
  evtxQuickFilterTerms,
  isEvtxBookmark,
  isEvtxMarkerAddressable,
} from "./evtx-marker-adapter";
import type { EvtxQuickFilter } from "./evtx-filter";
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
  level: EvtxLevel | null | undefined;
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
    // The single outer capture means odd split positions are exact regex matches. Re-testing with
    // localeCompare widened matching (for example, treating é as e) and highlighted text that the
    // quick-filter regular expression never matched.
    const matched = index % 2 === 1;
    return matched ? (
      <mark key={`${part}-${index}`} aria-label="Quick-filter match">
        {part}
      </mark>
    ) : (
      <Fragment key={`${part}-${index}`}>{part}</Fragment>
    );
  });
}

export function EvtxMarkerControls({
  record,
  marker,
  markerAddressable,
  fontSize,
  variant,
  onTag,
  onBookmark,
}: {
  record: EvtxRecord;
  marker: Marker | null;
  markerAddressable: boolean;
  fontSize: number;
  variant: "detail" | "timeline";
  onTag?: (record: EvtxRecord) => void;
  onBookmark?: (record: EvtxRecord) => void;
}) {
  const bookmark = isEvtxBookmark(marker);
  const compact = variant === "timeline";
  const stopPropagation = compact
    ? (event: MouseEvent<HTMLButtonElement>) => event.stopPropagation()
    : undefined;
  const stopKeyPropagation = compact
    ? (event: KeyboardEvent<HTMLButtonElement>) => event.stopPropagation()
    : undefined;

  const controls = (
    <>
      <button
        type="button"
        disabled={!markerAddressable}
        tabIndex={compact ? -1 : undefined}
        aria-label={
          markerAddressable
            ? marker && !bookmark
              ? "Remove event tag"
              : "Tag event"
            : "EventRecordID unavailable; tagging is disabled"
        }
        aria-pressed={Boolean(marker && !bookmark)}
        title={
          markerAddressable
            ? marker && !bookmark
              ? compact
                ? `Remove ${marker.category} tag`
                : "Remove event tag"
              : "Tag event"
            : "EventRecordID unavailable; tagging is disabled"
        }
        onClick={(event) => {
          stopPropagation?.(event);
          onTag?.(record);
        }}
        onKeyDown={stopKeyPropagation}
        style={{
          border: compact ? 0 : `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: compact ? "3px" : "4px",
          padding: compact ? "1px 4px" : "3px 7px",
          cursor: compact
            ? markerAddressable
              ? "pointer"
              : "not-allowed"
            : "pointer",
          color: compact
            ? !markerAddressable
              ? tokens.colorNeutralForeground4
              : marker && !bookmark
                ? marker.color
                : tokens.colorNeutralForeground3
            : tokens.colorNeutralForeground1,
          background: "transparent",
          fontSize: `${fontSize}px`,
        }}
      >
        {compact ? (marker && !bookmark ? "Tagged" : "Tag") : marker && !bookmark ? `Tagged: ${marker.category}` : "Tag"}
      </button>
      <button
        type="button"
        disabled={!markerAddressable}
        tabIndex={compact ? -1 : undefined}
        aria-label={
          markerAddressable
            ? bookmark
              ? "Remove bookmark"
              : "Bookmark event"
            : "EventRecordID unavailable; bookmarking is disabled"
        }
        aria-pressed={bookmark}
        title={
          markerAddressable
            ? bookmark
              ? "Remove bookmark"
              : "Bookmark event"
            : "EventRecordID unavailable; bookmarking is disabled"
        }
        onClick={(event) => {
          stopPropagation?.(event);
          onBookmark?.(record);
        }}
        onKeyDown={stopKeyPropagation}
        style={{
          border: compact ? 0 : `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: compact ? "3px" : "4px",
          padding: compact ? "1px 4px" : "3px 7px",
          cursor: compact
            ? markerAddressable
              ? "pointer"
              : "not-allowed"
            : "pointer",
          color: compact
            ? !markerAddressable
              ? tokens.colorNeutralForeground4
              : bookmark
                ? "#8b5cf6"
                : tokens.colorNeutralForeground3
            : bookmark
              ? "#8b5cf6"
              : tokens.colorNeutralForeground1,
          background: "transparent",
          fontSize: `${fontSize}px`,
        }}
      >
        {bookmark ? "Bookmarked" : "Bookmark"}
      </button>
    </>
  );
  return compact ? (
    controls
  ) : (
    <div role="group" aria-label="Selected event markers" style={{ display: "flex", gap: "6px" }}>
      {controls}
    </div>
  );
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
  quickFilter?: EvtxQuickFilter;
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
    const markerAddressable = isEvtxMarkerAddressable(record);
    const bookmark = isEvtxBookmark(marker);
    const filterMatch = quickFilterMatch;
    const highlightEnabled = Boolean(quickFilter?.highlight && filterMatch);
    const highlightTerms = highlightEnabled && quickFilter
      ? evtxQuickFilterTerms(quickFilter)
      : [];
    const visualState = resolveEvtxRowVisualState({
      isSelected,
      marker,
      level: record.level,
      quickFilterMatch: filterMatch,
    });
    const ariaDescription = [
      isSelected ? "Selected" : null,
      marker ? `Tagged ${marker.category}` : null,
      bookmark ? "Bookmarked" : null,
      filterMatch ? "Quick-filter match" : null,
      markerAddressable ? null : "Markers unavailable: EventRecordID is missing",
    ].filter(Boolean).join("; ");
    return (
      <div
        data-index={dataIndex}
        data-evtx-marker-key={evtxMarkerKey(record)}
        data-marker-category={marker?.category}
        data-quick-filter-match={highlightEnabled ? "true" : "false"}
        data-evtx-filter-match={filterMatch ? "true" : "false"}
        data-evtx-visual-state={visualState}
        ref={ref}
        onClick={() => onSelect(isSelected ? null : record.id)}
        onFocus={onFocus}
        role="row"
        aria-rowindex={dataIndex + 1}
        aria-level={grouped ? depth + 1 : undefined}
        aria-selected={isSelected}
        aria-description={ariaDescription}
        tabIndex={tabIndex}
        onKeyDown={(e) => {
          if (e.target instanceof HTMLButtonElement) return;
          const hasShortcutModifier =
            e.ctrlKey || e.altKey || e.shiftKey || e.metaKey;
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect(isSelected ? null : record.id);
          } else if (
            !hasShortcutModifier &&
            e.key.toLowerCase() === "t" &&
            markerAddressable &&
            onTag
          ) {
            e.preventDefault();
            onTag(record);
          } else if (
            !hasShortcutModifier &&
            e.key.toLowerCase() === "b" &&
            markerAddressable &&
            onBookmark
          ) {
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
          minWidth: 0,
          gap: "10px",
        }}
      >
        <div
          role="gridcell"
          aria-colindex={1}
          aria-label="Event markers"
          style={{
            display: "flex",
            alignItems: "center",
            flexShrink: 0,
          }}
        >
          <div
            role="group"
            aria-label="Event markers"
            style={{ display: "flex", gap: "4px", flexShrink: 0 }}
          >
            {filterMatch && (
              <span
                data-evtx-filter-match-label="true"
                aria-hidden="true"
                style={{
                  fontSize: `${smallFontSize}px`,
                  fontWeight: 600,
                  color: tokens.colorNeutralForeground2,
                }}
              >
                Match
              </span>
            )}
            <EvtxMarkerControls
              record={record}
              marker={marker}
              markerAddressable={markerAddressable}
              fontSize={smallFontSize}
              variant="timeline"
              onTag={onTag}
              onBookmark={onBookmark}
            />
          </div>
        </div>
        {columns.map((column, columnIndex) => {
          const width = columnWidth(columnConfig, column);
          const value = columnValue(record, column.id, timeZoneMode);

          if (column.id === "level") {
            return (
              <div
                key={column.id}
                role="gridcell"
                aria-colindex={columnIndex + 2}
                aria-label={`${column.label}: ${value || "Empty"}`}
                data-evtx-level-badge="true"
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
              role="gridcell"
              aria-colindex={columnIndex + 2}
              aria-label={`${column.label}: ${value || "Empty"}`}
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
