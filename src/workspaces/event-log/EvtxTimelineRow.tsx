import { Fragment, memo, forwardRef, type CSSProperties } from "react";
import { tokens } from "@fluentui/react-components";
import {
  ChevronDown12Regular,
  ChevronUp12Regular,
  Link12Regular,
  Link16Regular,
} from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { getThemeById, type ThemeId } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
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
  type EvtxColumnId,
  type EvtxColumnSpec,
} from "./evtx-columns";
import type { EvtxSortField } from "./evtx-store";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { buildEvtxVisualTokens, type EvtxVisualTokens } from "./evtx-visual-tokens";

/** Width of the left slot: the marker color when a marker is present (spec 8.7). */
const ROW_SLOT_PX = 4;
const ROW_PADDING_X = 12;
const ROW_GAP_PX = 10;
/** The selection inset (spec 6.2). */
const SELECTION_INSET_PX = 3;

/**
 * The narrowest a row can be without its columns overlapping: the insets, every column that has a
 * width, and the gaps. The description has none while it absorbs the remaining space, so it counts
 * as zero here.
 *
 * A row is at least this wide so that its tint, or the selection, still sits behind every column
 * when the grid is narrower and scrolls sideways. Without it the background stopped at the grid's
 * edge while the text carried on, and tinted-row text would be drawn on the bare surface.
 */
export function evtxRowMinWidth(
  config: EvtxColumnConfig,
  columns: readonly EvtxColumnSpec[]
): number {
  let width =
    ROW_SLOT_PX + ROW_PADDING_X * 2 + ROW_GAP_PX * Math.max(0, columns.length - 1);
  for (const column of columns) width += columnWidth(config, column) ?? 0;
  return width;
}

/**
 * Display name for the Channel column: the channel without its `Microsoft-Windows-` prefix, so
 * "Microsoft-Windows-AAD/Operational" reads "AAD/Operational" in a 120 px column. The full name
 * stays in the tooltip, the accessible name and quick-filter search.
 */
export function shortChannelName(channel: string): string {
  const prefix = "Microsoft-Windows-";
  return channel.startsWith(prefix) && channel.length > prefix.length
    ? channel.slice(prefix.length)
    : channel;
}

const visualTokensByTheme = new Map<ThemeId, EvtxVisualTokens>();

/**
 * The visual token map for a theme, built once per theme id. Every row of a virtualized list of
 * up to 100,000 records reads it, so it must not be rebuilt per row.
 */
function evtxVisualTokensForTheme(themeId: ThemeId): EvtxVisualTokens {
  let visual = visualTokensByTheme.get(themeId);
  if (!visual) {
    visual = buildEvtxVisualTokens(getThemeById(themeId));
    visualTokensByTheme.set(themeId, visual);
  }
  return visual;
}

/** Every color a row draws, for one level and selection state. */
export interface EvtxRowPalette {
  background: string;
  /** Primary text: ID, channel, message, and the text of tinted and selected rows. */
  ink: string;
  /** Time, provider and the optional columns. */
  secondary: string;
  /** The links cell. */
  link: string;
  /** The level icon. */
  icon: string;
  /** Outline for the channel swatch; null on a plain row, where the mark needs none. */
  swatchOutline: string | null;
  /** The 3 px selection inset; null when the row is not selected. */
  selectionInset: string | null;
  /**
   * The quick-filter highlight's outline and underline. It is the row's primary text color, so it
   * is as far from the row's own background as the text is (4.5:1 or better) whatever the tint,
   * and the highlight draws no fill, so it can never be taken for a tint or the selection.
   */
  highlight: string;
}

/**
 * The colors for a row.
 *
 * Every text role on a tinted row is the level's `rowText` (spec D3), and on a selected row the
 * selection foreground (Q-1, Q-18). Both pairs are measured at 4.5:1 or better in every theme by
 * the token tests. The Time, Provider and links text deliberately do not keep their spec 8.7
 * colors (fg2, `colorBrandForegroundLink`) on those rows: they measured 2.45:1 on
 * the classic Error row and 3.72:1 on its selection background (issue #836, Adam's criterion).
 * A plain row (Information, Verbose) keeps the neutral hierarchy of 8.7, which measures 4.5:1
 * or better in every theme.
 */
export function buildEvtxRowPalette(
  visual: EvtxVisualTokens,
  level: EvtxLevel,
  isSelected: boolean
): EvtxRowPalette {
  const levelVisual = visual.levels[level];
  if (isSelected) {
    const ink = visual.selection.foreground;
    return {
      background: visual.selection.background,
      ink,
      secondary: ink,
      link: ink,
      icon: levelVisual.selectedIconColor,
      swatchOutline: visual.markOutline("selected"),
      selectionInset: visual.selection.border,
      highlight: ink,
    };
  }
  // Plain levels take `colorNeutralBackground1` as their row background; the others are tinted.
  const tinted = levelVisual.rowBackground !== tokens.colorNeutralBackground1;
  if (tinted) {
    const ink = levelVisual.rowText;
    return {
      background: levelVisual.rowBackground,
      ink,
      secondary: ink,
      link: ink,
      icon: levelVisual.iconColor,
      swatchOutline: visual.markOutline(level),
      selectionInset: null,
      highlight: ink,
    };
  }
  return {
    background: levelVisual.rowBackground,
    ink: levelVisual.rowText,
    secondary: tokens.colorNeutralForeground2,
    link: tokens.colorBrandForegroundLink,
    icon: levelVisual.iconColor,
    swatchOutline: null,
    selectionInset: null,
    highlight: levelVisual.rowText,
  };
}

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

/**
 * The quick-filter highlight, drawn from the row's own colors.
 *
 * The browser's default `mark` paints yellow with black text, which is invisible on the classic
 * Warning row (#FFFF00) and close to the light theme's Warning tint. This keeps the row's text
 * color, draws no fill, and marks the term with a 1 px outline and a 2 px underline in the row's
 * primary text color, both of which survive forced colors. The outline sits inside the term's box
 * so the cell's clipping cannot cut an edge off it.
 */
function highlightStyle(color: string): CSSProperties {
  return {
    backgroundColor: "transparent",
    color: "inherit",
    outline: `1px solid ${color}`,
    // Inside the mark's box. Every text cell clips its content, so an outline drawn outside
    // would lose its left edge whenever a match starts the cell. An outline does not affect
    // layout, so this changes no cell's size.
    outlineOffset: "-1px",
    borderRadius: "2px",
    textDecorationLine: "underline",
    textDecorationColor: color,
    textDecorationThickness: "2px",
    textUnderlineOffset: "2px",
  };
}

function highlightValue(
  value: string,
  terms: readonly string[],
  caseSensitive: boolean,
  markStyle: CSSProperties
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
      <mark key={`${part}-${index}`} aria-label="Quick-filter match" style={markStyle}>
        {part}
      </mark>
    ) : (
      <Fragment key={`${part}-${index}`}>{part}</Fragment>
    );
  });
}

/**
 * Tag and bookmark buttons for the Details pane.
 *
 * The table row no longer carries them (spec 8.7: the row keeps only the marker color in its left
 * slot, and the `t` and `b` keys); this is the pointer route to the same two actions.
 *
 * `variant` does nothing: the timeline variant it once selected is gone. It stays only so the
 * Details pane's call is unchanged while Phase 4 (#830) rewrites that file. The prop and the
 * call-site attribute go together in whichever of Phase 4 (#830) and Phase 7 (#836) merges second.
 */
export function EvtxMarkerControls({
  record,
  marker,
  markerAddressable,
  fontSize,
  onTag,
  onBookmark,
}: {
  record: EvtxRecord;
  marker: Marker | null;
  markerAddressable: boolean;
  fontSize: number;
  variant: "detail";
  onTag?: (record: EvtxRecord) => void;
  onBookmark?: (record: EvtxRecord) => void;
}) {
  const bookmark = isEvtxBookmark(marker);

  return (
    <div role="group" aria-label="Selected event markers" style={{ display: "flex", gap: "6px" }}>
      <button
        type="button"
        disabled={!markerAddressable}
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
              ? "Remove event tag"
              : "Tag event"
            : "EventRecordID unavailable; tagging is disabled"
        }
        onClick={() => onTag?.(record)}
        style={{
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          padding: "3px 7px",
          cursor: "pointer",
          color: tokens.colorNeutralForeground1,
          background: "transparent",
          fontSize: `${fontSize}px`,
        }}
      >
        {marker && !bookmark ? `Tagged: ${marker.category}` : "Tag"}
      </button>
      <button
        type="button"
        disabled={!markerAddressable}
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
        onClick={() => onBookmark?.(record)}
        style={{
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          padding: "3px 7px",
          cursor: "pointer",
          color: bookmark ? "#8b5cf6" : tokens.colorNeutralForeground1,
          background: "transparent",
          fontSize: `${fontSize}px`,
        }}
      >
        {bookmark ? "Bookmarked" : "Bookmark"}
      </button>
    </div>
  );
}

const TRUNCATE: CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

/** Time, IDs and counts use the numeric face, not the monospace one (spec D4). */
const NUMERIC: CSSProperties = {
  fontFamily: tokens.fontFamilyNumeric,
  fontVariantNumeric: "tabular-nums",
};

/** Optional numeric columns, which share the numeric face. */
const NUMERIC_EXTRA_COLUMNS: ReadonlySet<EvtxColumnId> = new Set<EvtxColumnId>([
  "recordId",
  "task",
  "opcode",
  "processId",
  "threadId",
]);

/**
 * Width behavior of a column cell, shared by the rows and the header so that both place every
 * column at the same x. A column with no width absorbs the remaining space.
 */
export function columnCellBox(
  config: EvtxColumnConfig,
  column: EvtxColumnSpec
): CSSProperties {
  const width = columnWidth(config, column);
  return width != null
    ? { width: `${width}px`, flexShrink: 0, boxSizing: "border-box" }
    : { flex: 1, minWidth: 0, boxSizing: "border-box" };
}

export interface EvtxTimelineRowProps {
  record: EvtxRecord;
  dataIndex: number;
  isSelected: boolean;
  fontSize: number;
  monoFontSize: number;
  lineHeight: string;
  /** `getLogListMetrics(...).rowHeight`: the row's border-box height (spec D1). */
  rowHeight: number;
  columnConfig: EvtxColumnConfig;
  /** Precomputed by the list, since columnConfig is stable and this renders once per row. */
  columns: EvtxColumnSpec[];
  /** Passed rather than read from the store, so a memoized row re-renders when the clock changes. */
  timeZoneMode: EvtxTimeZoneMode;
  onSelect: (id: number | null) => void;
  marker?: Marker | null;
  quickFilter?: EvtxQuickFilter;
  quickFilterMatch?: boolean;
  /**
   * Position of the record's channel in channel display order (spec 6.3). Only the channel pane
   * defines that order; with no index the swatch is omitted rather than given a color that would
   * disagree with the pane.
   */
  channelIndex?: number;
  /**
   * Distinct records sharing an Exact or Candidate correlation edge with this one. Only a complete
   * edge index may supply it: the edges the UI holds are a bounded preview, and a count taken
   * from a prefix would pass an undercount off as the whole. Omitted, the links cell is empty.
   */
  linkCount?: number;
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
      monoFontSize,
      lineHeight,
      rowHeight,
      columnConfig,
      columns,
      timeZoneMode,
      onSelect,
      marker = null,
      quickFilter = undefined,
      quickFilterMatch = false,
      channelIndex,
      linkCount,
      onTag,
      onBookmark,
      grouped = false,
      depth = 0,
      tabIndex = 0,
      onFocus,
    },
    ref
  ) {
    const themeId = useUiStore((s) => s.themeId);
    const visual = evtxVisualTokensForTheme(themeId);
    const palette = buildEvtxRowPalette(visual, record.level, isSelected);
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
    const markStyle = highlightStyle(palette.highlight);
    const LevelIcon = visual.levels[record.level].GridIcon;
    const hasLinks = linkCount !== undefined && Number.isInteger(linkCount) && linkCount > 0;
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
          position: "relative",
          display: "flex",
          alignItems: "center",
          // The 4 px left slot belongs to the marker color. An unmarked row keeps its content at
          // the same x through padding, so the selection inset below sits flush with the edge.
          paddingLeft: `${marker ? ROW_PADDING_X : ROW_PADDING_X + ROW_SLOT_PX}px`,
          paddingRight: `${ROW_PADDING_X}px`,
          cursor: "pointer",
          // Severity is the row-wide tint (D3). A marker no longer tints the row: its color is a
          // user value whose text contrast cannot be measured, so it is the left slot only.
          backgroundColor: palette.background,
          color: palette.ink,
          borderLeft: marker ? `${ROW_SLOT_PX}px solid ${marker.color}` : undefined,
          borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
          boxShadow: palette.selectionInset
            ? `inset ${SELECTION_INSET_PX}px 0 0 ${palette.selectionInset}`
            : undefined,
          height: `${rowHeight}px`,
          boxSizing: "border-box",
          fontSize: `${fontSize}px`,
          lineHeight,
          minWidth: `${evtxRowMinWidth(columnConfig, columns)}px`,
          gap: `${ROW_GAP_PX}px`,
        }}
      >
        {columns.map((column, columnIndex) => {
          const box = columnCellBox(columnConfig, column);
          const value = columnValue(record, column.id, timeZoneMode);
          const common = {
            role: "gridcell",
            "aria-colindex": columnIndex + 1,
            "aria-label": `${column.label}: ${value || "Empty"}`,
          } as const;
          const text = (display: string) =>
            highlightEnabled
              ? highlightValue(
                  display,
                  highlightTerms,
                  quickFilter?.caseSensitive ?? false,
                  markStyle
                )
              : display;

          if (column.id === "level") {
            return (
              <div
                key={column.id}
                {...common}
                data-evtx-level-cell="true"
                style={{
                  ...box,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: palette.icon,
                }}
              >
                <LevelIcon aria-label={record.level} />
              </div>
            );
          }

          if (column.id === "links") {
            return (
              <div
                key={column.id}
                {...common}
                aria-label={hasLinks ? `${column.label}: ${linkCount}` : `${column.label}: Empty`}
                title={
                  hasLinks
                    ? `${linkCount} linked ${linkCount === 1 ? "event" : "events"}`
                    : undefined
                }
                data-evtx-links-cell={hasLinks ? "count" : "empty"}
                style={{
                  ...box,
                  display: "flex",
                  alignItems: "center",
                  gap: "3px",
                  ...NUMERIC,
                  // The spec's f - 3, held to the caption floor of 10 (section 7.1).
                  fontSize: `${Math.max(10, fontSize - 3)}px`,
                  fontWeight: 600,
                  color: palette.link,
                }}
              >
                {hasLinks && (
                  <>
                    <Link12Regular aria-hidden="true" />
                    <span>{linkCount}</span>
                  </>
                )}
              </div>
            );
          }

          if (column.id === "channel") {
            const name = shortChannelName(value);
            return (
              <div
                key={column.id}
                {...common}
                title={value}
                style={{
                  ...box,
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: `${fontSize}px`,
                  color: palette.ink,
                }}
              >
                {channelIndex !== undefined && (
                  <span
                    aria-hidden="true"
                    data-evtx-channel-swatch="true"
                    style={{
                      flex: "none",
                      width: "7px",
                      height: "7px",
                      borderRadius: "2px",
                      backgroundColor: visual.channelColor(channelIndex),
                      outline: palette.swatchOutline ? `1px solid ${palette.swatchOutline}` : undefined,
                    }}
                  />
                )}
                <span style={{ minWidth: 0, ...TRUNCATE }}>{text(name)}</span>
              </div>
            );
          }

          let cellStyle: CSSProperties;
          switch (column.id) {
            case "timestamp":
              cellStyle = {
                ...NUMERIC,
                fontSize: `${monoFontSize}px`,
                color: palette.secondary,
              };
              break;
            case "eventId":
              cellStyle = {
                ...NUMERIC,
                fontSize: `${fontSize}px`,
                fontWeight: 700,
                color: palette.ink,
              };
              break;
            case "provider":
              cellStyle = { fontSize: `${fontSize}px`, color: palette.secondary };
              break;
            case "message":
              cellStyle = {
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: `${fontSize}px`,
                color: palette.ink,
              };
              break;
            case "keywords":
              // The monospace face for a hex bitmask, at the grid font size like every other
              // text cell; only the time is f - 1 (spec 8.7).
              cellStyle = {
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: `${fontSize}px`,
                color: palette.secondary,
              };
              break;
            default:
              // Grid text is the font size (D1, 7.1), with the numeric face for numeric columns.
              cellStyle = {
                ...(NUMERIC_EXTRA_COLUMNS.has(column.id) ? NUMERIC : null),
                fontSize: `${fontSize}px`,
                color: palette.secondary,
              };
          }

          return (
            <div
              key={column.id}
              {...common}
              style={{ ...box, ...TRUNCATE, ...cellStyle }}
              title={value}
            >
              {text(value)}
            </div>
          );
        })}
        {isSelected && (
          // Forced colors (a Windows contrast theme) replaces the background and drops the inset
          // box-shadow, which would leave nothing to show the row is selected. A transparent
          // outline is drawn in the system color there, and is invisible otherwise. It is its own
          // element so it does not replace the row's focus ring, which an outline on the row
          // itself would.
          <span
            aria-hidden="true"
            data-evtx-selected-cue="true"
            style={{
              position: "absolute",
              inset: 0,
              pointerEvents: "none",
              outline: "2px solid transparent",
              outlineOffset: "-2px",
            }}
          />
        )}
      </div>
    );
  })
);

export interface EvtxTimelineHeaderProps {
  columns: EvtxColumnSpec[];
  columnConfig: EvtxColumnConfig;
  fontSize: number;
  /** `getLogListMetrics(...).headerLineHeight`. The header is that plus 2 px (spec D1). */
  headerLineHeight: number;
  sortField: EvtxSortField;
  sortDirection: "asc" | "desc";
}

/**
 * The column header (spec 8.7): `colorNeutralBackground3`, a `colorNeutralStroke1` bottom border,
 * 600 weight at the font size minus one. The time header carries the sort direction.
 *
 * Presentational and hidden from assistive technology, which is acceptable for this phase: every
 * gridcell already names its column ("Event Time: ..."), and a header row inside the grid would
 * shift every row's `aria-rowindex`. Sorting stays on the filter bar's Sort control, which is the
 * accessible one. A `columnheader` row in the grid, with `aria-sort` on the time header, is the
 * follow-up that replaces this.
 */
export const EvtxTimelineHeader = forwardRef<HTMLDivElement, EvtxTimelineHeaderProps>(
  function EvtxTimelineHeader(
    {
      columns,
      columnConfig,
      fontSize,
      headerLineHeight,
      sortField,
      sortDirection,
    },
    ref
  ) {
    const SortChevron = sortDirection === "desc" ? ChevronDown12Regular : ChevronUp12Regular;
    return (
      <div
        ref={ref}
        aria-hidden="true"
        data-evtx-table-header="true"
        style={{
          display: "flex",
          alignItems: "center",
          flexShrink: 0,
          boxSizing: "border-box",
          height: `${headerLineHeight + 2}px`,
          paddingLeft: `${ROW_PADDING_X + ROW_SLOT_PX}px`,
          paddingRight: `${ROW_PADDING_X}px`,
          gap: `${ROW_GAP_PX}px`,
          backgroundColor: tokens.colorNeutralBackground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
          color: tokens.colorNeutralForeground2,
          fontSize: `${fontSize - 1}px`,
          fontWeight: 600,
          lineHeight: `${headerLineHeight}px`,
          overflow: "hidden",
          // Reserves the same gutter as the scroller below it, so a classic scrollbar does not
          // push the rows' columns out from under the header.
          scrollbarGutter: "stable",
        }}
      >
        {columns.map((column) => {
          const centered = column.id === "level" || column.id === "links";
          return (
            <div
              key={column.id}
              data-evtx-header-cell={column.id}
              title={column.label}
              style={{
                ...columnCellBox(columnConfig, column),
                display: "flex",
                alignItems: "center",
                justifyContent: centered ? "center" : "flex-start",
                gap: "4px",
              }}
            >
              {column.id === "links" ? (
                <Link16Regular />
              ) : (
                <span style={{ minWidth: 0, ...TRUNCATE }}>{column.headerLabel ?? column.label}</span>
              )}
              {column.id === "timestamp" && sortField === "time" && (
                <SortChevron data-evtx-sort-direction={sortDirection} style={{ flex: "none" }} />
              )}
            </div>
          );
        })}
      </div>
    );
  }
);
