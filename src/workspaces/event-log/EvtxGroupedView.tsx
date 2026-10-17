/**
 * The Grouped view (spec section 8.8): one summary row per group of the visible records, sorted by
 * severity, each expandable to its 8 most recent events and, for an Event ID group, a "Show all
 * {n} in table" action that applies the Event ID filter and switches to the Table view.
 *
 * Rows are virtualized with TanStack Virtual, as the table is. Every row kind has a fixed height
 * derived from `getLogListMetrics`, set inline so the DOM matches what the virtualizer assumes;
 * an expanded group's events are rows of their own, so expanding one group renders only the rows
 * that fit the viewport and never another group's events.
 *
 * Keyboard: one tab stop roves over the controls (each group's disclosure button and each Show all
 * button). Up and Down move between them, Home and End jump to the ends, Right expands and Left
 * collapses a group (Left on Show all returns to its group). Enter and Space are the buttons' own.
 */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { makeStyles, tokens } from "@fluentui/react-components";
import {
  ChevronDown12Regular,
  ChevronRight12Regular,
  Link12Regular,
} from "@fluentui/react-icons";
import {
  getLogListMetrics,
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  type LogListMetrics,
} from "../../lib/log-accessibility";
import { contrastRatio, readableOn } from "../../lib/color-contrast";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import { EVTX_GROUP_LABELS, type EvtxGroupField } from "./evtx-filter";
import {
  buildGroupSummaries,
  classifyChannelReads,
  groupedViewField,
  GROUP_TREND_BINS,
  trendWindowLabel,
  type EvtxGroupSummary,
  type GroupSummariesInput,
  type GroupSummariesResult,
  type TrendBin,
} from "./evtx-group-summaries";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { isNewestOnlyGapReason, useEvtxStore } from "./evtx-store";
import { formatEventTime, timeZoneLabel, type EvtxTimeZoneMode } from "./evtx-time";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxRecord } from "./types";

/** Rows rendered beyond each edge of the viewport. */
export const GROUPED_OVERSCAN = 10;
/** Spec 11: derivations are debounced at 75 ms during live tail (DIAGNOSIS_DEBOUNCE_MS). */
export const GROUPED_DEBOUNCE_MS = 75;

/** Spec 8.8 column widths in px; the typical message takes the rest. */
const COLUMN = {
  chevron: 16,
  level: 20,
  id: 52,
  key: 170,
  count: 56,
  trend: 168,
  lastSeen: 120,
} as const;
/**
 * The gap between columns. 4 px puts the ID column at 12 + 16 + 4 + 20 + 4 = 56 px, the left
 * padding spec 8.8 gives the expanded events, so they line up under the ID.
 */
const COLUMN_GAP = 4;
const ROW_PADDING_X = 12;
const ITEMS_INDENT = 56;
const ITEMS_PADDING_TOP = 4;
const ITEMS_PADDING_BOTTOM = 6;
const TREND_HEIGHT = 18;
/** Each of the 24 bins is 7 units wide: a 6 unit bar and a 1 unit gap, 168 in all. */
const TREND_BIN_UNITS = COLUMN.trend / GROUP_TREND_BINS;

export interface GroupedRowHeights {
  header: number;
  /** A group row: spec 8.8 padding 6 px above and below, plus its 1 px bottom border. */
  group: number;
  /** One expanded event line, before the container's own padding. */
  item: number;
}

export function groupedRowHeights(metrics: LogListMetrics): GroupedRowHeights {
  return {
    header: metrics.headerLineHeight + 2,
    group: metrics.rowLineHeight + 12 + 1,
    item: metrics.rowLineHeight,
  };
}

type GroupedRow =
  | { kind: "group"; summary: EvtxGroupSummary; expanded: boolean }
  | {
      kind: "item";
      summary: EvtxGroupSummary;
      record: EvtxRecord;
      first: boolean;
      last: boolean;
    }
  | { kind: "more"; summary: EvtxGroupSummary };

function rowKey(row: GroupedRow): string {
  switch (row.kind) {
    case "group":
      return `group:${row.summary.key}`;
    case "item":
      return `item:${row.summary.key}:${row.record.id}`;
    case "more":
      return `more:${row.summary.key}`;
  }
}

/** The height a row is drawn at; the container's padding and closing border sit on its ends. */
function rowHeight(row: GroupedRow, heights: GroupedRowHeights): number {
  switch (row.kind) {
    case "group":
      return heights.group;
    case "item":
      return (
        heights.item +
        (row.first ? ITEMS_PADDING_TOP : 0) +
        (row.last ? ITEMS_PADDING_BOTTOM + 1 : 0)
      );
    case "more":
      return heights.item + ITEMS_PADDING_BOTTOM + 1;
  }
}

/** Text colors for one surface: primary text and secondary text, both at 4.5:1 or better. */
export interface GroupedSurface {
  background: string;
  ink: string;
  secondary: string;
}

export interface GroupedPalette {
  /** Collapsed group rows and the view's own messages (Background1). */
  row: GroupedSurface;
  /** Expanded group rows and the header (Background3). */
  expanded: GroupedSurface;
  /** The expanded events and Show all (Background2). */
  items: GroupedSurface;
}

/**
 * Text colors per surface. Primary text is `colorNeutralForeground1` where it reaches 4.5:1 and
 * otherwise the first of Foreground2 or black or white that does: solarized-dark's Foreground1 is
 * 4.11:1 on its Background2 and Background3, where its Foreground2 is 4.86:1. Secondary text is
 * Foreground2 under the same rule.
 */
export function buildGroupedPalette(theme: CMTraceTheme): GroupedPalette {
  const surface = (background: string): GroupedSurface => {
    const resolved = resolveToken(background, theme);
    const readable = (preferred: string, fallback: string): string => {
      for (const candidate of [preferred, fallback]) {
        if (contrastRatio(resolveToken(candidate, theme), resolved) >= 4.5) return candidate;
      }
      return readableOn(resolved, resolveToken(preferred, theme), 4.5);
    };
    return {
      background,
      ink: readable(tokens.colorNeutralForeground1, tokens.colorNeutralForeground2),
      secondary: readable(tokens.colorNeutralForeground2, tokens.colorNeutralForeground1),
    };
  };
  return {
    row: surface(tokens.colorNeutralBackground1),
    expanded: surface(tokens.colorNeutralBackground3),
    items: surface(tokens.colorNeutralBackground2),
  };
}

const visuallyHidden: CSSProperties = {
  position: "absolute",
  width: "1px",
  height: "1px",
  overflow: "hidden",
  clipPath: "inset(50%)",
  whiteSpace: "nowrap",
};

const numeric: CSSProperties = {
  fontFamily: tokens.fontFamilyNumeric,
  fontVariantNumeric: "tabular-nums",
};

const ellipsis: CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  minWidth: 0,
};

const useStyles = makeStyles({
  disclosure: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    width: `${COLUMN.chevron}px`,
    height: `${COLUMN.chevron}px`,
    padding: 0,
    border: "none",
    borderRadius: "2px",
    background: "none",
    color: tokens.colorNeutralForeground2,
    cursor: "pointer",
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
    },
  },
  itemRow: {
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "-2px",
    },
  },
  showAll: {
    padding: 0,
    border: "none",
    background: "none",
    fontFamily: "inherit",
    fontWeight: 600,
    cursor: "pointer",
    ":hover": { textDecorationLine: "underline" },
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
    },
  },
});

/** What the key column shows: the group's value, or for an Event ID group its provider(s). */
function keyColumnLabel(field: EvtxGroupField): string {
  return field === "eventId" ? "Provider" : EVTX_GROUP_LABELS[field];
}

function keyColumnValue(summary: EvtxGroupSummary): string {
  if (summary.field !== "eventId") return summary.value;
  if (summary.providers.length === 1) return summary.providers[0] || "(no provider)";
  return `${summary.providers.length} providers`;
}

function idColumnValue(summary: EvtxGroupSummary): string {
  return summary.eventIds.length === 1
    ? String(summary.eventIds[0])
    : `${summary.eventIds.length} IDs`;
}

function plural(count: number, one: string, many: string): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

/** The trend in words, for assistive technology: the sparkline itself is hidden from it. */
function trendDescription(summary: EvtxGroupSummary, windowLabel: string): string {
  const counted = summary.trend.filter((bin): bin is number => bin !== null && bin > 0);
  const unknown = summary.trend.filter((bin) => bin === null).length;
  const parts = [
    counted.length === 0
      ? "no events placed"
      : `${counted.length} of ${GROUP_TREND_BINS} intervals had events, busiest ${Math.max(...counted)}`,
  ];
  if (unknown > 0) parts.push(`${plural(unknown, "interval", "intervals")} not read`);
  if (summary.unplaced > 0) {
    parts.push(`${plural(summary.unplaced, "event", "events")} not placed`);
  }
  return `${windowLabel} trend: ${parts.join("; ")}`;
}

/**
 * The 24-bin sparkline. A counted bin is a bar scaled to the group's busiest bin (never under
 * 2 px); a bin read and empty is a 1 px baseline; a bin not read is left blank, so an unread span
 * never looks like zero.
 */
function TrendSparkline({
  trend,
  color,
  baseline,
}: {
  trend: readonly TrendBin[];
  color: string;
  baseline: string;
}) {
  const peak = Math.max(0, ...trend.map((bin) => bin ?? 0));
  const barWidth = TREND_BIN_UNITS - 1;
  return (
    <svg
      aria-hidden="true"
      width={COLUMN.trend}
      height={TREND_HEIGHT}
      viewBox={`0 0 ${COLUMN.trend} ${TREND_HEIGHT}`}
      style={{ display: "block", flexShrink: 0 }}
    >
      {trend.map((bin, index) => {
        if (bin === null) return null;
        const x = index * TREND_BIN_UNITS;
        if (bin === 0) {
          return (
            <rect
              key={index}
              data-trend-zero=""
              data-bin={index}
              x={x}
              y={TREND_HEIGHT - 1}
              width={barWidth}
              height={1}
              style={{ fill: baseline }}
            />
          );
        }
        const height = Math.min(
          TREND_HEIGHT,
          Math.max(2, Math.round((bin / peak) * TREND_HEIGHT)),
        );
        return (
          <rect
            key={index}
            data-trend-bar=""
            data-bin={index}
            x={x}
            y={TREND_HEIGHT - height}
            width={barWidth}
            height={height}
            style={{ fill: color }}
          />
        );
      })}
    </svg>
  );
}

export interface EvtxGroupedTableProps {
  result: GroupSummariesResult;
  /** The window as the trend header names it, for example "24 h". */
  windowLabel: string;
  timeZoneMode: EvtxTimeZoneMode;
  metrics: LogListMetrics;
  /** The active theme: the level colors come from its visual tokens, text from its palette. */
  theme: CMTraceTheme;
  /**
   * Applies an Event ID filter for the group and shows the table. Offered for Event ID groups
   * only: no existing filter selects exactly a provider or a day, and the channel and level
   * filters would overwrite the operator's own selection.
   */
  onShowAll?: (eventId: number) => void;
  /**
   * Records with an Exact or Candidate correlation edge, for the "Linked" badge. Only a complete
   * edge index may supply it: the edges the UI holds are a bounded preview, and a badge derived
   * from a prefix would leave linked events unmarked. Omitted, no event is badged.
   */
  linkedRecordIds?: ReadonlySet<number>;
  /** The selected record (the store's `selectedRecordId`, shared by every view). */
  selectedRecordId?: number | null;
  /** Selects an expanded event: clicking its row, or Enter or Space on it (spec 9). */
  onSelectRecord?: (id: number) => void;
}

export function EvtxGroupedTable({
  result,
  windowLabel,
  timeZoneMode,
  metrics,
  theme,
  onShowAll,
  linkedRecordIds,
  selectedRecordId = null,
  onSelectRecord,
}: EvtxGroupedTableProps) {
  const styles = useStyles();
  const visual = useMemo(() => buildEvtxVisualTokens(theme), [theme]);
  const palette = useMemo(() => buildGroupedPalette(theme), [theme]);
  const { field, summaries } = result;
  const heights = useMemo(() => groupedRowHeights(metrics), [metrics]);
  const f = metrics.fontSize;
  const rowFontSize = Math.max(10, f - 1);
  const headerFontSize = Math.max(10, f - 2);
  const lastSeenFontSize = Math.max(9, f - 3);
  const badgeFontSize = Math.max(10, f - 3);
  const showAllAvailable = field === "eventId" && onShowAll !== undefined;

  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set());
  const toggle = useCallback((key: string, open?: boolean) => {
    setExpanded((current) => {
      const isOpen = current.has(key);
      const next = open ?? !isOpen;
      if (next === isOpen) return current;
      const updated = new Set(current);
      if (next) updated.add(key);
      else updated.delete(key);
      return updated;
    });
  }, []);

  const rows = useMemo(() => {
    const list: GroupedRow[] = [];
    for (const summary of summaries) {
      const open = expanded.has(summary.key);
      list.push({ kind: "group", summary, expanded: open });
      if (!open) continue;
      summary.recent.forEach((record, index) => {
        list.push({
          kind: "item",
          summary,
          record,
          first: index === 0,
          last: index === summary.recent.length - 1 && !showAllAvailable,
        });
      });
      if (showAllAvailable) list.push({ kind: "more", summary });
    }
    return list;
  }, [summaries, expanded, showAllAvailable]);
  const rowKeys = useMemo(() => rows.map(rowKey), [rows]);
  const indexByKey = useMemo(
    () => new Map(rowKeys.map((key, index) => [key, index] as const)),
    [rowKeys],
  );

  const scrollerRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  // Both depend on the rows and the row heights: a new identity makes the virtualizer recompute
  // every offset when a group opens or the font size changes.
  const getItemKey = useCallback((index: number) => rowKeys[index] ?? index, [rowKeys, heights]);
  const estimateSize = useCallback(
    (index: number) => (rows[index] ? rowHeight(rows[index], heights) : heights.group),
    [rows, heights],
  );
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollerRef.current,
    estimateSize,
    getItemKey,
    overscan: GROUPED_OVERSCAN,
  });

  // The roving tab stop: the active row, else the first row.
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const activeIndex = useMemo(() => {
    const index = activeKey === null ? undefined : indexByKey.get(activeKey);
    if (index !== undefined && rows[index]) return index;
    return rows.length > 0 ? 0 : -1;
  }, [activeKey, indexByKey, rows]);

  // What takes focus in a row: an expanded event's row itself, otherwise the row's button.
  const focusTarget = useCallback((index: number): HTMLElement | null => {
    const element = scrollerRef.current?.querySelector<HTMLElement>(`[data-index="${index}"]`);
    if (!element) return null;
    return element.dataset.evtxGroupedRow === "item"
      ? element
      : element.querySelector<HTMLElement>("button");
  }, []);

  const focusRow = useCallback(
    (index: number) => {
      const key = rowKeys[index];
      if (key === undefined) return;
      setActiveKey(key);
      virtualizer.scrollToIndex(index, { align: "auto" });
      const element = focusTarget(index);
      if (element) element.focus();
      else if (typeof requestAnimationFrame === "function") {
        requestAnimationFrame(() => focusTarget(index)?.focus());
      }
    },
    [focusTarget, rowKeys, virtualizer],
  );

  const selectRecord = (index: number, id: number) => {
    setActiveKey(rowKeys[index]);
    onSelectRecord?.(id);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const rowElement =
      event.target instanceof HTMLElement
        ? event.target.closest<HTMLElement>("[data-index]")
        : null;
    const current = rowElement ? Number(rowElement.dataset.index) : activeIndex;
    const row = rows[current];
    if (!row) return;
    let target: number | null = null;
    switch (event.key) {
      case "ArrowDown":
        target = Math.min(rows.length - 1, current + 1);
        break;
      case "ArrowUp":
        target = Math.max(0, current - 1);
        break;
      case "Home":
        target = 0;
        break;
      case "End":
        target = rows.length - 1;
        break;
      case "ArrowRight":
        if (row.kind === "group" && !row.expanded) toggle(row.summary.key, true);
        break;
      case "ArrowLeft":
        if (row.kind === "group") {
          if (row.expanded) toggle(row.summary.key, false);
        } else {
          target = indexByKey.get(`group:${row.summary.key}`) ?? null;
        }
        break;
      case "Enter":
      case " ":
        // A button's own Enter and Space click it; an expanded event's row selects its record.
        if (row.kind !== "item") return;
        selectRecord(current, row.record.id);
        break;
      default:
        return;
    }
    event.preventDefault();
    if (target !== null && target >= 0) focusRow(target);
  };

  // A collapsed group can take the active control's row away; keep the tab stop on a real row.
  useEffect(() => {
    if (activeKey !== null && !indexByKey.has(activeKey)) setActiveKey(null);
  }, [activeKey, indexByKey]);

  const keyLabel = keyColumnLabel(field);
  const zoneLabel = timeZoneLabel(timeZoneMode);
  const virtualRows = virtualizer.getVirtualItems();
  // The one tab stop must be in the DOM. When the active row has scrolled out of the rendered
  // window, the first rendered row takes it, so Tab never skips the view.
  const tabStop = virtualRows.some((virtualRow) => virtualRow.index === activeIndex)
    ? activeIndex
    : (virtualRows[0]?.index ?? activeIndex);

  const headerCell = (label: string, width: number | null, hidden = false, alignEnd = false) => (
    <div
      role="columnheader"
      style={{
        ...(width === null ? { flex: "1 1 auto", minWidth: 0 } : { width: `${width}px`, flexShrink: 0 }),
        ...ellipsis,
        textAlign: alignEnd ? "right" : "left",
        position: hidden ? "relative" : undefined,
      }}
    >
      {hidden ? <span style={visuallyHidden}>{label}</span> : label}
    </div>
  );

  const renderGroup = (row: Extract<GroupedRow, { kind: "group" }>, index: number) => {
    const { summary } = row;
    const level = visual.levels[summary.level];
    const Icon = level.RailIcon;
    const surface = row.expanded ? palette.expanded : palette.row;
    const name = `${EVTX_GROUP_LABELS[field]} ${summary.value}, ${plural(summary.count, "event", "events")}`;
    return (
      <div
        key={rowKeys[index]}
        role="row"
        aria-rowindex={index + 2}
        data-index={index}
        data-evtx-grouped-row="group"
        data-group-value={summary.value}
        onClick={() => {
          setActiveKey(rowKeys[index]);
          toggle(summary.key);
        }}
        style={{
          display: "flex",
          alignItems: "center",
          gap: `${COLUMN_GAP}px`,
          height: `${heights.group}px`,
          boxSizing: "border-box",
          padding: `6px ${ROW_PADDING_X}px`,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: surface.background,
          color: surface.ink,
          fontSize: `${rowFontSize}px`,
          fontWeight: row.expanded ? 600 : 400,
          lineHeight: `${metrics.rowLineHeight}px`,
          cursor: "pointer",
        }}
      >
        <div role="gridcell" style={{ width: `${COLUMN.chevron}px`, flexShrink: 0 }}>
          <button
            type="button"
            className={styles.disclosure}
            aria-expanded={row.expanded}
            aria-label={name}
            tabIndex={index === tabStop ? 0 : -1}
            onFocus={() => setActiveKey(rowKeys[index])}
          >
            {row.expanded ? (
              <ChevronDown12Regular aria-hidden="true" />
            ) : (
              <ChevronRight12Regular aria-hidden="true" />
            )}
          </button>
        </div>
        <div
          role="gridcell"
          style={{ width: `${COLUMN.level}px`, flexShrink: 0, display: "flex", justifyContent: "center" }}
        >
          <span
            role="img"
            aria-label={summary.level}
            style={{ display: "inline-flex", color: level.railIconColor }}
          >
            <Icon aria-hidden="true" />
          </span>
        </div>
        <div
          role="gridcell"
          data-evtx-grouped-text="id"
          style={{
            ...numeric,
            ...ellipsis,
            width: `${COLUMN.id}px`,
            flexShrink: 0,
            fontWeight: 700,
            color: surface.ink,
          }}
        >
          {idColumnValue(summary)}
        </div>
        <div
          role="gridcell"
          data-evtx-grouped-text="key"
          title={keyColumnValue(summary)}
          style={{
            ...ellipsis,
            width: `${COLUMN.key}px`,
            flexShrink: 0,
            color: surface.secondary,
          }}
        >
          {keyColumnValue(summary)}
        </div>
        <div
          role="gridcell"
          data-evtx-grouped-message=""
          data-evtx-grouped-text={summary.typicalMessage ? "message" : "no message"}
          title={summary.typicalMessage || undefined}
          style={{
            ...ellipsis,
            flex: "1 1 auto",
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            color: summary.typicalMessage ? surface.ink : surface.secondary,
          }}
        >
          {summary.typicalMessage || "(no message)"}
        </div>
        <div
          role="gridcell"
          data-evtx-grouped-text="count"
          style={{
            ...numeric,
            width: `${COLUMN.count}px`,
            flexShrink: 0,
            textAlign: "right",
            color: surface.ink,
          }}
        >
          {summary.count.toLocaleString()}
        </div>
        <div
          role="gridcell"
          style={{ width: `${COLUMN.trend}px`, flexShrink: 0, position: "relative" }}
        >
          <TrendSparkline
            trend={summary.trend}
            color={level.barColor}
            baseline={tokens.colorNeutralStrokeAccessible}
          />
          <span style={visuallyHidden}>{trendDescription(summary, windowLabel)}</span>
        </div>
        <div
          role="gridcell"
          data-evtx-grouped-last-seen=""
          data-evtx-grouped-text="last seen"
          title={
            summary.lastSeenMs === null
              ? undefined
              : `${formatEventTime(summary.lastSeenMs, timeZoneMode)} ${zoneLabel}`
          }
          style={{
            ...numeric,
            ...ellipsis,
            width: `${COLUMN.lastSeen}px`,
            flexShrink: 0,
            fontSize: `${lastSeenFontSize}px`,
            color: surface.secondary,
          }}
        >
          {summary.lastSeenMs === null
            ? "Unknown"
            : formatEventTime(summary.lastSeenMs, timeZoneMode).slice(0, 19)}
        </div>
      </div>
    );
  };

  const containerRow = (
    row: Extract<GroupedRow, { kind: "item" | "more" }>,
    index: number,
    first: boolean,
    last: boolean,
    content: ReactNode,
  ) => {
    const item = row.kind === "item" ? row : null;
    const selected = item !== null && item.record.id === selectedRecordId;
    return (
      <div
        key={rowKeys[index]}
        role="row"
        aria-rowindex={index + 2}
        // An expanded event is a selectable row (spec 9); it takes focus itself, as the table's do.
        aria-selected={item === null ? undefined : selected}
        tabIndex={item === null ? undefined : index === tabStop ? 0 : -1}
        className={item === null ? undefined : styles.itemRow}
        onFocus={item === null ? undefined : () => setActiveKey(rowKeys[index])}
        onClick={item === null ? undefined : () => selectRecord(index, item.record.id)}
        data-index={index}
        data-evtx-grouped-row={row.kind}
        data-group-value={row.summary.value}
        style={{
          display: "flex",
          alignItems: "center",
          height: `${rowHeight(row, heights)}px`,
          boxSizing: "border-box",
          // Spec 8.8: the container's padding is 4px 0 6px 56px.
          padding: `${first ? ITEMS_PADDING_TOP : 0}px 0 ${last ? ITEMS_PADDING_BOTTOM : 0}px ${ITEMS_INDENT}px`,
          borderBottom: last ? `1px solid ${tokens.colorNeutralStroke2}` : undefined,
          // Spec 6.2 / Q-1: a selected row takes the selection triplet, as the table's does.
          backgroundColor: selected ? visual.selection.background : palette.items.background,
          boxShadow: selected ? `inset 3px 0 0 ${visual.selection.border}` : undefined,
          color: selected ? visual.selection.foreground : palette.items.ink,
          cursor: item === null ? undefined : "pointer",
          fontSize: `${rowFontSize}px`,
          lineHeight: `${metrics.rowLineHeight}px`,
        }}
      >
        <div
          role="gridcell"
          aria-colspan={8}
          style={{ display: "flex", alignItems: "center", gap: "8px", width: "100%", minWidth: 0 }}
        >
          {content}
        </div>
      </div>
    );
  };

  const renderItem = (row: Extract<GroupedRow, { kind: "item" }>, index: number) => {
    const { record } = row;
    const linked = linkedRecordIds?.has(record.id) ?? false;
    const selected = record.id === selectedRecordId;
    const ink = selected ? visual.selection.foreground : palette.items.ink;
    const secondary = selected ? visual.selection.foreground : palette.items.secondary;
    return containerRow(
      row,
      index,
      row.first,
      row.last,
      <>
        <span
          data-evtx-grouped-text="time"
          style={{
            ...numeric,
            flexShrink: 0,
            whiteSpace: "nowrap",
            color: secondary,
          }}
        >
          {record.timestampEpoch > 0
            ? formatEventTime(record.timestampEpoch, timeZoneMode, record.timestamp)
            : "No timestamp"}
        </span>
        <span
          data-testid="evtx-grouped-item-message"
          data-evtx-grouped-text={record.message.trim() ? "message" : "no message"}
          title={record.message || undefined}
          style={{
            ...ellipsis,
            flex: "1 1 auto",
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            color: record.message.trim() ? ink : secondary,
          }}
        >
          {record.message.trim() ? record.message : "(no message)"}
        </span>
        {linked && (
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "3px",
              flexShrink: 0,
              padding: "0 6px",
              borderRadius: "4px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              backgroundColor: palette.expanded.background,
              color: palette.expanded.secondary,
              fontSize: `${badgeFontSize}px`,
              lineHeight: `${badgeFontSize + 6}px`,
              fontWeight: 600,
            }}
          >
            <Link12Regular aria-hidden="true" />
            Linked
          </span>
        )}
      </>,
    );
  };

  const renderMore = (row: Extract<GroupedRow, { kind: "more" }>, index: number) =>
    containerRow(
      row,
      index,
      false,
      true,
      <button
        type="button"
        className={styles.showAll}
        tabIndex={index === tabStop ? 0 : -1}
        onFocus={() => setActiveKey(rowKeys[index])}
        onClick={() => onShowAll?.(row.summary.eventIds[0])}
        // Inline, so the color is explicit where it is measured; hover and focus are in the class.
        style={{ fontSize: `${rowFontSize}px`, color: tokens.colorBrandForegroundLink }}
      >
        {`Show all ${row.summary.count.toLocaleString()} in table`}
      </button>,
    );

  return (
    <div
      role="grid"
      aria-label={`Grouped events, ${plural(summaries.length, "group", "groups")} by ${EVTX_GROUP_LABELS[field]}`}
      aria-rowcount={rows.length + 1}
      onKeyDown={onKeyDown}
      style={{
        display: "flex",
        flexDirection: "column",
        flex: "1 1 auto",
        minHeight: 0,
        height: "100%",
        fontFamily: LOG_UI_FONT_FAMILY,
        backgroundColor: tokens.colorNeutralBackground1,
      }}
    >
      <div
        ref={headerRef}
        role="rowgroup"
        style={{ overflow: "hidden", flexShrink: 0, scrollbarGutter: "stable" }}
      >
        <div
          role="row"
          aria-rowindex={1}
          data-evtx-grouped-header=""
          style={{
            display: "flex",
            alignItems: "center",
            gap: `${COLUMN_GAP}px`,
            height: `${heights.header}px`,
            boxSizing: "border-box",
            padding: `0 ${ROW_PADDING_X}px`,
            backgroundColor: palette.expanded.background,
            borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
            color: palette.expanded.secondary,
            fontSize: `${headerFontSize}px`,
            fontWeight: 600,
          }}
        >
          {headerCell("Expand", COLUMN.chevron, true)}
          {headerCell("Level", COLUMN.level, true)}
          {headerCell("ID", COLUMN.id)}
          {headerCell(keyLabel, COLUMN.key)}
          {headerCell("Typical message", null)}
          {headerCell("Count", COLUMN.count, false, true)}
          {headerCell(`${windowLabel} trend`, COLUMN.trend)}
          {headerCell("Last seen", COLUMN.lastSeen)}
        </div>
      </div>
      <div
        ref={scrollerRef}
        role="rowgroup"
        data-evtx-grouped-scroller=""
        onScroll={(event) => {
          if (headerRef.current) headerRef.current.scrollLeft = event.currentTarget.scrollLeft;
        }}
        style={{ flex: "1 1 auto", minHeight: 0, overflow: "auto", scrollbarGutter: "stable" }}
      >
        <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: "100%",
              transform: `translateY(${virtualRows[0]?.start ?? 0}px)`,
            }}
          >
            {virtualRows.map((virtualRow) => {
              const row = rows[virtualRow.index];
              if (!row) return null;
              if (row.kind === "group") return renderGroup(row, virtualRow.index);
              if (row.kind === "item") return renderItem(row, virtualRow.index);
              return renderMore(row, virtualRow.index);
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * The first value is used at once; a later change applies the newest value `ms` after the change
 * that started the wait. Changes during the wait do not restart it, so a live tail that never goes
 * quiet still updates the view every `ms` instead of starving it.
 */
function useSettledValue<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  const latest = useRef(value);
  useEffect(() => {
    latest.current = value;
  });
  const pending = !Object.is(settled, value);
  useEffect(() => {
    if (!pending) return undefined;
    const timer = setTimeout(() => setSettled(latest.current), ms);
    return () => clearTimeout(timer);
  }, [pending, settled, ms]);
  return settled;
}

export interface EvtxGroupedViewProps {
  /** The visible records, as the table shows them (empty while loading). */
  records: EvtxRecord[];
  /** The workspace clock snapshot: a finite time window ends here. */
  nowEpoch: number;
}

/** The Grouped view, wired to the Event Logs stores. */
export function EvtxGroupedView({ records, nowEpoch }: EvtxGroupedViewProps) {
  const loadedRecords = useEvtxStore((s) => s.records);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const groupBy = useEvtxStore((s) => s.groupBy);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const channels = useEvtxStore((s) => s.channels);
  const coverageDetails = useEvtxStore((s) => s.coverageDetails);
  const sourceManifest = useEvtxStore((s) => s.sourceManifest);
  const coverageGaps = useEvtxStore((s) => s.coverageGaps);
  const tailCoverageGaps = useEvtxStore((s) => s.tailCoverageGaps);
  const setFilterEventIds = useEvtxStore((s) => s.setFilterEventIds);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const setSelectedRecordId = useEvtxStore((s) => s.setSelectedRecordId);
  const setActiveView = useEvtxLayoutStore((s) => s.setActiveView);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const themeId = useUiStore((s) => s.themeId);
  const theme = useMemo(() => getThemeById(themeId), [themeId]);
  const palette = useMemo(() => buildGroupedPalette(theme), [theme]);

  const channelRead = useMemo(
    () =>
      classifyChannelReads({
        remoteMachine,
        channels,
        coverageDetails,
        manifestCoverage: sourceManifest?.coverage ?? [],
        legacyCoverage: coverageGaps,
        tailCoverage: tailCoverageGaps,
        isNewestOnlyReason: isNewestOnlyGapReason,
      }),
    [remoteMachine, channels, coverageDetails, sourceManifest, coverageGaps, tailCoverageGaps],
  );
  const field = groupedViewField(groupBy);
  const input = useMemo<GroupSummariesInput>(
    () => ({
      records,
      loadedRecords,
      field,
      timeZoneMode,
      timeWindow,
      nowMs: nowEpoch,
      sourceMode,
      channelRead,
    }),
    [
      records,
      loadedRecords,
      field,
      timeZoneMode,
      timeWindow,
      nowEpoch,
      sourceMode,
      channelRead,
    ],
  );
  const settled = useSettledValue(input, GROUPED_DEBOUNCE_MS);
  const result = useMemo(() => buildGroupSummaries(settled), [settled]);
  const showAll = useCallback(
    (eventId: number) => {
      setFilterEventIds(String(eventId));
      setActiveView("table");
    },
    [setFilterEventIds, setActiveView],
  );

  const status = (text: string) => (
    <div
      role="status"
      style={{
        padding: "20px",
        textAlign: "center",
        fontFamily: LOG_UI_FONT_FAMILY,
        fontSize: `${metrics.fontSize}px`,
        // Secondary text, not Foreground3: that is 3.03:1 on dracula's Background1.
        color: palette.row.secondary,
      }}
    >
      {text}
    </div>
  );
  if (isLoading) return status("Loading events...");
  if (loadedRecords.length === 0) return status("No event log records loaded.");
  if (records.length === 0) return status("No records match the current filters.");

  return (
    <EvtxGroupedTable
      result={result}
      windowLabel={trendWindowLabel(timeWindow)}
      timeZoneMode={timeZoneMode}
      metrics={metrics}
      theme={theme}
      onShowAll={showAll}
      selectedRecordId={selectedRecordId}
      onSelectRecord={setSelectedRecordId}
    />
  );
}
