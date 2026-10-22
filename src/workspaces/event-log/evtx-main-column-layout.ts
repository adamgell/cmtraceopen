/**
 * The vertical floors of the workbench's main column: the active view, and the correlation dock
 * under it (EventLogWorkspace.tsx).
 *
 * The Table grid is the primary surface and is never squeezed to nothing. It sits under the unified
 * timeline strip, whose height is fixed, and the grid is only a `flex: 1` box that is a scroll
 * container, so its automatic minimum size is 0: with the strip above it and the dock below it
 * claiming their heights, the grid took whatever was left, and that was 52 px at a 900 px window
 * with the dock open and 0 px at 700 (62 px with the dock closed). The rules below stop that:
 *
 * - Every view keeps a floor (`viewMinHeightPx`), in every layout: the Table its strip and
 *   `TABLE_GRID_FLOOR_ROWS` grid rows, the Correlation view the height its chain list and its detail
 *   header need, and the placeholder views one generic minimum.
 * - Secondary panels give way first. The dock is a shrinkable flex item whose floor is its header
 *   plus one lane (`DOCK_MIN_HEIGHT_PX`), so its rendered height is the height the user chose,
 *   clamped to what is left once the view has its floor. The chosen height is never rewritten by
 *   the layout: the store keeps it, and a taller window shows it again.
 * - When the floors together do not fit, the main column scrolls. Nothing collapses to 0.
 * - The dock's resize handle speaks for the RENDERED height (`dockHandleBounds`): it reports it,
 *   drags and steps from it, and its range is what the dock can actually be.
 *
 * Kept apart from the workspace so the numbers are tested without a layout engine, and so the
 * workspace, which is over 300 lines, only reads them.
 */
import { MAX_LOG_LIST_FONT_SIZE, getLogListMetrics } from "../../lib/log-accessibility";
import { correlationSizes } from "./evtx-correlation-sizes";
import type { EvtxColumnId } from "./evtx-columns";
import type { EvtxViewId } from "./evtx-layout-store";
import { UNIFIED_TIMELINE_STRIP_HEIGHT_PX } from "./evtx-timeline-strip";

/** The grid rows the Table view keeps, whatever else is open. */
export const TABLE_GRID_FLOOR_ROWS = 5;

/** The shortest the unified timeline strip is ever drawn, in px. */
export const TIMELINE_STRIP_MIN_HEIGHT_PX = 240;

/** The tallest the strip is drawn, as a share of the window: it never takes more than half. */
export const TIMELINE_STRIP_MAX_WINDOW_RATIO = 0.5;

/**
 * One list row as the lists measure it (`getLogListMetrics(...).rowHeight + 2`, the unit the
 * unified timeline strip's own floor is counted in).
 */
export function listRowPx(rowHeight: number): number {
  return rowHeight + 2;
}

/** What a record row of the grid is taller than a list row while the Level column is shown. */
const GRID_LEVEL_BADGE_EXTRA_PX = 4;

/**
 * One record row of the Table grid: a list row, and 4 px more while the Level column (its badge) is
 * shown. The grid sizes its virtualized rows with this (EvtxTimeline.tsx) and the floor below counts
 * its rows with it, so five rows of the floor are five rows of the grid, whichever columns it shows
 * and whatever the font.
 */
export function gridRecordRowPx(rowHeight: number, columnOrder: readonly EvtxColumnId[]): number {
  return listRowPx(rowHeight) + (columnOrder.includes("level") ? GRID_LEVEL_BADGE_EXTRA_PX : 0);
}

/**
 * The height the strip is drawn at: its own 320 px, no shorter than 240 px and no taller than half
 * the window (the minimum wins when the two meet).
 */
export function timelineStripHeightPx(windowHeight: number): number {
  return Math.max(
    TIMELINE_STRIP_MIN_HEIGHT_PX,
    Math.min(UNIFIED_TIMELINE_STRIP_HEIGHT_PX, windowHeight * TIMELINE_STRIP_MAX_WINDOW_RATIO),
  );
}

/** The least height the Table grid keeps: `TABLE_GRID_FLOOR_ROWS` of its own rows (`gridRecordRowPx`). */
export function tableGridFloorPx(gridRowPx: number): number {
  return TABLE_GRID_FLOOR_ROWS * gridRowPx;
}

/** The least height the Table view keeps: the strip, then the grid's floor. */
export function tableViewMinHeightPx(gridRowPx: number, windowHeight: number): number {
  return timelineStripHeightPx(windowHeight) + tableGridFloorPx(gridRowPx);
}

/**
 * One line of text as the lists draw it: the log list's own rule, 1.5 times the size and never
 * under 20 px (`getLogListMetrics`' row line height).
 */
function lineHeightPx(textPx: number): number {
  return Math.max(20, Math.round(textPx * 1.5));
}

/** The caption above a list: 10 px above and 6 px below one line of label text. */
function listHeaderPx(logListFontSize: number): number {
  return 16 + lineHeightPx(correlationSizes(logListFontSize).label);
}

/** The chain rows the Correlation view keeps in sight, whatever else is open. */
export const CORRELATION_LIST_FLOOR_ROWS = 3;

/** The rows a placeholder view keeps in sight: the generic minimum of a view. */
export const GENERIC_VIEW_FLOOR_ROWS = 3;

/**
 * The least height the Correlation view keeps, its minimum usable height: the chain list's header
 * and three chain rows, or the detail column's header (its top padding, the title, the key and span
 * line and the legend) with its bottom padding, whichever is larger. A chain row is 8 px of padding
 * on both sides, three lines (the badge, the title at f - 1 and the span) 3 px apart, and its 1 px
 * border.
 */
export function correlationViewMinHeightPx(logListFontSize: number): number {
  const sizes = correlationSizes(logListFontSize);
  const chainRow = 8 * 2 + 3 * 2 + 1 + 3 * lineHeightPx(sizes.f - 1);
  const list = listHeaderPx(logListFontSize) + CORRELATION_LIST_FLOOR_ROWS * chainRow;
  const detailHeader =
    10 + lineHeightPx(sizes.f + 1) + 4 + lineHeightPx(sizes.lane) + 4 + lineHeightPx(sizes.lane) + 10;
  return Math.max(list, detailHeader);
}

/**
 * The generic minimum of a view that has no layout of its own to size from (the placeholder views):
 * a list header and `GENERIC_VIEW_FLOOR_ROWS` list rows.
 */
export function genericViewMinHeightPx(logListFontSize: number): number {
  return (
    listHeaderPx(logListFontSize) +
    GENERIC_VIEW_FLOOR_ROWS * listRowPx(getLogListMetrics(logListFontSize).rowHeight)
  );
}

/** The least height the active view keeps, for any view: the one place a view's floor is decided. */
export function viewMinHeightPx(input: {
  view: EvtxViewId;
  gridRowPx: number;
  windowHeight: number;
  logListFontSize: number;
}): number {
  switch (input.view) {
    case "table":
      return tableViewMinHeightPx(input.gridRowPx, input.windowHeight);
    case "correlation":
      return correlationViewMinHeightPx(input.logListFontSize);
    default:
      return genericViewMinHeightPx(input.logListFontSize);
  }
}

/** The dock's header: 6 px of padding above and below a 24 px control. */
const DOCK_HEADER_PX = 36;
/** The dock's top border, the padding under its body, and the lane plot's border and padding. */
const DOCK_CHROME_PX = 1 + 8 + 2 + 12;
/** One lane of the dock's plot (the 24 px marker box). */
const DOCK_LANE_PX = 24;
/** The plot's axis: 2 px of margin, the tick text and its 6 px of padding. */
const DOCK_AXIS_CHROME_PX = 2 + 6;

/**
 * The dock's minimum, the one number for what it is drawn at and what it can be set to: its header
 * plus one lane of the plot, with the plot's frame and axis. Below it the dock would clip the one
 * lane it exists to show. The axis text follows the log list font size, and the minimum is taken at
 * the largest, so it does not move with the font and the stored height and the handle share it
 * (`MIN_DOCK_HEIGHT` is this).
 */
export const DOCK_MIN_HEIGHT_PX =
  DOCK_HEADER_PX +
  DOCK_CHROME_PX +
  DOCK_LANE_PX +
  DOCK_AXIS_CHROME_PX +
  correlationSizes(MAX_LOG_LIST_FONT_SIZE).tick;

export interface DockHandleBounds {
  /** The rendered height, kept inside the range. */
  value: number;
  min: number;
  max: number;
}

/**
 * What the dock's resize handle reports, from the dock as it is rendered. `renderedHeight` is the
 * dock's own box (measured), `availableHeight` what the main column leaves it once the active view
 * has its floor, and `storeMax` the most the store lets it be (half the window). The range is the
 * dock's minimum up to the least of those, so a handle that is at a bound says so by its value and
 * a step toward it changes nothing.
 */
export function dockHandleBounds(input: {
  renderedHeight: number;
  availableHeight: number;
  storeMax: number;
}): DockHandleBounds {
  const min = DOCK_MIN_HEIGHT_PX;
  const max = Math.max(min, Math.min(input.storeMax, input.availableHeight));
  return { value: Math.min(max, Math.max(min, input.renderedHeight)), min, max };
}
