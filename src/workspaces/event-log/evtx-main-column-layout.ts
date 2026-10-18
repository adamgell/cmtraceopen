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
 * - The Table view keeps `TABLE_GRID_FLOOR_ROWS` grid rows, in every layout.
 * - Secondary panels give way first. The dock is a shrinkable flex item whose floor is its header
 *   plus one lane (`dockMinHeightPx`), so its rendered height is the height the user chose,
 *   clamped to what is left once the view has its floor. The chosen height is never rewritten: the
 *   store keeps it, and a taller window shows it again.
 * - When the floors together do not fit, the main column scrolls. Nothing collapses to 0.
 *
 * Kept apart from the workspace so the numbers are tested without a layout engine, and so the
 * workspace, which is over 300 lines, only reads them.
 */
import { correlationSizes } from "./evtx-correlation-sizes";
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

/** The least height the Table grid keeps. */
export function tableGridFloorPx(rowPx: number): number {
  return TABLE_GRID_FLOOR_ROWS * rowPx;
}

/** The least height the Table view keeps: the strip, then the grid's floor. */
export function tableViewMinHeightPx(rowPx: number, windowHeight: number): number {
  return timelineStripHeightPx(windowHeight) + tableGridFloorPx(rowPx);
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
 * The dock's rendered minimum: its header plus one lane of the plot, with the plot's frame and
 * axis. It is the least the dock is drawn at when the window is too short for its chosen height;
 * below it the dock would clip the one lane it exists to show. The tick text follows the user's
 * log list font size.
 */
export function dockMinHeightPx(logListFontSize: number): number {
  return (
    DOCK_HEADER_PX +
    DOCK_CHROME_PX +
    DOCK_LANE_PX +
    DOCK_AXIS_CHROME_PX +
    correlationSizes(logListFontSize).tick
  );
}
