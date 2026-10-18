/**
 * The layout of the strip the Table view gives the unified timeline (EventLogWorkspace.tsx), a flex
 * column of a header, the correlation details and the list (or, with nothing placed, the unplaced
 * entries).
 *
 * A scroll container's automatic minimum size is 0, so a list that is only `flex: 1` collapses to
 * nothing once everything else fills the strip: the details at their cap did exactly that. The list
 * and the unplaced container therefore keep a floor of three rows (or all they have), and the
 * details region is capped so that, at the strip's own height, the header, the summary, the region
 * and that floor fit together. In a strip shorter than that the floor still holds and the strip
 * scrolls instead. Kept apart from the view so the workspace can share the strip's height without
 * importing the view.
 */

/** The height of the strip. */
export const UNIFIED_TIMELINE_STRIP_HEIGHT_PX = 320;
/** The rows the list (or the unplaced container) keeps while the details above it are open. */
export const UNIFIED_TIMELINE_FLOOR_ROWS = 3;
/** The header strip and the details' summary, in rows (29 px and 33 px at the default font: 2.5). */
const CHROME_ROWS = 3;
/** The least the details region is ever given, in rows. */
const MIN_DETAILS_ROWS = 2;

export interface TimelineStripLayout {
  /** The floor of the list and of the unplaced container, in px. */
  floorPx: number;
  /** The cap of the details region, in px. */
  detailsMaxPx: number;
}

/** `rowPx` is one list row as the list measures it (`getLogListMetrics(...).rowHeight + 2`). */
export function timelineStripLayout(rowPx: number): TimelineStripLayout {
  return {
    floorPx: UNIFIED_TIMELINE_FLOOR_ROWS * rowPx,
    detailsMaxPx: Math.max(
      MIN_DETAILS_ROWS * rowPx,
      UNIFIED_TIMELINE_STRIP_HEIGHT_PX - (CHROME_ROWS + UNIFIED_TIMELINE_FLOOR_ROWS) * rowPx,
    ),
  };
}
