/**
 * The text sizes of the correlation surfaces, from the user's log list font size `f` (spec 7.1,
 * 8.11, 8.12). Kept apart from the lane plot so that a surface that only needs the sizes (the unplaced
 * list, the overview strip, the Details context) does not pull the plot in with them.
 *
 * The only floors are the spec's own: captions and badge text max(10, f - 3), axis ticks
 * max(9, f - 4). Secondary labels are f - 2 with none; `f` is at least 11 in the app.
 */
import { getLogListMetrics } from "../../lib/log-accessibility";

export interface CorrelationSizes {
  f: number;
  /** f - 2: lane labels in the view, the dock's subtitle and summary, secondary text. */
  lane: number;
  /** max(10, f - 3): marker labels, captions, badge text, the dock's lane labels. */
  label: number;
  /** max(9, f - 4): axis ticks. */
  tick: number;
}

export function correlationSizes(logListFontSize: number): CorrelationSizes {
  const f = getLogListMetrics(logListFontSize).fontSize;
  return {
    f,
    lane: f - 2,
    label: Math.max(10, f - 3),
    tick: Math.max(9, f - 4),
  };
}
