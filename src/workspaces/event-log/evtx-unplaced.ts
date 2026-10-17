/**
 * What the Correlation view says about items that carry no timestamp (spec 8.11a, "Not placed"):
 * the row, the pane's rows and header, the copy, the Insights card's line, and when "Open in Log
 * Viewer" may be offered. Pure: no React, no stores, no IO.
 *
 * Rules, all enforced here:
 * - An unplaced item is never given a position. Nothing in this module reads or produces a time,
 *   a window or a placement; it does not import the plot, the lanes or the overview, and a source
 *   guard in the test keeps it so.
 * - Every listed item is proven by the engine's own unplaced list (its only reason is a missing
 *   timestamp), so "carries no timestamp" is said per item without a scan. What needs a trusted
 *   count is HOW MANY: the list is a bounded preview with no pager, so the count is the same
 *   reply's own `totalUnplaced`, an untrusted count is unknown (never 0), and a count below the
 *   number of items listed is contradictory and also unknown.
 * - The cap says how much it left out: "first n of u; m omitted", from the count, never from the
 *   preview's length.
 * - The spec's row caption names text-log lines. Events with no parseable timestamp are on the same
 *   list, so that sentence is used only when the list is complete and every item is a log line.
 * - The engine's item carries an origin and a reason and nothing else. There is no message
 *   column because there is no message to show (recorded deviation from 8.11a).
 */
import { getBaseName } from "../../lib/file-paths";
import type { SourceOpenMode } from "../../lib/tab-snapshot-cache";
import { engineRecordIdentity } from "./evtx-insights-data";
import {
  isEventOrigin,
  originContext,
  originDetail,
  originLabel,
  timelineOriginId,
  unplacedSummary,
  type UnplacedItem,
} from "./unified-timeline";

/**
 * Rows listed at once (spec 8.11a `UNPLACED_PREVIEW_LIMIT`). The engine's own preview is capped at
 * the same number (`MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS`, analysis_session.rs); a test keeps the two
 * together. Past this the pane says how many it left out.
 */
export const UNPLACED_LIST_LIMIT = 100;

/** The engine's unplaced list as the first reply gave it (`UnplacedListData` in useEvtxCorrelation). */
export interface UnplacedListInput {
  items: readonly UnplacedItem[];
  /** The same reply's own count, or null when it was not a trusted count. */
  total: number | null;
}

export interface UnplacedRow {
  /** Unique within the list, for React. */
  key: string;
  originId: string;
  kind: "event" | "log";
  /** The kind chip the Chains tab uses (8.13): `EVT` or `LOG`. */
  chip: "EVT" | "LOG";
  /** `originLabel`: the file (with its component) or `channel leaf (event id)`. */
  label: string;
  /** `originContext`: machine and source. */
  context: string;
  /** `originDetail`, for a tooltip. */
  detail: string;
  /** `line 7` for a log line, `record 88456` (or `no record ID`) for an event. Never a time. */
  position: string;
  /** The log file, for a log line; null for an event. */
  file: string | null;
  /** The 1-based line, for a log line; null for an event. */
  line: number | null;
}

export interface UnplacedView {
  rows: UnplacedRow[];
  /** The count the engine gave, or null when it is not known or contradicts the items listed. */
  total: number | null;
  /** The list holds every unplaced item: the count is known and equals the items listed. */
  complete: boolean;
  /** Items the count says exist that are not listed. Null when the count is not known. */
  omitted: number | null;
  /** Every listed item is a text-log line. */
  allLogLines: boolean;
  /** There is something to show: a known non-zero count, or at least one listed item. */
  present: boolean;
}

function toRow(item: UnplacedItem, index: number): UnplacedRow {
  const origin = item.origin;
  const originId = timelineOriginId(origin);
  const base = {
    key: `${originId}#${index}`,
    originId,
    label: originLabel(origin),
    context: originContext(origin),
    detail: originDetail(origin),
  };
  if (isEventOrigin(origin)) {
    const record = engineRecordIdentity(origin.recordIdText, origin.recordId);
    return {
      ...base,
      kind: "event",
      chip: "EVT",
      position: record === null ? "no record ID" : `record ${record}`,
      file: null,
      line: null,
    };
  }
  return {
    ...base,
    kind: "log",
    chip: "LOG",
    position: `line ${origin.line}`,
    file: origin.file,
    line: origin.line,
  };
}

/** The list as the pane shows it: capped rows, and what the count says about the rest. */
export function describeUnplaced(
  list: UnplacedListInput,
  limit: number = UNPLACED_LIST_LIMIT,
): UnplacedView {
  const rows = list.items.slice(0, limit).map(toRow);
  // A count below the items listed contradicts them, so it is not a count that can be trusted.
  const total = list.total !== null && list.total >= list.items.length ? list.total : null;
  return {
    rows,
    total,
    complete: total !== null && total === list.items.length && list.items.length <= limit,
    omitted: total === null ? null : Math.max(0, total - rows.length),
    allLogLines: rows.length > 0 && rows.every((row) => row.kind === "log"),
    present: (total ?? 0) > 0 || list.items.length > 0,
  };
}

function count(value: number): string {
  return value.toLocaleString();
}

/** The "Not placed (u)" row's label. An unknown count is said, never printed as 0. */
export function notPlacedLabel(view: UnplacedView): string {
  return view.total === null ? "Not placed (count unknown)" : `Not placed (${count(view.total)})`;
}

/** The row's caption. The spec's sentence names text-log lines, so it needs a complete list of them. */
export function notPlacedCaption(view: UnplacedView): string {
  return view.complete && view.allLogLines
    ? "Text-log lines without timestamps are listed, never guessed onto the timeline."
    : "Entries without timestamps are listed, never guessed onto the timeline.";
}

const NO_ORDER = "Placing them would invent an order the evidence does not support.";

/** The pane's header (8.11a). With an unknown count it says so instead of printing a number. */
export function unplacedHeader(view: UnplacedView): string {
  if (view.total === null) {
    return `The number of items that carry no timestamp is not known. ${NO_ORDER}`;
  }
  return view.total === 1
    ? "1 item carries no timestamp. Placing it would invent an order the evidence does not support."
    : `${count(view.total)} items carry no timestamp. ${NO_ORDER}`;
}

/** The line after the rows when the cap or the engine's preview left some out, or null when none. */
export function unplacedOmittedNotice(view: UnplacedView): string | null {
  const shown = view.rows.length;
  if (view.total === null) {
    return shown === 0
      ? null
      : `Showing the first ${count(shown)} unplaced entries; the number in this session is not known.`;
  }
  if (view.omitted === null || view.omitted === 0) return null;
  return `Showing the first ${count(shown)} of ${count(view.total)}; ${count(view.omitted)} omitted. The engine returns a bounded preview, so the others cannot be listed here.`;
}

/** One row as a line of text: kind, label, context, and where it is. No time. */
export function unplacedRowText(row: UnplacedRow): string {
  return `${row.chip}  ${row.label}  ${row.context}  (${row.position})`;
}

/**
 * "Copy as text": the header, the caption, one line per row, and the omitted line. The same words
 * as the pane, so a pasted copy cannot read as more complete than the list.
 */
export function unplacedCopyText(view: UnplacedView): string {
  const lines = [unplacedHeader(view), notPlacedCaption(view), ""];
  view.rows.forEach((row, index) => lines.push(`${index + 1}. ${unplacedRowText(row)}`));
  const omitted = unplacedOmittedNotice(view);
  if (omitted !== null) lines.push("", omitted);
  return lines.join("\n");
}

/**
 * The Insights card's line (8.13 item 6), or null when there is nothing to say.
 * - A complete list uses the existing `unplacedSummary` wording, with the kind split.
 * - A known count over a partial list is said from the count: the preview's length is not it.
 * - An unknown count with items listed says "at least" and that the total is not known.
 */
export function unplacedCardLine(list: UnplacedListInput): string | null {
  const view = describeUnplaced(list);
  if (!view.present) return null;
  if (view.complete) {
    return unplacedSummary({ items: [], unplaced: [...list.items], edges: [], coverageGaps: [] });
  }
  if (view.total !== null) {
    return `${count(view.total)} timeline ${view.total === 1 ? "item" : "items"} could not be placed: no timestamp`;
  }
  return `At least ${count(list.items.length)} timeline ${list.items.length === 1 ? "item" : "items"} could not be placed: no timestamp. The total is not known.`;
}

/**
 * What the Log Viewer holds: the log store's own mode, the file it has open and which lines of that
 * file are loaded.
 */
export interface LogViewerLines {
  openFilePath: string | null;
  /**
   * The log store's `sourceOpenMode`. Only "single-file" means the entries are one file, in that
   * file's order, shown by the list that consumes a scroll target. The other modes keep
   * `openFilePath` and the entries in states that look like it and are not (see
   * `openAtLineAvailability`), so the file and the lines alone cannot tell them apart.
   */
  sourceOpenMode: SourceOpenMode;
  /** The line numbers loaded for `openFilePath`. */
  lines: ReadonlySet<number>;
}

/** The Log Viewer's mode, open file and that file's loaded lines, in one pass over the entries. */
export function logViewerLines(
  openFilePath: string | null,
  sourceOpenMode: SourceOpenMode,
  entries: readonly { filePath: string; lineNumber: number }[],
): LogViewerLines {
  const lines = new Set<number>();
  for (const entry of entries) if (entry.filePath === openFilePath) lines.add(entry.lineNumber);
  return { openFilePath, sourceOpenMode, lines };
}

export interface OpenAtLine {
  enabled: boolean;
  /** Why it is disabled; null when enabled. */
  reason: string | null;
  /** The accessible name: it says "near", because the Log Viewer selects the next line it shows. */
  name: string;
}

const NO_SINGLE_FILE = "The Log Viewer has no single file open, so this line cannot be opened there.";

/** Why each mode other than "single-file" cannot open a line at its place. */
const MODE_REASONS: Record<Exclude<SourceOpenMode, "single-file" | null>, string> = {
  merged:
    "The Log Viewer is showing a merged view of several files, which does not keep each file's lines in order.",
  diff: "The Log Viewer is showing a comparison, not the file, so it cannot open this line there.",
  "aggregate-folder":
    "The Log Viewer is showing a folder of files, so it cannot open one line of one file there.",
};

/**
 * Whether "Open in Log Viewer" may be offered for a log line. The Log Viewer consumes the target in
 * one place (LogListView), only when its open file is the target's, and selects the first line it
 * SHOWS whose number is at or after the target, without looking at the file. That is the right line
 * only when the entries are the one file in file order and that list is the one mounted. So it is
 * enabled only when the log store is in "single-file" mode, its open file is exactly the line's
 * file, and it holds exactly that line. Every other state is disabled with its reason:
 * - merged: the entries are in timestamp order, untimed lines last, so with the other files hidden
 *   the open file's line 7 is loaded and a click selects some other line; with them shown it can
 *   select another file's line;
 * - diff: the diff view is mounted instead of the list, so the target would never be consumed and
 *   would fire when the diff closes;
 * - aggregate-folder, and no mode (after the diff closes): there is no single file open.
 * The button is "near line n" because a filter in the Log Viewer can hide the line itself.
 */
export function openAtLineAvailability(
  viewer: LogViewerLines,
  file: string,
  line: number,
): OpenAtLine {
  const name = `Open ${getBaseName(file)} in the Log Viewer near line ${count(line)}`;
  const no = (reason: string): OpenAtLine => ({ enabled: false, reason, name });
  if (viewer.sourceOpenMode !== "single-file") {
    return no(
      viewer.sourceOpenMode === null
        ? NO_SINGLE_FILE
        : MODE_REASONS[viewer.sourceOpenMode],
    );
  }
  if (viewer.openFilePath === null) return no(NO_SINGLE_FILE);
  if (viewer.openFilePath !== file) {
    return no(`The Log Viewer has a different file open. Open ${getBaseName(file)} there first.`);
  }
  if (!viewer.lines.has(line)) {
    return no(`Line ${count(line)} is not among the lines the Log Viewer has loaded.`);
  }
  return { enabled: true, reason: null, name };
}
