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
import { EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT } from "./evtx-timeline-paging";
import {
  isEventOrigin,
  originContext,
  originDetail,
  originLabel,
  timelineOriginId,
  unplacedSummary,
  type UnplacedItem,
} from "./unified-timeline";

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

const NO_RUN: UnplacedView = {
  rows: [],
  total: null,
  complete: false,
  omitted: null,
  allLogLines: false,
  present: false,
};

/**
 * The list as the pane shows it: capped rows, and what the count says about the rest.
 *
 * `null` is no run at all (no session, nothing published), which has nothing to show. It is NOT the
 * same as a run whose count is unknown, `{ items: [], total: null }`: that run may have unplaced
 * items nobody counted, so it is shown, as unknown. The two are told apart by type, not by a value.
 */
export function describeUnplaced(
  list: UnplacedListInput | null,
  limit: number = EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT,
): UnplacedView {
  if (list === null) return NO_RUN;
  const rows = list.items.slice(0, limit).map(toRow);
  // A count below the items listed contradicts them, so it is not a count that can be trusted.
  const total = list.total !== null && list.total >= list.items.length ? list.total : null;
  return {
    rows,
    total,
    complete: total !== null && total === list.items.length && list.items.length <= limit,
    omitted: total === null ? null : Math.max(0, total - rows.length),
    allLogLines: rows.length > 0 && rows.every((row) => row.kind === "log"),
    // Only a counted 0 with nothing listed has nothing to show. An unknown count is not 0.
    present: !(total === 0 && list.items.length === 0),
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
function unplacedRowText(row: UnplacedRow): string {
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
 * The Insights card's line (8.13 item 6), or null when there is nothing to say (no run, or a
 * counted 0 with nothing listed).
 * - A complete list uses the existing `unplacedSummary` wording, with the kind split.
 * - A known count over a partial list is said from the count: the preview's length is not it.
 * - An unknown count with items listed says "at least" and that the total is not known.
 * - An unknown count with nothing listed says that the number is not known, in the words
 *   UnifiedTimelineView uses for the same case. It is not a zero.
 */
export function unplacedCardLine(list: UnplacedListInput | null): string | null {
  const view = describeUnplaced(list);
  if (list === null || !view.present) return null;
  if (view.complete) {
    return unplacedSummary({ items: [], unplaced: [...list.items], edges: [], coverageGaps: [] });
  }
  if (view.total !== null) {
    return `${count(view.total)} timeline ${view.total === 1 ? "item" : "items"} could not be placed: no timestamp`;
  }
  if (list.items.length === 0) {
    return "The number of timeline items that could not be placed is not known";
  }
  return `At least ${count(list.items.length)} timeline ${list.items.length === 1 ? "item" : "items"} could not be placed: no timestamp. The total is not known.`;
}

/**
 * What the Log Viewer holds: the log store's own mode, the file it has open, which lines of that
 * file are loaded, and whether the entries are in line order.
 */
export interface LogViewerLines {
  openFilePath: string | null;
  /**
   * The log store's `sourceOpenMode`. The modes other than "single-file" keep `openFilePath` and the
   * entries in states that look like a file and are not (see `openAtLineAvailability`), and diff
   * mounts a different view altogether. But "single-file" alone does not guarantee that the entries
   * are in the file's order either: the aggregate firewall tail (`applyFirewallTail`, log-store.ts)
   * writes a file's rows into its "single-file" snapshot in the aggregate's timestamp order, untimed
   * rows last, and the file sidebar restores that snapshot as the open file (#967). So the mode is
   * necessary and the order is checked as well (`inLineOrder`).
   */
  sourceOpenMode: SourceOpenMode;
  /** The wanted line numbers loaded for `openFilePath`. */
  lines: ReadonlySet<number>;
  /**
   * Of those, the lines that have an UNTIMED entry. An unplaced log row always names an entry whose
   * timestamp is null (unified_timeline/mod.rs, `from_log_entry`), so a line the list names must be
   * untimed here.
   */
  untimed: ReadonlySet<number>;
  /**
   * Of those, the lines that have a TIMED entry. One at a line the list names proves the list is
   * stale: after a rotation or a reload of the same path, line n is a different record now.
   */
  timed: ReadonlySet<number>;
  /**
   * The entries' line numbers never decrease, in the order the Log Viewer holds them. This is the
   * order the consumer of a scroll target needs: it selects the first shown entry whose line is at
   * or after the target, which is the target's own line only when no earlier entry has a larger
   * number. It is "never decreases", not "strictly increases": a parser may emit several entries for
   * one line, and equal numbers in a row do not move the find.
   */
  inLineOrder: boolean;
}

/**
 * The Log Viewer's mode, open file, that file's loaded lines (timed and untimed apart) and whether
 * the entries are in line order, in one pass over the entries.
 *
 * `wanted` narrows the three line sets to the lines the list names (at most a hundred), so a large
 * tailed file does not build a set of every line. The caller memoizes the result on the entries it
 * read; the pass is O(n) and the sets are small. Null keeps every line.
 */
export function logViewerLines(
  openFilePath: string | null,
  sourceOpenMode: SourceOpenMode,
  entries: readonly { filePath: string; lineNumber: number; timestamp: number | null }[],
  wanted: ReadonlySet<number> | null = null,
): LogViewerLines {
  const lines = new Set<number>();
  const untimed = new Set<number>();
  const timed = new Set<number>();
  let inLineOrder = true;
  let previous = Number.NEGATIVE_INFINITY;
  for (const entry of entries) {
    if (entry.filePath === openFilePath && (wanted === null || wanted.has(entry.lineNumber))) {
      lines.add(entry.lineNumber);
      (entry.timestamp === null ? untimed : timed).add(entry.lineNumber);
    }
    if (entry.lineNumber < previous) inLineOrder = false;
    previous = entry.lineNumber;
  }
  return { openFilePath, sourceOpenMode, lines, untimed, timed, inLineOrder };
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
 * file, the entries' line numbers never decrease, it holds exactly that line, that line is UNTIMED
 * there, and the correlation data is not being updated. Every other state is disabled with its
 * reason:
 * - merged: the entries are in timestamp order, untimed lines last, so with the other files hidden
 *   the open file's line 7 is loaded and a click selects some other line; with them shown it can
 *   select another file's line;
 * - diff: the diff view is mounted instead of the list, so the target would never be consumed and
 *   would fire when the diff closes;
 * - aggregate-folder, and no mode (after the diff closes): there is no single file open;
 * - single-file with the entries out of line order (#967): the aggregate firewall tail leaves a
 *   file's rows in timestamp order with the untimed ones last, so line 7 is loaded, at the end,
 *   and the first shown line at or after 7 is some other row. The order check also refuses the
 *   hidden-merged state on its own, whatever the mode;
 * - a TIMED entry at the line: an unplaced row names an entry with no timestamp, so the list on
 *   show is stale (a rotation or a reload of the same path made line n a different record);
 * - updating: the list belongs to the model on show, an older session than the one being scanned.
 * The button is "near line n" because a filter in the Log Viewer can hide the line itself.
 */
export function openAtLineAvailability(
  viewer: LogViewerLines,
  file: string,
  line: number,
  updating: boolean,
): OpenAtLine {
  const name = `Open ${getBaseName(file)} in the Log Viewer near line ${count(line)}`;
  const no = (reason: string): OpenAtLine => ({ enabled: false, reason, name });
  if (updating) {
    return no(
      "The correlation is being updated, so this list may belong to an earlier session. Try again when it has finished.",
    );
  }
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
  if (!viewer.inLineOrder) {
    return no(
      "The Log Viewer is not showing this file in its own line order, so it cannot open this line at its place.",
    );
  }
  if (!viewer.lines.has(line)) {
    return no(`Line ${count(line)} is not among the lines the Log Viewer has loaded.`);
  }
  if (viewer.timed.has(line)) {
    return no(
      `Line ${count(line)} of this file now has a timestamp in the Log Viewer, so the list of lines without one is out of date.`,
    );
  }
  return { enabled: true, reason: null, name };
}
