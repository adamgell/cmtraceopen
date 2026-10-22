/**
 * Builders for the tests of the window facts, the Details context model and its component (#843).
 * They sit on the shared correlation fixtures (`evtx-correlation-test-fixtures.ts`, which the dock
 * lane also edits, so nothing is added there): the same synthetic events, the same loaded records,
 * the same real chain model over real edges.
 *
 * Test code only: nothing outside a test file imports it.
 */
import { eventItem, makeCounts, recordFor, type DataOptions } from "./evtx-correlation-test-fixtures";
import type { EventLogAnalysisTimelineWindow } from "../../lib/commands";
import type { LoadedCorrelationWindow } from "./evtx-correlation-window";
import type { TimelineCorrelationEdge, TimelineItem } from "./unified-timeline";
import type { EvtxRecord } from "./types";

export const SESSION_KEY = "session:1";

/** Half of the Details context's window: ±5 min. */
export const FIVE_MIN = 300_000;

/** The window the loader would return for `record` over `items`: whole, unless overridden. */
export function windowAround(
  record: EvtxRecord,
  items: TimelineItem[],
  overrides: Partial<LoadedCorrelationWindow> = {},
  halfWidthMs = FIVE_MIN,
): LoadedCorrelationWindow {
  return {
    sessionKey: SESSION_KEY,
    centerMs: record.timestampEpoch,
    halfWidthMs,
    startMs: record.timestampEpoch - halfWidthMs,
    endMs: record.timestampEpoch + halfWidthMs,
    items,
    windowItems: items.length,
    omittedItems: 0,
    complete: true,
    stoppedBy: null,
    error: null,
    retainedBytes: 1_000,
    calls: 1,
    ...overrides,
  };
}

/** A read that stopped (the call limit) with `items` read of `windowItems` in the window. */
export function stoppedWindow(
  record: EvtxRecord,
  items: TimelineItem[],
  windowItems: number,
  overrides: Partial<LoadedCorrelationWindow> = {},
): LoadedCorrelationWindow {
  return windowAround(record, items, {
    complete: false,
    windowItems,
    omittedItems: windowItems - items.length,
    stoppedBy: "callLimit",
    ...overrides,
  });
}

type CountsOptions = Partial<Omit<DataOptions, "unplacedList">> & {
  unplacedList?: NonNullable<DataOptions["unplacedList"]>;
};

/** The counts-only model of session `SESSION_KEY` over `edges`, as the hook keeps it. */
export function countsFor(edges: TimelineCorrelationEdge[], extra: CountsOptions = {}) {
  return makeCounts({ items: [], edges, builtFor: SESSION_KEY, ...extra });
}

/** A second entry that names the same record as `item` (another stable id, every field equal). */
export function twinOf(item: TimelineItem, stableId: string): TimelineItem {
  return item.origin.kind === "event" ? { ...item, origin: { ...item.origin, stableId } } : item;
}

/** A record the join can never name: an event the provider never numbered. */
export function unnumbered(epoch: number): EvtxRecord {
  return { ...recordFor(1), eventRecordId: 0, eventRecordIdText: null, timestampEpoch: epoch };
}

/** An event on `channel` at `timestampMs`, named by record `n`. */
export function onChannel(n: number, timestampMs: number, channel: string): TimelineItem {
  const item = eventItem(n, timestampMs);
  return item.origin.kind === "event" ? { ...item, origin: { ...item.origin, channel } } : item;
}

/**
 * Text-log lines are transformed from a corpus exemplar, never invented: the message and the
 * component come from the parser crate's
 * `tests/fixtures/intune/windows/remediations/execution-completes-report-fails/AgentExecutor.log`
 * ("Starting Powershell Execution", component "AgentExecutor"). The folder is made up.
 */
export const LOG_FILE = "C:\\Logs\\AgentExecutor.log";

/** A text-log line of `LOG_FILE`, in the shape the engine gives a log origin. */
export function logItem(line: number, timestampMs: number): TimelineItem {
  return {
    timestampMs,
    severity: "info",
    message: "Starting Powershell Execution",
    origin: {
      kind: "log",
      file: LOG_FILE,
      component: "AgentExecutor",
      line,
      source: LOG_FILE,
      machine: null,
      bundle: null,
      recordId: line,
    },
  };
}

/**
 * The engine's reply to the window call for the closed interval `[startMs, endMs]` of session
 * `sessionId`, holding `items` whole (nothing omitted), as the loader reads it.
 */
export function windowReplyFor(
  sessionId: string,
  revision: number,
  startMs: number,
  endMs: number,
  items: TimelineItem[],
): EventLogAnalysisTimelineWindow {
  return {
    sessionId,
    revision,
    startMs,
    endMs,
    offset: 0,
    nextOffset: null,
    totalItems: items.length,
    windowItems: items.length,
    omittedItems: 0,
    items,
    serializedBytes: 1_000,
  };
}
