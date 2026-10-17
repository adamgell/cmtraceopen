/**
 * The timeline items within a window around one instant, read from a finalized analysis session
 * (spec 8.12 and Q-10; issue 842; the remaining acceptance item of 857). The dock reads it, and the
 * Details context list (11b) reads it again, so there is one place that knows how a window is paged.
 *
 * No React and no store: the IO is injected (`CorrelationWindowDeps`) and cancellation is a
 * callback, as in evtx-correlation-load.ts, whose retry, session and offset checks it shares.
 *
 * The backend answers the closed interval `[centerMs - halfWidthMs, centerMs + halfWidthMs]` with
 * the longest byte-bounded prefix of it and says how many in-window items it left out
 * (`omittedItems`) and where they begin (`nextOffset`). This loader continues the documented way,
 * and only that way:
 *
 *   remaining = omittedItems; offset = nextOffset
 *   while remaining > 0: page(offset, min(limit, remaining)); remaining -= rows read
 *
 * It never windows again from the last timestamp it read: rows tied on that timestamp would be read
 * twice or not at all.
 *
 * Rules, all enforced here:
 * - `windowItems`, the number of items inside the window, is the backend's count from the first
 *   reply. It is `null` when no reply gave it, and is never turned into 0.
 * - The result is complete only when every in-window item was read. Past the page limit (one window
 *   call and at most five more pages), past the byte budget, or on a failure, it is incomplete and
 *   says which, with the items that were read. `omittedItems` is then exact.
 * - Every reply must belong to the session and revision that were asked about, and a continuation
 *   page to the offset that was asked for. A reply that does not is NOT merged and not kept: the
 *   session changed under the read, so everything read is dropped and the error says so.
 * - Every item must lie inside the window and no earlier than the one before it. One that does not
 *   drops the read the same way.
 * - A failed call is retried as the unified timeline retries; after that the read stops with what it
 *   has. Cancellation throws `CorrelationLoadCancelled` before a call, after a reply, and in place
 *   of a failure: a call that fails because the caller itself closed the session is not reported.
 */
import {
  queryEventLogAnalysisTimeline,
  queryEventLogAnalysisTimelineWindow,
  type EventLogAnalysisSessionStatus,
  type EventLogAnalysisTimelinePage,
  type EventLogAnalysisTimelineWindow,
} from "../../lib/commands";
import {
  CorrelationLoadCancelled,
  messageOf,
  replyProblem,
  sessionKeyOf,
  sessionProblem,
  withRetry,
} from "./evtx-correlation-load";
import {
  EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT,
  EVENT_LOG_TIMELINE_PAGE_SIZE,
} from "./evtx-timeline-paging";
import type { TimelineItem } from "./unified-timeline";

/** Rows asked for per call: the most one call can return (`MAX_ANALYSIS_TIMELINE_PAGE_ITEMS`). */
export const CORRELATION_WINDOW_LIMIT = EVENT_LOG_TIMELINE_PAGE_SIZE;

/** Calls in one read: the window call and at most five continuation pages (the issue's 6-page cap). */
export const CORRELATION_WINDOW_MAX_CALLS = 6;

export interface CorrelationWindowDeps {
  queryWindow: (
    sessionId: string,
    startMs: number,
    endMs: number,
    limit: number,
  ) => Promise<EventLogAnalysisTimelineWindow>;
  queryTimelinePage: (
    sessionId: string,
    offset: number,
    limit: number,
  ) => Promise<EventLogAnalysisTimelinePage>;
  sleep: (ms: number) => Promise<void>;
}

export const DEFAULT_CORRELATION_WINDOW_DEPS: CorrelationWindowDeps = {
  queryWindow: queryEventLogAnalysisTimelineWindow,
  queryTimelinePage: queryEventLogAnalysisTimeline,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/** Why a read stopped before it had every in-window item. */
export type WindowStopReason = "callLimit" | "budget" | "error";

export interface LoadedCorrelationWindow {
  /** The session and revision the items were read from (`sessionKeyOf`). */
  sessionKey: string;
  centerMs: number;
  halfWidthMs: number;
  startMs: number;
  endMs: number;
  /** The items that were read, in timeline order. Empty when the read was dropped. */
  items: TimelineItem[];
  /** Every item inside the window, read or not: the backend's count, or null when no reply gave it. */
  windowItems: number | null;
  /** In-window items that were not read: exact when `windowItems` is known, else null. */
  omittedItems: number | null;
  /** Every in-window item was read. False for an unknown count, a stop and a dropped read. */
  complete: boolean;
  stoppedBy: WindowStopReason | null;
  error: string | null;
  /** The engine's serialized size of everything read: what the byte budget is measured on. */
  retainedBytes: number;
  /** Calls made, the window call included. */
  calls: number;
}

export interface LoadCorrelationWindowInput {
  status: Pick<EventLogAnalysisSessionStatus, "sessionId" | "revision">;
  centerMs: number;
  halfWidthMs: number;
  isCancelled: () => boolean;
  /** Rows per call, 1 to 1,000. Defaults to the most a call can return. */
  limit?: number;
  /** Most calls in the read. Defaults to `CORRELATION_WINDOW_MAX_CALLS`. */
  maxCalls?: number;
  /** Most bytes (as the engine serialized them) to keep. Defaults to the timeline cache bound. */
  byteBudget?: number;
  deps?: Partial<CorrelationWindowDeps>;
}

/**
 * The items of the closed window around `centerMs`. See the file header for what it guarantees.
 * Throws only `CorrelationLoadCancelled`; every other outcome is a result.
 */
export async function loadCorrelationWindow(
  input: LoadCorrelationWindowInput,
): Promise<LoadedCorrelationWindow> {
  const { status, centerMs, halfWidthMs, isCancelled } = input;
  const deps = { ...DEFAULT_CORRELATION_WINDOW_DEPS, ...input.deps };
  const limit = input.limit ?? CORRELATION_WINDOW_LIMIT;
  const maxCalls = input.maxCalls ?? CORRELATION_WINDOW_MAX_CALLS;
  const byteBudget = input.byteBudget ?? EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT;
  const startMs = centerMs - halfWidthMs;
  const endMs = centerMs + halfWidthMs;
  const sessionKey = sessionKeyOf(status) as string;
  if (isCancelled()) throw new CorrelationLoadCancelled();

  const base = { sessionKey, centerMs, halfWidthMs, startMs, endMs };
  // What a read that has no usable items says. The count is unknown, never 0.
  const dropped = (error: string, calls: number): LoadedCorrelationWindow => ({
    ...base,
    items: [],
    windowItems: null,
    omittedItems: null,
    complete: false,
    stoppedBy: "error",
    error,
    retainedBytes: 0,
    calls,
  });

  if (
    !Number.isSafeInteger(centerMs) ||
    !Number.isSafeInteger(halfWidthMs) ||
    halfWidthMs < 0 ||
    !Number.isSafeInteger(startMs) ||
    !Number.isSafeInteger(endMs)
  ) {
    return dropped("The correlation window needs a whole-millisecond center and half width.", 0);
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > CORRELATION_WINDOW_LIMIT || maxCalls < 1) {
    return dropped(`The correlation window reads 1 to ${CORRELATION_WINDOW_LIMIT} rows per call.`, 0);
  }

  let calls = 1;
  let first: EventLogAnalysisTimelineWindow;
  try {
    first = await withRetry(
      () => deps.queryWindow(status.sessionId, startMs, endMs, limit),
      isCancelled,
      deps.sleep,
    );
  } catch (error) {
    if (error instanceof CorrelationLoadCancelled) throw error;
    return dropped(messageOf(error), calls);
  }
  const mismatch =
    sessionProblem(first, status) ??
    (first.startMs !== startMs || first.endMs !== endMs
      ? "The event-log analysis returned another window."
      : null);
  if (mismatch !== null) return dropped(mismatch, calls);

  const items: TimelineItem[] = [];
  let retainedBytes = 0;
  // Items must lie in the window and never go back in time. Returns why not, or null.
  const itemProblem = (read: readonly TimelineItem[]): string | null => {
    let previous = items.length > 0 ? (items[items.length - 1] as TimelineItem).timestampMs : startMs;
    for (const item of read) {
      if (item.timestampMs < startMs || item.timestampMs > endMs || item.timestampMs < previous) {
        return "The event-log analysis returned an entry outside the window or out of order.";
      }
      previous = item.timestampMs;
    }
    return null;
  };
  const outsideWindow = itemProblem(first.items);
  if (outsideWindow !== null) return dropped(outsideWindow, calls);
  items.push(...first.items);
  retainedBytes += first.serializedBytes;

  const windowItems = first.windowItems;
  let remaining = first.omittedItems;
  let offset = first.nextOffset;
  const result = (
    stoppedBy: WindowStopReason | null,
    error: string | null,
  ): LoadedCorrelationWindow => ({
    ...base,
    items,
    windowItems,
    omittedItems: windowItems - items.length,
    complete: stoppedBy === null && error === null && items.length === windowItems,
    stoppedBy,
    error,
    retainedBytes,
    calls,
  });

  while (remaining > 0) {
    if (offset === null) {
      return result("error", "The event-log analysis lost track of where the window continues.");
    }
    if (retainedBytes > byteBudget) return result("budget", null);
    if (calls >= maxCalls) return result("callLimit", null);
    const at = offset;
    const clip = Math.min(limit, remaining);
    calls += 1;
    let page: EventLogAnalysisTimelinePage;
    try {
      page = await withRetry(
        () => deps.queryTimelinePage(status.sessionId, at, clip),
        isCancelled,
        deps.sleep,
      );
    } catch (error) {
      if (error instanceof CorrelationLoadCancelled) throw error;
      return result("error", messageOf(error));
    }
    const problem = replyProblem(page, status, at);
    if (problem !== null) return dropped(problem, calls);
    if (page.items.length > clip) {
      return dropped("The event-log analysis returned more rows than were asked for.", calls);
    }
    if (page.items.length === 0) {
      return result("error", "The event-log analysis returned a page that makes no progress.");
    }
    const outside = itemProblem(page.items);
    if (outside !== null) return dropped(outside, calls);
    items.push(...page.items);
    retainedBytes += page.serializedBytes;
    remaining -= page.items.length;
    if (remaining > 0 && page.nextOffset !== at + page.items.length) {
      return result("error", "The event-log analysis returned a page that makes no progress.");
    }
    offset = page.nextOffset;
  }
  return result(null, null);
}
