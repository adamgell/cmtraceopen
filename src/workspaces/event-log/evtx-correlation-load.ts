/**
 * Loads what the correlation chain model needs from an analysis session (spec 8.11, "Correlation
 * details are paged and bounded").
 *
 * No React and no store: the IO is injected (`CorrelationLoadDeps`), and cancellation is a
 * callback, so the hook owns the generation guard and the tests own the session.
 *
 * Two steps, each behind one function:
 * - `loadAnalysisEdges` reads the correlation edges. The reply to the first timeline page carries a
 *   bounded preview; when the preview is short of that SAME reply's `totalEdges`, the rest is paged
 *   with `queryEventLogAnalysisEdges`. Nothing is called when the preview is complete.
 * - `loadLinkedItems` finds the timeline items the edges name. The engine has no query for items by
 *   origin id, so it scans the timeline pages in order and keeps only the wanted items. This is the
 *   one function a backend by-origin-id query would replace.
 *
 * Rules, all enforced here:
 * - A total that is missing or not a non-negative safe integer is UNKNOWN (`null`). It is never
 *   turned into 0, and `modelEdgeTotal` gives the chain model a non-finite number for it, which the
 *   model reads as an incomplete input.
 * - Each total comes from the reply it arrived with. A reply for another session or revision, or
 *   for another offset, stops the load and is reported; it is never merged.
 * - Cancellation is checked before every call and after every reply.
 * - A failed page is retried as the unified timeline retries (`CORRELATION_RETRY_LIMIT` more tries,
 *   100 ms doubling), then the load stops with what it has and says it is incomplete.
 * - What was kept is bounded (`CORRELATION_RETAINED_BYTE_LIMIT` by default). Past the bound the
 *   scan stops and reports `stoppedBy: "budget"`; it never claims to be complete.
 */
import {
  queryEventLogAnalysisEdges,
  queryEventLogAnalysisTimeline,
  type EventLogAnalysisEdgePage,
  type EventLogAnalysisSessionStatus,
  type EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import { EVENT_LOG_ANALYSIS_PAGE_SIZE } from "./event-analysis-session";
import {
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineItem,
} from "./unified-timeline";

/** The most rows one call can return (`MAX_ANALYSIS_TIMELINE_PAGE_ITEMS` in analysis_session.rs). */
export const CORRELATION_EDGE_PAGE_SIZE = 1_000;
/** Items per page of the scan: the page size the first page was requested with. */
export const CORRELATION_TIMELINE_PAGE_SIZE = EVENT_LOG_ANALYSIS_PAGE_SIZE;
/**
 * Tries after the first for a failed page, and the byte bound on what a scan keeps. They equal
 * `EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT` and `EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT` in
 * UnifiedTimelineView.tsx, which this module does not import because that component pulls in the
 * store; a test pins the equality.
 */
export const CORRELATION_RETRY_LIMIT = 2;
export const CORRELATION_RETAINED_BYTE_LIMIT = 24 * 1024 * 1024;

export interface CorrelationLoadDeps {
  queryTimelinePage: (
    sessionId: string,
    offset: number,
    limit: number,
  ) => Promise<EventLogAnalysisTimelinePage>;
  queryEdgePage: (
    sessionId: string,
    offset: number,
    limit: number,
  ) => Promise<EventLogAnalysisEdgePage>;
  sleep: (ms: number) => Promise<void>;
}

export const DEFAULT_CORRELATION_LOAD_DEPS: CorrelationLoadDeps = {
  queryTimelinePage: queryEventLogAnalysisTimeline,
  queryEdgePage: queryEventLogAnalysisEdges,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/** Thrown when `isCancelled` turns true. It is not a failure: the caller has moved on. */
export class CorrelationLoadCancelled extends Error {
  constructor() {
    super("The correlation load was superseded.");
    this.name = "CorrelationLoadCancelled";
  }
}

/** A total that can be trusted as a count, or null. Never 0 for "not known". */
export function knownTotal(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

/**
 * The `totalTimelineEdges` for `buildCorrelationChains`. An unknown total is NaN, which the model
 * reads as an incomplete input (`edgeInputComplete` false, `unloadedEdgeCount` 0). Defaulting it to
 * 0 would make a model built from a bounded preview read as complete.
 */
export function modelEdgeTotal(total: number | null): number {
  return total ?? Number.NaN;
}

/** Every origin id the edges name: both endpoints and the candidates of an ambiguous relation. */
export function edgeEndpointIds(
  edges: readonly TimelineCorrelationEdge[],
): Set<string> {
  const ids = new Set<string>();
  for (const edge of edges) {
    ids.add(edge.fromId);
    if (edge.toId !== null) ids.add(edge.toId);
    for (const candidate of edge.candidateIds) ids.add(candidate);
  }
  return ids;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function withRetry<T>(
  call: () => Promise<T>,
  isCancelled: () => boolean,
  sleep: (ms: number) => Promise<void>,
): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    if (isCancelled()) throw new CorrelationLoadCancelled();
    try {
      const result = await call();
      if (isCancelled()) throw new CorrelationLoadCancelled();
      return result;
    } catch (error) {
      if (error instanceof CorrelationLoadCancelled) throw error;
      if (isCancelled()) throw new CorrelationLoadCancelled();
      if (attempt >= CORRELATION_RETRY_LIMIT) throw error;
      await sleep(100 * 2 ** attempt);
    }
  }
}

/** Why a reply cannot be used for this session, or null when it can. */
function replyProblem(
  reply: { sessionId: string; revision: number; offset: number },
  status: Pick<EventLogAnalysisSessionStatus, "sessionId" | "revision">,
  offset: number,
): string | null {
  if (reply.sessionId !== status.sessionId || reply.revision !== status.revision) {
    return "The event-log analysis session changed while paging.";
  }
  if (reply.offset !== offset) {
    return "The event-log analysis returned the wrong page.";
  }
  return null;
}

/** Whether the first timeline page belongs to the session `status` describes. */
function pageMatchesStatus(
  status: Pick<EventLogAnalysisSessionStatus, "sessionId" | "revision">,
  page: Pick<EventLogAnalysisTimelinePage, "sessionId" | "revision">,
): boolean {
  return page.sessionId === status.sessionId && page.revision === status.revision;
}

export interface LoadEdgesInput {
  /** Null while no session is published. */
  status: EventLogAnalysisSessionStatus | null;
  /** The reply for offset 0: its `edgesPreview` and its own `totalEdges` travel together. */
  initialPage: EventLogAnalysisTimelinePage | null;
  isCancelled: () => boolean;
  deps?: Partial<CorrelationLoadDeps>;
}

export interface LoadedEdges {
  edges: TimelineCorrelationEdge[];
  /**
   * The `totalEdges` of the reply the newest edges came from, or null when no reply gave a trusted
   * one (no session, no first page, or a total that is not a count). Pass it through
   * `modelEdgeTotal`.
   */
  totalEdges: number | null;
  /** Every edge the session holds was loaded. False when unknown, short or failed. */
  complete: boolean;
  /** Why paging stopped, when it did. */
  error: string | null;
}

/**
 * The correlation edges of the session. With no usable session or first page the result is empty
 * and UNKNOWN (`totalEdges: null`), never a total of 0.
 */
export async function loadAnalysisEdges(input: LoadEdgesInput): Promise<LoadedEdges> {
  const { status, initialPage, isCancelled } = input;
  if (isCancelled()) throw new CorrelationLoadCancelled();
  if (status === null || initialPage === null || !pageMatchesStatus(status, initialPage)) {
    return { edges: [], totalEdges: null, complete: false, error: null };
  }
  const deps = { ...DEFAULT_CORRELATION_LOAD_DEPS, ...input.deps };
  const edges: TimelineCorrelationEdge[] = [...initialPage.edgesPreview];
  let total = knownTotal(initialPage.totalEdges);
  const result = (error: string | null): LoadedEdges => ({
    edges,
    totalEdges: total,
    complete: total !== null && edges.length === total,
    error,
  });
  if (total === null || edges.length >= total) return result(null);

  let offset = edges.length;
  while (total === null || edges.length < total) {
    let page: EventLogAnalysisEdgePage;
    try {
      page = await withRetry(
        () => deps.queryEdgePage(status.sessionId, offset, CORRELATION_EDGE_PAGE_SIZE),
        isCancelled,
        deps.sleep,
      );
    } catch (error) {
      if (error instanceof CorrelationLoadCancelled) throw error;
      return result(messageOf(error));
    }
    const problem = replyProblem(page, status, offset);
    if (problem !== null) return result(problem);
    edges.push(...page.edges);
    total = knownTotal(page.totalEdges);
    if (page.nextOffset === null) break;
    if (page.nextOffset <= offset) {
      return result("The event-log analysis returned a page that makes no progress.");
    }
    offset = page.nextOffset;
  }
  return result(null);
}

export interface LinkedItemsProgress {
  scannedItems: number;
  totalItems: number;
  retainedItems: number;
}

export interface LoadLinkedItemsInput {
  status: EventLogAnalysisSessionStatus | null;
  /** The reply for offset 0. Its items are read first, so a one-page timeline needs no call. */
  initialPage: EventLogAnalysisTimelinePage | null;
  /** Origin ids to keep (`edgeEndpointIds`). Every other item is dropped as it is read. */
  wantedIds: ReadonlySet<string>;
  isCancelled: () => boolean;
  onProgress?: (progress: LinkedItemsProgress) => void;
  /** Most bytes (as the engine serialized them) to keep. Defaults to the timeline cache bound. */
  byteBudget?: number;
  deps?: Partial<CorrelationLoadDeps>;
}

export interface LoadedLinkedItems {
  /** The wanted items that were read, in timeline order. */
  items: TimelineItem[];
  /**
   * Every timeline page was read, so every wanted id that is a placed item is in `items`. A wanted
   * id that is missing from a COMPLETE load is not a placed item (it is unplaced, or it does not
   * exist). Under an incomplete load a missing id may simply not have been read.
   */
  complete: boolean;
  scannedItems: number;
  totalItems: number;
  /** The engine's serialized size of the kept items, estimated pro rata from each page's size. */
  retainedBytes: number;
  stoppedBy: "budget" | "error" | null;
  error: string | null;
}

/**
 * The timeline items for `wantedIds`: the one function to replace with a backend by-origin-id query.
 *
 * Reads the first page's items, then each following page in order, keeping only wanted items.
 */
export async function loadLinkedItems(
  input: LoadLinkedItemsInput,
): Promise<LoadedLinkedItems> {
  const { status, initialPage, wantedIds, isCancelled } = input;
  if (isCancelled()) throw new CorrelationLoadCancelled();
  const empty = (complete: boolean): LoadedLinkedItems => ({
    items: [],
    complete,
    scannedItems: 0,
    totalItems: status?.totalItems ?? 0,
    retainedBytes: 0,
    stoppedBy: null,
    error: null,
  });
  if (status === null || initialPage === null || !pageMatchesStatus(status, initialPage)) {
    return empty(false);
  }
  // Nothing is wanted, so nothing has to be read.
  if (wantedIds.size === 0) return empty(true);

  const deps = { ...DEFAULT_CORRELATION_LOAD_DEPS, ...input.deps };
  const byteBudget = input.byteBudget ?? CORRELATION_RETAINED_BYTE_LIMIT;
  const items: TimelineItem[] = [];
  let scannedItems = 0;
  let retainedBytes = 0;
  const totalItems = status.totalItems;

  const absorb = (page: EventLogAnalysisTimelinePage) => {
    const kept = page.items.filter((item) => wantedIds.has(timelineOriginId(item.origin)));
    items.push(...kept);
    scannedItems += page.items.length;
    if (page.items.length > 0) {
      retainedBytes += (page.serializedBytes * kept.length) / page.items.length;
    }
    input.onProgress?.({ scannedItems, totalItems, retainedItems: items.length });
  };
  const result = (
    stoppedBy: "budget" | "error" | null,
    error: string | null,
  ): LoadedLinkedItems => ({
    items,
    complete: stoppedBy === null && error === null && scannedItems === totalItems,
    scannedItems,
    totalItems,
    retainedBytes,
    stoppedBy,
    error:
      error ??
      (stoppedBy === null && scannedItems !== totalItems
        ? `The timeline scan read ${scannedItems} of ${totalItems} items.`
        : null),
  });

  absorb(initialPage);
  if (retainedBytes > byteBudget) return result("budget", null);
  let offset = initialPage.nextOffset;
  while (offset !== null) {
    const at = offset;
    let page: EventLogAnalysisTimelinePage;
    try {
      page = await withRetry(
        () => deps.queryTimelinePage(status.sessionId, at, CORRELATION_TIMELINE_PAGE_SIZE),
        isCancelled,
        deps.sleep,
      );
    } catch (error) {
      if (error instanceof CorrelationLoadCancelled) throw error;
      return result("error", messageOf(error));
    }
    const problem = replyProblem(page, status, at);
    if (problem !== null) return result("error", problem);
    absorb(page);
    if (retainedBytes > byteBudget) return result("budget", null);
    if (page.nextOffset !== null && page.nextOffset <= at) {
      return result("error", "The event-log analysis returned a page that makes no progress.");
    }
    offset = page.nextOffset;
  }
  return result(null, null);
}
