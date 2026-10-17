/**
 * The shared correlation data of the Event Logs workspace: one chain model per analysis session,
 * built once and read by the Correlation view, the rail card, the Chains tab, the Charts tile and
 * the status bar (spec 8.11 and 8.13: "same ordering, cap and D7 rules", one shared model).
 *
 * The workspace calls `useEvtxCorrelation` once and gives the result to `EvtxCorrelationProvider`.
 * The view is lazy and not kept alive, so this lives above it.
 *
 * Two stages, so that a count never waits on a scan:
 * - EDGES: from the first reply's preview, or paged when that reply says it is short. The model
 *   built from edges alone gives correct counts and the row count, but no titles, spans or
 *   positions, so `hasItems` is false and a consumer must not show those.
 * - ITEMS, only when `needItems` is true: the timeline pages are scanned for the items the edges
 *   name (`loadLinkedItems`), and the model is built again with them.
 *
 * Rules, all enforced here:
 * - A missing or non-finite edge total is unknown, never 0 (`edges.totalEdges` is null and the
 *   model reads the input as incomplete). With no session there is no model.
 * - Anything IPC waits for `settleMs` first, so a live tail that rebuilds the session every few
 *   hundred milliseconds does not start a scan per batch. A run is thrown away, not merged, when
 *   the session changes under it.
 * - While a session is being rebuilt the previous model stays and `updating` is true. It is never
 *   paired with the new session's counts.
 * - The model is built after the first paint (the build is not free at 25,000 edges).
 * - `findings` is empty (decision B on #838): chain titles are the derived `{eventId} · message`.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type {
  EventLogAnalysisSessionStatus,
  EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import {
  buildCorrelationChains,
  type ChainFindingCoverage,
  type CorrelationChainModel,
} from "./evtx-correlation-chains";
import {
  CorrelationLoadCancelled,
  DEFAULT_CORRELATION_LOAD_DEPS,
  edgeEndpointIds,
  knownTotal,
  loadAnalysisEdges,
  loadLinkedItems,
  modelEdgeTotal,
  type CorrelationLoadDeps,
  type LoadedEdges,
  type LoadedLinkedItems,
  type LinkedItemsProgress,
} from "./evtx-correlation-load";
import type { UnplacedEvidence } from "./evtx-correlation-copy";
import { itemsByOriginId, linkPartnerCounts } from "./evtx-correlation-origin-index";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

/** Wait before any IPC, so a session that is replaced inside it costs nothing. */
export const CORRELATION_SETTLE_MS = 500;

/** Decision B on #838 is open: no finding title is joined to a chain. */
export const NO_FINDINGS: readonly ChainFindingCoverage[] = [];

export type CorrelationStage =
  /** No session. Nothing is known. */
  | "unavailable"
  /** A session is being built. A previous model, if any, is still shown and `updating` is true. */
  | "pending"
  /** Edges are in and the model has counts only. */
  | "edgesOnly"
  /** The timeline is being scanned for the items the edges name. */
  | "scanning"
  /** The model was built with the items that were read. See `scan` for whether that was all. */
  | "ready";

export interface CorrelationScanState {
  state: "idle" | "running" | "complete" | "incomplete";
  progress: LinkedItemsProgress | null;
  stoppedBy: "budget" | "error" | null;
  error: string | null;
}

export interface CorrelationEdgeState {
  loaded: number;
  /** The total the newest reply gave, or null when none was trusted. Never 0 for unknown. */
  totalEdges: number | null;
  complete: boolean;
  error: string | null;
}

export interface EvtxCorrelationData {
  stage: CorrelationStage;
  /** The `sessionId:revision` the model was built for, or null. */
  builtFor: string | null;
  model: CorrelationChainModel | null;
  /** True once items were read: only then are titles, spans and positions meaningful. */
  hasItems: boolean;
  /** The items read, by origin id. Empty until `hasItems`. */
  itemsById: ReadonlyMap<string, TimelineItem>;
  edges: CorrelationEdgeState;
  scan: CorrelationScanState;
  /** What is known about members with no item. */
  unplaced: UnplacedEvidence;
  /** Distinct exact and candidate partners per origin id, from the uncapped pairs. */
  linkPartners: ReadonlyMap<string, number>;
  /** `model` belongs to an earlier session than the current one and is being rebuilt. */
  updating: boolean;
  /** A failure that is not a load result (those are in `edges` and `scan`), or null. */
  error: string | null;
  /** Runs the steps that failed or stopped early again. */
  retry: () => void;
}

const NO_UNPLACED: UnplacedEvidence = {
  scanComplete: false,
  unplacedListComplete: false,
  unplacedIds: new Set(),
};
const IDLE_SCAN: CorrelationScanState = {
  state: "idle",
  progress: null,
  stoppedBy: null,
  error: null,
};
const NO_EDGES: CorrelationEdgeState = {
  loaded: 0,
  totalEdges: null,
  complete: false,
  error: null,
};
const NO_ITEMS: ReadonlyMap<string, TimelineItem> = new Map();
const NO_PARTNERS: ReadonlyMap<string, number> = new Map();

export const UNAVAILABLE_CORRELATION: EvtxCorrelationData = {
  stage: "unavailable",
  builtFor: null,
  model: null,
  hasItems: false,
  itemsById: NO_ITEMS,
  edges: NO_EDGES,
  scan: IDLE_SCAN,
  unplaced: NO_UNPLACED,
  linkPartners: NO_PARTNERS,
  updating: false,
  error: null,
  retry: () => undefined,
};

/** What a run has built so far; the hook turns it into `EvtxCorrelationData`. */
interface RunState {
  stage: CorrelationStage;
  builtFor: string | null;
  model: CorrelationChainModel | null;
  hasItems: boolean;
  itemsById: ReadonlyMap<string, TimelineItem>;
  edges: CorrelationEdgeState;
  scan: CorrelationScanState;
  linkPartners: ReadonlyMap<string, number>;
  error: string | null;
}

const EMPTY_RUN: RunState = {
  stage: "unavailable",
  builtFor: null,
  model: null,
  hasItems: false,
  itemsById: NO_ITEMS,
  edges: NO_EDGES,
  scan: IDLE_SCAN,
  linkPartners: NO_PARTNERS,
  error: null,
};

/** What a session has already given, so toggling `needItems` does not reload the edges. */
interface SessionCache {
  page: EventLogAnalysisTimelinePage;
  edges?: LoadedEdges;
  edgesOnly?: CorrelationChainModel;
  items?: LoadedLinkedItems;
  /** The newest state this session produced, republished without rebuilding when it still serves. */
  published?: RunState;
}

export interface UseEvtxCorrelationOptions {
  /** The published session, or null while none is. */
  status: EventLogAnalysisSessionStatus | null;
  /** The reply for offset 0: its edge preview and its own `totalEdges` travel together. */
  initialPage: EventLogAnalysisTimelinePage | null;
  /** A session is being built, so a null `status` is a gap and not an end. */
  pending: boolean;
  /**
   * Whether a consumer needs titles, spans and positions (the Correlation view, the Chains tab).
   * Counts do not, so the Insights card alone never causes a scan.
   */
  needItems: boolean;
  settleMs?: number;
  deps?: Partial<CorrelationLoadDeps>;
}

function sessionKeyOf(status: EventLogAnalysisSessionStatus | null): string | null {
  return status === null ? null : `${status.sessionId}:${status.revision}`;
}

export function useEvtxCorrelation(options: UseEvtxCorrelationOptions): EvtxCorrelationData {
  const { status, initialPage, pending, needItems } = options;
  const settleMs = options.settleMs ?? CORRELATION_SETTLE_MS;
  const depsRef = useRef(options.deps);
  depsRef.current = options.deps;

  const [run, setRun] = useState<RunState>(EMPTY_RUN);
  const [retryNonce, setRetryNonce] = useState(0);
  const generationRef = useRef(0);
  const cacheRef = useRef<SessionCache | null>(null);
  const retryRef = useRef(false);

  const sessionId = status?.sessionId ?? null;
  const revision = status?.revision ?? null;
  const key = sessionKeyOf(status);

  useEffect(() => {
    const generation = (generationRef.current += 1);
    const cancelled = () => generationRef.current !== generation;
    const deps = { ...DEFAULT_CORRELATION_LOAD_DEPS, ...depsRef.current };

    if (status === null || initialPage === null) {
      // A gap while the session is rebuilt keeps the last model; the end of data clears it.
      cacheRef.current = null;
      setRun((previous) =>
        pending && previous.model !== null
          ? { ...previous, stage: "pending" }
          : { ...EMPTY_RUN, stage: pending ? "pending" : "unavailable" },
      );
      return () => {
        generationRef.current += 1;
      };
    }

    if (cacheRef.current?.page !== initialPage) cacheRef.current = { page: initialPage };
    const cache = cacheRef.current;
    if (retryRef.current) {
      retryRef.current = false;
      if (cache.edges !== undefined && !cache.edges.complete) {
        cache.edges = undefined;
        cache.edgesOnly = undefined;
      }
      if (cache.items !== undefined && !cache.items.complete) cache.items = undefined;
      cache.published = undefined;
    }
    const sessionKey = sessionKeyOf(status) as string;

    const commit = (next: RunState) => {
      cache.published = next;
      if (!cancelled()) setRun(next);
    };
    const update = (patch: Partial<RunState>) => {
      if (!cancelled()) setRun((previous) => ({ ...previous, ...patch }));
    };
    const edgeState = (loaded: LoadedEdges): CorrelationEdgeState => ({
      loaded: loaded.edges.length,
      totalEdges: loaded.totalEdges,
      complete: loaded.complete,
      error: loaded.error,
    });
    const build = (edges: LoadedEdges, items: readonly TimelineItem[]) =>
      buildCorrelationChains({
        items,
        timelineEdges: edges.edges,
        totalTimelineEdges: modelEdgeTotal(edges.totalEdges),
        findings: NO_FINDINGS,
      });

    // A model with items serves every consumer, and a model without them serves one that does not
    // need items: neither is rebuilt for a toggle of `needItems`.
    const published = cache.published;
    if (published !== undefined && (published.hasItems || !needItems)) {
      setRun(published);
      return () => {
        generationRef.current += 1;
      };
    }
    // Until this session's own model is in, the previous one stays and is marked by `updating`.
    setRun((previous) =>
      previous.builtFor === sessionKey ? previous : { ...previous, stage: "pending" },
    );

    void (async () => {
      try {
        let edges = cache.edges;
        if (edges === undefined) {
          // The first reply's preview is enough when it holds every edge that same reply counts.
          const total = knownTotal(initialPage.totalEdges);
          if (total === null || initialPage.edgesPreview.length < total) {
            await deps.sleep(settleMs);
            if (cancelled()) return;
          }
          edges = await loadAnalysisEdges({ status, initialPage, isCancelled: cancelled, deps });
          cache.edges = edges;
        }
        const loadedEdges = edges;

        let edgesOnly = cache.edgesOnly;
        if (edgesOnly === undefined) {
          await deps.sleep(0);
          if (cancelled()) return;
          edgesOnly = build(loadedEdges, []);
          cache.edgesOnly = edgesOnly;
        }
        const counts = edgesOnly;
        const edgesOnlyState: RunState = {
          stage: "edgesOnly",
          builtFor: sessionKey,
          model: counts,
          hasItems: false,
          itemsById: NO_ITEMS,
          edges: edgeState(loadedEdges),
          scan: IDLE_SCAN,
          linkPartners: linkPartnerCounts(counts.linkedPairs),
          error: null,
        };
        commit(edgesOnlyState);
        if (!needItems) return;

        let items = cache.items;
        if (items === undefined) {
          const wantedIds = edgeEndpointIds(loadedEdges.edges);
          update({
            stage: "scanning",
            scan: { state: "running", progress: null, stoppedBy: null, error: null },
          });
          if (initialPage.nextOffset !== null && wantedIds.size > 0) {
            await deps.sleep(settleMs);
            if (cancelled()) return;
          }
          items = await loadLinkedItems({
            status,
            initialPage,
            wantedIds,
            isCancelled: cancelled,
            onProgress: (progress) =>
              update({ scan: { state: "running", progress, stoppedBy: null, error: null } }),
            deps,
          });
          cache.items = items;
        }

        await deps.sleep(0);
        if (cancelled()) return;
        const scanned = items;
        const full = build(loadedEdges, scanned.items);
        commit({
          stage: "ready",
          builtFor: sessionKey,
          model: full,
          hasItems: true,
          itemsById: itemsByOriginId(scanned.items),
          edges: edgeState(loadedEdges),
          scan: {
            state: scanned.complete ? "complete" : "incomplete",
            progress: {
              scannedItems: scanned.scannedItems,
              totalItems: scanned.totalItems,
              retainedItems: scanned.items.length,
            },
            stoppedBy: scanned.stoppedBy,
            error: scanned.error,
          },
          linkPartners: linkPartnerCounts(full.linkedPairs),
          error: null,
        });
      } catch (error) {
        // Cancellation is the only expected throw; anything else is shown, not swallowed.
        if (cancelled() || error instanceof CorrelationLoadCancelled) return;
        update({ error: error instanceof Error ? error.message : String(error) });
      }
    })();

    return () => {
      generationRef.current += 1;
    };
    // `status` and `initialPage` are read through their identifiers: a new object for the same
    // session and revision is the same session. `initialPage` is listed because the first page
    // belongs to the session it was fetched for.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, revision, initialPage, pending, needItems, settleMs, retryNonce]);

  const retry = useCallback(() => {
    retryRef.current = true;
    setRetryNonce((nonce) => nonce + 1);
  }, []);

  const unplaced = useMemo<UnplacedEvidence>(() => {
    if (status === null || initialPage === null) return NO_UNPLACED;
    return {
      scanComplete: run.scan.state === "complete",
      unplacedListComplete: initialPage.unplacedPreview.length === status.totalUnplaced,
      unplacedIds: new Set(initialPage.unplacedPreview.map((entry) => timelineOriginId(entry.origin))),
    };
  }, [status, initialPage, run.scan.state]);

  return useMemo<EvtxCorrelationData>(
    () => ({
      stage: run.stage,
      builtFor: run.builtFor,
      model: run.model,
      hasItems: run.hasItems,
      itemsById: run.itemsById,
      edges: run.edges,
      scan: run.scan,
      unplaced,
      linkPartners: run.linkPartners,
      updating: run.model !== null && run.builtFor !== key,
      error: run.error,
      retry,
    }),
    [run, unplaced, key, retry],
  );
}

const EvtxCorrelationContext = createContext<EvtxCorrelationData>(UNAVAILABLE_CORRELATION);

export function EvtxCorrelationProvider({
  value,
  children,
}: {
  value: EvtxCorrelationData;
  children: ReactNode;
}) {
  return <EvtxCorrelationContext.Provider value={value}>{children}</EvtxCorrelationContext.Provider>;
}

/** The workspace's shared correlation data. Outside a provider it reads as unavailable. */
export function useEvtxCorrelationData(): EvtxCorrelationData {
  return useContext(EvtxCorrelationContext);
}
