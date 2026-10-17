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
 *   positions, so `hasItems` is false and a consumer must not show those. It is kept apart as
 *   `counts`, for a consumer that needs counts only (the Insights card).
 * - ITEMS, only when `needItems` is true: the timeline pages are scanned for the items the edges
 *   name (`loadLinkedItems`), and the model is built again with them.
 *
 * Rules, all enforced here:
 * - A missing or non-finite edge total is unknown, never 0 (`edges.totalEdges` is null and the
 *   model reads the input as incomplete). With no session there is no model.
 * - Anything IPC waits for `settleMs` first, so a live tail that rebuilds the session every few
 *   hundred milliseconds does not start a scan per batch. A run is thrown away, not merged, when
 *   the session changes under it.
 * - While a session is being rebuilt the previous FULL model stays in `model`, with `updating`
 *   true, until the new scan completes: a counts-only model never replaces a full one. The newest
 *   counts are in `counts`.
 * - Everything a model is read with (`itemsById`, `origins`, `edges`, `scan`, `unplaced`) is stored
 *   with it and comes from the run that built it, never from a newer status.
 * - What a scan found answers for the exact edge set it was scanned for. A different edge set (a
 *   retry that loaded more edges) is scanned again.
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
import {
  classifyCoverageGaps,
  gapsClearCompleteness,
  UNKNOWN_CORRELATION_GAPS,
  type CorrelationGaps,
} from "./evtx-correlation-gaps";
import {
  itemsByOriginId,
  linkPartnerCounts,
  originLookup,
  type OriginLookup,
} from "./evtx-correlation-origin-index";
import type { ScopeDisclosureInput } from "./evtx-correlation-copy";
import type { UnplacedEvidence } from "./evtx-correlation-view-model";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

/** Wait before any IPC, so a session that is replaced inside it costs nothing. */
export const CORRELATION_SETTLE_MS = 500;

/** Decision B on #838 is open: no finding title is joined to a chain. */
export const NO_FINDINGS: readonly ChainFindingCoverage[] = [];

export type CorrelationStage =
  /** No session. Nothing is known. */
  | "unavailable"
  /** A session is being built or loaded. A previous model, if any, is still shown and `updating` is true. */
  | "pending"
  /** Edges are in and the newest session has a counts-only model. */
  | "edgesOnly"
  /** The timeline is being scanned for the items the newest session's edges name. */
  | "scanning"
  /** The newest session's model was built with the items that were read. See `scan`. */
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

/** The counts-only model of the newest session, for a consumer that needs no items. */
export interface CorrelationCounts {
  /** Built from edges alone: correct counts and row count, no titles, spans or positions. */
  model: CorrelationChainModel;
  builtFor: string;
  edges: CorrelationEdgeState;
  linkPartners: ReadonlyMap<string, number>;
  /**
   * The engine's correlation coverage gaps of the session `model` was built from: the same run, the
   * same first reply. A reader that pairs this model with anything else about its session (the
   * dock pairs it with a window of that session's items) must read the gaps here, never from
   * `EvtxCorrelationData.gaps`, which belongs to the full model and can be an older session's.
   */
  gaps: CorrelationGaps;
  /**
   * What the session `model` was built from, from the same run, for the same reason as `gaps`.
   * Null when the caller did not know it.
   */
  scope: ScopeDisclosureInput | null;
  /** An earlier session's counts, shown while the newest is loaded. */
  updating: boolean;
}

export interface EvtxCorrelationData {
  /** How far the NEWEST session has got. The fields below describe `model`, which may be older. */
  stage: CorrelationStage;
  /** The `sessionId:revision` `model` was built for, or null. */
  builtFor: string | null;
  /**
   * The model for a consumer that needs items. It is the newest FULL model there is: while a newer
   * session is scanned the previous full model stays here, with `updating` true, and only a
   * completed scan replaces it. Before any scan finished it is the counts-only model
   * (`hasItems` false). Counts-only consumers read `counts`.
   */
  model: CorrelationChainModel | null;
  /** True once items were read: only then are titles, spans and positions meaningful. */
  hasItems: boolean;
  /** The items `model` was built with, by origin id. Empty until `hasItems`. */
  itemsById: ReadonlyMap<string, TimelineItem>;
  /** The placed items' origins and the unplaced origins `model` was built from: the join's input. */
  origins: OriginLookup;
  /** The edges `model` was built from. */
  edges: CorrelationEdgeState;
  /**
   * The engine's correlation coverage gaps of the session `model` was built from. Pass them to the
   * links index and to the plot: without them a record the engine never correlated reads as having
   * no link. The origins they name were read with the items, so `origins` holds them.
   */
  gaps: CorrelationGaps;
  /**
   * What the session `model` was built from: the visible, loaded and text-log counts at the time.
   * It travels with the model, so it is always the scope of the model shown, however many newer
   * sessions have been published since. Null when the caller did not know it.
   */
  scope: ScopeDisclosureInput | null;
  /** The scan `model` was built from. */
  scan: CorrelationScanState;
  /** The scan in flight for a newer session, with its progress, or null. */
  nextScan: CorrelationScanState | null;
  /**
   * What is known about members with no item, from the SAME session, page and scan `model` was
   * built from, never from a newer status that has not replaced it.
   */
  unplaced: UnplacedEvidence;
  /** Distinct exact and candidate partners per origin id, from the uncapped pairs of `model`. */
  linkPartners: ReadonlyMap<string, number>;
  /** The newest session's counts-only model, or null. */
  counts: CorrelationCounts | null;
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
const NO_ORIGINS: OriginLookup = new Map();
const NO_PARTNERS: ReadonlyMap<string, number> = new Map();

export const UNAVAILABLE_CORRELATION: EvtxCorrelationData = {
  stage: "unavailable",
  builtFor: null,
  model: null,
  hasItems: false,
  itemsById: NO_ITEMS,
  origins: NO_ORIGINS,
  edges: NO_EDGES,
  gaps: UNKNOWN_CORRELATION_GAPS,
  scope: null,
  scan: IDLE_SCAN,
  nextScan: null,
  unplaced: NO_UNPLACED,
  linkPartners: NO_PARTNERS,
  counts: null,
  updating: false,
  error: null,
  retry: () => undefined,
};

/** One model with everything that was true when it was built, so nothing is paired across runs. */
interface ModelState {
  builtFor: string;
  model: CorrelationChainModel;
  hasItems: boolean;
  itemsById: ReadonlyMap<string, TimelineItem>;
  origins: OriginLookup;
  edges: CorrelationEdgeState;
  gaps: CorrelationGaps;
  scope: ScopeDisclosureInput | null;
  scan: CorrelationScanState;
  unplaced: UnplacedEvidence;
  linkPartners: ReadonlyMap<string, number>;
}

/**
 * What the runs have built so far; the hook turns it into `EvtxCorrelationData`.
 *
 * `error` belongs to a run that has ended: every successful publish of a later run (counts, a
 * reused model, a full model) and the gap that follows a session clears it, so a recovered session
 * never shows the old message beside its valid models.
 */
interface RunState {
  phase: CorrelationStage;
  /** The newest full model. Kept across sessions until a newer one is built. */
  detail: ModelState | null;
  /** The newest counts-only model. */
  counts: ModelState | null;
  nextScan: CorrelationScanState | null;
  error: string | null;
}

const EMPTY_RUN: RunState = {
  phase: "unavailable",
  detail: null,
  counts: null,
  nextScan: null,
  error: null,
};

/** What a session has already given, so toggling `needItems` does not reload the edges. */
interface SessionCache {
  page: EventLogAnalysisTimelinePage;
  edges?: LoadedEdges;
  counts?: ModelState;
  items?: LoadedLinkedItems;
  /** The edge load `items` was scanned for: the scan answers for exactly those endpoints. */
  itemsFor?: LoadedEdges;
  detail?: ModelState;
}

export interface UseEvtxCorrelationOptions {
  /** The published session, or null while none is. */
  status: EventLogAnalysisSessionStatus | null;
  /**
   * The reply for offset 0: its edge preview and its own `totalEdges` travel together. Pass the
   * same object for the life of a session: the hook keys what it has loaded on it.
   */
  initialPage: EventLogAnalysisTimelinePage | null;
  /** A session is being built, so a null `status` is a gap and not an end. */
  pending: boolean;
  /**
   * What THIS session (`status` and `initialPage`) was built from, given together with them so the
   * hook can store it with the models it builds. Null when there is no session or it is not known.
   */
  scope: ScopeDisclosureInput | null;
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
  const { status, initialPage, pending, needItems, scope } = options;
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
    const stop = () => {
      generationRef.current += 1;
    };

    if (status === null || initialPage === null) {
      // A gap while the session is rebuilt keeps the last models; the end of data clears them.
      cacheRef.current = null;
      setRun((previous) =>
        pending && (previous.detail !== null || previous.counts !== null)
          ? { ...previous, phase: "pending", nextScan: null, error: null }
          : { ...EMPTY_RUN, phase: pending ? "pending" : "unavailable" },
      );
      return stop;
    }

    if (cacheRef.current?.page !== initialPage) cacheRef.current = { page: initialPage };
    const cache = cacheRef.current;
    if (retryRef.current) {
      retryRef.current = false;
      if (cache.edges !== undefined && !cache.edges.complete) {
        // Every model built from the short edge set is stale, whatever its scan said.
        cache.edges = undefined;
        cache.counts = undefined;
        cache.items = undefined;
        cache.itemsFor = undefined;
        cache.detail = undefined;
      }
      if (cache.items !== undefined && !cache.items.complete) {
        cache.items = undefined;
        cache.itemsFor = undefined;
        cache.detail = undefined;
      }
    }
    const sessionKey = sessionKeyOf(status) as string;

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
    // From this run's own first reply: its gap preview and its own count travel together, and an
    // untrusted count is unknown, never 0.
    const gaps = classifyCoverageGaps(
      initialPage.coverageGapsPreview,
      knownTotal(initialPage.totalCoverageGaps),
    );
    // From this run's own page and status, so the evidence belongs to the model it is stored with.
    const unplacedEvidence = (scanComplete: boolean): UnplacedEvidence => ({
      scanComplete,
      unplacedListComplete: initialPage.unplacedPreview.length === status.totalUnplaced,
      unplacedIds: new Set(initialPage.unplacedPreview.map((entry) => timelineOriginId(entry.origin))),
    });

    // A finished full model serves every consumer; a counts-only one serves a consumer that needs
    // no items. Neither is rebuilt for a toggle of `needItems`.
    if (cache.detail !== undefined) {
      const detail = cache.detail;
      setRun((previous) => ({
        ...previous,
        phase: "ready",
        detail,
        counts: cache.counts ?? previous.counts,
        nextScan: null,
        error: null,
      }));
      return stop;
    }
    if (!needItems && cache.counts !== undefined) {
      const counts = cache.counts;
      setRun((previous) => ({ ...previous, phase: "edgesOnly", counts, nextScan: null, error: null }));
      return stop;
    }
    // Until this session's own model is in, the previous ones stay and `updating` says so.
    setRun((previous) =>
      previous.counts?.builtFor === sessionKey
        ? { ...previous, phase: needItems ? "scanning" : "edgesOnly" }
        : { ...previous, phase: "pending" },
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

        let counts = cache.counts;
        if (counts === undefined) {
          await deps.sleep(0);
          if (cancelled()) return;
          const model = build(loadedEdges, []);
          counts = {
            builtFor: sessionKey,
            model,
            hasItems: false,
            itemsById: NO_ITEMS,
            origins: originLookup([], initialPage.unplacedPreview),
            edges: edgeState(loadedEdges),
            gaps,
            scope,
            scan: IDLE_SCAN,
            unplaced: unplacedEvidence(false),
            linkPartners: linkPartnerCounts(model.linkedPairs),
          };
          cache.counts = counts;
        }
        update({ counts, phase: needItems ? "scanning" : "edgesOnly", error: null });
        if (!needItems) return;

        let items = cache.items;
        if (items === undefined || cache.itemsFor !== loadedEdges) {
          // The origins the gaps name are read too: a gap says an origin was never correlated, and
          // which records that makes unknown needs its fields, whether or not it has an edge. Only
          // while that can matter: once a limit or a cut preview already clears completeness, no
          // attribution makes the answer complete, and a session with no edge would pay a full
          // scan for nothing.
          const wantedIds = edgeEndpointIds(loadedEdges.edges);
          if (!gapsClearCompleteness(gaps)) {
            for (const originId of gaps.originIds) wantedIds.add(originId);
          }
          update({ nextScan: { state: "running", progress: null, stoppedBy: null, error: null } });
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
              update({
                nextScan: { state: "running", progress, stoppedBy: null, error: null },
              }),
            deps,
          });
          cache.items = items;
          cache.itemsFor = loadedEdges;
        }

        await deps.sleep(0);
        if (cancelled()) return;
        const scanned = items;
        const full = build(loadedEdges, scanned.items);
        const detail: ModelState = {
          builtFor: sessionKey,
          model: full,
          hasItems: true,
          itemsById: itemsByOriginId(scanned.items),
          origins: originLookup(scanned.items, initialPage.unplacedPreview),
          edges: edgeState(loadedEdges),
          gaps,
          scope,
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
          unplaced: unplacedEvidence(scanned.complete),
          linkPartners: linkPartnerCounts(full.linkedPairs),
        };
        cache.detail = detail;
        update({ detail, phase: "ready", nextScan: null, error: null });
      } catch (error) {
        // Cancellation is the only expected throw; anything else is shown, not swallowed.
        if (cancelled() || error instanceof CorrelationLoadCancelled) return;
        update({ nextScan: null, error: error instanceof Error ? error.message : String(error) });
      }
    })();

    return stop;
    // `status` and `initialPage` are read through their identifiers: a new object for the same
    // session and revision is the same session. `initialPage` is listed because the first page
    // belongs to the session it was fetched for.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, revision, initialPage, pending, needItems, settleMs, retryNonce]);

  const retry = useCallback(() => {
    retryRef.current = true;
    setRetryNonce((nonce) => nonce + 1);
  }, []);

  return useMemo<EvtxCorrelationData>(() => {
    const primary = run.detail ?? run.counts;
    return {
      stage: run.phase,
      builtFor: primary?.builtFor ?? null,
      model: primary?.model ?? null,
      hasItems: primary?.hasItems ?? false,
      itemsById: primary?.itemsById ?? NO_ITEMS,
      origins: primary?.origins ?? NO_ORIGINS,
      edges: primary?.edges ?? NO_EDGES,
      gaps: primary?.gaps ?? UNKNOWN_CORRELATION_GAPS,
      scope: primary?.scope ?? null,
      scan: primary?.scan ?? IDLE_SCAN,
      nextScan: run.nextScan,
      unplaced: primary?.unplaced ?? NO_UNPLACED,
      linkPartners: primary?.linkPartners ?? NO_PARTNERS,
      counts:
        run.counts === null
          ? null
          : {
              model: run.counts.model,
              builtFor: run.counts.builtFor,
              edges: run.counts.edges,
              linkPartners: run.counts.linkPartners,
              gaps: run.counts.gaps,
              scope: run.counts.scope,
              updating: run.counts.builtFor !== key,
            },
      updating: primary !== null && primary.builtFor !== key,
      error: run.error,
      retry,
    };
  }, [run, key, retry]);
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
