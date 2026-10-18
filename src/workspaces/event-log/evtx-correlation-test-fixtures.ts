/**
 * Fixtures for the Correlation view's tests: edges from the parser crate's own reducer
 * (`__fixtures__/correlation-edges.json`), synthetic edges for what the engine cannot yet produce,
 * events and the loaded records they name, and `makeData`, which builds the shared correlation data
 * as the hook stores it (the real chain model over these items and edges).
 *
 * Test code only: nothing outside a test file imports it.
 */
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import { classifyCoverageGaps, type CorrelationGaps } from "./evtx-correlation-gaps";
import { itemsByOriginId, linkPartnerCounts, originLookup } from "./evtx-correlation-origin-index";
import { UNAVAILABLE_CORRELATION, type EvtxCorrelationData } from "./useEvtxCorrelation";
import type { EvtxRecord } from "./types";
import {
  assertUnifiedTimelineShape,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineItem,
  type TimelineSeverity,
} from "./unified-timeline";

export const rid = (n: number) => `source4:Live|machine10:DESKTOP-01|channel6:System|record${n}`;
export const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
export const CLEAR_GAPS = classifyCoverageGaps([], 0);

export function fixtureEdges(name: string, offset = 0): TimelineCorrelationEdge[] {
  const scenarios = fixtureDocument.scenarios as unknown as Record<
    string,
    { edges: unknown[]; coverageGaps: unknown[] }
  >;
  const scenario = scenarios[name];
  if (scenario === undefined) throw new Error(`no fixture scenario ${name}`);
  const shifted = JSON.parse(
    JSON.stringify(scenario).replace(/record(\d+)/g, (_m, n: string) => `record${Number(n) + offset}`),
  ) as typeof scenario;
  return assertUnifiedTimelineShape({
    items: [],
    unplaced: [],
    edges: shifted.edges,
    coverageGaps: shifted.coverageGaps,
  }).edges;
}

export function synthetic(
  id: string,
  fromId: string,
  toId: string,
  strength: TimelineCorrelationEdge["strength"] = "exact",
): TimelineCorrelationEdge {
  return {
    id,
    fromId,
    toId,
    key: { kind: "activityId", value: `key-${id}` },
    strength,
    confidence: "high",
    candidateIds: [],
    evidence: [
      { originId: fromId, field: "activityId", value: `key-${id}` },
      { originId: toId, field: "activityId", value: `key-${id}` },
    ],
    coverage: { state: "covered" },
  };
}

/** Every origin id an edge set names. */
export function idsOf(edges: readonly TimelineCorrelationEdge[]): string[] {
  const ids = new Set<string>();
  for (const edge of edges) {
    ids.add(edge.fromId);
    if (edge.toId !== null) ids.add(edge.toId);
    for (const candidate of edge.candidateIds) ids.add(candidate);
  }
  return [...ids];
}

export const numberOf = (id: string) => Number(/record(\d+)$/.exec(id)?.[1]);

export function eventItem(
  n: number,
  timestampMs: number,
  severity: TimelineSeverity = "info",
  message = `message ${n}`,
): TimelineItem {
  return {
    timestampMs,
    severity,
    message,
    origin: {
      kind: "event",
      stableId: rid(n),
      source: "Live",
      machine: "DESKTOP-01",
      bundle: null,
      channel: "System",
      provider: "P",
      processId: null,
      eventId: 100 + n,
      recordId: n,
    },
  };
}

/** The loaded record the origin of `eventItem(n)` names, field for field. */
export function recordFor(n: number): EvtxRecord {
  return {
    id: n,
    eventRecordId: n,
    eventRecordIdText: String(n),
    timestamp: "",
    timestampEpoch: T0 + n * 1_000,
    provider: "P",
    channel: "System",
    eventId: 100 + n,
    level: "Information",
    computer: "DESKTOP-01",
    message: `message ${n}`,
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
  };
}

export interface DataOptions {
  items: TimelineItem[];
  edges: TimelineCorrelationEdge[];
  totalEdges?: number;
  hasItems?: boolean;
  gaps?: CorrelationGaps;
  updating?: boolean;
  builtFor?: string;
  stage?: EvtxCorrelationData["stage"];
  scan?: Partial<EvtxCorrelationData["scan"]>;
  nextScan?: EvtxCorrelationData["nextScan"];
  unplaced?: Partial<EvtxCorrelationData["unplaced"]>;
  /**
   * The unplaced list and its count; by default an empty list the session counts as empty. Null is
   * NO RUN, as in the hook: `makeData` then returns the unavailable shape (no model, no counts, a
   * null list). A run whose count is unknown is `{ items: [], total: null }`. The `unplaced`
   * evidence is derived from the list, as the hook derives it.
   */
  unplacedList?: EvtxCorrelationData["unplacedList"];
  edgeState?: Partial<EvtxCorrelationData["edges"]>;
  error?: string | null;
  retry?: () => void;
  /** Overrides the counts-only model; null is a session whose counts are not in yet. */
  counts?: EvtxCorrelationData["counts"];
  /** What the session was built from; by default nothing was narrowed. Null is not known. */
  scope?: EvtxCorrelationData["scope"];
}

/** Nine events loaded and nine visible, no text logs: nothing narrowed. */
export const UNNARROWED_SCOPE = { visibleCount: 9, loadedCount: 9, textLogCount: 0 } as const;

/** An unplaced list the session counts as empty: no item, and a trusted count of 0. */
export const EMPTY_UNPLACED_LIST: NonNullable<EvtxCorrelationData["unplacedList"]> = { items: [], total: 0 };

/** The edge total the hook would store: a count, or null when none can be trusted. */
function knownEdgeTotal(total: number): number | null {
  return Number.isSafeInteger(total) && total >= 0 ? total : null;
}

/**
 * The edges-only model of the session, as the hook keeps it beside the full one. There are counts
 * only for a run, so an unplaced list of null (no run) is refused by the type: it must not become a
 * counted zero here. `makeData` gives no counts for it.
 */
export function makeCounts(
  options: Omit<DataOptions, "unplacedList"> & {
    unplacedList?: NonNullable<DataOptions["unplacedList"]>;
  },
): NonNullable<EvtxCorrelationData["counts"]> {
  const total = options.totalEdges ?? options.edges.length;
  const model = buildCorrelationChains({
    items: [],
    timelineEdges: options.edges,
    totalTimelineEdges: total,
    findings: [],
  });
  return {
    model,
    builtFor: options.builtFor ?? "session:1",
    edges: {
      loaded: options.edges.length,
      totalEdges: knownEdgeTotal(total),
      complete: model.edgeInputComplete,
      error: null,
      ...options.edgeState,
    },
    linkPartners: linkPartnerCounts(model.linkedPairs),
    unplacedList: options.unplacedList === undefined ? EMPTY_UNPLACED_LIST : options.unplacedList,
    updating: options.updating ?? false,
  };
}

/**
 * Shared data as the hook would store it: the real chain model over these items and edges.
 *
 * A default here is written `??` only where null is NOT a state of that field (a count, a flag, a
 * name). Where null means something (`scope`: not known; `counts`: not in yet; `unplacedList`: no
 * run), the default is an `=== undefined` check, so a test that asks for null gets null and not a
 * neighbouring value such as a counted zero.
 */
export function makeData(options: DataOptions): EvtxCorrelationData {
  // No run (an unplaced list of null) is the hook's unavailable shape: no model, no items, no
  // counts, no evidence. It is not a "ready" model with the list taken away.
  if (options.unplacedList === null) {
    return {
      ...UNAVAILABLE_CORRELATION,
      stage: options.stage === "pending" ? "pending" : "unavailable",
      error: options.error ?? null,
      retry: options.retry ?? UNAVAILABLE_CORRELATION.retry,
    };
  }
  const list = options.unplacedList === undefined ? EMPTY_UNPLACED_LIST : options.unplacedList;
  const hasItems = options.hasItems ?? true;
  const items = hasItems ? options.items : [];
  const model = buildCorrelationChains({
    items,
    timelineEdges: options.edges,
    totalTimelineEdges: options.totalEdges ?? options.edges.length,
    findings: [],
  });
  return {
    ...UNAVAILABLE_CORRELATION,
    stage: options.stage ?? "ready",
    builtFor: options.builtFor ?? "session:1",
    model,
    hasItems,
    itemsById: itemsByOriginId(items),
    origins: originLookup(items, []),
    edges: {
      loaded: options.edges.length,
      totalEdges: knownEdgeTotal(options.totalEdges ?? options.edges.length),
      complete: model.edgeInputComplete,
      error: null,
      ...options.edgeState,
    },
    gaps: options.gaps ?? CLEAR_GAPS,
    scope: options.scope === undefined ? UNNARROWED_SCOPE : options.scope,
    scan: { state: "complete", progress: null, stoppedBy: null, error: null, ...options.scan },
    nextScan: options.nextScan ?? null,
    // The evidence is derived from the list as the hook derives it: complete only when the count is
    // known and equals the items listed, and the ids are the listed items'. A test that wants a
    // contradiction (a complete list with an unknown count) has to say so with `unplaced`.
    unplaced: {
      scanComplete: true,
      unplacedListComplete: list.total !== null && list.items.length === list.total,
      unplacedIds: new Set(list.items.map((item) => timelineOriginId(item.origin))),
      ...options.unplaced,
    },
    unplacedList: list,
    linkPartners: linkPartnerCounts(model.linkedPairs),
    counts: options.counts !== undefined ? options.counts : makeCounts({ ...options, unplacedList: list }),
    updating: options.updating ?? false,
    error: options.error ?? null,
    retry: options.retry ?? (() => undefined),
  };
}
