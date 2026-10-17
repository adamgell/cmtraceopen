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
  edgeState?: Partial<EvtxCorrelationData["edges"]>;
  error?: string | null;
  retry?: () => void;
}

/** Shared data as the hook would store it: the real chain model over these items and edges. */
export function makeData(options: DataOptions): EvtxCorrelationData {
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
      totalEdges: options.totalEdges ?? options.edges.length,
      complete: model.edgeInputComplete,
      error: null,
      ...options.edgeState,
    },
    gaps: options.gaps ?? CLEAR_GAPS,
    scan: { state: "complete", progress: null, stoppedBy: null, error: null, ...options.scan },
    nextScan: options.nextScan ?? null,
    unplaced: {
      scanComplete: true,
      unplacedListComplete: true,
      unplacedIds: new Set(),
      ...options.unplaced,
    },
    linkPartners: linkPartnerCounts(model.linkedPairs),
    counts: null,
    updating: options.updating ?? false,
    error: options.error ?? null,
    retry: options.retry ?? (() => undefined),
  };
}
