/**
 * Correlation chain model for the Event Logs workbench (spec section 8.11, decision Q-4).
 *
 * Pure: no React, no stores, no IO. Turns correlation relations into the rows the Correlation
 * view and the rail show, and nothing more than the relations support.
 *
 * Rules, all enforced here:
 * - A chain is a connected component over `exact` and `candidate` relations. Its strength is its
 *   weakest relation.
 * - `ambiguous` and `coverageBlocked` relations never merge components. Each is one standalone
 *   item. Ambiguous and blocked relations are not evidence of a link.
 * - `timestampOnly` basis and `notCausal` status are never a chain, a chain count or a connector
 *   (D7). They only populate `nearby`. Time alone does not establish causality.
 */

import type {
  DiagnosisCorrelationEdge,
  DiagnosisCorrelationEvidence,
} from "./types";
import {
  TIMELINE_SEVERITY_RANK,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineCorrelationKey,
  type TimelineItem,
} from "./unified-timeline";

/** Same bound as `UNPLACED_PREVIEW_LIMIT` in `UnifiedTimelineView`. */
export const CORRELATION_CHAIN_RENDER_LIMIT = 100;

const TITLE_HEAD_LIMIT = 80;

export type CorrelationChainStrength =
  | "exact"
  | "candidate"
  | "ambiguous"
  | "coverageBlocked";

const STRENGTH_ORDER: readonly CorrelationChainStrength[] = [
  "exact",
  "candidate",
  "ambiguous",
  "coverageBlocked",
];

export interface CorrelationEvidenceRow {
  originId: string;
  field: string;
  value: string;
}

/**
 * A diagnosis finding reduced to what the chain title needs. The caller resolves the finding's
 * evidence references to timeline origin ids; `DiagnosisEvidence` does not carry them.
 */
export interface ChainFindingCoverage {
  findingId: string;
  title: string;
  originIds: readonly string[];
}

export interface CorrelationChainInput {
  /** Placed timeline items, used for titles, spans and member order. */
  items: readonly TimelineItem[];
  timelineEdges: readonly TimelineCorrelationEdge[];
  diagnosisEdges: readonly DiagnosisCorrelationEdge[];
  findings: readonly ChainFindingCoverage[];
}

export interface CorrelationChainEdge {
  /** Endpoints are ordered; `right` is null only for a relation with candidates. */
  left: string;
  right: string | null;
  strength: CorrelationChainStrength;
  keys: TimelineCorrelationKey[];
}

export interface CorrelationChain {
  id: string;
  strength: CorrelationChainStrength;
  /** Members in timestamp order, unknown timestamps last, then by id. */
  memberIds: string[];
  edges: CorrelationChainEdge[];
  keys: TimelineCorrelationKey[];
  evidence: CorrelationEvidenceRow[];
  startMs: number | null;
  endMs: number | null;
  /** D19. Null when no member has a placed timeline item to derive a title from. */
  title: string | null;
}

export interface NearbyRelation {
  left: string;
  right: string | null;
  evidence: CorrelationEvidenceRow[];
}

export interface CorrelationChainModel {
  /** Ordered rows, capped at `CORRELATION_CHAIN_RENDER_LIMIT`. */
  chains: CorrelationChain[];
  /** Rows before the cap. Never includes `nearby`. */
  totalCount: number;
  omittedCount: number;
  /** Rows per strength before the cap. Never includes `nearby`. */
  counts: Record<CorrelationChainStrength, number>;
  /** "Nearby, not linked": timestamp-only and not-causal relations. Not capped. */
  nearby: NearbyRelation[];
  /** Exact or candidate relations that cannot link two entries (no second endpoint, or a self-link). */
  ignoredRelationCount: number;
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareNullableNumber(a: number | null, b: number | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a - b;
}

interface Relation {
  left: string;
  right: string | null;
  strength: CorrelationChainStrength;
  candidateIds: string[];
  keys: TimelineCorrelationKey[];
  evidence: CorrelationEvidenceRow[];
}

type Classified =
  | { kind: "relation"; relation: Relation }
  | { kind: "nearby"; relation: Relation };

function orderEndpoints(
  left: string,
  right: string | null,
): { left: string; right: string | null } {
  return right !== null && right < left
    ? { left: right, right: left }
    : { left, right };
}

function evidenceRows(
  rows: readonly DiagnosisCorrelationEvidence[],
): CorrelationEvidenceRow[] {
  return rows.map(({ originId, field, value }) => ({ originId, field, value }));
}

function classifyTimelineEdge(edge: TimelineCorrelationEdge): Classified {
  // A coverage gap blocks the link, whatever the edge strength says.
  let strength: CorrelationChainStrength =
    edge.coverage.state === "gap" ? "coverageBlocked" : edge.strength;
  // A secondary key is a candidate identifier and can never be stronger than candidate.
  if (strength === "exact" && edge.key.kind === "secondary") {
    strength = "candidate";
  }
  return {
    kind: "relation",
    relation: {
      ...orderEndpoints(edge.fromId, edge.toId),
      strength,
      candidateIds: [...edge.candidateIds],
      keys: [{ kind: edge.key.kind, value: edge.key.value }],
      evidence: evidenceRows(edge.evidence),
    },
  };
}

function classifyDiagnosisEdge(edge: DiagnosisCorrelationEdge): Classified {
  const base = {
    ...orderEndpoints(edge.left, edge.right),
    candidateIds: [...edge.candidateIds],
    keys: [],
    evidence: evidenceRows(edge.evidence),
  };
  // D7: time alone is never a link, whatever status was attached to it.
  if (edge.basis === "timestampOnly" || edge.status === "notCausal") {
    return {
      kind: "nearby",
      relation: { ...base, strength: "ambiguous" },
    };
  }
  let strength: CorrelationChainStrength = edge.status;
  if (strength === "exact" && edge.basis === "candidateIdentifier") {
    strength = "candidate";
  }
  return { kind: "relation", relation: { ...base, strength } };
}

function relationKey(relation: Relation): string {
  return [
    relation.strength,
    relation.left,
    relation.right ?? "",
    [...relation.candidateIds].sort().join("\u0000"),
  ].join("\u0001");
}

function keyId(key: TimelineCorrelationKey): string {
  return `${key.kind}\u0001${key.value}`;
}

function rowId(row: CorrelationEvidenceRow): string {
  return `${row.originId}\u0001${row.field}\u0001${row.value}`;
}

function uniqueSorted<T>(values: readonly T[], id: (value: T) => string): T[] {
  const byId = new Map<string, T>();
  for (const value of values) byId.set(id(value), value);
  return [...byId.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, value]) => value);
}

/** Collapses duplicate relations (the same link seen by both inputs) into one. */
function mergeRelations(
  relations: readonly Relation[],
  keyOf: (relation: Relation) => string,
): Relation[] {
  const merged = new Map<string, Relation>();
  for (const relation of relations) {
    const key = keyOf(relation);
    const existing = merged.get(key);
    merged.set(
      key,
      existing === undefined
        ? relation
        : {
            ...existing,
            keys: [...existing.keys, ...relation.keys],
            evidence: [...existing.evidence, ...relation.evidence],
          },
    );
  }
  return [...merged.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, relation]) => ({
      ...relation,
      candidateIds: [...relation.candidateIds].sort(),
      keys: uniqueSorted(relation.keys, keyId),
      evidence: uniqueSorted(relation.evidence, rowId),
    }));
}

class DisjointSet {
  private readonly parent = new Map<string, string>();

  find(id: string): string {
    let root = id;
    for (;;) {
      const next = this.parent.get(root);
      if (next === undefined || next === root) break;
      root = next;
    }
    this.parent.set(id, root);
    return root;
  }

  union(a: string, b: string): void {
    const rootA = this.find(a);
    const rootB = this.find(b);
    if (rootA !== rootB) this.parent.set(rootA, rootB);
  }
}

function messageHead(message: string): string {
  const line =
    message
      .split(/\r?\n/)
      .map((part) => part.trim())
      .find((part) => part !== "") ?? "";
  return line.length > TITLE_HEAD_LIMIT
    ? `${line.slice(0, TITLE_HEAD_LIMIT - 3)}...`
    : line;
}

function itemLabel(item: TimelineItem): string {
  return item.origin.kind === "event"
    ? String(item.origin.eventId)
    : `${item.origin.source} · line ${item.origin.line}`;
}

/** D19: highest-severity member, ties broken by earliest timestamp, then by id. */
function derivedTitle(
  memberIds: readonly string[],
  itemsById: ReadonlyMap<string, TimelineItem>,
): string | null {
  let bestId: string | null = null;
  let best: TimelineItem | null = null;
  for (const id of memberIds) {
    const item = itemsById.get(id);
    if (item === undefined) continue;
    if (best === null || bestId === null) {
      best = item;
      bestId = id;
      continue;
    }
    const rank =
      TIMELINE_SEVERITY_RANK[item.severity] -
      TIMELINE_SEVERITY_RANK[best.severity];
    if (
      rank > 0 ||
      (rank === 0 &&
        (item.timestampMs < best.timestampMs ||
          (item.timestampMs === best.timestampMs && id < bestId)))
    ) {
      best = item;
      bestId = id;
    }
  }
  if (best === null) return null;
  const head = messageHead(best.message);
  return head === "" ? itemLabel(best) : `${itemLabel(best)} · ${head}`;
}

function coveringFindingTitle(
  memberIds: readonly string[],
  findings: readonly ChainFindingCoverage[],
): string | null {
  const covering = findings
    .filter((finding) => {
      const covered = new Set(finding.originIds);
      return memberIds.every((id) => covered.has(id));
    })
    .sort((a, b) => compareStrings(a.findingId, b.findingId));
  return covering[0]?.title ?? null;
}

function span(
  memberIds: readonly string[],
  itemsById: ReadonlyMap<string, TimelineItem>,
): { startMs: number | null; endMs: number | null } {
  let startMs: number | null = null;
  let endMs: number | null = null;
  for (const id of memberIds) {
    const timestamp = itemsById.get(id)?.timestampMs;
    if (timestamp === undefined) continue;
    startMs = startMs === null ? timestamp : Math.min(startMs, timestamp);
    endMs = endMs === null ? timestamp : Math.max(endMs, timestamp);
  }
  return { startMs, endMs };
}

function sortMembers(
  ids: Iterable<string>,
  itemsById: ReadonlyMap<string, TimelineItem>,
): string[] {
  return [...new Set(ids)].sort(
    (a, b) =>
      compareNullableNumber(
        itemsById.get(a)?.timestampMs ?? null,
        itemsById.get(b)?.timestampMs ?? null,
      ) || compareStrings(a, b),
  );
}

function weakest(
  relations: readonly Relation[],
): Extract<CorrelationChainStrength, "exact" | "candidate"> {
  return relations.some((relation) => relation.strength === "candidate")
    ? "candidate"
    : "exact";
}

function toChain(
  id: string,
  strength: CorrelationChainStrength,
  relations: readonly Relation[],
  memberIds: readonly string[],
  itemsById: ReadonlyMap<string, TimelineItem>,
  findings: readonly ChainFindingCoverage[],
): CorrelationChain {
  const members = sortMembers(memberIds, itemsById);
  const isChain = strength === "exact" || strength === "candidate";
  return {
    id,
    strength,
    memberIds: members,
    edges: relations.map((relation) => ({
      left: relation.left,
      right: relation.right,
      strength: relation.strength,
      keys: relation.keys,
    })),
    keys: uniqueSorted(
      relations.flatMap((relation) => relation.keys),
      keyId,
    ),
    evidence: uniqueSorted(
      relations.flatMap((relation) => relation.evidence),
      rowId,
    ),
    ...span(members, itemsById),
    // Only a chain may borrow a finding's title; an ambiguous or blocked item is not a conclusion.
    title:
      (isChain ? coveringFindingTitle(members, findings) : null) ??
      derivedTitle(members, itemsById),
  };
}

export function buildCorrelationChains(
  input: CorrelationChainInput,
): CorrelationChainModel {
  const itemsById = new Map<string, TimelineItem>();
  for (const item of input.items) {
    const id = timelineOriginId(item.origin);
    const existing = itemsById.get(id);
    if (existing === undefined || item.timestampMs < existing.timestampMs) {
      itemsById.set(id, item);
    }
  }

  const classified = [
    ...input.timelineEdges.map(classifyTimelineEdge),
    ...input.diagnosisEdges.map(classifyDiagnosisEdge),
  ];

  const nearby = mergeRelations(
    classified.filter((c) => c.kind === "nearby").map((c) => c.relation),
    (relation) =>
      [
        relation.left,
        relation.right ?? "",
        [...relation.candidateIds].sort().join("\u0000"),
      ].join("\u0001"),
  ).map(({ left, right, evidence }) => ({ left, right, evidence }));

  const relations = mergeRelations(
    classified.filter((c) => c.kind === "relation").map((c) => c.relation),
    relationKey,
  );

  const links: Relation[] = [];
  const standalone: Relation[] = [];
  let ignoredRelationCount = 0;
  for (const relation of relations) {
    if (relation.strength === "exact" || relation.strength === "candidate") {
      if (relation.right === null || relation.right === relation.left) {
        ignoredRelationCount += 1;
      } else {
        links.push(relation);
      }
    } else {
      standalone.push(relation);
    }
  }

  // Only exact and candidate relations are ever unioned. This is the Q-4 invariant.
  const sets = new DisjointSet();
  for (const relation of links) {
    sets.union(relation.left, relation.right as string);
  }
  const components = new Map<string, Relation[]>();
  for (const relation of links) {
    const root = sets.find(relation.left);
    components.set(root, [...(components.get(root) ?? []), relation]);
  }

  const rows: CorrelationChain[] = [];
  for (const componentRelations of components.values()) {
    const members = componentRelations.flatMap((relation) => [
      relation.left,
      relation.right as string,
    ]);
    const smallest = [...new Set(members)].sort(compareStrings)[0] as string;
    rows.push(
      toChain(
        `chain\u0001${smallest}`,
        weakest(componentRelations),
        componentRelations,
        members,
        itemsById,
        input.findings,
      ),
    );
  }
  for (const relation of standalone) {
    rows.push(
      toChain(
        relationKey(relation),
        relation.strength,
        [relation],
        [
          relation.left,
          ...(relation.right === null ? [] : [relation.right]),
          ...relation.candidateIds,
        ],
        itemsById,
        input.findings,
      ),
    );
  }

  rows.sort(
    (a, b) =>
      STRENGTH_ORDER.indexOf(a.strength) - STRENGTH_ORDER.indexOf(b.strength) ||
      b.memberIds.length - a.memberIds.length ||
      compareNullableNumber(a.startMs, b.startMs) ||
      compareStrings(a.id, b.id),
  );

  const counts: Record<CorrelationChainStrength, number> = {
    exact: 0,
    candidate: 0,
    ambiguous: 0,
    coverageBlocked: 0,
  };
  for (const row of rows) counts[row.strength] += 1;

  const chains = rows.slice(0, CORRELATION_CHAIN_RENDER_LIMIT);
  return {
    chains,
    totalCount: rows.length,
    omittedCount: rows.length - chains.length,
    counts,
    nearby,
    ignoredRelationCount,
  };
}
