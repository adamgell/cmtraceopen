/**
 * Correlation chain model for the Event Logs workbench (spec section 8.11, decision Q-4).
 *
 * Pure: no React, no stores, no IO. Turns the unified timeline's correlation edges into the rows
 * the Correlation view and the rail show, and nothing more than those edges support.
 *
 * Rules, all enforced here:
 * - Every timeline edge is one observation about an unordered pair of entries. Observations are
 *   reduced to ONE relation per pair, taking the WEAKEST label (exact > candidate > ambiguous >
 *   coverageBlocked). A non-linking observation (ambiguous or coverageBlocked) therefore vetoes a
 *   link, and the same link seen twice is still one edge.
 * - A chain is a connected component over pairs labeled `exact` or `candidate`. Its strength is
 *   its weakest relation.
 * - `ambiguous` and `coverageBlocked` relations never merge components. They are collapsed by the
 *   exact key (label, sorted member set): a backend ambiguous group of N ids arrives as N(N-1)/2
 *   pairwise edges that all share one member set and so become ONE row. Overlapping but unequal
 *   member sets are never merged.
 * - The backend produces no timestamp-only or not-causal edge, and the decoder rejects them (D7).
 *   Diagnosis correlations are a redacted, truncated projection of the same edges and are not an
 *   input here.
 */

import type { DiagnosisFindingClass } from "./types";
import {
  TIMELINE_SEVERITY_RANK,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineCorrelationKey,
  type TimelineCoverageGap,
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

/** Strongest first. A higher index is a weaker label and wins a contradiction. */
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
 * A diagnosis finding reduced to what the chain title needs.
 *
 * `originIds` must be EXACT timeline origin ids. They must never be rebuilt from redacted
 * diagnosis evidence, or from partial tuples such as event id + record id: that is weak identity
 * (ADR-002) and can attach a title to the wrong chain. Callers pass `[]` until the owner decides
 * how to restore that join.
 */
export interface ChainFindingCoverage {
  findingId: string;
  title: string;
  originIds: readonly string[];
  /**
   * Required, mirroring `DiagnosisFinding.class`: a caller that drops it gets a type error rather
   * than a finding that silently competes for titles. Only `TITLE_CONCLUSION_CLASSES` may title a
   * chain; any other value, including one this build does not know, is ignored for titles.
   *
   * When several findings cover a chain, a `confirmedFailure` wins over every other class, then
   * the lowest `findingId` wins.
   */
  findingClass: DiagnosisFindingClass;
}

export interface CorrelationChainInput {
  /** Placed timeline items, used for titles, spans and member order. */
  items: readonly TimelineItem[];
  /**
   * The edges that were loaded. The backend reply carries a bounded preview (at most 100 edges
   * within a byte budget), so this can be a prefix of the session's edges.
   */
  timelineEdges: readonly TimelineCorrelationEdge[];
  /**
   * Every timeline edge the session holds (the backend `totalEdges`), loaded or not. Required so a
   * bounded preview cannot be mistaken for the whole set. Compared with `timelineEdges.length`
   * to fill `edgeInputComplete` and `unloadedEdgeCount`.
   */
  totalTimelineEdges: number;
  findings: readonly ChainFindingCoverage[];
}

export interface CorrelationChainEdge {
  /** Endpoints are ordered (`left` <= `right`); `right` is null only for a relation with candidates. */
  left: string;
  right: string | null;
  /** The reduced label of this pair, after every observation of it was combined. */
  strength: CorrelationChainStrength;
  keys: TimelineCorrelationKey[];
}

export interface CorrelationChain {
  id: string;
  strength: CorrelationChainStrength;
  /**
   * Resolved members only (those present in `items`), in timestamp order, ties broken by id.
   * The view must mark a chain partial whenever `unresolvedMemberIds` is non-empty.
   */
  memberIds: string[];
  /** Members with no loaded timeline item, sorted by id. They are never given a position. */
  unresolvedMemberIds: string[];
  /** Total members, resolved and unresolved. Drives the "{n} entries" label and the row order. */
  memberCount: number;
  edges: CorrelationChainEdge[];
  keys: TimelineCorrelationKey[];
  evidence: CorrelationEvidenceRow[];
  /** De-duplicated, sorted union of the coverage gaps of this row's edges. */
  coverageGaps: TimelineCoverageGap[];
  /** From resolved members only. Null when none is resolved. */
  startMs: number | null;
  endMs: number | null;
  /** D19. From resolved members only. Null when none is resolved. */
  title: string | null;
}

export interface CorrelationChainModel {
  /** Ordered rows, capped at `CORRELATION_CHAIN_RENDER_LIMIT`. */
  chains: CorrelationChain[];
  /** Rows before the 100-row render cap. This is NOT about edges that were never loaded. */
  totalCount: number;
  /** Rows dropped by the 100-row render cap only. See `unloadedEdgeCount` for unloaded edges. */
  omittedCount: number;
  /**
   * True only when `totalTimelineEdges` is a non-negative safe integer equal to the number of
   * loaded edges. False when edges are missing (the chains were built from a bounded preview and
   * more may exist) and also when the total is contradictory (below the loaded count) or invalid
   * (NaN, infinite, negative, fractional): coverage states are not success evidence. Drives the
   * spec 8.11 "paged and bounded" copy.
   */
  edgeInputComplete: boolean;
  /**
   * Timeline edges the session holds that were not loaded into this model: never negative, and 0
   * when the total is contradictory or invalid (see `edgeInputComplete`, which is false then).
   */
  unloadedEdgeCount: number;
  /** Rows per strength before the cap, after collapsing. */
  counts: Record<CorrelationChainStrength, number>;
  /**
   * Reduced pairs that cannot link two entries: fewer than 2 distinct member ids, or an exact or
   * candidate relation with no second endpoint. Counted once per reduced pair, whatever the label.
   */
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

// Same length-prefixed convention as `timelineKeyPart` in unified-timeline.ts, so a value that
// contains a separator can never collide with a different tuple.
const utf8Encoder = new TextEncoder();
function keyPart(value: string): string {
  return `${utf8Encoder.encode(value).length}:${value}`;
}

function keyOf(...parts: readonly string[]): string {
  return parts.map(keyPart).join("|");
}

function strengthIndex(strength: CorrelationChainStrength): number {
  return STRENGTH_ORDER.indexOf(strength);
}

function isLinking(
  strength: CorrelationChainStrength,
): strength is "exact" | "candidate" {
  return strength === "exact" || strength === "candidate";
}

/** One reduced relation: every observation of one ordered pair, combined. */
interface Relation {
  left: string;
  right: string | null;
  strength: CorrelationChainStrength;
  candidateIds: string[];
  keys: TimelineCorrelationKey[];
  evidence: CorrelationEvidenceRow[];
  gaps: TimelineCoverageGap[];
}

function orderEndpoints(
  left: string,
  right: string | null,
): { left: string; right: string | null } {
  return right !== null && right < left
    ? { left: right, right: left }
    : { left, right };
}

function classifyTimelineEdge(edge: TimelineCorrelationEdge): Relation {
  let strength: CorrelationChainStrength;
  if (edge.strength === "ambiguous") {
    // Ambiguous stays ambiguous even when the edge also carries a coverage gap.
    strength = "ambiguous";
  } else if (edge.coverage.state === "gap") {
    strength = "coverageBlocked";
  } else if (edge.strength === "exact" && edge.key.kind === "secondary") {
    // A secondary key is a candidate identifier and can never be stronger than candidate.
    strength = "candidate";
  } else {
    strength = edge.strength;
  }
  const gap = edge.coverage.gap;
  return {
    ...orderEndpoints(edge.fromId, edge.toId),
    strength,
    candidateIds: [...edge.candidateIds],
    keys: [{ kind: edge.key.kind, value: edge.key.value }],
    evidence: edge.evidence.map(({ originId, field, value }) => ({
      originId,
      field,
      value,
    })),
    gaps:
      edge.coverage.state === "gap" && gap !== undefined && gap !== null
        ? [{ source: gap.source, reason: gap.reason }]
        : [],
  };
}

function relationKeyId(key: TimelineCorrelationKey): string {
  return keyOf(key.kind, key.value);
}

function evidenceId(row: CorrelationEvidenceRow): string {
  return keyOf(row.originId, row.field, row.value);
}

function gapId(gap: TimelineCoverageGap): string {
  return keyOf(gap.source, gap.reason);
}

function uniqueSorted<T>(values: readonly T[], id: (value: T) => string): T[] {
  const byId = new Map<string, T>();
  for (const value of values) byId.set(id(value), value);
  return [...byId.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, value]) => value);
}

function uniqueSortedStrings(values: Iterable<string>): string[] {
  return [...new Set(values)].sort(compareStrings);
}

function combine(relations: readonly Relation[]): Relation {
  const first = relations[0] as Relation;
  let strength = first.strength;
  for (const relation of relations) {
    if (strengthIndex(relation.strength) > strengthIndex(strength)) {
      strength = relation.strength;
    }
  }
  return {
    left: first.left,
    right: first.right,
    strength,
    candidateIds: uniqueSortedStrings(relations.flatMap((r) => r.candidateIds)),
    keys: uniqueSorted(
      relations.flatMap((r) => r.keys),
      relationKeyId,
    ),
    evidence: uniqueSorted(
      relations.flatMap((r) => r.evidence),
      evidenceId,
    ),
    gaps: uniqueSorted(
      relations.flatMap((r) => r.gaps),
      gapId,
    ),
  };
}

/** Reduces observations to one relation per ordered pair, taking the weakest label. */
function reduceByPair(observations: readonly Relation[]): Relation[] {
  const byPair = new Map<string, Relation[]>();
  for (const observation of observations) {
    const key =
      observation.right === null
        ? keyOf(observation.left, "-")
        : keyOf(observation.left, "+", observation.right);
    const group = byPair.get(key);
    if (group === undefined) byPair.set(key, [observation]);
    else group.push(observation);
  }
  return [...byPair.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, group]) => combine(group));
}

function memberSet(relation: Relation): string[] {
  return uniqueSortedStrings([
    relation.left,
    ...(relation.right === null ? [] : [relation.right]),
    ...relation.candidateIds,
  ]);
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
  // Count code points, not UTF-16 units, so a cut never lands inside a surrogate pair.
  const points = Array.from(line);
  return points.length > TITLE_HEAD_LIMIT
    ? `${points.slice(0, TITLE_HEAD_LIMIT - 3).join("")}...`
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

/**
 * The finding classes that state a conclusion, and so may lend their title to a chain. This is an
 * allow-list over `DiagnosisFindingClass` (`types.ts`): `coverageGap`, `contradictoryEvidence` and
 * `unknown` describe the absence or contradiction of a conclusion and are left out, as is any
 * class added later, so a new class fails closed until someone lists it here.
 */
const TITLE_CONCLUSION_CLASSES: ReadonlySet<string> = new Set<DiagnosisFindingClass>([
  "confirmedFailure",
  "likelyContributor",
  "symptom",
  "recovered",
]);

/**
 * Picks the title of the finding that covers the whole chain.
 *
 * Covers ALL members, resolved or not: a finding must account for the whole chain.
 *
 * Only the allow-listed conclusion classes may title a chain: never `coverageGap`,
 * `contradictoryEvidence`, `unknown`, an unset class or a class this build does not know.
 * A `contradictoryEvidence` finding that covers the whole chain vetoes every title.
 * Callers pass `originIds: []` today, so this never fires in the app. When the owner restores
 * the finding join (decision B on #838), keep this restriction: a finding that says "we
 * could not see" or "the evidence conflicts" must not be shown as the name of a correlated chain.
 */
function coveringFindingTitle(
  allMemberIds: readonly string[],
  findings: readonly ChainFindingCoverage[],
): string | null {
  const classRank = (finding: ChainFindingCoverage) =>
    finding.findingClass === "confirmedFailure" ? 0 : 1;
  const coversChain = (finding: ChainFindingCoverage) => {
    const covered = new Set(finding.originIds);
    return allMemberIds.every((id) => covered.has(id));
  };
  // A covering conflict means no terminal conclusion is asserted (the backend overview ranks
  // contradictoryEvidence before confirmedFailure), so no conclusion may name the chain. A
  // conflict that covers only part of the chain does not veto yet: that is left to owner
  // decision B on #838, together with the rest of the finding join.
  if (
    findings.some(
      (finding) =>
        finding.findingClass === "contradictoryEvidence" && coversChain(finding),
    )
  ) {
    return null;
  }
  const covering = findings
    .filter(
      (finding) =>
        TITLE_CONCLUSION_CLASSES.has(finding.findingClass) &&
        coversChain(finding),
    )
    .sort(
      (a, b) =>
        classRank(a) - classRank(b) || compareStrings(a.findingId, b.findingId),
    );
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

/**
 * Keeps one item per origin id, independent of input order: earliest timestamp, then the
 * higher severity, then the message, then the serialized origin. The id is equal by construction,
 * so the lexicographic tie-break runs over the remaining content.
 */
function preferItem(a: TimelineItem, b: TimelineItem): TimelineItem {
  if (a.timestampMs !== b.timestampMs) {
    return a.timestampMs < b.timestampMs ? a : b;
  }
  const rank =
    TIMELINE_SEVERITY_RANK[a.severity] - TIMELINE_SEVERITY_RANK[b.severity];
  if (rank !== 0) return rank > 0 ? a : b;
  const byMessage = compareStrings(a.message, b.message);
  if (byMessage !== 0) return byMessage < 0 ? a : b;
  return compareStrings(JSON.stringify(a.origin), JSON.stringify(b.origin)) <= 0
    ? a
    : b;
}

function toRow(
  id: string,
  strength: CorrelationChainStrength,
  relations: readonly Relation[],
  memberIds: readonly string[],
  itemsById: ReadonlyMap<string, TimelineItem>,
  findings: readonly ChainFindingCoverage[],
): CorrelationChain {
  const all = uniqueSortedStrings(memberIds);
  const resolved = all
    .filter((member) => itemsById.has(member))
    .sort(
      (a, b) =>
        compareNullableNumber(
          itemsById.get(a)?.timestampMs ?? null,
          itemsById.get(b)?.timestampMs ?? null,
        ) || compareStrings(a, b),
    );
  const unresolved = all.filter((member) => !itemsById.has(member));
  return {
    id,
    strength,
    memberIds: resolved,
    unresolvedMemberIds: unresolved,
    memberCount: all.length,
    edges: relations.map((relation) => ({
      left: relation.left,
      right: relation.right,
      strength: relation.strength,
      keys: relation.keys,
    })),
    keys: uniqueSorted(
      relations.flatMap((relation) => relation.keys),
      relationKeyId,
    ),
    evidence: uniqueSorted(
      relations.flatMap((relation) => relation.evidence),
      evidenceId,
    ),
    coverageGaps: uniqueSorted(
      relations.flatMap((relation) => relation.gaps),
      gapId,
    ),
    ...span(resolved, itemsById),
    // Only a chain may borrow a finding's title; an ambiguous or blocked item is not a conclusion.
    title:
      resolved.length === 0
        ? null
        : (isLinking(strength) ? coveringFindingTitle(all, findings) : null) ??
          derivedTitle(resolved, itemsById),
  };
}

export function buildCorrelationChains(
  input: CorrelationChainInput,
): CorrelationChainModel {
  const itemsById = new Map<string, TimelineItem>();
  for (const item of input.items) {
    const id = timelineOriginId(item.origin);
    const existing = itemsById.get(id);
    itemsById.set(id, existing === undefined ? item : preferItem(existing, item));
  }

  const reduced = reduceByPair(input.timelineEdges.map(classifyTimelineEdge));

  const links: Relation[] = [];
  const nonLinking = new Map<string, Relation[]>();
  let ignoredRelationCount = 0;
  for (const relation of reduced) {
    const members = memberSet(relation);
    const cannotLink =
      isLinking(relation.strength) &&
      (relation.right === null || relation.right === relation.left);
    if (members.length < 2 || cannotLink) {
      ignoredRelationCount += 1;
    } else if (isLinking(relation.strength)) {
      links.push(relation);
    } else {
      // Collapse by the exact key (label, sorted member set). Unequal sets are never merged.
      const key = keyOf(relation.strength, ...members);
      const group = nonLinking.get(key);
      if (group === undefined) nonLinking.set(key, [relation]);
      else group.push(relation);
    }
  }

  // Only exact and candidate pairs are ever unioned. This is the Q-4 invariant.
  const sets = new DisjointSet();
  for (const relation of links) {
    sets.union(relation.left, relation.right as string);
  }
  const components = new Map<string, Relation[]>();
  for (const relation of links) {
    const root = sets.find(relation.left);
    const group = components.get(root);
    if (group === undefined) components.set(root, [relation]);
    else group.push(relation);
  }

  const rows: CorrelationChain[] = [];
  for (const componentRelations of components.values()) {
    const members = componentRelations.flatMap((relation) => [
      relation.left,
      relation.right as string,
    ]);
    const smallest = uniqueSortedStrings(members)[0] as string;
    const strength = componentRelations.reduce<"exact" | "candidate">(
      (weakest, relation) =>
        relation.strength === "candidate" ? "candidate" : weakest,
      "exact",
    );
    rows.push(
      toRow(
        keyOf("chain", smallest),
        strength,
        componentRelations,
        members,
        itemsById,
        input.findings,
      ),
    );
  }
  for (const [key, group] of nonLinking) {
    const first = group[0] as Relation;
    rows.push(
      toRow(
        key,
        first.strength,
        group,
        group.flatMap(memberSet),
        itemsById,
        input.findings,
      ),
    );
  }

  rows.sort(
    (a, b) =>
      strengthIndex(a.strength) - strengthIndex(b.strength) ||
      b.memberCount - a.memberCount ||
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
  const totalIsValid =
    Number.isSafeInteger(input.totalTimelineEdges) &&
    input.totalTimelineEdges >= 0;
  return {
    chains,
    totalCount: rows.length,
    omittedCount: rows.length - chains.length,
    edgeInputComplete:
      totalIsValid && input.timelineEdges.length === input.totalTimelineEdges,
    unloadedEdgeCount: totalIsValid
      ? Math.max(0, input.totalTimelineEdges - input.timelineEdges.length)
      : 0,
    counts,
    ignoredRelationCount,
  };
}
