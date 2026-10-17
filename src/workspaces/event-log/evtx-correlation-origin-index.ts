/**
 * Joins timeline origins to the loaded event records (spec sections 8.11 and 9, ADR-002).
 *
 * Pure: no React, no stores. Three things need the join, and they share this module so they cannot
 * disagree: the chain's record scope ("Filter table to chain"), selecting a marker's record, and
 * the per-record links count.
 *
 * Nothing in the engine's reply names the record an origin came from. The join therefore compares
 * the ORIGIN'S OWN FIELDS with the record's, with the same matchers finding evidence uses
 * (`buildEvidenceIndex`, `redactedValueMatches`). It never reads, parses or rebuilds a stable id
 * string: an origin whose record has no usable identity is recognised from `recordIdText` and
 * `recordId`, not from the `|missing` marker the stable id would carry.
 *
 * Rules, all enforced here:
 * - A record names the origin only when the event ID, the record identity (the engine's order: a
 *   usable `recordIdText`, then a non-zero `recordId`), the provider, the channel, the source label
 *   and the normalized machine ALL agree.
 * - Several matching records are ONE ambiguous reference. Every candidate is kept and counted, and
 *   none is guessed. Identical duplicates, such as the same archive loaded twice, are therefore
 *   reported as ambiguous.
 * - An origin with no usable identity matches nothing.
 * - A text-log origin is not a grid record and is never counted, as finding evidence is.
 * - Nothing here holds a record id: `EvtxRecord.id` is renumbered on every merge, so a result is
 *   held by record OBJECT and resolved at use time.
 */
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import type { CorrelationChain } from "./evtx-correlation-chains";
import { countScopeReferences, type EvtxRecordScopeCounts } from "./evtx-filter";
import {
  engineRecordIdentity,
  recordsForIdentity,
  redactedValueMatches,
  type EvidenceIndex,
} from "./evtx-insights-data";
import type { EvtxRecord } from "./types";
import {
  timelineOriginId,
  type TimelineItem,
  type TimelineOrigin,
  type UnplacedItem,
} from "./unified-timeline";

type EventOrigin = Extract<TimelineOrigin, { kind: "event" }>;

/** Placed items by the origin id the edges name them with. The first of two equal ids wins. */
export function itemsByOriginId(
  items: readonly TimelineItem[],
): Map<string, TimelineItem> {
  const byId = new Map<string, TimelineItem>();
  for (const item of items) {
    const id = timelineOriginId(item.origin);
    if (!byId.has(id)) byId.set(id, item);
  }
  return byId;
}

/** Timeline origins by the origin id the edges name them with. */
export type OriginLookup = ReadonlyMap<string, TimelineOrigin>;

/**
 * Every origin the session gave us, by id: the placed items AND the unplaced ones. The engine
 * correlates unplaced origins too (an event with no parseable timestamp can share an ActivityId
 * with a timed one), so a member that has no item can still be an unplaced origin whose record is
 * loaded. A placed item wins over an unplaced one with the same id.
 */
export function originLookup(
  items: readonly TimelineItem[],
  unplaced: readonly UnplacedItem[],
): Map<string, TimelineOrigin> {
  const byId = new Map<string, TimelineOrigin>();
  for (const entry of unplaced) {
    const id = timelineOriginId(entry.origin);
    if (!byId.has(id)) byId.set(id, entry.origin);
  }
  for (const item of items) byId.set(timelineOriginId(item.origin), item.origin);
  return byId;
}

/** The words the engine treats as "no machine" (`normalized_provenance` in event_log/timeline.rs). */
const NO_PROVENANCE = new Set([
  "unknown",
  "n/a",
  "na",
  "none",
  "null",
  "not available",
  "not_applicable",
]);

/** The engine's machine normalization: trimmed, and nothing for empty or a placeholder word. */
function normalizedMachine(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  const lowered = trimmed.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  return NO_PROVENANCE.has(lowered) ? null : trimmed;
}

/**
 * The origin's record identity text, by the same rule the record side uses
 * (`engineRecordIdentity`): the engine's own, so a record and the origin built from it are keyed
 * alike whatever their text looks like. Read from the origin's fields; the stable id is never
 * consulted.
 */
export function originIdentityText(origin: EventOrigin): string | null {
  return engineRecordIdentity(origin.recordIdText, origin.recordId);
}

/**
 * Whether the origin's own fields, other than its identity, agree with the record's. The engine
 * copies provider, channel and source label from the record after bounding each to the transport's
 * identity limit, and normalizes the machine, so the comparison goes through `redactedValueMatches`
 * (which reproduces the bounding) and the same machine normalization.
 */
function fieldsAgree(origin: EventOrigin, record: EvtxRecord): boolean {
  if (origin.eventId !== record.eventId) return false;
  if (!redactedValueMatches(origin.provider, record.provider)) return false;
  if (!redactedValueMatches(origin.channel, record.channel)) return false;
  if (!redactedValueMatches(origin.source, record.sourceLabel)) return false;
  if (origin.machine === null) return normalizedMachine(record.computer) === null;
  const bounded = boundUtf8WithDigest(
    record.computer,
    EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
  );
  const seen = normalizedMachine(bounded);
  return seen !== null && seen === origin.machine;
}

export type OriginResolution =
  /** A text-log origin. It is not a grid record. */
  | { kind: "notEvent" }
  /** The record carried no identity a record can be matched on. */
  | { kind: "noUsableIdentity" }
  /** The loaded records the origin names: none (not loaded), one, or several (ambiguous). */
  | { kind: "matches"; records: readonly EvtxRecord[] };

/**
 * The loaded records one timeline origin names. `index` is `buildEvidenceIndex(records)`; build it
 * once per record set and resolve many origins against it.
 */
export function resolveOriginRecords(
  origin: TimelineOrigin,
  index: EvidenceIndex,
): OriginResolution {
  if (origin.kind !== "event") return { kind: "notEvent" };
  const identity = originIdentityText(origin);
  if (identity === null) return { kind: "noUsableIdentity" };
  return {
    kind: "matches",
    records: recordsForIdentity(index, origin.eventId, identity).filter((record) =>
      fieldsAgree(origin, record),
    ),
  };
}

/** The one record an origin names, or null when it names none or several (never a guess). */
export function soleRecordForOrigin(
  origin: TimelineOrigin,
  index: EvidenceIndex,
): EvtxRecord | null {
  const resolution = resolveOriginRecords(origin, index);
  return resolution.kind === "matches" && resolution.records.length === 1
    ? (resolution.records[0] as EvtxRecord)
    : null;
}

export interface ChainScope {
  /** The distinct loaded records the chain's event members name. */
  records: EvtxRecord[];
  /**
   * One entry per event member: the loaded records it names (none, one, or several). `counts` is
   * computed from this, and the record scope keeps it so it can be pruned by reference. A scope
   * built without it counts every pruned record as one "not loaded" reference (6a record 24).
   */
  references: EvtxRecord[][];
  counts: EvtxRecordScopeCounts;
}

export interface ChainScopeOptions {
  /**
   * Whether every timeline edge of the session was loaded (`CorrelationChainModel.edgeInputComplete`).
   * When it is not, the chain may have more members than the edges loaded show, so the scope is
   * marked bounded and never claims to be the whole chain.
   */
  edgeInputComplete: boolean;
}

/**
 * The loaded records a chain's event members name, and what could not be resolved.
 *
 * Every member, placed or not, is looked up in `origins` (the placed items and the unplaced
 * origins). One with an origin is one reference: it names zero, one or several loaded records, or
 * has no usable identity and is counted apart without a reference, as in `scopeForFinding`. A
 * member with NO origin at all (its item was not read, and it is not on the unplaced list) is
 * UNRESOLVED: nothing is known about which record it names, so it is counted in its own class and
 * is never called "not loaded", which is an absence found by looking. Text-log members are not
 * grid records and are not counted.
 */
export function scopeForChain(
  chain: Pick<CorrelationChain, "memberIds" | "unresolvedMemberIds">,
  origins: OriginLookup,
  index: EvidenceIndex,
  options: ChainScopeOptions,
): ChainScope {
  const records = new Set<EvtxRecord>();
  const references: EvtxRecord[][] = [];
  let noUsableIdentity = 0;
  let unresolved = 0;
  for (const memberId of new Set([...chain.memberIds, ...chain.unresolvedMemberIds])) {
    const origin = origins.get(memberId);
    if (origin === undefined) {
      unresolved += 1;
      continue;
    }
    const resolution = resolveOriginRecords(origin, index);
    if (resolution.kind === "notEvent") continue;
    if (resolution.kind === "noUsableIdentity") {
      noUsableIdentity += 1;
      continue;
    }
    references.push([...resolution.records]);
    for (const record of resolution.records) records.add(record);
  }
  return {
    records: [...records],
    references,
    counts: countScopeReferences(
      references,
      noUsableIdentity,
      !options.edgeInputComplete,
      unresolved,
    ),
  };
}

/**
 * Distinct partners per origin id, from the model's reduced exact and candidate pairs (pass
 * `CorrelationChainModel.linkedPairs`, which the render cap does not trim). An id with no partner
 * is absent: a count is never 0.
 */
export function linkPartnerCounts(
  pairs: readonly { left: string; right: string }[],
): Map<string, number> {
  const partners = new Map<string, Set<string>>();
  const add = (from: string, to: string) => {
    const set = partners.get(from);
    if (set === undefined) partners.set(from, new Set([to]));
    else set.add(to);
  };
  for (const pair of pairs) {
    if (pair.left === pair.right) continue;
    add(pair.left, pair.right);
    add(pair.right, pair.left);
  }
  return new Map([...partners].map(([id, set]) => [id, set.size]));
}

export interface RecordLinkCounts {
  /** Partners per loaded record, positive only, held by record OBJECT. */
  counts: Map<EvtxRecord, number>;
  /**
   * Linked origins that could not be given to one record: no item to match (never placed or not
   * loaded), no usable identity, a text-log line, or no loaded record. Their records, if any,
   * show no count, which is a gap in what is known, not a statement that they have no link.
   */
  unmatchedOrigins: number;
  /** Linked origins that name more than one loaded record. None of them is given the count. */
  ambiguousOrigins: number;
}

/**
 * The link count of each loaded record. An origin is given to a record only when it names exactly
 * one, so a count is never attributed by guessing between candidates.
 */
export function linkCountsByRecord(
  partnerCounts: ReadonlyMap<string, number>,
  origins: OriginLookup,
  index: EvidenceIndex,
): RecordLinkCounts {
  const counts = new Map<EvtxRecord, number>();
  let unmatchedOrigins = 0;
  let ambiguousOrigins = 0;
  for (const [originId, partners] of partnerCounts) {
    if (partners <= 0) continue;
    const origin = origins.get(originId);
    const resolution = origin === undefined ? undefined : resolveOriginRecords(origin, index);
    if (resolution?.kind !== "matches" || resolution.records.length === 0) {
      unmatchedOrigins += 1;
    } else if (resolution.records.length > 1) {
      ambiguousOrigins += 1;
    } else {
      const record = resolution.records[0] as EvtxRecord;
      counts.set(record, Math.max(counts.get(record) ?? 0, partners));
    }
  }
  return { counts, unmatchedOrigins, ambiguousOrigins };
}
