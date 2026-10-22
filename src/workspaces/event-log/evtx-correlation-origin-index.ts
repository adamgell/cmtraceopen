/**
 * Joins timeline origins to the loaded event records (spec sections 8.11 and 9, ADR-002).
 *
 * Pure: no React, no stores. Three things need the join, and they share this module so they cannot
 * disagree: the chain's record scope ("Filter table to chain"), selecting a marker's record, and
 * the per-record links count.
 *
 * Nothing in the engine's reply names the record an origin came from. The join therefore compares
 * the ORIGIN'S OWN FIELDS with the record's. It never reads, parses or rebuilds a stable id
 * string: an origin whose record has no usable identity is recognised from `recordIdText` and
 * `recordId`, not from the `|missing` marker the stable id would carry.
 *
 * The origin is what the ENGINE made of the record, and the engine changes three things on the way
 * (event_log/timeline.rs, analysis_session.rs): it compacts every identity text over 256 UTF-8 bytes
 * into its own `...[{len} bytes; digest={hex}]` form, it trims machine and component and drops
 * placeholder words BEFORE it compacts them, and it rewrites a record identity it refuses before it
 * builds the origin. The join reproduces each (`timelineTextMatches`, `provenanceAgrees`,
 * `engineTimelineRecordIdentity`) and does not compare text any other way.
 *
 * Rules, all enforced here:
 * - A record names the origin only when the event ID, the record identity (the engine's order, as
 *   the engine left it on the origin), the provider, the channel, the source label and the
 *   normalized machine ALL agree.
 * - Several matching records are ONE ambiguous reference. Every candidate is kept and counted, and
 *   none is guessed. Identical duplicates, such as the same archive loaded twice, are therefore
 *   reported as ambiguous.
 * - An origin with no usable identity matches nothing.
 * - A text-log ORIGIN is not resolved by the event join (`resolveOriginRecords` answers "notEvent")
 *   and so is not counted by it, as finding evidence is not. An archive text row IS a loaded grid
 *   record (`originKind` "log") and the engine gives it a log origin; `logOriginNamesRecord` is the
 *   strict matcher for that pair.
 * - Nothing here holds a record id: `EvtxRecord.id` is renumbered on every merge, so a result is
 *   held by record OBJECT and resolved at use time.
 */
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import { bundleOfSource } from "./evtx-collector-bundle";
import type { CorrelationChain } from "./evtx-correlation-chains";
import { countScopeReferences, type EvtxRecordScopeCounts } from "./evtx-filter";
import {
  engineRecordIdentity,
  engineTimelineRecordIdentity,
  recordsForOriginIdentity,
  timelineTextMatches,
  type EvidenceIndex,
} from "./evtx-insights-data";
import { gapsClearCompleteness, type CorrelationGaps } from "./evtx-correlation-gaps";
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

/**
 * The entries `itemsByOriginId` leaves out: each one whose origin id an earlier entry of `items`
 * already has, in the order read. A surface that counts the entries read but shows each origin once
 * uses it to say how many it left out, and where they are in time; the first of an origin is the
 * one `itemsByOriginId` keeps, by position, so an entry that is the same object twice counts once.
 */
export function repeatedItems(items: readonly TimelineItem[]): TimelineItem[] {
  const seen = new Set<string>();
  const repeats: TimelineItem[] = [];
  for (const item of items) {
    const id = timelineOriginId(item.origin);
    if (seen.has(id)) repeats.push(item);
    else seen.add(id);
  }
  return repeats;
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

/**
 * The engine's machine and component normalization (`normalized_provenance`): trimmed, and nothing
 * for empty or a placeholder word. It runs BEFORE the 256-byte compaction.
 */
export function normalizedProvenance(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  const lowered = trimmed.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  return NO_PROVENANCE.has(lowered) ? null : trimmed;
}

/**
 * Whether an origin's machine (or a log origin's component) is the record's. The engine normalizes
 * the record's value first and compacts what is left (`origin_of`, then `compact_timeline_origin`),
 * so the record's value is normalized here BEFORE it is compared: a name that is padded past 256
 * bytes and fits once trimmed is not compacted at all, and comparing before trimming would find
 * another length and digest. `null` on the origin means the engine found no usable value.
 *
 * A record the transport projected (over 8 MiB) reached the engine already bounded to the identity
 * limit, so the engine normalized the BOUNDED text; that order is accepted too.
 */
export function provenanceAgrees(origin: string | null, record: string): boolean {
  const normalized = normalizedProvenance(record);
  if (origin === null) return normalized === null;
  if (normalized !== null && timelineTextMatches(origin, normalized)) return true;
  const seen = normalizedProvenance(
    boundUtf8WithDigest(record, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT),
  );
  return seen !== null && seen === origin;
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
 * copies provider, channel and source label from the record and compacts each over 256 UTF-8 bytes
 * into its own form (a record the transport projected arrives already bounded in the transport's
 * form), so those go through `timelineTextMatches`; the machine is normalized first and then
 * compared (`provenanceAgrees`), which is the engine's order.
 */
function fieldsAgree(origin: EventOrigin, record: EvtxRecord): boolean {
  if (origin.eventId !== record.eventId) return false;
  if (!timelineTextMatches(origin.provider, record.provider)) return false;
  if (!timelineTextMatches(origin.channel, record.channel)) return false;
  if (!timelineTextMatches(origin.source, record.sourceLabel)) return false;
  return provenanceAgrees(origin.machine, record.computer);
}

/** The largest line number a log origin carries (`u32::MAX`): a larger record id is clamped to it. */
const LOG_LINE_MAX = 4_294_967_295;

/**
 * Whether a log origin's bundle is the one the engine derived from the record's source label
 * (`bundle_from_source`, then `compact_timeline_origin`). The engine derives it from the label it
 * RECEIVED: the whole label for a record it received whole, and the transport's bounded label for
 * one the transport projected (over 8 MiB), whose file the engine then holds in that bounded form.
 * Which of the two applies is read off the origin's own file, so the bundle is judged against one
 * label and not against whichever agrees. A label with no bundle is the empty value, which agrees
 * only with an origin that has none; a bundle id the engine compacted is compared as it left it.
 */
function bundleAgrees(origin: Extract<TimelineOrigin, { kind: "log" }>, sourceLabel: string): boolean {
  const bounded = boundUtf8WithDigest(sourceLabel, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
  const received = bounded !== sourceLabel && origin.file === bounded ? bounded : sourceLabel;
  return provenanceAgrees(origin.bundle, bundleOfSource(received) ?? "");
}

/**
 * Whether a log origin is the one the engine built from an archive text row (`originKind` "log"):
 * `origin_of` in src-tauri/src/event_log/timeline.rs sets file and source to the record's source
 * label, the line to its EventRecordID clamped to a u32, the record id to the EventRecordID, the
 * machine and component to the normalized computer and provider, and the bundle from the source;
 * `compact_timeline_origin` then compacts every text over 256 bytes.
 * EVERY one of them must agree, each through the matcher that reproduces what the engine did:
 * `timelineTextMatches` for file and source, `provenanceAgrees` (normalize first, then compare) for
 * machine, component and bundle. A record id that is not a safe non-negative integer matches nothing.
 */
export function logOriginNamesRecord(origin: TimelineOrigin, record: EvtxRecord): boolean {
  if (origin.kind !== "log" || record.originKind !== "log") return false;
  const id = record.eventRecordId;
  if (!Number.isSafeInteger(id) || id < 0) return false;
  if (origin.recordId !== id) return false;
  if (origin.line !== Math.min(id, LOG_LINE_MAX)) return false;
  if (!timelineTextMatches(origin.file, record.sourceLabel)) return false;
  if (!timelineTextMatches(origin.source, record.sourceLabel)) return false;
  if (!provenanceAgrees(origin.machine, record.computer)) return false;
  if (!provenanceAgrees(origin.component, record.provider)) return false;
  return bundleAgrees(origin, record.sourceLabel);
}

/**
 * Whether the event join can never name `record`, whatever the timeline holds: an EVENT record whose
 * timeline origin carries no usable record identity. The engine still places such a record and gives
 * it an origin, but the join matches events by the identity the origin carries and an origin with
 * none matches nothing (`resolveOriginRecords`: "noUsableIdentity"). The origin's identity is what
 * `engineTimelineRecordIdentity` predicts, which is the join's own mirror of the engine's refusal of
 * a malformed identity, so there is one definition. A log-kind record is matched by
 * `logOriginNamesRecord`, not by identity.
 */
export function isUnmatchableEvent(record: EvtxRecord): boolean {
  return record.originKind !== "log" && engineTimelineRecordIdentity(record) === null;
}

export type OriginResolution =
  /**
   * A log origin: the EVENT join does not resolve it. (An archive text row is a loaded grid record
   * with a log origin; `logOriginNamesRecord` is the matcher for that pair.)
   */
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
    records: recordsForOriginIdentity(index, origin.eventId, identity).filter((record) =>
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

export interface LinkIndexOptions {
  /** Every loaded record: needed to find the records of a channel an origin could not be resolved in. */
  records: readonly EvtxRecord[];
  /** Every timeline edge of the session was loaded (`CorrelationChainModel.edgeInputComplete`). */
  edgeInputComplete: boolean;
  /** The scan read every timeline page (`LoadedLinkedItems.complete`). */
  scanComplete: boolean;
  /**
   * The engine's correlation coverage gaps (`classifyCoverageGaps`). Required: the absence of gaps
   * must be said, not assumed, because a record the engine never correlated has no edge and would
   * otherwise read as having no link. The origin each gap names has to be in `origins`, so the
   * caller reads those items too (their ids are `gaps.originIds`).
   */
  gaps: CorrelationGaps;
}

export interface RecordLinkCounts {
  /** Partners per loaded record, positive only, held by record OBJECT. */
  counts: Map<EvtxRecord, number>;
  /**
   * Records whose link status is UNKNOWN even where the index is otherwise complete: every
   * candidate of an origin that names several (an origin cannot be told apart from its twin, so
   * which copy carries the link is unknown), and every record of a source and channel in which an
   * origin had no usable identity (that origin could be any record there), and every record of an
   * origin a correlation coverage gap names (the engine never correlated it, so it has no edge
   * because none was computed, not because none exists).
   */
  unknownRecords: Set<EvtxRecord>;
  /**
   * Linked origins that could not be placed at all: no origin was read for them, so their channel
   * is not known either. Any record might be theirs.
   */
  unmatchedOrigins: number;
  /** Linked origins that name more than one loaded record. */
  ambiguousOrigins: number;
  /** Linked origins with a usable identity that name no loaded record. Their records are not here. */
  unloadedOrigins: number;
  /**
   * Origins a correlation coverage gap names that were not among the origins read, so which
   * records they are cannot be told.
   */
  unattributedGapOrigins: number;
  /**
   * The edges are complete, the scan is complete, no origin was unmatched, and the engine's gaps
   * allow it: no limit or truncation left origins uncorrelated, the preview shows every gap, and
   * every gap's origin was read. Only then may a record with no count be read as having no link
   * (`recordLinkStatus`).
   */
  complete: boolean;
}

/**
 * What the Links cell may say about one record. An empty cell means "no Exact or Candidate edge"
 * (spec 8.7), so it is for `none` only: a record the index could not resolve is `unknown`, and a
 * count that may be short is `atLeast`.
 */
export type RecordLinkStatus =
  | { kind: "linked"; count: number; atLeast: boolean }
  | { kind: "unknown" }
  | { kind: "none" };

/**
 * The link count of each loaded record, and which records the index cannot speak for. An origin is
 * given to a record only when it names exactly one, so a count is never attributed by guessing
 * between candidates. A text-log origin is not a record and affects no record's status.
 */
export function linkCountsByRecord(
  partnerCounts: ReadonlyMap<string, number>,
  origins: OriginLookup,
  index: EvidenceIndex,
  options: LinkIndexOptions,
): RecordLinkCounts {
  const counts = new Map<EvtxRecord, number>();
  const unknownRecords = new Set<EvtxRecord>();
  const unknownLanes = new Map<string, EventOrigin>();
  let unmatchedOrigins = 0;
  let ambiguousOrigins = 0;
  let unloadedOrigins = 0;
  for (const [originId, partners] of partnerCounts) {
    if (partners <= 0) continue;
    const origin = origins.get(originId);
    if (origin === undefined) {
      unmatchedOrigins += 1;
      continue;
    }
    // A text-log origin is not a record: it changes nothing about any record.
    if (origin.kind !== "event") continue;
    const resolution = resolveOriginRecords(origin, index);
    if (resolution.kind !== "matches") {
      unknownLanes.set(`${origin.source}\u0000${origin.channel}`, origin);
      continue;
    }
    if (resolution.records.length === 0) {
      unloadedOrigins += 1;
    } else if (resolution.records.length > 1) {
      ambiguousOrigins += 1;
      for (const record of resolution.records) unknownRecords.add(record);
    } else {
      const record = resolution.records[0] as EvtxRecord;
      counts.set(record, Math.max(counts.get(record) ?? 0, partners));
    }
  }
  // An origin the engine's gaps name was not correlated: its records are unknown, edge or no edge.
  let unattributedGapOrigins = 0;
  for (const gapOriginId of options.gaps.originIds) {
    const origin = origins.get(gapOriginId);
    if (origin === undefined) {
      unattributedGapOrigins += 1;
      continue;
    }
    if (origin.kind !== "event") continue;
    const resolution = resolveOriginRecords(origin, index);
    if (resolution.kind !== "matches") {
      unknownLanes.set(`${origin.source}\u0000${origin.channel}`, origin);
      continue;
    }
    for (const record of resolution.records) unknownRecords.add(record);
  }
  if (unknownLanes.size > 0) {
    for (const record of options.records) {
      for (const origin of unknownLanes.values()) {
        if (
          timelineTextMatches(origin.source, record.sourceLabel) &&
          timelineTextMatches(origin.channel, record.channel)
        ) {
          unknownRecords.add(record);
          break;
        }
      }
    }
  }
  return {
    counts,
    unknownRecords,
    unmatchedOrigins,
    ambiguousOrigins,
    unloadedOrigins,
    unattributedGapOrigins,
    complete:
      options.edgeInputComplete &&
      options.scanComplete &&
      unmatchedOrigins === 0 &&
      unattributedGapOrigins === 0 &&
      !gapsClearCompleteness(options.gaps),
  };
}

/** What a record's Links cell may show, from `linkCountsByRecord`. */
export function recordLinkStatus(result: RecordLinkCounts, record: EvtxRecord): RecordLinkStatus {
  const count = result.counts.get(record);
  const unknown = result.unknownRecords.has(record);
  if (count !== undefined) {
    return { kind: "linked", count, atLeast: unknown || !result.complete };
  }
  return unknown || !result.complete ? { kind: "unknown" } : { kind: "none" };
}
