/**
 * Pure derivations for the Insights rail (spec sections 8.13 and 11): no React, no stores.
 *
 * `summarizeRecords` takes its level counts from `countByLevel` in `evtx-filter.ts`, the count the
 * filter row's toggles show, so the rail and the filter row cannot disagree about one.
 */
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import { countByLevel, EVTX_LEVELS, hasUsableTimestamp } from "./evtx-filter";
import type {
  DiagnosisEventEvidence,
  DiagnosisFinding,
  DiagnosisSummary,
  EvtxLevel,
  EvtxRecord,
} from "./types";

export const TOP_EVENT_ID_COUNT = 7;
export const SAME_ID_BIN_COUNT = 24;

/** Counts as the app shows them elsewhere (the status bar uses the same locale formatting). */
export function formatCount(value: number): string {
  return value.toLocaleString();
}

export interface LevelMixEntry {
  level: EvtxLevel;
  count: number;
}

export interface TopEventId {
  eventId: number;
  count: number;
}

export interface RecordSummary {
  total: number;
  levelMix: LevelMixEntry[];
  topEventIds: TopEventId[];
}

export function summarizeRecords(records: readonly EvtxRecord[]): RecordSummary {
  const idCounts = new Map<number, number>();
  for (const record of records) {
    idCounts.set(record.eventId, (idCounts.get(record.eventId) ?? 0) + 1);
  }
  // Most severe first, the order of the level-mix bar and its legend.
  const levelCounts = countByLevel(records);
  const levelMix = EVTX_LEVELS.flatMap((level) => {
    const count = levelCounts[level];
    return count > 0 ? [{ level, count }] : [];
  });
  const topEventIds = [...idCounts.entries()]
    .map(([eventId, count]) => ({ eventId, count }))
    .sort((a, b) => b.count - a.count || a.eventId - b.eventId)
    .slice(0, TOP_EVENT_ID_COUNT);
  return { total: records.length, levelMix, topEventIds };
}

export interface SameIdSeries {
  /** Every matching record, including any without a usable timestamp. */
  occurrences: number;
  /** Counts per bin over the window; empty when no match has a usable timestamp. */
  bins: number[];
  /** Earliest usable timestamp among the matches, or null. */
  firstEpoch: number | null;
}

/**
 * The same event ID from the same provider across `window`, the visible records. A record without
 * a usable timestamp is counted as an occurrence but never binned (it must not read as bin 0).
 * The window is the extent of the usable timestamps of ALL visible records, so the sparkline
 * shows when the ID occurred relative to the rest of what is on screen.
 */
export function buildSameIdSeries(
  window: readonly EvtxRecord[],
  selected: EvtxRecord,
  binCount = SAME_ID_BIN_COUNT,
): SameIdSeries {
  const matches = window.filter(
    (record) => record.eventId === selected.eventId && record.provider === selected.provider,
  );
  const timed = matches.filter(hasUsableTimestamp);
  if (timed.length === 0) {
    return { occurrences: matches.length, bins: [], firstEpoch: null };
  }
  let start = Infinity;
  let end = -Infinity;
  for (const record of window) {
    if (!hasUsableTimestamp(record)) continue;
    start = Math.min(start, record.timestampEpoch);
    end = Math.max(end, record.timestampEpoch);
  }
  const span = end - start;
  const bins = new Array<number>(binCount).fill(0);
  let first = Infinity;
  for (const record of timed) {
    first = Math.min(first, record.timestampEpoch);
    const index =
      span <= 0
        ? 0
        : Math.min(binCount - 1, Math.floor(((record.timestampEpoch - start) / span) * binCount));
    bins[index] += 1;
  }
  return { occurrences: matches.length, bins, firstEpoch: first };
}

/**
 * The record before or after `id` in `ordered`, or null at the ends or when `id` is not in the
 * list (a selection the current filters hide has no neighbor).
 */
export function neighborRecordId(
  ordered: readonly EvtxRecord[],
  id: number | null,
  step: -1 | 1,
): number | null {
  if (id === null) return null;
  const index = ordered.findIndex((record) => record.id === id);
  if (index < 0) return null;
  return ordered[index + step]?.id ?? null;
}

/** True when `value` is a real EventRecordID text: present and not the parser's zero placeholder. */
function hasRecordIdText(value: string | null | undefined): value is string {
  return typeof value === "string" && value.length > 0 && value !== "0";
}

/**
 * How an evidence reference names its record, following the engine's `stable_id` order: a
 * non-zero `recordIdText`, then `fallbackIdentity`, then a non-zero `recordId`. A record the
 * provider never numbered says so; it is never printed as "record 0".
 */
export function eventRecordIdentity(evidence: DiagnosisEventEvidence): string {
  if (hasRecordIdText(evidence.recordIdText)) return `record ${evidence.recordIdText}`;
  if (evidence.fallbackIdentity) return `ref ${evidence.fallbackIdentity.slice(0, 8)}`;
  if (evidence.recordId !== 0) return `record ${evidence.recordId}`;
  return "no record ID";
}

/** Whether the findings' event evidence spans more than one source or machine. */
export function evidenceSpansSources(findings: readonly DiagnosisFinding[]): boolean {
  const sources = new Set<string>();
  const machines = new Set<string>();
  for (const finding of findings) {
    for (const evidence of finding.evidence) {
      if (evidence.kind !== "event") continue;
      sources.add(evidence.value.source);
      machines.add(evidence.value.machine ?? "");
    }
  }
  return sources.size > 1 || machines.size > 1;
}

export function eventEvidenceLabel(
  evidence: DiagnosisEventEvidence,
  includeOrigin: boolean,
): string {
  const parts = [
    String(evidence.eventId),
    evidence.channel ?? evidence.provider,
    eventRecordIdentity(evidence),
  ];
  if (includeOrigin) {
    parts.push(evidence.source);
    if (evidence.machine) parts.push(evidence.machine);
  }
  return parts.join(" · ");
}

/** The redaction token the engine writes: `[kind:16 hex digits]`, as in `[host:0123456789abcdef]`. */
const REDACTION_TOKEN = /\[[a-z]+:[0-9a-f]{16}\]/g;

/** The suffix `boundUtf8WithDigest` writes on a value it bounded. */
const TRUNCATED_SUFFIX = /\u2026\[truncated:([0-9a-f]{16})\]$/;

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** `evidence` with each redaction token a non-empty wildcard and the rest literal, anchored. */
function matchesWithTokens(evidence: string, raw: string): boolean {
  if (!evidence.match(REDACTION_TOKEN)) return evidence === raw;
  const segments = evidence.split(REDACTION_TOKEN).map(escapeRegExp);
  return new RegExp(`^${segments.join(".+")}$`, "s").test(raw);
}

/**
 * Whether an evidence value from the redacted display projection names the record's raw value.
 * The engine redacts identifiers partially: a profile segment or a machine name inside a longer
 * string becomes a `[kind:hex16]` token (`C:\Users\[user:...]\Downloads\System.evtx`,
 * `Remote: [host:...]`). A value with tokens is compared with each token as a non-empty wildcard
 * and the rest literal; a value without tokens must be equal.
 *
 * An identity field over the transport's byte limit reaches the engine digest-bounded: a prefix
 * plus `\u2026[truncated:hex16]`. When the EVIDENCE carries that suffix, the record's value is
 * bounded the same way; its digest must equal the evidence's, and the prefixes are compared with
 * the same token rule. Evidence without the suffix is never matched against a long value as if it
 * were bounded.
 */
export function redactedValueMatches(evidenceValue: string, recordValue: string): boolean {
  const truncated = TRUNCATED_SUFFIX.exec(evidenceValue);
  if (!truncated) return matchesWithTokens(evidenceValue, recordValue);
  const bounded = boundUtf8WithDigest(recordValue, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
  const boundedSuffix = TRUNCATED_SUFFIX.exec(bounded);
  if (!boundedSuffix || boundedSuffix[1] !== truncated[1]) return false;
  return matchesWithTokens(
    evidenceValue.slice(0, truncated.index),
    bounded.slice(0, boundedSuffix.index),
  );
}

/** The record's identity text in the engine's order, or null when the provider never numbered it. */
function recordIdentityText(record: EvtxRecord): string | null {
  if (hasRecordIdText(record.eventRecordIdText)) return record.eventRecordIdText;
  return record.eventRecordId !== 0 ? String(record.eventRecordId) : null;
}

/**
 * Whether event evidence names `record`. Matched on the fields that survive redaction: event ID,
 * provider, channel, and the record identity in the engine's `stable_id` order (non-zero
 * `recordIdText`, then `fallbackIdentity`, then non-zero `recordId`). A `fallbackIdentity` is a hash
 * the record cannot reproduce, so evidence identified only that way never matches. Machine, source,
 * provider and channel are compared with `redactedValueMatches`, so partial redaction still matches.
 */
export function evidenceMatchesRecord(
  value: DiagnosisEventEvidence,
  record: EvtxRecord,
): boolean {
  if (value.eventId !== record.eventId) return false;
  // Record identity first: it is a string compare, so a live tail does not build patterns for every
  // record that merely shares the event ID.
  const own = recordIdentityText(record);
  if (own === null) return false;
  if (hasRecordIdText(value.recordIdText)) {
    if (value.recordIdText !== own) return false;
  } else if (value.fallbackIdentity) {
    return false;
  } else if (value.recordId === 0 || String(value.recordId) !== own) {
    return false;
  }
  if (!redactedValueMatches(value.provider, record.provider)) return false;
  if (value.channel && !redactedValueMatches(value.channel, record.channel)) return false;
  if (value.machine && !redactedValueMatches(value.machine, record.computer)) return false;
  if (value.source && !redactedValueMatches(value.source, record.sourceLabel)) return false;
  return true;
}

/**
 * The first finding (in the order given) whose event evidence names `record`, and only when that
 * evidence names exactly one of the `loaded` records. Several candidates (two archives from
 * different machines sharing channel, provider, ID and record ID) or none means no match: the UI
 * never guesses which record a finding means.
 */
export function findingForRecord(
  findings: readonly DiagnosisFinding[],
  record: EvtxRecord,
  loaded: readonly EvtxRecord[],
): DiagnosisFinding | null {
  for (const finding of findings) {
    for (const evidence of finding.evidence) {
      if (evidence.kind !== "event" || !evidenceMatchesRecord(evidence.value, record)) continue;
      let candidates = 0;
      for (const other of loaded) {
        if (evidenceMatchesRecord(evidence.value, other) && ++candidates > 1) break;
      }
      if (candidates === 1) return finding;
    }
  }
  return null;
}

export interface CorrelationBreakdown {
  exact: number;
  candidate: number;
  ambiguous: number;
  coverageBlocked: number;
  /** The preview holds every edge the overview counts. */
  complete: boolean;
  /** exact + candidate + ambiguous: the only edges that are correlations. */
  correlations: number;
}

/**
 * Correlation counts for the summary card. Only exact, candidate and ambiguous edges are
 * correlations; a coverage-blocked relation is a coverage state (soul.md) and is counted apart,
 * never folded into the total.
 */
export function correlationBreakdown(summary: DiagnosisSummary): CorrelationBreakdown {
  const count = (status: string) =>
    summary.correlations.filter((edge) => edge.status === status).length;
  const exact = count("exact");
  const candidate = count("candidate");
  const ambiguous = count("ambiguous");
  return {
    exact,
    candidate,
    ambiguous,
    coverageBlocked: count("coverageBlocked"),
    complete: summary.correlations.length >= summary.overview.correlationCount,
    correlations: exact + candidate + ambiguous,
  };
}

/**
 * The record with `id`. Record ids are assigned as indexes when records are merged, so the index
 * is tried first and a scan is only the fallback; the lookup is O(1) in the common case.
 */
export function findRecordById(
  records: readonly EvtxRecord[],
  id: number | null,
): EvtxRecord | null {
  if (id === null) return null;
  const direct = records[id];
  if (direct?.id === id) return direct;
  return records.find((record) => record.id === id) ?? null;
}
