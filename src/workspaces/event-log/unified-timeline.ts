/**
 * Frontend model for the unified timeline.
 *
 * Mirrors `cmtraceopen_parser::unified_timeline`. The merge itself happens in Rust; this side
 * handles presentation, which mostly means deciding what to show about items that could not be
 * placed.
 */

import type { EvtxRecord } from "./types";
import type { LogEntry, LogSource } from "../../types/log";
import type { SourceOpenMode } from "../../lib/tab-snapshot-cache";

function logEntryBelongsToSource(entry: LogEntry, source: LogSource | null): boolean {
  if (source === null) return false;
  const root = source.kind === "known" ? source.defaultPath : source.path;
  const normalize = (value: string) =>
    value.replace(/[\\/]+/g, "/").replace(/\/+$/, "").toLowerCase();
  const normalizedRoot = normalize(root);
  if (normalizedRoot === "" || normalizedRoot === "/") return true;
  const normalizedEntry = normalize(entry.filePath);
  return normalizedEntry === normalizedRoot || normalizedEntry.startsWith(`${normalizedRoot}/`);
}

export function scopeLogEntries(
  entries: LogEntry[],
  source: LogSource | null,
  mode: SourceOpenMode
): LogEntry[] {
  return mode === "merged"
    ? entries
    : entries.filter((entry) => logEntryBelongsToSource(entry, source));
}

export type TimelineSeverity =
  | "verbose"
  | "info"
  | "warning"
  | "error"
  | "critical";

export type TimelineOrigin =
  | {
      kind: "log";
      file: string;
      component: string | null;
      line: number;
      source: string;
      machine: string | null;
      bundle: string | null;
      recordId: number;
    }
  | {
      kind: "event";
      /** Stable source/channel identity plus EventRecordID; unaffected by live UI reindexing. */
      stableId: string;
      source: string;
      machine: string | null;
      bundle: string | null;
      channel: string;
      provider: string;
      processId: number | null;
      activityId?: string | null;
      relatedActivityId?: string | null;
      sessionId?: string | null;
      deviceId?: string | null;
      userId?: string | null;
      processStartTime?: string | null;
      eventId: number;
      /** Lossless decimal EventRecordID, when supplied by the backend. */
      recordIdText?: string | null;
      /** EventRecordID, scoped to the event channel. */
      recordId: number;
    };
export interface TimelineItem {
  timestampMs: number;
  severity: TimelineSeverity;
  message: string;
  origin: TimelineOrigin;
}

export interface UnplacedItem {
  origin: TimelineOrigin;
  reason: "missingTimestamp";
}

export type TimelineCorrelationKeyKind =
  | "activityId"
  | "relatedActivityId"
  | "providerChannelEventRecord"
  | "processStart"
  | "sessionId"
  | "deviceId"
  | "userId"
  | "secondary";

export interface TimelineCorrelationKey {
  kind: TimelineCorrelationKeyKind;
  value: string;
}

export type TimelineCorrelationStrength = "exact" | "candidate" | "ambiguous";
export type TimelineCorrelationConfidence = "high" | "low" | "unknown";

export interface TimelineCorrelationEvidence {
  originId: string;
  field: string;
  value: string;
}

export interface TimelineCoverageGap {
  source: string;
  reason: string;
}

export interface TimelineCorrelationEdge {
  id: string;
  fromId: string;
  toId: string | null;
  key: TimelineCorrelationKey;
  strength: TimelineCorrelationStrength;
  confidence: TimelineCorrelationConfidence;
  candidateIds: string[];
  evidence: TimelineCorrelationEvidence[];
  coverage: {
    state: "covered" | "gap";
    gap?: TimelineCoverageGap | null;
  };
}

export interface UnifiedTimeline {
  items: TimelineItem[];
  unplaced: UnplacedItem[];
  /** Defaulted by Rust for older producers that do not emit correlation edges. */
  edges?: TimelineCorrelationEdge[];
  coverageGaps?: TimelineCoverageGap[];
}

const utf8Encoder = new TextEncoder();

function missingRecordDigest(record: EvtxRecord): string {
  const input = `${record.timestampEpoch}|${record.eventId}|${record.provider}|${record.message}|${record.rawXml}`;
  let first = 2_166_136_261;
  let second = (first ^ 0x9e37_79b9) >>> 0;
  for (const byte of utf8Encoder.encode(input)) {
    first = Math.imul(first ^ byte, 16_777_619) >>> 0;
    second = Math.imul(second ^ (byte ^ 0xa5), 16_777_619) >>> 0;
  }
  return `${first.toString(16).padStart(8, "0")}${second.toString(16).padStart(8, "0")}`;
}

function eventIdentityPrefix(record: EvtxRecord): string {
  const source = `source${utf8Encoder.encode(record.sourceLabel).length}:${record.sourceLabel}`;
  const hasComputer = record.computer !== undefined;
  const machineValue = record.computer?.trim() ?? "";
  const machine = hasComputer
    ? `machine${utf8Encoder.encode(machineValue).length}:${machineValue}|`
    : "";
  const channel = `channel${utf8Encoder.encode(record.channel).length}:${record.channel}`;
  return `${source}|${machine}${channel}`;
}

function exactRecordIdText(record: EvtxRecord): string | null {
  const text = record.eventRecordIdText?.trim();
  if (!text || !/^\d+$/.test(text)) return null;
  try {
    return BigInt(text) === 0n ? null : text;
  } catch {
    return null;
  }
}

function stableRecordBase(record: EvtxRecord): string {
  const prefix = eventIdentityPrefix(record);
  const exactId = exactRecordIdText(record);
  if (exactId !== null) {
    return `${prefix}|record${exactId}`;
  }
  if (record.eventRecordId !== 0) {
    return Number.isSafeInteger(record.eventRecordId)
      ? `${prefix}|record${record.eventRecordId}`
      : `${prefix}|record`;
  }
  return `${prefix}|missing${missingRecordDigest(record)}`;
}

export function stableRecordIdentity(record: EvtxRecord): string {
  return stableRecordBase(record);
}

function canonicalRecordKeys(records: EvtxRecord[]): Map<EvtxRecord, string> {
  const ordered = [...records].sort(
    (left, right) =>
      (left.timestampEpoch ?? 0) - (right.timestampEpoch ?? 0) ||
      compareRustStrings(stableRecordBase(left), stableRecordBase(right)) ||
      compareRustStrings(left.timestamp ?? "", right.timestamp ?? "") ||
      compareRustStrings(left.message ?? "", right.message ?? "") ||
      compareRustStrings(left.rawXml ?? "", right.rawXml ?? "")
  );
  const occurrences = new Map<string, number>();
  const keys = new Map<EvtxRecord, string>();
  for (const record of ordered) {
    const base = stableRecordBase(record);
    if (record.eventRecordId !== 0 || exactRecordIdText(record) !== null) {
      keys.set(record, base);
      continue;
    }
    const occurrence = occurrences.get(base) ?? 0;
    occurrences.set(base, occurrence + 1);
    keys.set(record, `${base}-${occurrence}`);
  }
  return keys;
}
function compareRustStrings(left: string, right: string): number {
  const leftBytes = utf8Encoder.encode(left);
  const rightBytes = utf8Encoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index] - rightBytes[index];
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

/**
 * Filters a cached backend timeline to the records currently visible in the event list.
 *
 * Provenance/activity is parsed once when the raw record set changes; channel, level, Event ID,
 * and search transitions only select from that cached result and never resend raw XML to Tauri.
 */
export function filterTimelineToRecords(
  timeline: UnifiedTimeline,
  records: EvtxRecord[],
  allRecords: EvtxRecord[] = records
): UnifiedTimeline {
  const canonicalKeys = canonicalRecordKeys(allRecords);
  const keys = new Set(
    records.map((record) => canonicalKeys.get(record) ?? stableRecordBase(record))
  );
  const unsafePrefixes = new Set(
    records
      .filter(
        (record) =>
          record.eventRecordId !== 0 &&
          exactRecordIdText(record) === null &&
          !Number.isSafeInteger(record.eventRecordId)
      )
      .map((record) => canonicalKeys.get(record) ?? stableRecordBase(record))
  );
  const unsafeOriginCounts = new Map<string, number>();
  for (const item of [...timeline.items, ...timeline.unplaced]) {
    if (item.origin.kind !== "event") continue;
    const marker = item.origin.stableId.lastIndexOf("|record");
    if (marker < 0) continue;
    const prefix = item.origin.stableId.replace(/record\d+$/, "record");
    unsafeOriginCounts.set(prefix, (unsafeOriginCounts.get(prefix) ?? 0) + 1);
  }
  const keep = (origin: TimelineOrigin) => {
    if (origin.kind === "log") return true;
    if (keys.has(origin.stableId)) return true;
    const marker = origin.stableId.lastIndexOf("|record");
    const prefix = origin.stableId.replace(/record\d+$/, "record");
    return marker >= 0 && unsafePrefixes.has(prefix) && unsafeOriginCounts.get(prefix) === 1;
  };
  const items = timeline.items.filter((item) => keep(item.origin));
  const unplaced = timeline.unplaced.filter((item) => keep(item.origin));
  const visibleIds = new Set(
    [...items, ...unplaced]
      .filter((item) => item.origin.kind === "event")
      .map((item) => item.origin.stableId),
  );
  const edges = (timeline.edges ?? []).filter(
    (edge) =>
      visibleIds.has(edge.fromId) &&
      (edge.toId === null ||
        visibleIds.has(edge.toId) ||
        edge.candidateIds.some((candidate) => visibleIds.has(candidate))),
  );
  const coverageGaps = (timeline.coverageGaps ?? []).filter(
    (gap) => gap.source.length === 0 || visibleIds.has(gap.source),
  );
  return { items, unplaced, edges, coverageGaps };
}

export const TIMELINE_SEVERITY_RANK: Record<TimelineSeverity, number> = {
  verbose: 0,
  info: 1,
  warning: 2,
  error: 3,
  critical: 4,
};

/** Short label for an item's source, for a column narrow enough to scan. */
export function originLabel(origin: TimelineOrigin): string {
  if (origin.kind === "log") {
    // The file name alone; the full path is available as a tooltip and is far too long to scan.
    const name = origin.file.split(/[\\/]/).pop() || origin.file;
    return origin.component ? `${name} [${origin.component}]` : name;
  }
  // The leaf of the channel path, since the Microsoft-Windows- prefix is on nearly every channel
  // and carries no distinguishing information in a narrow column.
  const leaf = origin.channel.split("/").pop() || origin.channel;
  return `${leaf} (${origin.eventId})`;
}

/** Compact machine/source context shown beside the stable source label. */
export function originContext(origin: TimelineOrigin): string {
  const machine = origin.machine ?? "machine unknown";
  return `${machine} · ${origin.source}`;
}

/** Full source description, for a tooltip. */
export function originDetail(origin: TimelineOrigin): string {
  if (origin.kind === "log") {
    const provenance = [
      `source ${origin.source}`,
      origin.machine ? `machine ${origin.machine}` : null,
      origin.bundle ? `bundle ${origin.bundle}` : null,
      `record ${origin.recordId}`,
    ]
      .filter((part): part is string => part !== null)
      .join(" / ");
    return `${origin.file}:${origin.line}${origin.component ? ` (${origin.component})` : ""} / ${provenance}`;
  }
  const provenance = [
    `source ${origin.source}`,
    origin.machine ? `machine ${origin.machine}` : null,
    origin.bundle ? `bundle ${origin.bundle}` : null,
    origin.processId !== null ? `process ${origin.processId}` : null,
    origin.activityId ? `activity ${origin.activityId}` : null,
    origin.relatedActivityId ? `related ${origin.relatedActivityId}` : null,
    origin.sessionId ? `session ${origin.sessionId}` : null,
    origin.deviceId ? `device ${origin.deviceId}` : null,
    origin.userId ? `user ${origin.userId}` : null,
    origin.processStartTime ? `process start ${origin.processStartTime}` : null,
    `stable ${origin.stableId}`,
  ]
    .filter((part): part is string => part !== null)
    .join(" / ");
  const record =
    origin.recordIdText ??
    (origin.recordId === 0
      ? "missing"
      : Number.isSafeInteger(origin.recordId)
        ? String(origin.recordId)
        : "unavailable (see stable identity)");
  return `${origin.channel} / ${origin.provider} / event ${origin.eventId} / record ${record} / ${provenance}`;
}

/** Human-readable summary of what could not be placed.
 *
 * Returns null when nothing was dropped, so the caller can hide the notice entirely rather than
 * showing a reassuring "0 items" that invites no attention.
 */
export function unplacedSummary(timeline: UnifiedTimeline): string | null {
  const total = timeline.unplaced.length;
  if (total === 0) return null;

  const logs = timeline.unplaced.filter((item) => item.origin.kind === "log").length;
  const events = total - logs;

  const parts: string[] = [];
  if (logs > 0) parts.push(`${logs} log ${logs === 1 ? "line" : "lines"}`);
  if (events > 0) parts.push(`${events} ${events === 1 ? "event" : "events"}`);

  return `${parts.join(" and ")} could not be placed: no timestamp`;
}

/** Counts by source kind, for a coverage readout. */
export function timelineCounts(timeline: UnifiedTimeline): {
  logs: number;
  events: number;
  unplaced: number;
} {
  let logs = 0;
  let events = 0;
  for (const item of timeline.items) {
    if (item.origin.kind === "event") events += 1;
    else logs += 1;
  }
  return { logs, events, unplaced: timeline.unplaced.length };
}
