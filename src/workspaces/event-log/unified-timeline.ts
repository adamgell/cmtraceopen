/**
 * Frontend model for the unified timeline.
 *
 * Mirrors `cmtraceopen_parser::unified_timeline`. The merge itself happens in Rust; this side
 * handles presentation, which mostly means deciding what to show about items that could not be
 * placed.
 */

import type { EvtxRecord } from "./types";
import type { LogEntry, LogSource, PlatformKind } from "../../types/log";
import type { SourceOpenMode } from "../../lib/tab-snapshot-cache";

function logEntryBelongsToSource(
  entry: LogEntry,
  source: LogSource | null,
  platform: Exclude<PlatformKind, "all">,
): boolean {
  if (source === null) return false;
  const root = source.kind === "known" ? source.defaultPath : source.path;
  const normalize = (value: string) => {
    const normalized = value
      .replace(/[\\/]+/g, "/")
      .replace(/\/+$/, "");
    return platform === "windows" ? normalized.toLowerCase() : normalized;
  };
  const normalizedRoot = normalize(root);
  if (normalizedRoot === "" || normalizedRoot === "/") return true;
  const normalizedEntry = normalize(entry.filePath);
  return (
    normalizedEntry === normalizedRoot ||
    normalizedEntry.startsWith(`${normalizedRoot}/`)
  );
}

export function scopeLogEntries(
  entries: LogEntry[],
  source: LogSource | null,
  mode: SourceOpenMode,
  platform: Exclude<PlatformKind, "all">,
): LogEntry[] {
  return mode === "merged"
    ? entries
    : entries.filter((entry) =>
        logEntryBelongsToSource(entry, source, platform),
      );
}

export type TimelineSeverity =
  "verbose" | "info" | "warning" | "error" | "critical";

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
      identityConflicts?: string[];
      eventId: number;
      /** Lossless decimal EventRecordID, when supplied by the backend. */
      recordIdText?: string | null;
      /** EventRecordID, scoped to the event channel. */
      recordId: number;
    };
export function isEventOrigin(
  origin: TimelineOrigin,
): origin is Extract<TimelineOrigin, { kind: "event" }> {
  return origin.kind === "event";
}
const utf8Encoder = new TextEncoder();
function timelineKeyPart(value: string): string {
  return `${utf8Encoder.encode(value).length}:${value}`;
}

export function timelineOriginId(origin: TimelineOrigin): string {
  if (isEventOrigin(origin)) return origin.stableId;
  return `log|${timelineKeyPart(origin.source)}|${timelineKeyPart(origin.file)}|${origin.line}|${origin.recordId}`;
}
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

/**
 * Reserved source identity for the bounded aggregate marker emitted when correlation gaps are
 * truncated. Unlike an origin-backed gap, this marker must survive event-row filtering.
 */
export const CORRELATION_GAP_AGGREGATE_SOURCE = "correlation";
/** Reserved source identity for malformed EventRecordID coverage emitted by diagnosis. */
export const EVENT_RECORD_IDENTITY_GAP_SOURCE = "event-record-identity";

export function isAggregateCoverageGap(gap: TimelineCoverageGap): boolean {
  return gap.source === CORRELATION_GAP_AGGREGATE_SOURCE;
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

type TimelineRecord = Record<string, unknown>;

function timelineRecord(value: unknown, path: string): TimelineRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Invalid unified timeline: ${path}`);
  }
  return value as TimelineRecord;
}

function timelineString(value: unknown, path: string): string {
  if (typeof value !== "string")
    throw new Error(`Invalid unified timeline: ${path}`);
  return value;
}

function timelineNullableString(value: unknown, path: string): string | null {
  if (value !== null && typeof value !== "string") {
    throw new Error(`Invalid unified timeline: ${path}`);
  }
  return value;
}

function timelineOptionalNullableString(
  object: TimelineRecord,
  field: string,
  path: string,
): string | null | undefined {
  const value = object[field];
  return value === undefined
    ? undefined
    : timelineNullableString(value, `${path}.${field}`);
}

function timelineNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Invalid unified timeline: ${path}`);
  }
  return value;
}

function timelineInteger(value: unknown, path: string): number {
  const number = timelineNumber(value, path);
  if (!Number.isInteger(number))
    throw new Error(`Invalid unified timeline: ${path}`);
  return number;
}

function timelineArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value))
    throw new Error(`Invalid unified timeline: ${path}`);
  return value;
}

const TIMELINE_SEVERITIES = [
  "verbose",
  "info",
  "warning",
  "error",
  "critical",
] as const;
const TIMELINE_KEY_KINDS = [
  "activityId",
  "relatedActivityId",
  "providerChannelEventRecord",
  "processStart",
  "sessionId",
  "deviceId",
  "userId",
  "secondary",
] as const;
const TIMELINE_EDGE_STRENGTHS = ["exact", "candidate", "ambiguous"] as const;
const TIMELINE_EDGE_CONFIDENCES = ["high", "low", "unknown"] as const;

function timelineEnum<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`Invalid unified timeline: ${path}`);
  }
  return value as T;
}

function decodeTimelineOrigin(value: unknown, path: string): TimelineOrigin {
  const origin = timelineRecord(value, path);
  const kind = origin.kind;
  if (kind === "log") {
    return {
      kind,
      file: timelineString(origin.file, `${path}.file`),
      component: timelineNullableString(origin.component, `${path}.component`),
      line: timelineInteger(origin.line, `${path}.line`),
      source: timelineString(origin.source, `${path}.source`),
      machine: timelineNullableString(origin.machine, `${path}.machine`),
      bundle: timelineNullableString(origin.bundle, `${path}.bundle`),
      recordId: timelineInteger(origin.recordId, `${path}.recordId`),
    };
  }
  if (kind !== "event")
    throw new Error(`Invalid unified timeline: ${path}.kind`);

  const identityConflicts = origin.identityConflicts;
  const decodedIdentityConflicts =
    identityConflicts === undefined
      ? undefined
      : timelineArray(identityConflicts, `${path}.identityConflicts`).map(
          (entry, index) =>
            timelineString(entry, `${path}.identityConflicts[${index}]`),
        );
  const activityId = timelineOptionalNullableString(origin, "activityId", path);
  const relatedActivityId = timelineOptionalNullableString(
    origin,
    "relatedActivityId",
    path,
  );
  const sessionId = timelineOptionalNullableString(origin, "sessionId", path);
  const deviceId = timelineOptionalNullableString(origin, "deviceId", path);
  const userId = timelineOptionalNullableString(origin, "userId", path);
  const processStartTime = timelineOptionalNullableString(
    origin,
    "processStartTime",
    path,
  );
  const recordIdText = timelineOptionalNullableString(
    origin,
    "recordIdText",
    path,
  );
  return {
    kind,
    stableId: timelineString(origin.stableId, `${path}.stableId`),
    source: timelineString(origin.source, `${path}.source`),
    machine: timelineNullableString(origin.machine, `${path}.machine`),
    bundle: timelineNullableString(origin.bundle, `${path}.bundle`),
    channel: timelineString(origin.channel, `${path}.channel`),
    provider: timelineString(origin.provider, `${path}.provider`),
    processId:
      origin.processId == null
        ? null
        : timelineInteger(origin.processId, `${path}.processId`),
    ...(activityId === undefined ? {} : { activityId }),
    ...(relatedActivityId === undefined ? {} : { relatedActivityId }),
    ...(sessionId === undefined ? {} : { sessionId }),
    ...(deviceId === undefined ? {} : { deviceId }),
    ...(userId === undefined ? {} : { userId }),
    ...(processStartTime === undefined ? {} : { processStartTime }),
    ...(decodedIdentityConflicts === undefined
      ? {}
      : { identityConflicts: decodedIdentityConflicts }),
    eventId: timelineInteger(origin.eventId, `${path}.eventId`),
    recordId: timelineInteger(origin.recordId, `${path}.recordId`),
    ...(recordIdText === undefined ? {} : { recordIdText }),
  };
}

function decodeTimelineCoverageGap(
  value: unknown,
  path: string,
): TimelineCoverageGap {
  const gap = timelineRecord(value, path);
  return {
    source: timelineString(gap.source, `${path}.source`),
    reason: timelineString(gap.reason, `${path}.reason`),
  };
}

function decodeTimelineKey(
  value: unknown,
  path: string,
): TimelineCorrelationKey {
  const key = timelineRecord(value, path);
  return {
    kind: timelineEnum(key.kind, `${path}.kind`, TIMELINE_KEY_KINDS),
    value: timelineString(key.value, `${path}.value`),
  };
}

function decodeTimelineEvidence(
  value: unknown,
  path: string,
): TimelineCorrelationEvidence {
  const evidence = timelineRecord(value, path);
  return {
    originId: timelineString(evidence.originId, `${path}.originId`),
    field: timelineString(evidence.field, `${path}.field`),
    value: timelineString(evidence.value, `${path}.value`),
  };
}

function decodeTimelineEdge(
  value: unknown,
  path: string,
): TimelineCorrelationEdge {
  const edge = timelineRecord(value, path);
  const candidateIds =
    edge.candidateIds === undefined
      ? []
      : timelineArray(edge.candidateIds, `${path}.candidateIds`);
  const evidence =
    edge.evidence === undefined
      ? []
      : timelineArray(edge.evidence, `${path}.evidence`);
  const coverage = timelineRecord(edge.coverage, `${path}.coverage`);
  const state = timelineEnum(coverage.state, `${path}.coverage.state`, [
    "covered",
    "gap",
  ] as const);
  const gap = coverage.gap;
  if (state === "gap" && (gap === undefined || gap === null)) {
    throw new Error(
      `Invalid unified timeline: ${path}.coverage.gap is required for gap state`,
    );
  }
  if (state === "covered" && gap !== undefined && gap !== null) {
    throw new Error(
      `Invalid unified timeline: ${path}.coverage.gap is not allowed for covered state`,
    );
  }
  return {
    id: timelineString(edge.id, `${path}.id`),
    fromId: timelineString(edge.fromId, `${path}.fromId`),
    toId: edge.toId === null ? null : timelineString(edge.toId, `${path}.toId`),
    key: decodeTimelineKey(edge.key, `${path}.key`),
    strength: timelineEnum(
      edge.strength,
      `${path}.strength`,
      TIMELINE_EDGE_STRENGTHS,
    ),
    confidence: timelineEnum(
      edge.confidence,
      `${path}.confidence`,
      TIMELINE_EDGE_CONFIDENCES,
    ),
    candidateIds: candidateIds.map((entry, index) =>
      timelineString(entry, `${path}.candidateIds[${index}]`),
    ),
    evidence: evidence.map((entry, index) =>
      decodeTimelineEvidence(entry, `${path}.evidence[${index}]`),
    ),
    coverage: {
      state,
      ...(gap == null
        ? {}
        : { gap: decodeTimelineCoverageGap(gap, `${path}.coverage.gap`) }),
    },
  };
}

function decodeTimelineItem(value: unknown, path: string): TimelineItem {
  const item = timelineRecord(value, path);
  return {
    timestampMs: timelineNumber(item.timestampMs, `${path}.timestampMs`),
    severity: timelineEnum(
      item.severity,
      `${path}.severity`,
      TIMELINE_SEVERITIES,
    ),
    message: timelineString(item.message, `${path}.message`),
    origin: decodeTimelineOrigin(item.origin, `${path}.origin`),
  };
}

function decodeUnplacedItem(value: unknown, path: string): UnplacedItem {
  const item = timelineRecord(value, path);
  return {
    origin: decodeTimelineOrigin(item.origin, `${path}.origin`),
    reason: timelineEnum(item.reason, `${path}.reason`, [
      "missingTimestamp",
    ] as const),
  };
}

/**
 * Decodes the value crossing the Tauri boundary into the shape consumed by the timeline UI.
 *
 * Optional correlation fields remain omitted when older backend producers omit them. Edge arrays
 * retain their Rust defaults when an individual edge omits the serde-defaulted fields.
 */
export function assertUnifiedTimelineShape(value: unknown): UnifiedTimeline {
  const timeline = timelineRecord(value, "timeline");
  const items = timelineArray(timeline.items, "items").map((item, index) =>
    decodeTimelineItem(item, `items[${index}]`),
  );
  const unplaced = timelineArray(timeline.unplaced, "unplaced").map(
    (item, index) => decodeUnplacedItem(item, `unplaced[${index}]`),
  );
  const edges =
    timeline.edges === undefined
      ? undefined
      : timelineArray(timeline.edges, "edges").map((edge, index) =>
          decodeTimelineEdge(edge, `edges[${index}]`),
        );
  const coverageGaps =
    timeline.coverageGaps === undefined
      ? undefined
      : timelineArray(timeline.coverageGaps, "coverageGaps").map((gap, index) =>
          decodeTimelineCoverageGap(gap, `coverageGaps[${index}]`),
        );
  return {
    items,
    unplaced,
    ...(edges === undefined ? {} : { edges }),
    ...(coverageGaps === undefined ? {} : { coverageGaps }),
  };
}

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
  const machineValue = record.computer.trim();
  const machine = `machine${utf8Encoder.encode(machineValue).length}:${machineValue}|`;
  const channel = `channel${utf8Encoder.encode(record.channel).length}:${record.channel}`;
  return `${source}|${machine}${channel}`;
}

function exactNonzeroDecimalText(value: string | null | undefined): string | null {
  const text = value?.trim();
  if (!text || !/^\d+$/.test(text)) return null;
  try {
    return BigInt(text) === 0n ? null : text;
  } catch {
    return null;
  }
}

function exactRecordIdText(record: EvtxRecord): string | null {
  return exactNonzeroDecimalText(record.eventRecordIdText);
}

function hasUnsafeEventRecordIdentity(
  origin: Extract<TimelineOrigin, { kind: "event" }>,
): boolean {
  return (
    origin.recordId !== 0 &&
    !Number.isSafeInteger(origin.recordId) &&
    exactNonzeroDecimalText(origin.recordIdText) === null
  );
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

export function stableRecordIdentityMap(
  records: readonly EvtxRecord[],
): Map<EvtxRecord, string> {
  const decorated = records.map((record) => ({
    record,
    base: stableRecordBase(record),
  }));
  const occurrences = new Map<string, number>();
  const keys = new Map<EvtxRecord, string>();
  for (const { record, base } of decorated) {
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

/**
 * Filters a cached backend timeline to the records currently visible in the event list.
 *
 * Provenance/activity is parsed once when the raw record set changes; channel, level, Event ID,
 * and search transitions only select from that cached result and never resend raw XML to Tauri.
 */
export function filterTimelineToRecords(
  timeline: UnifiedTimeline,
  records: EvtxRecord[],
  allRecords: EvtxRecord[] = records,
): UnifiedTimeline {
  const canonicalKeys = stableRecordIdentityMap(allRecords);
  const keys = new Set(
    records.map(
      (record) => canonicalKeys.get(record) ?? stableRecordBase(record),
    ),
  );
  const unsafePrefixes = new Set(
    records
      .filter(
        (record) =>
          record.eventRecordId !== 0 &&
          exactRecordIdText(record) === null &&
          !Number.isSafeInteger(record.eventRecordId),
      )
      .map((record) => canonicalKeys.get(record) ?? stableRecordBase(record)),
  );
  const unsafeOriginCounts = new Map<string, number>();
  for (const item of [...timeline.items, ...timeline.unplaced]) {
    if (item.origin.kind !== "event") continue;
    if (!hasUnsafeEventRecordIdentity(item.origin)) continue;
    const marker = item.origin.stableId.lastIndexOf("|record");
    if (marker < 0) continue;
    const prefix = item.origin.stableId.replace(/record\d+$/, "record");
    unsafeOriginCounts.set(prefix, (unsafeOriginCounts.get(prefix) ?? 0) + 1);
  }
  const ambiguousUnsafePrefixes = new Map(
    [...unsafeOriginCounts].filter(
      ([prefix, count]) => unsafePrefixes.has(prefix) && count > 1,
    ),
  );
  const keep = (origin: TimelineOrigin) => {
    if (origin.kind === "log") return true;
    if (keys.has(origin.stableId)) return true;
    const marker = origin.stableId.lastIndexOf("|record");
    const prefix = origin.stableId.replace(/record\d+$/, "record");
    return (
      marker >= 0 &&
      hasUnsafeEventRecordIdentity(origin) &&
      unsafePrefixes.has(prefix) &&
      unsafeOriginCounts.get(prefix) === 1
    );
  };
  const items = timeline.items.filter((item) => keep(item.origin));
  const unplaced = timeline.unplaced.filter((item) => keep(item.origin));
  const visibleOriginIds = new Set(
    [...items, ...unplaced].map((item) => timelineOriginId(item.origin)),
  );
  const edges = (timeline.edges ?? []).flatMap((edge) => {
    const fromVisible = visibleOriginIds.has(edge.fromId);
    const visibleEndpointId = fromVisible
      ? edge.fromId
      : edge.toId !== null && visibleOriginIds.has(edge.toId)
        ? edge.toId
        : null;
    if (visibleEndpointId === null) return [];

    const hiddenEndpointId =
      edge.toId !== null && !visibleOriginIds.has(edge.toId)
        ? edge.toId
        : !fromVisible
          ? edge.fromId
          : null;
    const hasHiddenEndpoint = hiddenEndpointId !== null;
    if (
      hasHiddenEndpoint &&
      edge.strength !== "ambiguous" &&
      edge.coverage.state !== "gap"
    ) {
      return [];
    }

    const candidateIds = edge.candidateIds.filter((candidate) =>
      visibleOriginIds.has(candidate),
    );
    const evidence = edge.evidence.filter((entry) =>
      visibleOriginIds.has(entry.originId),
    );
    const hiddenReferences = [
      ...(hiddenEndpointId === null ? [] : [hiddenEndpointId]),
      ...edge.candidateIds.filter(
        (candidate) => !visibleOriginIds.has(candidate),
      ),
      ...edge.evidence
        .filter((entry) => !visibleOriginIds.has(entry.originId))
        .map((entry) => entry.originId),
    ];
    const hiddenCorrelation = hasHiddenEndpoint || hiddenReferences.length > 0;
    const coverage =
      hiddenCorrelation &&
      (edge.strength === "ambiguous" || edge.coverage.state === "gap")
        ? {
            state: "gap" as const,
            gap: {
              source: visibleEndpointId,
              reason: "correlation candidates are outside the current filter",
            },
          }
        : edge.coverage;
    return [
      {
        ...edge,
        fromId: visibleEndpointId,
        toId: hasHiddenEndpoint ? null : edge.toId,
        candidateIds,
        evidence,
        coverage,
      },
    ];
  });
  const coverageGaps = [
    ...(timeline.coverageGaps ?? []).filter(
      (gap) =>
        isAggregateCoverageGap(gap) ||
        gap.source === EVENT_RECORD_IDENTITY_GAP_SOURCE ||
        gap.source.length === 0 ||
        visibleOriginIds.has(gap.source),
    ),
    ...[...ambiguousUnsafePrefixes].map(([prefix, count]) => ({
      source: EVENT_RECORD_IDENTITY_GAP_SOURCE,
      reason: `unsafe EventRecordID identity is ambiguous: ${count} timeline origins share ${prefix} and cannot be matched uniquely`,
    })),
  ];
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
  const textId = origin.recordIdText?.trim();
  let exactId: string | null = null;
  if (textId && /^\d+$/.test(textId)) {
    try {
      if (BigInt(textId) !== 0n) exactId = textId;
    } catch {
      exactId = null;
    }
  }
  const record =
    exactId ??
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

  const logs = timeline.unplaced.filter(
    (item) => item.origin.kind === "log",
  ).length;
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
