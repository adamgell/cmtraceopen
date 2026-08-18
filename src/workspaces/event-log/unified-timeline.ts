/**
 * Frontend model for the unified timeline.
 *
 * Mirrors `cmtraceopen_parser::unified_timeline`. The merge itself happens in Rust; this side
 * handles presentation, which mostly means deciding what to show about items that could not be
 * placed.
 */

import type { EvtxRecord } from "./types";

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
      activityId: string | null;
      eventId: number;
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

export interface UnifiedTimeline {
  items: TimelineItem[];
  unplaced: UnplacedItem[];
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

function stableRecordIdentity(record: EvtxRecord): string {
  const source = `source${utf8Encoder.encode(record.sourceLabel).length}:${record.sourceLabel}`;
  const channel = `channel${utf8Encoder.encode(record.channel).length}:${record.channel}`;
  if (record.eventRecordId !== 0) {
    return `${source}|${channel}|record${record.eventRecordId}`;
  }
  return `${source}|${channel}|missing${missingRecordDigest(record)}`;
}

/**
 * Filters a cached backend timeline to the records currently visible in the event list.
 *
 * Provenance/activity is parsed once when the raw record set changes; channel, level, Event ID,
 * and search transitions only select from that cached result and never resend raw XML to Tauri.
 */
export function filterTimelineToRecords(
  timeline: UnifiedTimeline,
  records: EvtxRecord[]
): UnifiedTimeline {
  const visibleKeys = new Set(records.map(stableRecordIdentity));
  const keep = (origin: TimelineOrigin) =>
    origin.kind === "log" || visibleKeys.has(origin.stableId);
  return {
    items: timeline.items.filter((item) => keep(item.origin)),
    unplaced: timeline.unplaced.filter((item) => keep(item.origin)),
  };
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
    `stable ${origin.stableId}`,
  ]
    .filter((part): part is string => part !== null)
    .join(" / ");
  const record =
    origin.recordId === 0
      ? "record missing"
      : Number.isSafeInteger(origin.recordId)
        ? `record ${origin.recordId}`
        : "record unavailable (see stable identity)";
  return `${origin.channel} / ${origin.provider} / event ${origin.eventId} / ${record} / ${provenance}`;
}

/** True when the item came from a Windows event rather than a text log. */
export function isEventOrigin(origin: TimelineOrigin): boolean {
  return origin.kind === "event";
}

/**
 * Human-readable summary of what could not be placed.
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
