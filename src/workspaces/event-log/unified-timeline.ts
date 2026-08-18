/**
 * Frontend model for the unified timeline.
 *
 * Mirrors `cmtraceopen_parser::unified_timeline`. The merge itself happens in Rust; this side
 * handles presentation, which mostly means deciding what to show about items that could not be
 * placed.
 */

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
      /** Stable source-collection identity; distinct even for reused channel record IDs. */
      stableId: number;
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
  return `${origin.channel} / ${origin.provider} / event ${origin.eventId} / record ${origin.recordId} / ${provenance}`;
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
