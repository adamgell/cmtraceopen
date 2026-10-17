/**
 * The pure model behind the Grouped view (spec section 8.8): one summary per group of the visible
 * records, with its typical message, count, 24-bin trend, last seen and most recent items, sorted
 * by severity.
 *
 * Kept out of `evtx-filter.ts` on purpose: the group labels come from that module's
 * `buildGroupedRows`, so the Grouped view and the table's group headers name a group the same way,
 * without this phase editing a module another phase is changing.
 *
 * Evidence rule for the trend (soul.md): a bin holding events shows their count, which is
 * evidence. An empty bin is 0 only when every channel the group's events came from was read
 * across the whole bin; otherwise it is `null`, unknown, and must not be drawn as zero. What
 * "read" means comes from the coverage the store holds (see `classifyChannelReads`).
 *
 * Nothing here reads a clock; the caller passes `nowMs`.
 */
import { formatCoverageGap } from "./evtx-coverage";
import { buildGroupedRows, type EvtxGroupField } from "./evtx-filter";
import type { EvtxTimeZoneMode } from "./evtx-time";
import {
  EVTX_TIME_WINDOW_MS,
  type EventLogSourceCoverage,
  type EvtxChannelInfo,
  type EvtxCoverageGap,
  type EvtxCoverageGapKind,
  type EvtxLevel,
  type EvtxRecord,
  type EvtxTimeWindow,
} from "./types";

export const GROUP_TREND_BINS = 24;
/** Spec 8.8: an expanded group lists up to 8 of its most recent events. */
export const GROUP_RECENT_ITEMS = 8;

/** Spec 8.8: the first Group by field, Event ID when Group by is None. */
export function groupedViewField(groupBy: readonly EvtxGroupField[]): EvtxGroupField {
  return groupBy[0] ?? "eventId";
}

/**
 * The window as the "{window} trend" header names it. "All loaded" because with no time window the
 * trend spans the loaded records, which is not all time.
 */
export function trendWindowLabel(window: EvtxTimeWindow): string {
  switch (window) {
    case "1h":
      return "1 h";
    case "24h":
      return "24 h";
    case "7d":
      return "7 d";
    case "30d":
      return "30 d";
    case "all":
      return "All loaded";
  }
}

const LEVEL_RANK: Record<EvtxLevel, number> = {
  Critical: 0,
  Error: 1,
  Warning: 2,
  Information: 3,
  Verbose: 4,
};

/**
 * The event's time in Unix milliseconds, or null when it has none. The backend writes 0 for a
 * timestamp it could not read, and a negative value predates any event log.
 */
function placedMs(record: EvtxRecord): number | null {
  const epoch = record.timestampEpoch;
  return Number.isFinite(epoch) && epoch > 0 ? epoch : null;
}

// ── Which channels were read, from the coverage the store holds ─────────────

/**
 * How much of a channel's time the loaded records cover.
 * - `complete`: no gap says an event of the channel is missing.
 * - `newestOnly`: the automatic load stopped at its bound and kept the newest events, so the
 *   channel was read from its oldest loaded event onward and not before it.
 * - `incomplete`: a gap says events are missing, at times nothing records.
 */
export type ChannelReadKind = "complete" | "newestOnly" | "incomplete";

export interface ChannelReadInput {
  remoteMachine: string | null;
  channels: readonly EvtxChannelInfo[];
  /** Structured parser and query gaps (`coverageDetails`). */
  coverageDetails: readonly EvtxCoverageGap[];
  /** Source-level gaps from the manifest of a file or folder open. */
  manifestCoverage: readonly EventLogSourceCoverage[];
  /** The store's gap strings (`coverageGaps`), "source: reason". */
  legacyCoverage: readonly string[];
  /** The live tail's gap strings (`tailCoverageGaps`), "source: reason". */
  tailCoverage: readonly string[];
  /**
   * True for the reason a load gives when it stopped at its bound and kept the newest events
   * (`isNewestOnlyGapReason` in `evtx-store.ts`, beside the code that writes it). Passed in, so
   * this module stays free of the store and the wording lives in one place.
   */
  isNewestOnlyReason: (reason: string) => boolean;
}

/** Kinds that leave every event in place: an unformatted message, or a source that holds none. */
const COMPLETE_DESPITE_KINDS: ReadonlySet<EvtxCoverageGapKind> = new Set(["provider", "empty"]);

/**
 * Gap strings that do not mean an event was lost: a tail that could not start or fell back to
 * polling, and a provider message shown as raw data. Every other string counts as a loss.
 */
const NEUTRAL_REASON =
  /\blive tail unavailable\b|polling fallback is active|raw event data is shown instead|provider database lookup failed/i;

interface SourcedReason {
  source: string;
  reason: string;
  /** Null for a gap string, which carries no kind. */
  kind: EvtxCoverageGapKind | null;
}

function parseGapString(text: string): SourcedReason | null {
  const message = text.trim();
  const separator = message.indexOf(": ");
  if (separator <= 0) return null;
  return {
    source: message.slice(0, separator).trim(),
    reason: message.slice(separator + 2).trim(),
    kind: null,
  };
}

/**
 * Reads the store's coverage into a per-channel answer. A gap belongs to a channel when its source
 * is the channel's name, "machine/channel" for a remote query, or the path of a file the channel
 * was read from. A gap no channel claims concerns a source with no loaded events, so no group's
 * trend depends on it (the coverage banner still reports it).
 */
export function classifyChannelReads(input: ChannelReadInput): (channel: string) => ChannelReadKind {
  const channelsBySource = new Map<string, Set<string>>();
  const claim = (source: string, channel: string) => {
    const owners = channelsBySource.get(source);
    if (owners) owners.add(channel);
    else channelsBySource.set(source, new Set([channel]));
  };
  for (const channel of input.channels) {
    if (typeof channel.sourceType === "object" && "file" in channel.sourceType) {
      claim(channel.sourceType.file.path, channel.name);
    }
  }
  const remotePrefix = input.remoteMachine ? `${input.remoteMachine}/` : null;
  const ownersOf = (source: string): Iterable<string> => {
    const owners = new Set(channelsBySource.get(source) ?? []);
    owners.add(
      remotePrefix !== null && source.startsWith(remotePrefix)
        ? source.slice(remotePrefix.length)
        : source,
    );
    return owners;
  };

  const structured: EvtxCoverageGap[] = [
    ...input.coverageDetails,
    ...input.manifestCoverage.map(({ path, kind, reason }) => ({ source: path, kind, reason })),
  ];
  // The store also writes each structured gap as a string (`formatCoverageGap`). That twin says
  // nothing new, and read without its kind it would turn a gap that loses no event into a loss.
  const twins = new Set(structured.map(formatCoverageGap));
  const gaps: SourcedReason[] = [
    ...structured.map(({ source, kind, reason }) => ({ source, kind, reason })),
    ...[...input.legacyCoverage, ...input.tailCoverage]
      .filter((text) => !twins.has(text.trim()))
      .map(parseGapString)
      .filter((gap): gap is SourcedReason => gap !== null),
  ];

  const kinds = new Map<string, ChannelReadKind>();
  for (const gap of gaps) {
    let kind: ChannelReadKind | null;
    if (gap.kind !== null) {
      kind = COMPLETE_DESPITE_KINDS.has(gap.kind) ? null : "incomplete";
    } else if (input.isNewestOnlyReason(gap.reason)) {
      kind = "newestOnly";
    } else {
      kind = NEUTRAL_REASON.test(gap.reason) ? null : "incomplete";
    }
    if (kind === null) continue;
    for (const channel of ownersOf(gap.source)) {
      if (kinds.get(channel) !== "incomplete") kinds.set(channel, kind);
    }
  }
  return (channel) => kinds.get(channel) ?? "complete";
}

// ── Summaries ───────────────────────────────────────────────────────────────

export interface TrendSpan {
  startMs: number;
  endMs: number;
}

/** A count of events (evidence), 0 for a bin read and empty, or null for a bin not read. */
export type TrendBin = number | null;

export interface EvtxGroupSummary {
  /** Stable identity: the table's group key for the same field and value. */
  key: string;
  field: EvtxGroupField;
  /** The group's value as the table's group header writes it. */
  value: string;
  /** The most severe level among the group's events. */
  level: EvtxLevel;
  count: number;
  /** Distinct event IDs, ascending. */
  eventIds: readonly number[];
  /** Distinct providers, sorted. */
  providers: readonly string[];
  /** The most frequent non-empty message, ties to the latest; empty when no event has one. */
  typicalMessage: string;
  lastSeenMs: number | null;
  /** `GROUP_TREND_BINS` bins over the shared span. */
  trend: readonly TrendBin[];
  /** Events in `count` but in no bin: no timestamp, or outside the span. */
  unplaced: number;
  /** Up to `GROUP_RECENT_ITEMS` events, newest first; events without a timestamp last. */
  recent: readonly EvtxRecord[];
}

export interface GroupSummariesInput {
  /** The visible records: what the table would show. */
  records: readonly EvtxRecord[];
  /** Every loaded record: the "All time" span and each channel's oldest and newest event. */
  loadedRecords: readonly EvtxRecord[];
  field: EvtxGroupField;
  timeZoneMode: EvtxTimeZoneMode;
  timeWindow: EvtxTimeWindow;
  /** The workspace clock snapshot: a finite window ends here. */
  nowMs: number;
  sourceMode: "files" | "live" | null;
  channelRead: (channel: string) => ChannelReadKind;
}

export interface GroupSummariesResult {
  field: EvtxGroupField;
  /** The time all trends share, or null when nothing loaded carries a timestamp. */
  span: TrendSpan | null;
  summaries: EvtxGroupSummary[];
}

function trendSpan(input: GroupSummariesInput): TrendSpan | null {
  if (input.timeWindow !== "all") {
    return { startMs: input.nowMs - EVTX_TIME_WINDOW_MS[input.timeWindow], endMs: input.nowMs };
  }
  let earliest = Infinity;
  let latest = -Infinity;
  for (const record of input.loadedRecords) {
    const at = placedMs(record);
    if (at === null) continue;
    if (at < earliest) earliest = at;
    if (at > latest) latest = at;
  }
  if (earliest === Infinity) return null;
  // Events that share one instant still get a span, so they land in the first bin.
  return { startMs: earliest, endMs: latest > earliest ? latest : earliest + 1 };
}

interface Interval {
  startMs: number;
  endMs: number;
}

/**
 * The time each channel was read across, or null where nothing about its empty bins is known.
 *
 * It ends at the channel's newest loaded event in every mode. The store keeps no time for a
 * channel's last read, and the records changing is no proof either: loading another channel or a
 * tail batch for another channel changes them too. So nothing after a channel's newest event is
 * claimed, and a quiet channel's latest bins are left unknown rather than shown as zero.
 *
 * It starts at the window's start for a live channel read whole under a time window (the query
 * asked for the whole window). Otherwise it starts at the channel's oldest event: a load that kept
 * the newest events only, a query with no window (what came before the oldest retained event is
 * unknown), and a file, which holds a contiguous run of events and nothing either side of it.
 */
function channelIntervals(
  input: GroupSummariesInput,
  span: TrendSpan,
): (channel: string) => Interval | null {
  const bounds = new Map<string, Interval>();
  for (const record of input.loadedRecords) {
    const at = placedMs(record);
    if (at === null) continue;
    const known = bounds.get(record.channel);
    if (known === undefined) bounds.set(record.channel, { startMs: at, endMs: at });
    else {
      if (at < known.startMs) known.startMs = at;
      if (at > known.endMs) known.endMs = at;
    }
  }
  const cache = new Map<string, Interval | null>();
  return (channel) => {
    const cached = cache.get(channel);
    if (cached !== undefined) return cached;
    const read = input.channelRead(channel);
    const own = bounds.get(channel);
    let interval: Interval | null = null;
    if (read !== "incomplete" && own !== undefined) {
      const fromWindowStart =
        input.sourceMode === "live" && read === "complete" && input.timeWindow !== "all";
      interval = { startMs: fromWindowStart ? span.startMs : own.startMs, endMs: own.endMs };
    }
    cache.set(channel, interval);
    return interval;
  };
}

interface Bucket {
  key: string;
  value: string;
  records: EvtxRecord[];
}

/** Groups through the table's own row builder, so a group's value and key match its header. */
function bucketsFor(input: GroupSummariesInput): Bucket[] {
  const buckets: Bucket[] = [];
  let current: Bucket | null = null;
  for (const row of buildGroupedRows(
    input.records as EvtxRecord[],
    [input.field],
    new Set(),
    input.timeZoneMode,
  )) {
    if (row.kind === "group") {
      current = { key: row.key, value: row.label, records: [] };
      buckets.push(current);
    } else if (current !== null) {
      current.records.push(row.record);
    }
  }
  return buckets;
}

function typicalMessage(records: readonly EvtxRecord[]): string {
  const seen = new Map<string, { count: number; latest: number }>();
  for (const record of records) {
    const message = record.message.trim();
    if (message === "") continue;
    const at = placedMs(record) ?? -Infinity;
    const entry = seen.get(message);
    if (entry === undefined) seen.set(message, { count: 1, latest: at });
    else {
      entry.count += 1;
      if (at > entry.latest) entry.latest = at;
    }
  }
  let best = "";
  let bestCount = 0;
  let bestLatest = -Infinity;
  for (const [message, { count, latest }] of seen) {
    if (count > bestCount || (count === bestCount && latest > bestLatest)) {
      best = message;
      bestCount = count;
      bestLatest = latest;
    }
  }
  return best;
}

function newestFirst(a: EvtxRecord, b: EvtxRecord): number {
  const at = placedMs(a);
  const bt = placedMs(b);
  if (at !== bt) {
    if (at === null) return 1;
    if (bt === null) return -1;
    return bt - at;
  }
  return b.id - a.id;
}

function summarize(
  bucket: Bucket,
  field: EvtxGroupField,
  span: TrendSpan | null,
  intervalOf: ((channel: string) => Interval | null) | null,
): EvtxGroupSummary {
  let level: EvtxLevel = "Verbose";
  let lastSeenMs: number | null = null;
  let unplaced = 0;
  const eventIds = new Set<number>();
  const providers = new Set<string>();
  const channels = new Set<string>();
  const counts = new Array<number>(GROUP_TREND_BINS).fill(0);
  const width = span === null ? 0 : (span.endMs - span.startMs) / GROUP_TREND_BINS;

  for (const record of bucket.records) {
    if (LEVEL_RANK[record.level] < LEVEL_RANK[level]) level = record.level;
    eventIds.add(record.eventId);
    providers.add(record.provider);
    channels.add(record.channel);
    const at = placedMs(record);
    if (at !== null && (lastSeenMs === null || at > lastSeenMs)) lastSeenMs = at;
    if (at === null || span === null || at < span.startMs || at > span.endMs) {
      unplaced += 1;
    } else {
      // The end of the span belongs to the last bin; every other edge to the later bin.
      counts[Math.min(GROUP_TREND_BINS - 1, Math.floor((at - span.startMs) / width))] += 1;
    }
  }

  // Known only where every channel the group's events came from was read.
  let known: Interval | null = null;
  if (span !== null && intervalOf !== null) {
    known = { startMs: -Infinity, endMs: Infinity };
    for (const channel of channels) {
      const interval = intervalOf(channel);
      if (interval === null) {
        known = null;
        break;
      }
      known.startMs = Math.max(known.startMs, interval.startMs);
      known.endMs = Math.min(known.endMs, interval.endMs);
    }
  }
  const trend: TrendBin[] = counts.map((count, bin) => {
    if (count > 0) return count;
    if (span === null || known === null) return null;
    const binStart = span.startMs + bin * width;
    const binEnd = bin === GROUP_TREND_BINS - 1 ? span.endMs : span.startMs + (bin + 1) * width;
    return binStart >= known.startMs && binEnd <= known.endMs ? 0 : null;
  });

  return {
    key: bucket.key,
    field,
    value: bucket.value,
    level,
    count: bucket.records.length,
    eventIds: [...eventIds].sort((a, b) => a - b),
    providers: [...providers].sort((a, b) => a.localeCompare(b)),
    typicalMessage: typicalMessage(bucket.records),
    lastSeenMs,
    trend,
    unplaced,
    recent: [...bucket.records].sort(newestFirst).slice(0, GROUP_RECENT_ITEMS),
  };
}

function compareValues(field: EvtxGroupField, a: string, b: string): number {
  if (field === "eventId") return Number(a) - Number(b);
  return a.localeCompare(b);
}

/**
 * Summaries of the visible records grouped by `field`, sorted by severity rank (the group's most
 * severe level), then count descending, then last seen (latest first), then the key, so the order
 * is total and stable.
 */
export function buildGroupSummaries(input: GroupSummariesInput): GroupSummariesResult {
  const span = trendSpan(input);
  const intervalOf = span === null ? null : channelIntervals(input, span);
  const summaries = bucketsFor(input).map((bucket) =>
    summarize(bucket, input.field, span, intervalOf),
  );
  summaries.sort(
    (a, b) =>
      LEVEL_RANK[a.level] - LEVEL_RANK[b.level] ||
      b.count - a.count ||
      (b.lastSeenMs ?? -Infinity) - (a.lastSeenMs ?? -Infinity) ||
      compareValues(input.field, a.value, b.value),
  );
  return { field: input.field, span, summaries };
}
