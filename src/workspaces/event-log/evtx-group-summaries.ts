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
 * evidence. An empty bin is 0 only when every channel in the visible scope (and any channel the
 * group's events came from) was read across the whole bin; otherwise it is `null`, unknown, and
 * must not be drawn as zero. What "read" means comes from the coverage the store holds
 * (`classifyChannelReads`), each live load's read time (`readThrough`) and, for files, each file's
 * own run of events (`channelReadSpans`). Records never extend a live read.
 *
 * Nothing here reads a clock; the caller passes `nowMs` and the read times.
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

/** A gap string as "source: reason". One with no source keeps an empty source. */
function parseGapString(text: string): SourcedReason {
  const message = text.trim();
  const separator = message.indexOf(": ");
  if (separator <= 0) return { source: "", reason: message, kind: null };
  return {
    source: message.slice(0, separator).trim(),
    reason: message.slice(separator + 2).trim(),
    kind: null,
  };
}

/**
 * A single event log file (an `.evtx`, a rotated `.evtx.N`, or such a member of an archive). A gap
 * on one that no channel claims is a file that never opened: none of its events are loaded and no
 * channel in the view stands for it, so it is outside the visible scope.
 */
const EVENT_LOG_FILE = /\.evtx(?:\.\d+)?$/i;

/** The coverage the store holds, read per channel. */
export interface ChannelReads {
  kind: (channel: string) => ChannelReadKind;
  /**
   * True when a gap that says events may be missing names no channel: a coalesced summary such as
   * `<coverage>` or `<live tail coverage>`, a folder, a pattern, or no source at all. Which
   * channel it hides is unknown, so no empty bin anywhere can be called read.
   */
  unattributedLoss: boolean;
}

/**
 * Reads the store's coverage into a per-channel answer. A gap belongs to a channel when its source
 * is the channel's name, "machine/channel" for a remote query, or the path of a file the channel
 * was read from. A loss on a source no channel claims sets `unattributedLoss`, except for a single
 * event log file that never opened (see `EVENT_LOG_FILE`).
 *
 * A loss wins over the bound whatever order the gaps come in: the store writes a loss line before
 * the bound's note, and structured gaps are read before strings.
 */
export function classifyChannelReads(input: ChannelReadInput): ChannelReads {
  const channelNames = new Set(input.channels.map((channel) => channel.name));
  const channelsBySource = new Map<string, Set<string>>();
  for (const channel of input.channels) {
    if (typeof channel.sourceType === "object" && "file" in channel.sourceType) {
      const path = channel.sourceType.file.path;
      const owners = channelsBySource.get(path);
      if (owners) owners.add(channel.name);
      else channelsBySource.set(path, new Set([channel.name]));
    }
  }
  const remotePrefix = input.remoteMachine ? `${input.remoteMachine}/` : null;
  const ownersOf = (source: string): Set<string> => {
    const owners = new Set(channelsBySource.get(source) ?? []);
    const name =
      remotePrefix !== null && source.startsWith(remotePrefix)
        ? source.slice(remotePrefix.length)
        : source;
    if (channelNames.has(name)) owners.add(name);
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
      .map(parseGapString),
  ];

  const kinds = new Map<string, ChannelReadKind>();
  let unattributedLoss = false;
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
    const owners = ownersOf(gap.source);
    if (owners.size === 0) {
      if (!EVENT_LOG_FILE.test(gap.source)) unattributedLoss = true;
      continue;
    }
    for (const channel of owners) {
      if (kinds.get(channel) !== "incomplete") kinds.set(channel, kind);
    }
  }
  return { kind: (channel) => kinds.get(channel) ?? "complete", unattributedLoss };
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
  channelReads: ChannelReads;
  /**
   * The channels the visible records can come from: the selected channels that are loaded (live)
   * or the selected channels of the file set. An empty bin is 0 only where every one of them was
   * read across the whole bin, whatever channels the group's own events came from.
   */
  scopeChannels: readonly string[];
  /** Live: per channel, the instant its current load read through (`channelReadThrough`). */
  readThrough: ReadonlyMap<string, number>;
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

/** The union of `intervals` as disjoint intervals, earliest first. Overlapping ones merge. */
function union(intervals: Iterable<Interval>): Interval[] {
  const sorted = [...intervals].sort((a, b) => a.startMs - b.startMs);
  const merged: Interval[] = [];
  for (const interval of sorted) {
    const last = merged[merged.length - 1];
    if (last !== undefined && interval.startMs <= last.endMs) {
      last.endMs = Math.max(last.endMs, interval.endMs);
    } else {
      merged.push({ ...interval });
    }
  }
  return merged;
}

/**
 * The times each channel was read across, or null where nothing about its empty bins is known.
 *
 * Live: one interval ending where the channel's current load read through (`readThrough`), never
 * at a record, so live-tail records never extend it. It starts at the window's start for a channel
 * read whole under a time window (the query asked for the whole window), and at the channel's
 * oldest kept event when the load kept the newest only or asked for no window. A channel with no
 * read time was not read by a load this view knows of.
 *
 * Files: a file holds a contiguous run of events and nothing either side of it, so each file
 * covers its own oldest to newest event, and a channel read from several files covers the union
 * of those, never the hull: the time between two files was not read.
 */
function channelReadSpans(
  input: GroupSummariesInput,
  span: TrendSpan,
): (channel: string) => readonly Interval[] | null {
  const live = input.sourceMode === "live";
  const oldest = new Map<string, number>();
  const files = new Map<string, Map<string, Interval>>();
  for (const record of input.loadedRecords) {
    const at = placedMs(record);
    if (at === null) continue;
    const known = oldest.get(record.channel);
    if (known === undefined || at < known) oldest.set(record.channel, at);
    if (live) continue;
    let byFile = files.get(record.channel);
    if (byFile === undefined) {
      byFile = new Map();
      files.set(record.channel, byFile);
    }
    const file = byFile.get(record.sourceLabel);
    if (file === undefined) byFile.set(record.sourceLabel, { startMs: at, endMs: at });
    else {
      if (at < file.startMs) file.startMs = at;
      if (at > file.endMs) file.endMs = at;
    }
  }
  const cache = new Map<string, readonly Interval[] | null>();
  const spansOf = (channel: string): readonly Interval[] | null => {
    const read = input.channelReads.kind(channel);
    if (read === "incomplete") return null;
    if (!live) {
      const byFile = files.get(channel);
      return byFile === undefined ? null : union(byFile.values());
    }
    const end = input.readThrough.get(channel);
    const start =
      read === "complete" && input.timeWindow !== "all" ? span.startMs : oldest.get(channel);
    return end === undefined || start === undefined ? null : [{ startMs: start, endMs: end }];
  };
  return (channel) => {
    if (!cache.has(channel)) cache.set(channel, spansOf(channel));
    return cache.get(channel) ?? null;
  };
}

/** Bin `bin`'s start and end on `span`. The end of the span belongs to the last bin. */
function binBounds(span: TrendSpan, bin: number): Interval {
  const width = (span.endMs - span.startMs) / GROUP_TREND_BINS;
  return {
    startMs: span.startMs + bin * width,
    endMs: bin === GROUP_TREND_BINS - 1 ? span.endMs : span.startMs + (bin + 1) * width,
  };
}

/** Per bin: true when every one of `channels` was read across the whole bin. */
function binsRead(
  span: TrendSpan,
  channels: Iterable<string>,
  spansOf: (channel: string) => readonly Interval[] | null,
): boolean[] {
  const list = [...channels];
  return Array.from({ length: GROUP_TREND_BINS }, (_, bin) => {
    const { startMs, endMs } = binBounds(span, bin);
    return list.every((channel) =>
      (spansOf(channel) ?? []).some(
        (interval) => startMs >= interval.startMs && endMs <= interval.endMs,
      ),
    );
  });
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

/** Which bins of a group's trend were read: the scope's, narrowed by any channel outside it. */
interface ReadBins {
  span: TrendSpan;
  scope: ReadonlySet<string>;
  scopeRead: readonly boolean[];
  spansOf: (channel: string) => readonly Interval[] | null;
  /** True when nothing about any empty bin is known (`ChannelReads.unattributedLoss`). */
  none: boolean;
}

function summarize(
  bucket: Bucket,
  field: EvtxGroupField,
  span: TrendSpan | null,
  readBins: ReadBins | null,
): EvtxGroupSummary {
  let level: EvtxLevel = "Verbose";
  let lastSeenMs: number | null = null;
  let unplaced = 0;
  const eventIds = new Set<number>();
  const providers = new Set<string>();
  const outsideScope = new Set<string>();
  const counts = new Array<number>(GROUP_TREND_BINS).fill(0);
  const width = span === null ? 0 : (span.endMs - span.startMs) / GROUP_TREND_BINS;

  for (const record of bucket.records) {
    if (LEVEL_RANK[record.level] < LEVEL_RANK[level]) level = record.level;
    eventIds.add(record.eventId);
    providers.add(record.provider);
    if (readBins !== null && !readBins.scope.has(record.channel)) outsideScope.add(record.channel);
    const at = placedMs(record);
    if (at !== null && (lastSeenMs === null || at > lastSeenMs)) lastSeenMs = at;
    if (at === null || span === null || at < span.startMs || at > span.endMs) {
      unplaced += 1;
    } else {
      // The end of the span belongs to the last bin; every other edge to the later bin.
      counts[Math.min(GROUP_TREND_BINS - 1, Math.floor((at - span.startMs) / width))] += 1;
    }
  }

  // An empty bin is 0 only where every channel in the visible scope, and any channel the group's
  // events came from outside it, was read across the whole bin.
  const read =
    readBins === null || readBins.none
      ? null
      : outsideScope.size === 0
        ? readBins.scopeRead
        : binsRead(readBins.span, outsideScope, readBins.spansOf).map(
            (known, bin) => known && readBins.scopeRead[bin],
          );
  const trend: TrendBin[] = counts.map((count, bin) => {
    if (count > 0) return count;
    return read !== null && read[bin] ? 0 : null;
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
  let readBins: ReadBins | null = null;
  if (span !== null) {
    const spansOf = channelReadSpans(input, span);
    const scope = new Set(input.scopeChannels);
    const none = input.channelReads.unattributedLoss;
    readBins = {
      span,
      scope,
      spansOf,
      none,
      scopeRead: none ? [] : binsRead(span, scope, spansOf),
    };
  }
  const summaries = bucketsFor(input).map((bucket) =>
    summarize(bucket, input.field, span, readBins),
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
