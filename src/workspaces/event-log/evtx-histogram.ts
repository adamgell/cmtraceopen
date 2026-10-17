/**
 * The Event Logs histogram's data and geometry (spec section 8.5), with no React and no clock.
 *
 * What it promises, because the brush and the table read it:
 *
 * - A bucket is half open, `[startMs, endMs)`, like `EvtxTimeRange` (`evtx-filter.ts`). A record on
 *   an edge belongs to the later bucket, and a brush over buckets `a` to `b` is
 *   `{ startMs: edges[a], endMs: edges[b + 1] }`, so the table shows exactly the events those bars
 *   count.
 * - The x axis is the extent of the TIMED records it is given, never a time window. A load is capped
 *   (`AUTO_LOAD_MAX_EVENTS`), so a stretch of the window the load never read must not draw as
 *   zero. Nothing here reads the clock.
 * - A record with no usable timestamp (`hasUsableTimestamp`) cannot be placed. It is counted in
 *   `untimed` and nowhere else, so the placed buckets plus `untimed` are the records given.
 * - Buckets are edges in the displayed zone's wall clock. Epoch flooring is right only in UTC: a
 *   local day is 23 or 25 hours across a DST change and some zones sit at +5:30 or +5:45. The zone
 *   arrives as a `ZoneClock` so the DST and the half-hour paths are tested without the host's zone.
 * - Every bucket is drawn at the same width. Below a day every bucket also lasts the same real time
 *   (the labels, not the counts, shift by a DST jump). A bucket of a day or more steps by calendar
 *   days, so on a DST change it lasts 23 or 25 hours.
 */
import { hasUsableTimestamp, type EvtxTimeRange } from "./evtx-filter";
import { formatCount } from "./evtx-insights-data";
import {
  eventDateKey,
  formatClock,
  formatDayClock,
  formatTimeRange,
  timeRangeNeedsYear,
  timeZoneLabel,
  type EvtxTimeZoneMode,
} from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

/** Height of the bar area in pixels (spec 8.5). */
export const HISTOGRAM_BAR_AREA_PX = 56;
/** The separator a segment draws on its top edge (spec 8.5): a segment's height includes it. */
export const SEPARATOR_PX = 1;
/**
 * A non-empty segment shows at least this many pixels of its level colour (spec 8.5 "at least 2 px,
 * with a 1 px separator on top"), so its height is at least this plus the separator: a lone Critical
 * event in a tall bucket is a 2 px band of red, not a 1 px line under a 1 px line of surface.
 */
export const MIN_SEGMENT_PX = 2;

/** Levels from the bottom of a bar to the top: Info, Warning, Error, Critical (spec 8.5), with Verbose under them. */
export const HISTOGRAM_STACK_ORDER: readonly EvtxLevel[] = [
  "Verbose",
  "Information",
  "Warning",
  "Error",
  "Critical",
];

/** The legend and table labels: the level toggles' short forms (spec 8.3), so the 84 px column holds them. */
export const HISTOGRAM_LEVEL_LABELS: Readonly<Record<EvtxLevel, string>> = {
  Critical: "Critical",
  Error: "Error",
  Warning: "Warning",
  Information: "Info",
  Verbose: "Verbose",
};

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/**
 * The widths a bucket may have. Spec 8.5 lists 1, 2, 5, 10, 15, 20 and 30 minutes, 1, 2, 3, 6 and 12
 * hours, and 1 day, which reach 48 to 96 buckets only for spans of about 3 hours to 90 days. The
 * seconds and the multi-day rungs extend it at both ends (a recorded deviation).
 */
export const HISTOGRAM_INTERVALS_MS: readonly number[] = [
  SECOND,
  2 * SECOND,
  5 * SECOND,
  10 * SECOND,
  15 * SECOND,
  30 * SECOND,
  MINUTE,
  2 * MINUTE,
  5 * MINUTE,
  10 * MINUTE,
  15 * MINUTE,
  20 * MINUTE,
  30 * MINUTE,
  HOUR,
  2 * HOUR,
  3 * HOUR,
  6 * HOUR,
  12 * HOUR,
  DAY,
  2 * DAY,
  7 * DAY,
  14 * DAY,
  30 * DAY,
  90 * DAY,
  365 * DAY,
];

/** The count the width is chosen for (spec 8.5: 72 buckets, 20 minutes for 24 hours). */
export const TARGET_BUCKETS = 72;
export const MIN_BUCKETS = 48;
export const MAX_BUCKETS = 96;

/** Wall-clock parts in a zone. `month` is 0 to 11, as in `Date`. */
export interface WallParts {
  year: number;
  month: number;
  day: number;
  hours: number;
  minutes: number;
  seconds: number;
}

/**
 * A zone seen as a wall clock. `instant` takes parts that overflow (day 32, month 12) as `Date`
 * does, and resolves a time the zone skips or repeats the way `Date` does.
 */
export interface ZoneClock {
  wall: (epochMs: number) => WallParts;
  instant: (parts: WallParts) => number;
}

export const UTC_CLOCK: ZoneClock = {
  wall: (epochMs) => {
    const date = new Date(epochMs);
    return {
      year: date.getUTCFullYear(),
      month: date.getUTCMonth(),
      day: date.getUTCDate(),
      hours: date.getUTCHours(),
      minutes: date.getUTCMinutes(),
      seconds: date.getUTCSeconds(),
    };
  },
  instant: (p) => Date.UTC(p.year, p.month, p.day, p.hours, p.minutes, p.seconds),
};

export const LOCAL_CLOCK: ZoneClock = {
  wall: (epochMs) => {
    const date = new Date(epochMs);
    return {
      year: date.getFullYear(),
      month: date.getMonth(),
      day: date.getDate(),
      hours: date.getHours(),
      minutes: date.getMinutes(),
      seconds: date.getSeconds(),
    };
  },
  instant: (p) => new Date(p.year, p.month, p.day, p.hours, p.minutes, p.seconds).getTime(),
};

export function zoneClockFor(mode: EvtxTimeZoneMode): ZoneClock {
  return mode === "utc" ? UTC_CLOCK : LOCAL_CLOCK;
}

export type LevelCounts = Readonly<Record<EvtxLevel, number>>;

export interface HistogramBucket {
  startMs: number;
  endMs: number;
  counts: LevelCounts;
  total: number;
}

export interface EvtxHistogram {
  /** The width the buckets were chosen at. Zero when nothing is placed. */
  intervalMs: number;
  /** `buckets.length + 1` instants, strictly increasing. Empty when nothing is placed. */
  edges: readonly number[];
  buckets: readonly HistogramBucket[];
  /** Records with no usable timestamp: counted here and in no bucket. */
  untimed: number;
  /** Records in a bucket. `placed + untimed` is the number of records given. */
  placed: number;
  /** The tallest bucket's total, for scaling. */
  maxTotal: number;
  /** First edge to last edge, or null when nothing is placed. */
  domain: EvtxTimeRange | null;
  /**
   * Day labels carry the year (`timeRangeNeedsYear`, the Time chip's rule too): the domain is not
   * entirely within the current year in the zone, crosses a calendar year, or spans 365 days or more.
   * Otherwise buckets of different years would read alike.
   */
  showYear: boolean;
}

const EMPTY_COUNTS: LevelCounts = {
  Critical: 0,
  Error: 0,
  Warning: 0,
  Information: 0,
  Verbose: 0,
};

/** The edges of buckets `intervalMs` wide that cover `[minMs, maxMs]`; the last edge is above `maxMs`. */
export function bucketEdges(
  minMs: number,
  maxMs: number,
  intervalMs: number,
  clock: ZoneClock,
): number[] {
  const edges: number[] = [];
  if (intervalMs >= DAY) {
    const stepDays = Math.round(intervalMs / DAY);
    const origin = clock.wall(minMs);
    for (let step = 0; step < 100_000; step += 1) {
      const edge = clock.instant({
        year: origin.year,
        month: origin.month,
        day: origin.day + step * stepDays,
        hours: 0,
        minutes: 0,
        seconds: 0,
      });
      if (edges.length > 0 && edge <= edges[edges.length - 1]) continue;
      edges.push(edge);
      if (edge > maxMs) break;
    }
    // A zone whose midnight is skipped can resolve the first edge above the first record.
    while (edges[0] > minMs) edges[0] -= intervalMs;
    return edges;
  }
  const origin = clock.wall(minMs);
  const stepSeconds = intervalMs / SECOND;
  const secondOfDay = origin.hours * 3600 + origin.minutes * 60 + origin.seconds;
  const floored = Math.floor(secondOfDay / stepSeconds) * stepSeconds;
  let edge = clock.instant({
    year: origin.year,
    month: origin.month,
    day: origin.day,
    hours: Math.floor(floored / 3600),
    minutes: Math.floor((floored % 3600) / 60),
    seconds: floored % 60,
  });
  // A wall time the zone skips resolves forward, which can pass the first record by an interval.
  while (edge > minMs) edge -= intervalMs;
  // A wall time the zone repeats (a DST fall-back) resolves to its FIRST occurrence, up to a whole
  // shift before the first record. Leading buckets that end before it hold nothing that was read.
  while (edge + intervalMs <= minMs) edge += intervalMs;
  edges.push(edge);
  while (edge <= maxMs) {
    edge += intervalMs;
    edges.push(edge);
  }
  return edges;
}

/** Beyond this many edges a rung is out of the running and is counted by estimate, not built. */
const BUILD_LIMIT = 300;

/**
 * The width and edges for a span. Only rungs that fit in 96 buckets are candidates; of those, the
 * one in 48 to 96 nearest 72 where there is one, and otherwise the finest that fits (the span is in
 * a jump between two rungs, and the finer one is over 96). A multiple of the 365 day rung is taken
 * only when EVERY rung is over 96 buckets, so the count is never above 96 and a span is never
 * charted as a single bucket of years while a rung would have fitted.
 */
export function chooseBuckets(
  minMs: number,
  maxMs: number,
  clock: ZoneClock,
): { intervalMs: number; edges: number[] } {
  const span = maxMs - minMs + 1;
  let best: { intervalMs: number; edges: number[]; count: number } | null = null;
  const score = (count: number) => ({
    inBand: count >= MIN_BUCKETS,
    distance: Math.abs(count - TARGET_BUCKETS),
  });
  for (const intervalMs of HISTOGRAM_INTERVALS_MS) {
    const estimate = Math.ceil(span / intervalMs) + 1;
    if (estimate > BUILD_LIMIT) continue;
    const edges = bucketEdges(minMs, maxMs, intervalMs, clock);
    const count = edges.length - 1;
    if (count > MAX_BUCKETS) continue;
    const candidate = score(count);
    const current = best === null ? null : score(best.count);
    if (
      current === null ||
      (candidate.inBand && !current.inBand) ||
      (candidate.inBand === current.inBand && candidate.distance < current.distance)
    ) {
      best = { intervalMs, edges, count };
    }
  }
  if (best !== null) return best;
  const widest = 365 * DAY;
  for (let multiple = Math.max(2, Math.ceil(span / (TARGET_BUCKETS * widest))); ; multiple += 1) {
    const intervalMs = multiple * widest;
    const edges = bucketEdges(minMs, maxMs, intervalMs, clock);
    if (edges.length - 1 <= MAX_BUCKETS) return { intervalMs, edges };
  }
}

/**
 * Buckets `records` by time in `clock`'s zone. Two passes over the records and one binary search
 * per record: the first finds the extent of the timed ones, the second counts. The work does not
 * grow with the number of buckets. `nowMs` is the clock the years of the day labels are compared
 * with (see `showYear`); the real one unless a test gives another.
 */
export function buildHistogram(
  records: readonly EvtxRecord[],
  mode: EvtxTimeZoneMode,
  clock: ZoneClock = zoneClockFor(mode),
  nowMs: number = Date.now(),
): EvtxHistogram {
  let minMs = Infinity;
  let maxMs = -Infinity;
  let untimed = 0;
  for (const record of records) {
    if (!hasUsableTimestamp(record)) {
      untimed += 1;
      continue;
    }
    const at = record.timestampEpoch;
    if (at < minMs) minMs = at;
    if (at > maxMs) maxMs = at;
  }
  if (minMs > maxMs) {
    return {
      intervalMs: 0,
      edges: [],
      buckets: [],
      untimed,
      placed: 0,
      maxTotal: 0,
      domain: null,
      showYear: false,
    };
  }

  const { intervalMs, edges } = chooseBuckets(minMs, maxMs, clock);
  const count = edges.length - 1;
  const stride = HISTOGRAM_STACK_ORDER.length;
  const flat = new Uint32Array(count * stride);
  const slotOf = new Map<EvtxLevel, number>(HISTOGRAM_STACK_ORDER.map((level, slot) => [level, slot]));
  for (const record of records) {
    if (!hasUsableTimestamp(record)) continue;
    const at = record.timestampEpoch;
    let low = 0;
    let high = count - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if (edges[middle] <= at) low = middle;
      else high = middle - 1;
    }
    flat[low * stride + (slotOf.get(record.level) ?? 0)] += 1;
  }

  const buckets: HistogramBucket[] = [];
  let placed = 0;
  let maxTotal = 0;
  for (let index = 0; index < count; index += 1) {
    const counts = { ...EMPTY_COUNTS } as Record<EvtxLevel, number>;
    let total = 0;
    HISTOGRAM_STACK_ORDER.forEach((level, slot) => {
      const value = flat[index * stride + slot];
      counts[level] = value;
      total += value;
    });
    buckets.push({ startMs: edges[index], endMs: edges[index + 1], counts, total });
    placed += total;
    if (total > maxTotal) maxTotal = total;
  }
  const domain = { startMs: edges[0], endMs: edges[count] };
  return {
    intervalMs,
    edges,
    buckets,
    untimed,
    placed,
    maxTotal,
    domain,
    showYear: timeRangeNeedsYear(domain.startMs, domain.endMs, mode, nowMs),
  };
}

/** The index of the bucket holding `epochMs`, or -1 outside the domain. */
export function bucketIndexAt(histogram: EvtxHistogram, epochMs: number): number {
  const { edges } = histogram;
  if (edges.length < 2 || epochMs < edges[0] || epochMs >= edges[edges.length - 1]) return -1;
  let low = 0;
  let high = edges.length - 2;
  while (low < high) {
    const middle = (low + high + 1) >> 1;
    if (edges[middle] <= epochMs) low = middle;
    else high = middle - 1;
  }
  return low;
}

/**
 * Where an instant sits across the plot, 0 to 1. Buckets are drawn at equal width, so the position
 * is bucket-wise: whole buckets before it plus the part of its own bucket. Below 0 or above 1 when
 * the instant is outside the domain.
 */
export function fractionAt(histogram: EvtxHistogram, epochMs: number): number {
  const { edges } = histogram;
  const count = edges.length - 1;
  if (count < 1) return 0;
  if (epochMs <= edges[0]) return (epochMs - edges[0]) / (edges[1] - edges[0]) / count;
  if (epochMs >= edges[count]) {
    return (count + (epochMs - edges[count]) / (edges[count] - edges[count - 1])) / count;
  }
  const index = bucketIndexAt(histogram, epochMs);
  return (index + (epochMs - edges[index]) / (edges[index + 1] - edges[index])) / count;
}

export interface RangeOnPlot {
  /** 0 to 1 across the plot, clipped to it. */
  left: number;
  right: number;
  /** The range runs past that side of the plot, so the edge drawn there is not the range's own. */
  clippedLeft: boolean;
  clippedRight: boolean;
}

/** The part of `range` that falls on the plot, or null when it falls wholly outside it. */
export function rangeOnPlot(histogram: EvtxHistogram, range: EvtxTimeRange): RangeOnPlot | null {
  if (histogram.domain === null) return null;
  if (range.endMs <= histogram.domain.startMs || range.startMs >= histogram.domain.endMs) return null;
  const left = fractionAt(histogram, range.startMs);
  const right = fractionAt(histogram, range.endMs);
  return {
    left: Math.max(0, left),
    right: Math.min(1, right),
    clippedLeft: left < 0,
    clippedRight: right > 1,
  };
}

/** `20 minutes`, `1 hour`, `2 days`: the interval as the figure's label reads it. */
export function describeInterval(intervalMs: number): string {
  const units: [number, string][] = [
    [DAY, "day"],
    [HOUR, "hour"],
    [MINUTE, "minute"],
    [SECOND, "second"],
  ];
  for (const [size, name] of units) {
    if (intervalMs % size === 0) {
      const amount = intervalMs / size;
      return `${formatCount(amount)} ${name}${amount === 1 ? "" : "s"}`;
    }
  }
  return `${formatCount(intervalMs)} milliseconds`;
}

/**
 * The accessible name of the figure (spec 8.5): the interval and the span actually charted with its
 * zone. The span is the loaded events', not the time window's, which a capped load may not fill.
 */
export function describeFigure(histogram: EvtxHistogram, mode: EvtxTimeZoneMode): string {
  const { domain } = histogram;
  if (domain === null) return "Events per interval, stacked by level";
  return (
    `Events per ${describeInterval(histogram.intervalMs)} over ` +
    `${formatTimeRange(domain.startMs, domain.endMs, mode, histogram.showYear)} ` +
    `(${timeZoneLabel(mode, domain.startMs)}), stacked by level`
  );
}

const noun = (amount: number, singular: string, plural: string) =>
  `${formatCount(amount)} ${amount === 1 ? singular : plural}`;

/**
 * The counts of one bucket: the spec's trio always (an empty bucket reads "0 errors, 0 warnings, 0
 * info"), and Critical and Verbose when there are any.
 */
export function describeCounts(bucket: HistogramBucket): string {
  const { counts } = bucket;
  const parts: string[] = [];
  if (counts.Critical > 0) parts.push(`${formatCount(counts.Critical)} critical`);
  parts.push(noun(counts.Error, "error", "errors"));
  parts.push(noun(counts.Warning, "warning", "warnings"));
  parts.push(`${formatCount(counts.Information)} info`);
  if (counts.Verbose > 0) parts.push(`${formatCount(counts.Verbose)} verbose`);
  return parts.join(", ");
}

/**
 * The tooltip, the slider's value text and the hidden table's first cell, one string so none can
 * disagree: `09:00-09:20 · 3 errors, 5 warnings, 40 info (UTC-05:00)`, the range with the spec's
 * separator. The zone is the bucket's own, so a bucket across a DST change says so.
 */
export function describeBucket(
  bucket: HistogramBucket,
  mode: EvtxTimeZoneMode,
  withYear = false,
): string {
  return (
    `${formatTimeRange(bucket.startMs, bucket.endMs, mode, withYear)} · ${describeCounts(bucket)} ` +
    `(${timeZoneLabel(mode, bucket.startMs)})`
  );
}

export interface AxisTick {
  /** Index of the edge the label sits on, 0 to the bucket count. */
  edgeIndex: number;
  /** 0 to 1 across the plot. */
  fraction: number;
  label: string;
}

const AXIS_TICKS = 7;

/**
 * Seven evenly spaced labels (spec 8.5), each on the nearest bucket edge so a label names a time a
 * brush can start or end at. Fewer when there are fewer than six buckets. Times carry their day when
 * the span crosses one, and seconds when buckets are under a minute.
 */
export function buildAxisTicks(histogram: EvtxHistogram, mode: EvtxTimeZoneMode): AxisTick[] {
  const count = histogram.edges.length - 1;
  const { domain } = histogram;
  if (count < 1 || domain === null) return [];
  const withSeconds = histogram.intervalMs < MINUTE;
  const crossesDays =
    eventDateKey(domain.startMs, mode) !== eventDateKey(Math.max(domain.startMs, domain.endMs - 1), mode);
  const ticks: AxisTick[] = [];
  const seen = new Set<number>();
  for (let step = 0; step < AXIS_TICKS; step += 1) {
    const edgeIndex = Math.round((step * count) / (AXIS_TICKS - 1));
    if (seen.has(edgeIndex)) continue;
    seen.add(edgeIndex);
    const at = histogram.edges[edgeIndex];
    ticks.push({
      edgeIndex,
      fraction: edgeIndex / count,
      label:
        crossesDays || histogram.showYear
          ? formatDayClock(at, mode, withSeconds, histogram.showYear)
          : formatClock(at, mode, withSeconds),
    });
  }
  return ticks;
}

/** The caption for records the chart cannot place. */
export function describeUntimed(untimed: number): string {
  return untimed === 1
    ? "1 event without a timestamp is not charted."
    : `${formatCount(untimed)} events without a timestamp are not charted.`;
}

/** The caption when events may be missing from the loaded set: an empty bar is then not a zero. */
export function describeCoverage(gaps: number): string {
  return `Counts cover loaded events only; ${gaps === 1 ? "1 gap" : `${formatCount(gaps)} gaps`} in this view may hide events.`;
}

export interface BarSegment {
  level: EvtxLevel;
  count: number;
  heightPx: number;
}

const segmentHeight = (count: number, pxPerEvent: number) =>
  count === 0 ? 0 : Math.max(MIN_SEGMENT_PX + SEPARATOR_PX, Math.round(count * pxPerEvent));

const stackHeight = (counts: LevelCounts, pxPerEvent: number) =>
  HISTOGRAM_STACK_ORDER.reduce((sum, level) => sum + segmentHeight(counts[level], pxPerEvent), 0);

/**
 * The largest pixels-per-event at which the tallest bucket still fits `areaPx`, floors included.
 * Every bucket is rounded the same way, so the tallest bucket at this scale is at most the area.
 */
export function fitScale(histogram: EvtxHistogram, areaPx = HISTOGRAM_BAR_AREA_PX): number {
  if (histogram.maxTotal === 0) return 0;
  let low = 0;
  let high = areaPx;
  for (let step = 0; step < 24; step += 1) {
    const middle = (low + high) / 2;
    const fits = histogram.buckets.every((bucket) => stackHeight(bucket.counts, middle) <= areaPx);
    if (fits) low = middle;
    else high = middle;
  }
  return low;
}

/** The non-empty segments of a bucket, bottom to top, with their pixel heights at `pxPerEvent`. */
export function bucketSegments(bucket: HistogramBucket, pxPerEvent: number): BarSegment[] {
  const segments: BarSegment[] = [];
  for (const level of HISTOGRAM_STACK_ORDER) {
    const count = bucket.counts[level];
    if (count > 0) segments.push({ level, count, heightPx: segmentHeight(count, pxPerEvent) });
  }
  return segments;
}
